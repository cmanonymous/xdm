#define pr_fmt(fmt) "node_syncer: " fmt
//#define DEBUG_IO

#include <linux/kthread.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_packet.h"
#include "hadm_thread.h"

#include "bwr.h"
#include "bio_handler.h"
#include "dbm.h"
#include "bio_helper.h"
#include "buffer.h"
#include "fullsync.h"
#include "utils.h"
#include "../include/common_string.h"

void sync_write_endio(struct bio *bio, int err)
{
	int count;
        struct bwr *bwr = bio->bi_private;
	struct bwr_data *bwr_data;

	if (err == 0) {
		bwr_data = (struct bwr_data *)page_private(bio->bi_io_vec[0].bv_page);
		count = buffer_inuse_del(bwr->hadmdev->buffer, bwr_data);
		if (count < 0) {
			pr_err("local_site sync error.\n");
			dump_buffer_inuse(bwr->hadmdev->buffer);
			dump_buffer_data(bwr->hadmdev->buffer);
			hadmdev_set_error(bwr->hadmdev);
			//BUG();
		}
		if (count > 0)
			bwr_site_head_add(bwr, get_site_id(), count);
		IO_DEBUG("sync bwr_data %llu(%lu:%lu) finished.\n",
				bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector,
				bwr_data->meta.dev_sector);
	} else {
		pr_err("%s io error %d.", __FUNCTION__, err);
	}

	bio_put(bio);
}

int sync_local_bwrdata(struct bwr *bwr, struct bwr_data *bwr_data)
{
	struct bio *wbio;
	struct hadmdev *dev;
	DECLARE_COMPLETION_ONSTACK(compl);

	IO_DEBUG("local_site try sync data: %llu(%lu:%lu).\n",
			bwr_data->meta.bwr_seq,
			bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
	dev = bwr->hadmdev;
	wbio = bio_alloc(GFP_KERNEL, 1);
	if (wbio == NULL) {
		return -1;
	}

	wbio->bi_bdev = dev->bdev;
	wbio->bi_rw = WRITE;
	wbio->bi_sector = bwr_data->meta.dev_sector;
	wbio->bi_end_io = sync_write_endio;
        wbio->bi_private = bwr;

	if (bio_add_page(wbio, bwr_data->data_page, PAGE_SIZE, 0) != PAGE_SIZE) {
		goto err_wbio;
	}

	generic_make_request(wbio);
	return 0;

err_wbio:
	bio_put(wbio);
	return -1;
}

int sync_local_thread(void *arg)
{
	struct hadmdev *dev = arg;
	struct bwr_data *prev_data = NULL;
	struct bwr_data *snd_head_data = NULL;
	struct hadm_thread *thread = dev->threads[LOCAL_SYNC_HANDLER];

	pr_info("sync_local_thread is running\n");
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		if (down_timeout(&dev->buffer->data_sema, msecs_to_jiffies(100)) == -ETIME) {
			continue;
		}

		//msleep(3000);
		if (unlikely(!prev_data))
			snd_head_data = dev->buffer->inuse_head;
		else {
			snd_head_data = list_entry(prev_data->list.next, struct bwr_data, list);
			if (!bwr_data_inbuffer(prev_data))
				snd_head_data = dev->buffer->inuse_head;
			bwr_data_put(prev_data);
		}
		IO_DEBUG("get send_head_data: %llu(%lu:%lu). prev:%llu\n",
				bwr_data_seq(snd_head_data), snd_head_data->meta.bwr_sector, snd_head_data->meta.dev_sector,
				prev_data ? bwr_data_seq(prev_data) : 0);
		bwr_data_get(snd_head_data);
		prev_data = snd_head_data;
		sync_local_bwrdata(dev->bwr, snd_head_data);
	}

	if (prev_data)
		bwr_data_put(prev_data);
	/* thread exit */
	complete(&thread->ev_exit);
	return 0;
}

/* 发送包到对端 */
int sync_remote_thread(void *arg)
{
	struct hadmdev *dev = arg;
	struct bwr *bwr = dev->bwr;
	struct hadm_site *runsite;
	struct bwr_data *bwr_data;
	int online_secondary=0;
	int pack_sent, cstate, dstate, local_node_id;
	struct hadm_thread *thread=dev->threads[REMOTE_SYNC_HANDLER];

	pr_info("sync_remote_thread is running\n");

	local_node_id = get_site_id();

	init_completion(&bwr->have_snd_data);
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		pack_sent = 0;
		online_secondary=0;
		list_for_each_entry(runsite, &dev->hadm_site_list, site) {
			if (runsite->id == local_node_id)
				continue;
			cstate = hadm_site_get(runsite, SECONDARY_STATE, S_CSTATE);
			dstate = hadm_site_get(runsite, SECONDARY_STATE, S_DSTATE);
			if (cstate != C_SYNC || dstate != D_CONSISTENT)
				continue;
			online_secondary++;

			/* 当node数据发送完后，不发送 */
			bwr_data = get_send_head_data(bwr, runsite->id);
			if (bwr_data == NULL)
				continue;

			sync_site_bwrdata(runsite, bwr_data, P_SD_DATA);
			bwr_data_put(bwr_data);
			snd_head_condition_update(runsite, S_CSTATE, C_SYNC);
			pack_sent++;
		}

		/* 如果没有数据发送，则等待 */
		if (online_secondary==0) {
			msleep(200);
		}
		else if(pack_sent==0) {
			wait_for_completion_timeout(&bwr->have_snd_data,msecs_to_jiffies(1000));
		}
		schedule();
	}

	/* thread exit */
	complete(&thread->ev_exit);
	return 0;
}

/* 写本地dbm */
/* FIXME: dbm需要处理好并发、同步速度等问题，多个节点的情况下，
 * 同步写会拖慢整体速度, 需要重新设计
 */
int sync_dbm_thread(void *arg)
{
	int ret;
	struct hadmdev *dev = arg;
	struct bwr *bwr = dev->bwr;
	struct hadm_site *runsite;
	struct bwr_data *bwr_data;
	int dbm_written, dstate, cstate;
	unsigned long flags1, flags2;
	sector_t snd_head;
	struct hadm_thread *thread=dev->threads[DBM_SYNC_HANDLER];

	pr_info("sync dbm thread run.\n");
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		dbm_written = 0;
		list_for_each_entry(runsite, &dev->hadm_site_list, site) {
			if(runsite->id==get_site_id())
				continue;
			cstate = hadm_site_get(runsite, SECONDARY_STATE, S_CSTATE);
			dstate = hadm_site_get(runsite, SECONDARY_STATE, S_DSTATE);

			/* sync data to dbm in memory */
			if (cstate == C_STOPPED && dstate != D_CONSISTENT){
				bwr_data = get_send_head_data(bwr, runsite->id);
				if(bwr_data){
					/**set dbm/dbm_dbm bits in memory **/
					dbm_set_sector(runsite->dbm,bwr_data->meta.dev_sector);
					snd_head_condition_update(runsite, S_CSTATE, C_STOPPED);
					dbm_written++;
					bwr_data_put(bwr_data);
				}
			}

			if(time_to_flush_dbm(runsite->dbm)) {
				/*
				 * flush dbm 到磁盘，当完成后，将head置为sndhead
				 * 这个操作在delta_sync的时候也会进行，
				 */
				if (0 && runsite->dbm->last_dirty_record) {
					//IO_DEBUG("nr_bit:%d, last_nr_bit:%d.\n",
						//nr_bit, last_nr_bit);
					snd_head = hadm_site_get(runsite, SECONDARY_STATE, S_SND_HEAD);
					ret = dbm_store(runsite->dbm);
					if (ret < 0) {
						pr_err("sync bwr data faild.%d\n", ret);
						hadmdev_set_error(dev);
						break;
					} else if (ret > 0) {
						/* require two lock:
						 * node->s_state.lock
						 *	bwr->lock
						 */
						spin_lock_irqsave(&runsite->s_state.lock, flags1);
						dstate= __hadm_site_get(&runsite->s_state, S_DSTATE);
						cstate= __hadm_site_get(&runsite->s_state, S_CSTATE);

						if (dstate == D_INCONSISTENT && cstate== C_STOPPED) {
							write_lock_irqsave(&bwr->lock, flags2);
							__bwr_set_site_head(bwr, runsite->id, snd_head);
							write_unlock_irqrestore(&bwr->lock, flags2);
						}
						spin_unlock_irqrestore(&runsite->s_state.lock, flags1);
					}
				}
				async_bwr_meta(bwr);
				set_last_flush_time(runsite->dbm);
			}
		}

		/* 如果没有数据发送，则等待 */
		if (dbm_written == 0)
			msleep(200);
		else
			schedule();
	}

	/* thread exit */
	complete(&thread->ev_exit);
	return 0;
}
