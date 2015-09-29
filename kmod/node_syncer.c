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
#include "hadm_node.h"
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
			pr_err("local sync error.\n");
			hadmdev_set_error(bwr->hadmdev, __BDEV_ERR);
		}
		if (count > 0)
			bwr_node_head_add(bwr, get_node_id(), count);
	} else {
		pr_err("%s io error %d.", __FUNCTION__, err);
		hadmdev_set_error(bwr->hadmdev, __BDEV_ERR);
	}

	bio_put(bio);
}

int sync_local_bwrdata(struct bwr *bwr, struct bwr_data *bwr_data)
{
	struct bio *wbio;
	struct hadmdev *dev;
	DECLARE_COMPLETION_ONSTACK(compl);
	char *addr;

	addr = page_address(bwr_data->data_page);
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

#define META_FLUSH_INVL 1
int sync_local_thread(void *arg)
{
	struct hadmdev *dev = arg;
	struct bwr_data *prev_data = NULL;
	struct bwr_data *snd_head_data = NULL;
	struct hadm_thread *thread = dev->worker_thread[LOCAL_SYNC_HANDLER];
	unsigned long last_meta_flush_time = jiffies;

	pr_info("sync_local_thread is running\n");
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		if(hadmdev_error(dev)){
			msleep(2000);
			continue;
		}

		/**
		 *之所以在这里sync_disk_meta，是因为primary/secondary都要定时更新meta
		 *而secondary只启动sync_local_thread
		 */
		//FIXME secondary也操作buffer，因此该函数的无锁实现可能需要重新设计
		if(time_before(last_meta_flush_time + META_FLUSH_INVL * HZ, jiffies)) {
			sync_disk_meta(dev->bwr);
			last_meta_flush_time = jiffies;
		}
		if (down_timeout(&dev->buffer->data_sema, msecs_to_jiffies(100)) == -ETIME) {
			continue;
		}
		if (unlikely(!prev_data))
			snd_head_data = dev->buffer->inuse_head;
		else {
			snd_head_data = list_entry(prev_data->list.next, struct bwr_data, list);
			if (!bwr_data_inbuffer(prev_data))
				snd_head_data = dev->buffer->inuse_head;
			bwr_data_put(prev_data);
		}
		if(IS_ERR_OR_NULL(snd_head_data)) {
			continue;
		}
		bwr_data_get(snd_head_data);
		prev_data = snd_head_data;
		sync_local_bwrdata(dev->bwr, snd_head_data);
	}

	if (prev_data)
		bwr_data_put(prev_data);
	/* thread exit */
	hadm_thread_terminate(thread);
	return 0;
}

/* 发送包到对端 */
int sync_remote_thread(void *arg)
{
	struct hadmdev *dev = arg;
	struct bwr *bwr = dev->bwr;
	struct hadm_node *runnode;
	struct bwr_data *bwr_data;
	int online_secondary = 0;
	int node_disconnected = 0 ;
	int pack_sent, cstate, data_state, dstate, local_node_id;
	struct hadm_thread *thread=dev->worker_thread[REMOTE_SYNC_HANDLER];
	unsigned long flags;
	sector_t last_seq[MAX_NODES] = {0} ;

	pr_info("sync_remote_thread is running\n");

	local_node_id = get_node_id();
	//memset((void *)last_seq, 0, sizeof(sector_t) * MAX_NODES);

	init_completion(&bwr->have_snd_data);
	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		pack_sent = 0;
		online_secondary=0;
		if(hadmdev_error(dev)){
			msleep(2000);
			continue;
		}

		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if (runnode->id == local_node_id)
				continue;
			node_disconnected = 0 ;
			spin_lock_irqsave(&runnode->s_state.lock, flags);
			cstate = __hadm_node_get(&runnode->s_state, S_CSTATE);
			dstate = __hadm_node_get(&runnode->s_state, S_DSTATE);
			data_state = __hadm_node_get(&runnode->s_state, S_DATA_STATE);
			if(cstate != C_SYNC && runnode->conf.real_protocol == PROTO_SYNC) {
				pr_info("node %d's trans protocol change from SYNC TO ASYNC when cstate is not C_SYNC\n", runnode->id);
				runnode->conf.real_protocol = PROTO_ASYNC;
				node_disconnected = 1; 
			}
			spin_unlock_irqrestore(&runnode->s_state.lock, flags);

			if(node_disconnected) {
				last_seq[runnode->id] = 0;
				sync_mask_clear_after_node_disconnect(dev, runnode->id);
				continue;
			}

			if (cstate != C_SYNC || dstate != D_CONSISTENT || data_state != DATA_CONSISTENT){
				last_seq[runnode->id] = 0;
				continue;
			}
			online_secondary++;

			/* 当node数据发送完后，不发送 */
			bwr_data = get_send_head_data(bwr, runnode->id, last_seq[runnode->id]);
			if (bwr_data == NULL)
				continue;

			IO_DEBUG("%s:get send head data (snd_head = %llu, head = %llu) for node %d, bwr_data = %p, bwr_seq = %llu\n", 
					__FUNCTION__, 
					(unsigned long long)hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD), 
					(unsigned long long)bwr_node_head(bwr, runnode->id),
					runnode->id, bwr_data, bwr_data->meta.bwr_seq);
			if(last_seq[runnode->id] && bwr_data->meta.bwr_seq != last_seq[runnode->id] + 1) {
				pr_warn("%s: Bug occurs, sync node %d with unordered data. snd_head = %llu, last_seq = %llu, bwr_seq = %llu, bwr_data = %p.\n",
						__FUNCTION__, runnode->id ,
						(unsigned long long)hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD), 
						(unsigned long long)last_seq[runnode->id] ,
						(unsigned long long)bwr_data->meta.bwr_seq, bwr_data);
				bwr_dump(bwr);
				BUG();
			}
			last_seq[runnode->id] = bwr_data->meta.bwr_seq ;
			sync_node_bwrdata(runnode, bwr_data, P_DATA);
			bwr_data_put(bwr_data);
			snd_head_condition_update(runnode, S_CSTATE, C_SYNC);
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
	hadm_thread_terminate(thread);
	return 0;
}

/* 写本地dbm */
int sync_dbm_thread(void *arg)
{
	int ret;
	struct hadmdev *dev = arg;
	struct bwr *bwr = dev->bwr;
	struct hadm_node *runnode;
	struct bwr_data *bwr_data;
	int dbm_written, dstate , cstate;
	unsigned long flags1, flags2;
	sector_t snd_head;
	sector_t last_seq[MAX_NODES];
	struct hadm_thread *thread=dev->worker_thread[DBM_SYNC_HANDLER];

	pr_info("sync dbm thread run.\n");
	memset((void *)last_seq, 0, sizeof(sector_t) * MAX_NODES);

	while (hadm_thread_get_state(thread) == HADM_THREAD_RUN) {
		if(hadmdev_error(dev)){
			msleep(2000);
			continue;
		}
		dbm_written = 0;

		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if(runnode->id==get_node_id())
				continue;
			cstate = hadm_node_get(runnode, SECONDARY_STATE, S_CSTATE);
			dstate = hadm_node_get(runnode, SECONDARY_STATE, S_DSTATE);

			/* sync data to dbm in memory */
			/*
			 *这里将检测d_state改成data_state，主要是因为如果收到对端的io错误的信息后，
			 *会将对端的d_state改为D_FAIL，这时候是不应该触发写DBM的，只有当bwr满了之后
			 *才会触发写DBM
			 */
			if (cstate == C_STOPPED && dstate != D_CONSISTENT){
				if(!last_seq[runnode->id]){
					IO_DEBUG("%s: start to write dbm for node %d, snd_head=%llu, dstate=%d\n",
							__FUNCTION__, runnode->id, 
							hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD), dstate);
				}

				bwr_data = get_send_head_data(bwr, runnode->id, last_seq[runnode->id]);
				if(bwr_data){
					/**set dbm/dbm_dbm bits in memory **/
					last_seq[runnode->id] = bwr_data->meta.bwr_seq; 
					dbm_set_sector(runnode->dbm,bwr_data->meta.dev_sector);
					snd_head_condition_update(runnode, S_CSTATE, C_STOPPED);
					dbm_written++;
					bwr_data_put(bwr_data);
					/**
					pr_info("update_dbm:%d\t\t%llu\t\t%llu\t%llu\t\t%llu\t%llu\n",
						runnode->id,
						(unsigned long long)dev->bwr->mem_meta.tail, 
						(unsigned long long)dev->bwr->mem_meta.head[runnode->id],
						(unsigned long long)runnode->s_state.snd_head,
						(unsigned long long)runnode->s_state.snd_ack_head,
						(unsigned long long)last_seq[runnode->id]
						);
					**/


				}
			}else {
				last_seq[runnode->id] = 0 ;
			}

			if(time_to_flush_dbm(runnode->dbm)) {

				/*
				 * flush dbm 到磁盘，当完成后，将head置为sndhead
				 * 这个操作在delta_sync的时候也会进行，
				 */
				if (runnode->dbm->last_dirty_record) {
					//IO_DEBUG("nr_bit:%d, last_nr_bit:%d.\n",
						//nr_bit, last_nr_bit);
					ret = dbm_store(runnode->dbm);
					if (ret < 0) {
						pr_err("sync bwr data faild.%d\n", ret);
						hadmdev_set_error(dev, __BWR_ERR);
						break;
					}
				}
				/* require two lock:
				 * node->s_state.lock
				 *	bwr->lock
				 */
				spin_lock_irqsave(&runnode->s_state.lock, flags1);
				snd_head = __hadm_node_get(&runnode->s_state, S_SND_HEAD);
				dstate = __hadm_node_get(&runnode->s_state, S_DSTATE);
				cstate = __hadm_node_get(&runnode->s_state, S_CSTATE);

				if (dstate == D_INCONSISTENT && cstate== C_STOPPED) {
					write_lock_irqsave(&bwr->lock, flags2);
					__bwr_set_node_head(bwr, runnode->id, snd_head);
					write_unlock_irqrestore(&bwr->lock, flags2);
				}
				spin_unlock_irqrestore(&runnode->s_state.lock, flags1);
				set_last_flush_time(runnode->dbm);
				/**
				pr_info("time_to_flush_dbm(dstate:%s, cstate:%s):%d\t%llu\t%llu\t%llu\n",
						dstate_name[dstate], cstate_name[cstate], 
						runnode->id,
						(unsigned long long)dev->bwr->mem_meta.head[runnode->id],
						(unsigned long long)runnode->s_state.snd_head,
						(unsigned long long)runnode->s_state.snd_ack_head
						);
				**/

			}
		}

		/* 如果没有数据发送，则等待 */
		if (dbm_written == 0)
			msleep(200);
		else
			schedule();
	}

	/* thread exit */
	hadm_thread_terminate(thread);
	return 0;
}
