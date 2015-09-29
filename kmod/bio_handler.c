#define pr_fmt(fmt) "bio_handler: " fmt
//#define DEBUG_IO

#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/tracepoint.h>
#include "hadm_tracing.h"

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "hadm_struct.h"
#include "hadm_thread.h"

#include "bio_handler.h"
#include "dbm.h"
#include "bwr.h"
#include "bio_helper.h"

void read_bio_data(void *dest, struct bio *src)
{
	struct bio_vec *vec;
	int i;
	void *p = dest, *ptr;

	bio_for_each_segment(vec, src, i) {
		ptr = page_address(vec->bv_page);
		memcpy(p, ptr + vec->bv_offset, vec->bv_len);
		p += vec->bv_len;
	}
}

void write_bio_data(struct bio *bio, void *src, size_t len)
{
	int i;
	struct bio_vec *vec;
	char *tmptr, *destptr;
	size_t minlen;

	tmptr = src;
	bio_for_each_segment(vec, bio, i) {
		destptr = page_address(vec->bv_page);
		minlen = min((unsigned int)len, vec->bv_len);
		memcpy(destptr + vec->bv_offset, tmptr, minlen);
		if (len < vec->bv_len)
			break;
		tmptr += minlen;
		len -= minlen;
	}
}

void hadm_free_bio(struct bio *bio)
{
	struct bio_vec *bvec;
	int i;

	bio_for_each_segment(bvec, bio, i) {
		__free_page(bvec->bv_page);
	}

	bio_put(bio);
}

/* 这里是文件系统的数据入口，用户将数据写入设备，将会在这个函数处理这些数据 */
MAKE_REQUEST_TYPE hadmdev_make_request(struct request_queue *q, struct bio *bio)
{
	int ret;
	struct bio_wrapper *wrapper;
	struct hadm_queue *wrapper_queue;
	bio_wrapper_end_io_t *endio;
	struct hadmdev *hadmdev;

	IO_DEBUG("%s: bio:%p, rw=%s, disk_sector=%llu, size=%u[qazz1]\n", __FUNCTION__,
			bio,
			bio_data_dir(bio) == READ ? "READ" : "WRITE",
			(unsigned long long)bio->bi_sector,
			bio->bi_size);
	hadmdev = find_hadmdev_by_minor(MINOR(bio->bi_bdev->bd_dev));
	if (!hadmdev) {
		pr_err("%s no such hadm device.\n", __FUNCTION__);
		goto fail;
	}
	if(hadmdev_error(hadmdev)){
		goto fail;
	}

	if (bio_data_dir(bio) == WRITE) {
		hadmdev->acct_info[W_BIO]++;
	} else {
		hadmdev->acct_info[R_BIO]++;
	}
	trace_make_request(NULL);

	endio = bio_data_dir(bio) == READ ? NULL: primary_data_end_io;
	wrapper_queue = hadmdev->bio_wrapper_queue[bio_data_dir(bio)];
	wrapper = init_bio_wrapper(bio, endio);
	if (!wrapper) {
		pr_err("%s hadm%d alloc wrapper faild.\n", __FUNCTION__, hadmdev->minor);
		goto fail;
	}

	if (bio_data_dir(bio) == READ) {
		submit_read_wrapper(wrapper);
		goto out;
	}

	bio_wrapper_prepare_io(wrapper);
try:
	ret = hadm_queue_push_timeout_fn(wrapper_queue, &wrapper->node,
			msecs_to_jiffies(1000),set_sync_mask, wrapper);
	if (ret < 0) {
		if (hadmdev_error(hadmdev)) {
			free_bio_wrapper(wrapper);
			goto fail;
		}
		if (ret == -EHADM_QUEUE_FREEZE)
			msleep(500);
		goto try;
	}
	if (bio_data_dir(bio) == WRITE) {
		IO_DEBUG("submit bio_wrapper %p, sync_mask = 0x%llx\n", wrapper, wrapper->sync_node_mask);

	}
out:
	MAKE_REQUEST_RETURN(0);
fail:
	bio_endio(bio, -EIO);
	goto out;
}

/* 读写分离，异步读，同步写 */
int bio_read_handler_run(void *arg)
{
	struct hadmdev *dev = arg;
	struct bio_wrapper *bio_wrapper;
	struct hadm_queue *wrapper_queue;
	struct hadm_thread *bio_handler;

	bio_handler = dev->worker_thread[BIO_RD_HANDLER];
	wrapper_queue = dev->bio_wrapper_queue[HADM_IO_READ];

	while ((hadm_thread_get_state(bio_handler)) == HADM_THREAD_RUN) {
		bio_wrapper = hadm_queue_pop_entry_timeout(wrapper_queue,
				struct bio_wrapper, node, msecs_to_jiffies(1000));
		if (IS_ERR_OR_NULL(bio_wrapper)) {
			if (PTR_RET(bio_wrapper) == -EHADM_QUEUE_FREEZE)
				msleep(500);
			continue;
		}
		if (hadmdev_error(dev)) {
			bio_wrapper->err |= -EIO;
			bio_wrapper_end_io(bio_wrapper);
			continue;
		}

		submit_bio_wrapper(bio_wrapper);
	}
	hadm_thread_terminate(bio_handler);
	return 0;
}

int bio_write_handler_run(void *arg)
{
	struct hadmdev *dev = arg;
	struct bio_wrapper *bio_wrapper;
	struct hadm_queue *wrapper_queue;
	struct list_head *cur_node = NULL,  *cur_node_next = NULL;
	struct hadm_thread *bio_handler;
	unsigned long flags;
	static uint64_t last_sync_mask = 1, sync_mask;
	struct hadm_pack_node *ack_node = NULL;
	int local_node_id = get_node_id();


	bio_handler = dev->worker_thread[BIO_WR_HANDLER];
	wrapper_queue = dev->bio_wrapper_queue[HADM_IO_WRITE];
	hadm_queue_lock(wrapper_queue,flags, 1);
	cur_node_next = &wrapper_queue->head;
	wrapper_queue->private = NULL;
	hadm_queue_unlock(wrapper_queue,flags, 1);

	while ((hadm_thread_get_state(bio_handler)) == HADM_THREAD_RUN) {
		if(hadmdev_error(dev)){
			wrapper_queue_io_error(dev);
			msleep(2000);
			continue;
		}
		if(hadmdev_get_primary_id(dev) == local_node_id) {
			sync_mask = gen_sync_node_mask(dev);
			if(sync_mask != last_sync_mask) {
				pr_info("hadm%d sync mask is changed from 0x%llx to 0x%llx.\n",
						dev->minor,
						(unsigned long long)last_sync_mask,
						(unsigned long long)sync_mask);
				sync_mask_clear_queue(dev, sync_mask, last_sync_mask);
				last_sync_mask = sync_mask;
			}
		}

		hadm_queue_lock(wrapper_queue,flags, 1);
		if(wrapper_queue->unused == 0){
			hadm_queue_unlock(wrapper_queue,flags, 1);
			hadm_queue_wait_data_timeout(wrapper_queue, msecs_to_jiffies(1000));
			continue;
		}
		if(cur_node_next == &wrapper_queue->head) {
			if(wrapper_queue->private == NULL) {
				cur_node = cur_node_next->next;
			}else {
				cur_node = ((struct list_head *)wrapper_queue->private)->next;
			}
		}else {
			cur_node = cur_node_next;
		}
		if(cur_node == NULL || cur_node == &wrapper_queue->head) {
			pr_warn("%s: hadm%d wrapper_queue->unused = %d , but no data pop from wrapper_queue.\n",
					__FUNCTION__, dev->minor, wrapper_queue->unused);
			BUG();
		}
		cur_node_next = cur_node->next;
		wrapper_queue->private = cur_node;
		bio_wrapper = list_entry(cur_node, struct bio_wrapper , node);

		if(bio_wrapper->private){
			ack_node = (struct hadm_pack_node *)bio_wrapper->private;
			if(ack_node->pack->type == P_RS_DATA_ACK) {
				wrapper_queue->private = NULL;
				__hadm_queue_del_node(wrapper_queue, &bio_wrapper->node);
			}
		}
		wrapper_queue->unused --;
		hadm_queue_unlock(wrapper_queue,flags, 1);

		if (hadmdev_error(dev)) {
			continue;
		}
		//TODO: lock
		if (submit_bio_wrapper(bio_wrapper) < 0) {
			hadmdev_set_error(dev, __BWR_ERR);
			bio_wrapper->err |= -EIO;
		}
	}
	hadm_thread_terminate(bio_handler);
	return 0;
}
