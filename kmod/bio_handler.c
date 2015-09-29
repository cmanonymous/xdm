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
#include "hadm_site.h"
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

int hadmdev_submit_master_bio(struct hadmdev *dev, struct bio *bio)
{
	int ret;
	struct bio_wrapper *wrapper;
	struct hadm_queue *wrapper_queue;

	wrapper = hadmdev_create_local_wrapper(dev, bio);
	if (wrapper == NULL) {
		pr_err("%s alloc wrapper faild.\n", __FUNCTION__);
		ret = -ENOMEM;
		goto out;
	}

	if (bio_data_dir(bio) == READ)
		wrapper_queue = dev->queues[RD_WRAPPER_Q];
	else
		wrapper_queue = dev->queues[WR_WRAPPER_Q];
	bio_wrapper_prepare_io(wrapper);
try:
	ret = hadm_queue_push_timeout(wrapper_queue, &wrapper->node,
			msecs_to_jiffies(1000));
	if (ret < 0) {
		if (hadmdev_error(dev)) {
			free_bio_wrapper(wrapper);
			goto out;
		}
		if (ret == -EHADM_QUEUE_FREEZE)
			msleep(500);
		goto try;
	}

out:
	return ret;
}

int hadmdev_submit_slaver_bio(struct hadmdev *dev, struct bio *bio)
{
	int ret;
	struct sbio *sbio;

	sbio = sbio_create(bio, GFP_KERNEL);
	if (!sbio)
		return -ENOMEM;

	ret = hadmdev_sbio_add(dev, sbio);
	if (ret < 0)
		goto out;
	else if (ret == 1)
		ret = hadmdev_sbio_send(dev, sbio);

out:
	return ret;
}

/* 这里是文件系统的数据入口，用户将数据写入设备，将会在这个函数处理这些数据 */
MAKE_REQUEST_TYPE hadmdev_make_request(struct request_queue *q, struct bio *bio)
{
	int ret;
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

	if (bio_data_dir(bio) == WRITE) {
		hadmdev->acct_info[W_BIO]++;
	} else {
		hadmdev->acct_info[R_BIO]++;
	}
	trace_make_request(NULL);

	if (hadmdev_local_master(hadmdev))
		ret = hadmdev_submit_master_bio(hadmdev, bio);
	else
		ret = hadmdev_submit_slaver_bio(hadmdev, bio);
	if (ret < 0)
		goto fail;

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

	bio_handler = dev->threads[BIO_RD_HANDLER];
	wrapper_queue = dev->queues[RD_WRAPPER_Q];

	while ((hadm_thread_get_state(bio_handler)) == HADM_THREAD_RUN) {
		bio_wrapper = hadm_queue_pop_entry_timeout(wrapper_queue,
				struct bio_wrapper, node, msecs_to_jiffies(1000));
		if (IS_ERR_OR_NULL(bio_wrapper)) {
			if (PTR_RET(bio_wrapper) == -EHADM_QUEUE_FREEZE)
				msleep(500);
			continue;
		}
		if (hadmdev_error(dev)) {
			bio_wrapper_end_io(bio_wrapper, -EIO);
			continue;
		}

		submit_bio_wrapper(bio_wrapper);
	}

	complete(&bio_handler->ev_exit);
	return 0;
}

int bio_write_handler_run(void *arg)
{
	struct hadmdev *dev = arg;
	struct bio_wrapper *bio_wrapper;
	struct hadm_queue *wrapper_queue;
	struct hadm_thread *bio_handler;

	bio_handler = dev->threads[BIO_WR_HANDLER];
	wrapper_queue = dev->queues[WR_WRAPPER_Q];

	while ((hadm_thread_get_state(bio_handler)) == HADM_THREAD_RUN) {
		bio_wrapper = hadm_queue_pop_entry_timeout(wrapper_queue,
				struct bio_wrapper, node, msecs_to_jiffies(1000));
		if (IS_ERR_OR_NULL(bio_wrapper)) {
			if (PTR_RET(bio_wrapper) == -EHADM_QUEUE_FREEZE)
				msleep(500);
			continue;
		}
		if (hadmdev_error(dev)) {
			bio_endio(bio_wrapper->bio, bio_wrapper->err);
			bio_wrapper_end_io(bio_wrapper, bio_wrapper->err);
			continue;
		}
		if (submit_bio_wrapper(bio_wrapper) < 0) {
			hadmdev_set_error(dev);
			bio_endio(bio_wrapper->bio, bio_wrapper->err);
			pr_err("BUG %s: bio io error. %d.\n", __FUNCTION__, bio_wrapper->err);
			bio_wrapper_end_io(bio_wrapper, bio_wrapper->err);
		}
#if 0
		/* FIXME sync model, implement in future. */
		sync_node_mask = gen_sync_node_mask(dev->bwr);
		if (sync_node_mask != last_mask) {
			pr_info("sync node mask changed: %llu -> %llu.\n", last_mask, sync_node_mask);
			last_mask = sync_node_mask;
		}

		if (submit_bio_wrapper(bio_wrapper) < 0)
			bio_wrapper->err = -EIO;
		if (!bio_wrapper->err) {
			if (sync_node_mask) {
				ret = wait_sync_node_finsh(dev->bwr);
			}
		} else {
			bio_endio(bio_wrapper->bio, bio_wrapper->err);
			pr_err("BUG %s: bio io error. %d.\n", __FUNCTION__, bio_wrapper->err);
		}
#endif

	}
	complete(&bio_handler->ev_exit);
	return 0;
}
