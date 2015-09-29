#define pr_fmt(fmt) "hadm_device: " fmt

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_node.h"
#include "hadm_socket.h"
#include "hadm_config.h"
#include "hadm_thread.h"

#include "bio_handler.h"
#include "dbm.h"
#include "bwr.h"
#include "node_syncer.h"
#include "bio_helper.h"
#include "buffer.h"
#include "p_worker.h"

extern const struct file_operations hadm_proc_fops;

static struct hadm_thread_info p_handler_threads[] = {
	[SITE_CTRL_WORKER] = { site_ctrl_worker, "sc_worker"},
	[SITE_DATA_WORKER] = { site_data_worker, "sd_worker"},
	[NODE_CTRL_WORKER] = { node_ctrl_worker, "nc_worker"},
	[NODE_DATA_WORKER] = { node_data_worker, "nd_worker"},

	[BIO_RD_HANDLER] = { bio_read_handler_run, "bio_rd"},
	[BIO_WR_HANDLER] = { bio_write_handler_run, "bio_wr"},
	[SLAVER_BIO_HANDLER] = { sbio_worker, "sbio_handler"},
	[LOCAL_SYNC_HANDLER] = { sync_local_thread, "lsync"},
	[REMOTE_SYNC_HANDLER] = { sync_remote_thread, "rsync"},
	[DBM_SYNC_HANDLER] = { sync_dbm_thread, "dbmsync"},
	[DBM_FLUSH_HANDLER] = { dbm_flusher, "dbmflush"},

	[HADMDEV_THREAD_MAX] = { NULL, NULL},
};

static struct hadm_queue_info hadmdev_queues[] = {
	[SITE_CTRL_Q] = { "sc_worker_q", MAX_QUEUE_LEN, hdpacket_queue_free},
	[SITE_DATA_Q] = { "sd_worker_q", MAX_QUEUE_LEN, hdpacket_queue_free},
	[NODE_CTRL_Q] = { "nc_worker_q", MAX_QUEUE_LEN, hdpacket_queue_free},
	[NODE_DATA_Q] = { "nd_worker_q", MAX_QUEUE_LEN, hdpacket_queue_free},

	/* sbio_queue->len * MAX_NODES <= node_send_q->len */
	[SBIO_Q] = { "sbio_q", 512, NULL},

	[RD_WRAPPER_Q] = { "read_wrapper_q", MAX_QUEUE_LEN, NULL},
	[WR_WRAPPER_Q] = { "write_wrapper_q", MAX_QUEUE_LEN, NULL},
	[SLAVER_SBIO_Q] = { "slaver_sbio_q", MAX_QUEUE_LEN, hdpacket_queue_free},

	[HADMDEV_QUEUE_MAX] = { NULL, 0, NULL},
};


int hadmdev_alloc_threads(struct hadmdev *dev)
{
	int i;
	char name[MAX_QUEUE_NAME];
	struct hadm_thread *thr;
	struct hadm_thread_info *thr_info;

	for (i = 0; i < HADMDEV_THREAD_MAX; i++) {
		thr_info = &p_handler_threads[i];

		thr = hadm_thread_alloc();
		if (!thr)
			goto err;
		memset(name, 0, sizeof(name));
		snprintf(name, MAX_QUEUE_NAME, "%s%02d", thr_info->name,
				dev->minor);
		hadm_thread_init(thr, name, thr_info->func, dev, NULL);
		dev->threads[i] = thr;
	}

	return 0;
err:
	hadmdev_free_threads(dev);
	return -ENOMEM;
}

void hadmdev_stop_threads(struct hadmdev *dev)
{
	int i;
	struct hadm_thread *thr;

	for (i = 0; i < HADMDEV_THREAD_MAX; i++) {
		thr = dev->threads[i];
		if (thr)
			hadm_thread_stop(thr);
	}
}

void hadmdev_free_threads(struct hadmdev *dev)
{
	int i;
	struct hadm_thread *thr;

	for (i = 0; i < HADMDEV_THREAD_MAX; i++) {
		thr = dev->threads[i];

		if (thr) {
			hadm_thread_free(&thr);
			dev->threads[i] = NULL;
		}
	}
}

void hadmdev_start_io_threads(struct hadmdev *dev)
{
	hadm_thread_start(dev->threads[LOCAL_SYNC_HANDLER]);
	hadm_thread_start(dev->threads[REMOTE_SYNC_HANDLER]);
	hadm_thread_start(dev->threads[SLAVER_BIO_HANDLER]);
	hadm_thread_start(dev->threads[BIO_RD_HANDLER]);
	hadm_thread_start(dev->threads[BIO_WR_HANDLER]);
	hadm_thread_start(dev->threads[DBM_SYNC_HANDLER]);
	hadm_thread_start(dev->threads[DBM_FLUSH_HANDLER]);
}

void hadmdev_stop_io_threads(struct hadmdev *dev)
{
	hadm_thread_stop(dev->threads[LOCAL_SYNC_HANDLER]);
	hadm_thread_stop(dev->threads[REMOTE_SYNC_HANDLER]);
	hadm_thread_stop(dev->threads[SLAVER_BIO_HANDLER]);
	hadm_thread_stop(dev->threads[BIO_RD_HANDLER]);
	hadm_thread_stop(dev->threads[BIO_WR_HANDLER]);
	hadm_thread_stop(dev->threads[DBM_SYNC_HANDLER]);
	hadm_thread_stop(dev->threads[DBM_FLUSH_HANDLER]);
}

int hadmdev_alloc_queues(struct hadmdev *dev)
{
	int i;
	char name[MAX_QUEUE_NAME];
	struct hadm_queue *q;
	struct hadm_queue_info *q_info;

	for (i = 0; i < HADMDEV_QUEUE_MAX; i++) {
		q_info = &hadmdev_queues[i];

		memset(name, 0, sizeof(name));
		snprintf(name, MAX_QUEUE_NAME, "%s%02d", q_info->name,
				dev->minor);
		q = hadm_queue_create(name, q_info->len);
		if (!q)
			goto err;
		dev->queues[i] = q;
	}

	return 0;
err:
	hadmdev_free_queues(dev);
	return -ENOMEM;
}

void hadmdev_freeze_queues(struct hadmdev *dev)
{
	int i;
	struct hadm_queue *q;

	for (i = 0; i < HADMDEV_QUEUE_MAX; i++) {
		q = dev->queues[i];
		if (q)
			hadm_queue_freeze_all(q);
	}
}

void hadmdev_free_queues(struct hadmdev *dev)
{
	int i;
	struct hadm_queue *q;
	struct hadm_queue_info *q_info;

	for (i = 0; i < HADMDEV_QUEUE_MAX; i++) {
		q = dev->queues[i];
		q_info = &hadmdev_queues[i];

		if (q) {
			if (q_info->free)
				q_info->free(q);
			else
				hadm_queue_free(q);
			dev->queues[i] = NULL;
		}
	}
}

void hadmdev_free_disk(struct hadmdev *dev)
{
	del_gendisk(dev->disk);
	put_disk(dev->disk);
	blk_cleanup_queue(dev->rq);
	set_device_ro(dev->bdev, 0);
	blkdev_put(dev->bdev, HADMDEV_MODE);

	dev->disk = NULL;
	dev->rq = NULL;
	dev->bdev = NULL;
}

void hadmdev_free(struct hadmdev *dev)
{
	if (dev->disk)
		hadmdev_free_disk(dev);

	if (dev->bwr)
		free_bwr(dev->bwr);

	if (atomic_read(&dev->hadm_site_list_len))
		hadmdev_site_list_clear(dev);

	if (atomic_read(&dev->hadm_node_list_len))
		hadmdev_node_list_clear(dev);

	if (dev->threads)
		hadmdev_free_threads(dev);

	if (dev->queues)
		hadmdev_free_queues(dev);

	if (dev->buffer)
		free_data_buffer(dev->buffer);
}

void hadmdev_put(struct hadmdev *dev)
{
	pr_info("%s: free resource %s.\n", __func__, dev->name);

	hadmdev_freeze_queues(dev);

	hadmdev_stop_threads(dev);

	hadmdev_free(dev);
}

struct hadmdev *hadmdev_alloc(int gfp_mask)
{
	int ret;
	struct hadmdev *dev;

	dev = kzalloc(sizeof(*dev), gfp_mask);
	if (!dev)
		return NULL;

	mutex_init(&dev->lock);
	INIT_LIST_HEAD(&dev->node);
	atomic_set(&dev->openers, 0);

	INIT_LIST_HEAD(&dev->hadm_site_list);
	spin_lock_init(&dev->hadm_site_list_lock);
	atomic_set(&dev->hadm_site_list_len, 0);
	spin_lock_init(&dev->primary_lock);

	INIT_LIST_HEAD(&dev->hadm_node_list);
	atomic_set(&dev->hadm_node_list_len, 0);
	spin_lock_init(&dev->hadm_node_list_lock);
	spin_lock_init(&dev->master_lock);

	ret = hadmdev_alloc_threads(dev);
	if (ret < 0)
		goto err;

	ret = hadmdev_alloc_queues(dev);
	if (ret < 0)
		goto err;

	dev->buffer = init_data_buffer(MAX_QUEUE_LEN, dev);
	if (!dev->buffer)
		goto err;

	dev->bwr = bwr_alloc(GFP_KERNEL);
	if (!dev->bwr)
		goto err;
	dev->bwr->hadmdev = dev;

	return dev;
err:
	hadmdev_free(dev);
	return NULL;
}

int hadmdev_init(struct hadmdev *dev)
{
	return 0;
}

static int hadmdev_open(struct block_device *bdev, fmode_t mode)
{
	int role, ret = 0;
	int notify = 0;
	struct hadmdev *dev;
	struct hadm_node *master;

	dev = bdev->bd_disk->private_data;

	master = hadmdev_get_master(dev);

	mutex_lock(&dev->lock) ;
	role = hadm_site_get(dev->local_site, SECONDARY_STATE, S_ROLE);
	if (role == R_SECONDARY) {
		ret = -EPERM;
	} else {
		/* role == R_PRIMARY || (role == R_SECONDARY && (mode & FMOD_READ)) */
		//BUG_ON(!master);
		if (atomic_inc_return(&dev->openers) == 1)
			if (master && master != dev->local_node)
				notify = 1;
	}

	mutex_unlock(&dev->lock);

	if (notify)
		hadmdev_send_node_state(dev, master);

	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
static int hadmdev_release(struct gendisk *gd, fmode_t mode)
#else
static void hadmdev_release(struct gendisk *gd, fmode_t mode)
#endif
{
	int notify = 0;
	struct hadmdev *dev;
	struct hadm_node *master;

	dev = gd->private_data;
	master = hadmdev_get_master(dev);

	mutex_lock(&dev->lock) ;
	if (atomic_dec_and_test(&dev->openers)) {
		if (master && master != dev->local_node)
			notify = 1;
	}
	mutex_unlock(&dev->lock);

	if (notify)
		hadmdev_send_node_state(dev, master);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
	return 0;
#endif
}

int hadmdev_opened(struct hadmdev *dev)
{
	int ret;

	mutex_lock(&dev->lock);
	ret = atomic_read(&dev->openers);
	mutex_unlock(&dev->lock);

	return !!ret;
}

static struct block_device_operations hadmdev_fops = {
	.owner = THIS_MODULE,
	.open = hadmdev_open,
	.release = hadmdev_release,
};

int hadm_attach_device(struct hadmdev *dev, int major, int minor,
		       char *virtual_device_name, char *low_disk_name)
{
	int ret = 0;
	struct request_queue *q;
	struct gendisk *d;
	uint64_t disk_size;
	struct block_device *bdev;

	hadm_site_set(dev->local_site, SECONDARY_STATE, S_ROLE, R_SECONDARY);

	bdev = blkdev_get_by_path(low_disk_name, HADMDEV_MODE, dev);
	if (IS_ERR(bdev)) {
		pr_err("hadm_attach_device: open %s failed\n", low_disk_name);
		ret = -EBUSY;
		goto err_bdev;
	}

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		ret = -ENOMEM;
		goto err_queue;
	}
	blk_queue_make_request(q, hadmdev_make_request);

	d = alloc_disk(1);	/* no partition */
	if (!d) {
		ret = -ENOMEM;
		goto err_disk;
	}
	snprintf(d->disk_name, sizeof(d->disk_name), "%s", virtual_device_name);
	d->major = major;
	d->first_minor = minor;
	d->fops = &hadmdev_fops;
	d->queue = q;
	d->private_data = dev;	/* for open/release function */
	/**align disk to 16M to avoid dbm overflow**/
	disk_size = (i_size_read(bdev->bd_inode) >> 24) << 15; // FIXME
	set_device_ro(bdev, 1);
	set_capacity(d, disk_size);

	dev->bdev = bdev;
	dev->rq = q;
	dev->disk = d;
	dev->bdev_disk_size = disk_size;

	add_disk(dev->disk);
	pr_info("%s attach to %s(bdev=%p), minor=%d, size=%llu(sectors)*512\n",
		dev->name, low_disk_name, dev->bdev, minor,dev->bdev_disk_size);
	return 0;

err_disk:
	blk_cleanup_queue(q);
err_queue:
	blkdev_put(bdev, HADMDEV_MODE);
err_bdev:
	return ret;
}

void hadm_detach_device(struct hadmdev *dev)
{
	if (dev == NULL || IS_ERR(dev))
		return;
	if (dev->local_site == NULL || IS_ERR(dev->local_site))
		return;
	if (dev->disk != NULL && !IS_ERR(dev->disk)) {
		del_gendisk(dev->disk);
		put_disk(dev->disk);
		dev->disk = NULL;
	}
	if (dev->rq != NULL && !IS_ERR(dev->rq)) {
		blk_cleanup_queue(dev->rq);
		dev->rq = NULL;
	}
	if (dev->bdev != NULL && !IS_ERR(dev->bdev)) {
		set_device_ro(dev->bdev, 0);
		blkdev_put(dev->bdev, HADMDEV_MODE);
		dev->bdev = NULL;
	}
}

void hadmdev_site_add(struct hadmdev *dev, struct hadm_site *hadm_site)
{
	spin_lock(&dev->hadm_site_list_lock);
	list_add_tail(&hadm_site->site, &dev->hadm_site_list);
	atomic_inc(&dev->hadm_site_list_len);
	pr_info("add site:%s id:%u, proto:%u, ip:%s, disk:%s, bwr_disk:%s.\n",
			hadm_site->conf.name,
			hadm_site->id,
			hadm_site->conf.protocol,
			hadm_site->conf.ipaddr,
			hadm_site->conf.disk,
			hadm_site->conf.bwr_disk);
	spin_unlock(&dev->hadm_site_list_lock);
}

void hadmdev_site_del(struct hadmdev *dev, struct hadm_site *hadm_site)
{
	spin_lock(&dev->hadm_site_list_lock);
	list_del(&hadm_site->site);
	atomic_dec(&dev->hadm_site_list_len);
	spin_unlock(&dev->hadm_site_list_lock);
}

/* FIXME need config? or just res_config? */
int hadmdev_create_site_list(struct hadmdev *dev, struct config *cfg)
{
	int idx;
	struct res_config *res_cfg;
	//struct site_config *site_cfg;
	struct runsite_config *rsite_cfg;
	struct hadm_site *site;

	res_cfg = find_resource(cfg, dev->minor);
	if (!res_cfg) {
		pr_err("%s: no such resource.\n", __func__);
		goto err;
	}

	for (idx = 0; idx < res_cfg->runsite_num; idx++) {
		rsite_cfg = &res_cfg->runsites[idx];
		/*
		// need site_cfg?
		site_cfg = find_site(cfg, rsite_cfg->id);
		if (!site_cfg) {
			pr_err("%s: no site correspond runsite id %d.\n",
					__func__, rsite_cfg->id);
			goto err;
		}
		*/
		pr_info("%s: site: %d %s.\n", __func__, rsite_cfg->id,
				rsite_cfg->disk);
		site = hadm_site_create(rsite_cfg->id, rsite_cfg->proto,
				rsite_cfg->disk, rsite_cfg->bwr_disk);
		if (!site) {
			pr_err("%s: create site(%d) failed.\n", __func__,
					rsite_cfg->id);
			goto err;
		}
		if (site->id == get_site_id())
			dev->local_site = site;

		site->hadmdev = dev;
		hadmdev_site_add(dev, site);
	}

	if (!dev->local_site) {
		pr_err("%s: no local site(%d).\n", __func__, get_site_id());
		goto err;
	}

	return 0;

err:
	hadmdev_site_list_clear(dev);
	return -1;
}

int hadmdev_site_list_init(struct hadmdev *dev)
{
	struct dbm *dbm;
	struct hadm_site *site, *tmp;

	list_for_each_entry_safe(site, tmp, &dev->hadm_site_list, site) {
		hadm_site_reset_send_head(site);
		dbm = dbm_create(
			dev->bwr_bdev, dev->bwr->disk_meta.dbm_start, site,
			dev->bdev_disk_size << HADM_SECTOR_SHIFT, GFP_NOWAIT);
		if (!dbm) {
			pr_err("create node %d dbm failed\n", site->id);
			return -ENOMEM;
		}
	}

	return 0;
}

void hadmdev_site_list_clear(struct hadmdev *dev)
{
	struct hadm_site *site, *tmp;

	spin_lock(&dev->hadm_site_list_lock);
	list_for_each_entry_safe(site, tmp, &dev->hadm_site_list, site) {
		list_del(&site->site);
		hadm_site_free(site);
	}
	atomic_set(&dev->hadm_site_list_len, 0);
	spin_unlock(&dev->hadm_site_list_lock);
}

void hadmdev_node_add(struct hadmdev *dev, struct hadm_node *hadm_node)
{
	spin_lock(&dev->hadm_node_list_lock);
	list_add_tail(&hadm_node->node, &dev->hadm_node_list);
	atomic_inc(&dev->hadm_node_list_len);
	pr_info("add node:%s id:%u, ip:%s.\n",
			hadm_node->name,
			hadm_node->id,
			hadm_node->ipaddr);

	spin_unlock(&dev->hadm_node_list_lock);
}

void hadmdev_node_del(struct hadmdev *dev, struct hadm_node *hadm_node)
{
	spin_lock(&dev->hadm_node_list_lock);
	list_del(&hadm_node->node);
	atomic_dec(&dev->hadm_node_list_len);
	spin_unlock(&dev->hadm_node_list_lock);
}

struct hadm_node *hadmdev_node_find(struct hadmdev *dev, int id)
{
	struct hadm_node *iter;

	list_for_each_entry(iter, &dev->hadm_node_list, node) {
		if (iter->id == id)
			return iter;
	}

	return NULL;
}

void hadmdev_node_connect(struct hadmdev *dev, struct hadm_node *node)
{
	set_hadm_node_connect(node);
}

void hadmdev_node_disconnect(struct hadmdev *dev, struct hadm_node *node)
{
	int master;

	/* master_lock
	 *	-> primary_lock
	 *	-> site_state_lock
	 */
	master = 0;
	spin_lock(&dev->master_lock);
	if (dev->master == node) {
		master = 1;
		if (hadmdev_local_primary(dev)) {
			set_disk_ro(dev->disk, true);
			hadmdev_set_primary(dev, NULL);
			hadm_site_set(dev->local_site, SECONDARY_STATE, S_ROLE,
					R_SECONDARY);
		}

		pr_info("%s clear master(%s(%d))\n",
				__FUNCTION__, node->name, node->id);
		dev->master = NULL;
	} else {
		clear_hadm_node_open(node);
	}
	spin_unlock(&dev->master_lock);

	if (master)
		/* since master disconnect, we need return sbio -EIO */
		hadmdev_sbio_clear(dev);

	//hadmdev_slaver_primary_run(dev);

	hadm_node_disconnect(node);
}

void hadmdev_node_list_clear(struct hadmdev *dev)
{
	struct hadm_node *node, *tmp;

	spin_lock(&dev->hadm_node_list_lock);
	list_for_each_entry_safe(node, tmp, &dev->hadm_node_list, node) {
		list_del(&node->node);
	}
	atomic_set(&dev->hadm_node_list_len, 0);
	spin_unlock(&dev->hadm_node_list_lock);
}

int hadmdev_create_node_list(struct hadmdev *dev, struct site_config *site_cfg)
{
	int idx;
	struct node_config *node_cfg;
	struct hadm_node *node;

	for (idx = 0; idx < site_cfg->node_num; idx++) {
		node_cfg = &site_cfg->nodes[idx];
		node = hadm_node_create(node_cfg->id, node_cfg->hostname,
				node_cfg->ipaddr);
		if (!node) {
			pr_err("%s: node create failed.\n", __func__);
			goto err;
		}
		if (node->id == get_node_id())
			dev->local_node = node;
		node->hadmdev = dev;
		hadmdev_node_add(dev, node);
	}

	if (!dev->local_node) {
		pr_err("%s: no local node find(%d).\n", __func__, get_node_id());
		goto err;
	}

	return 0;

err:
	hadmdev_node_list_clear(dev);
	return -1;
}

void hadmdev_disconnect_all(struct hadmdev *dev)
{
	struct hadm_site *site_iter;
	struct hadm_node *node_iter;

	list_for_each_entry(site_iter, &dev->hadm_site_list, site)
		if (site_iter->id != get_site_id())
			disconnect_site(site_iter);
	list_for_each_entry(node_iter, &dev->hadm_node_list, node)
		if (node_iter->id != get_node_id())
			hadmdev_node_disconnect(dev, node_iter);
}

/* FIXME */
int hadmdev_stop_site_all(struct hadmdev *dev)
{
	struct hadm_site *site_iter;

	list_for_each_entry(site_iter, &dev->hadm_site_list, site) {
		if (site_iter->id == get_site_id())
			continue;
		hadm_thread_stop(site_iter->delta_sync);
	}

	hadm_queue_freeze_all(dev->queues[SITE_CTRL_Q]);
	hadm_queue_freeze_all(dev->queues[SITE_DATA_Q]);
	hadm_thread_stop(dev->threads[SITE_DATA_WORKER]);
	hadm_thread_stop(dev->threads[SITE_CTRL_WORKER]);

	return 0;
}

void hadmdev_wait_io_finish(struct hadmdev *dev)
{
	/* wrapper include local/remote io */
	hadm_queue_try_wait_empty(dev->queues[WR_WRAPPER_Q]);
	hadm_queue_try_wait_empty(dev->queues[RD_WRAPPER_Q]);

	/* not necessary, but why not */
	hadm_queue_try_wait_empty(dev->queues[SLAVER_SBIO_Q]);
}

int hadmdev_clean_site_pack(struct hadmdev *dev)
{
	hdpacket_queue_clean(dev->queues[SITE_DATA_Q]);
	hdpacket_queue_clean(dev->queues[SITE_CTRL_Q]);

	return 0;
}

int hadmdev_set_master(struct hadmdev *dev, struct hadm_node *master)
{
	int ret = 0;

	spin_lock(&dev->master_lock);
	if (!dev->master || !master)
		dev->master = master;
	else if (dev->master == master)
		ret = 1;
	else
		ret = -1;
	spin_unlock(&dev->master_lock);

	return ret;
}

struct hadm_node *hadmdev_get_master(struct hadmdev *dev)
{
	struct hadm_node *master;

	spin_lock(&dev->master_lock);
	master = dev->master;
	spin_unlock(&dev->master_lock);

	return master;
}

int hadmdev_local_master(struct hadmdev *dev)
{
	int ret;

	spin_lock(&dev->master_lock);
	ret = dev->master == dev->local_node;
	spin_unlock(&dev->master_lock);

	return ret;
}

void set_io_fail_flag(struct block_device *bdev)
{
	struct hadmdev *dev;

	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		if (dev->bwr_bdev == bdev) {
			set_bit(BWR_FAILED_BIT,&dev->ioflags);
			return;
		} else if (dev->bdev == bdev) {
			set_bit(BDEV_FAILED_BIT,&dev->ioflags);
			return ;
		}
	}
	pr_warn("%s:no device io flag is set.\n",__FUNCTION__);
}

int io_failed(struct hadmdev *dev)
{
	return dev->ioflags!=0;
}

int hadmdev_get_nr_dbm_node(struct hadmdev *dev)
{
	struct hadm_site *hadm_site;
	int nr_node, data_state, local_node_id;

	nr_node = 0;
	local_node_id = get_site_id();
	list_for_each_entry(hadm_site, &dev->hadm_site_list, site) {
		if (hadm_site->id == local_node_id)
			continue;
		data_state = hadm_site_get(hadm_site, SECONDARY_STATE, S_DATA_STATE);
		if (data_state == DATA_DBM)
			nr_node += 1;
	}

	return nr_node;
}

struct hadm_site *hadmdev_get_primary(struct hadmdev *dev)
{
	struct hadm_site *primary;

	spin_lock(&dev->primary_lock);
	primary = dev->primary;
	spin_unlock(&dev->primary_lock);

	return primary;
}

/* 只允许清空primary，或者在没有primary的情况下设置primary
 * FIXME
 * 为区分当前primary节点和要设置的节点是同一节点的情况，加入返回值1
 * */
int hadmdev_set_primary(struct hadmdev *dev, struct hadm_site *primary)
{
	int ret = 0;

	spin_lock(&dev->primary_lock);
	if (!dev->primary || !primary)
		dev->primary = primary;
	else if (dev->primary == primary)
		ret = 1;
	else
		ret = -1;
	spin_unlock(&dev->primary_lock);

	return ret;
}

static int hadmdev_slaver_primary_run(struct hadmdev *dev)
{
	return 0;
}

int hadmdev_set_slaver_master(struct hadmdev *dev, struct hadm_node *master)
{
	int err;
	unsigned long flags;
	struct sbio *tail_send = NULL;
	struct sbio *iter, *tmp;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	/* ->master_lock
	 *	->sbio_queue.lock
	 */
	err = 0;
	spin_lock(&dev->master_lock);
	if (dev->master) {
		if (!master) {
			/* clear master */
			dev->master = NULL;
			spin_lock_irqsave(&q->lock, flags);
			clear_hadm_queue_inwork(q);
			spin_unlock_irqrestore(&q->lock, flags);
		}
		else if (dev->master != master) {
			pr_err("%s: have a master %d.\n",
					__func__, dev->master->id);
			err = -EKMOD_MASTER_EXIST;
		}
	} else {
		if (master) {
			/* set master */
			dev->master = master;
			spin_lock_irqsave(&q->lock, flags);
			set_hadm_queue_inwork(q);
			tail_send = list_entry(q->head.prev, struct sbio, list);
			spin_unlock_irqrestore(&q->lock, flags);
		}
	}
	spin_unlock(&dev->master_lock);

	if (tail_send) {
		/* send pending sbio, no need lock */
		list_for_each_entry_safe(iter, tmp, &q->head, list) {
			err = hadmdev_sbio_send(dev, iter);
			if (err < 0)
				break;
			if (iter == tail_send)
				break;
		}
	}

	return err;
}

int hadmdev_do_slaver_primary(struct hadmdev *dev)
{
	int ret = 0;
	struct hadm_site *local_site;

	local_site = dev->local_site;
	ret = hadmdev_set_primary(dev, local_site);
	if (ret != 0)
		return -1;
	hadm_site_set(local_site, SECONDARY_STATE, S_ROLE, R_PRIMARY);
	set_disk_ro(dev->disk,false);

	hadmdev_slaver_primary_run(dev);

	return 0;
}

int hadmdev_do_slaver_secondary(struct hadmdev *dev)
{
	set_disk_ro(dev->disk, true);
	hadm_site_set(dev->local_site, SECONDARY_STATE, S_ROLE, R_SECONDARY);

	return hadmdev_set_primary(dev, NULL);
}

int hadmdev_get_primary_id(struct hadmdev *dev)
{
	int id;

	spin_lock(&dev->primary_lock);
	if (dev->primary == NULL || IS_ERR(dev->primary)) {
		id = INVALID_ID;
		spin_unlock(&dev->primary_lock);
		goto done;
	}
	id = dev->primary->id;
	spin_unlock(&dev->primary_lock);

done:
	return id;
}

int hadmdev_local_primary(struct hadmdev *dev)
{
	int ret;

	spin_lock(&dev->primary_lock);
	ret = dev->primary == dev->local_site;
	spin_unlock(&dev->primary_lock);

	return ret;
}

int get_nr_primary(struct hadmdev *hadmdev)
{
	struct hadm_site *hadm_site;
	int role, nr_primary, state;

	nr_primary = 0;
	list_for_each_entry(hadm_site, &hadmdev->hadm_site_list, site) {
		state = !hadm_site_get(hadm_site, PRIMARY_STATE, S_INVALID)
			? PRIMARY_STATE : SECONDARY_STATE;
		role = hadm_site_get(hadm_site, state, S_ROLE);
		if (role == R_PRIMARY)
			nr_primary += 1;
	}

	return nr_primary;
}

unsigned long hadmdev_get_connect_nodes(struct hadmdev *dev)
{
	unsigned long node_map = 0;
	struct hadm_node *node_iter;

	list_for_each_entry(node_iter, &dev->hadm_node_list, node) {
		if (node_iter->id == get_node_id())
			continue;
		set_bit(node_iter->id, &node_map);
	}

	return node_map;
}

int hadmdev_send_node_state_request(struct hadmdev *dev, struct hadm_node *node)
{
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pack = node_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack)
		return -ENOMEM;
	head = &pack->head;
	head->type = P_NC_STATE_REQ;
	if (node)
		head->node_to = 1 << node->id;
	else
		head->node_to = hadmdev_get_connect_nodes(dev);

	if (hadm_queue_push(q, &pack->list) < 0) {
		pr_err("%s: push state packet faild.\n", __FUNCTION__);
		hdpacket_free(pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

/* FIXME: node state
 * master -> node
 * node -> master
 */
int hadmdev_send_node_state(struct hadmdev *dev, struct hadm_node *node)
{
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pack = node_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack)
		return -ENOMEM;
	head = &pack->head;
	head->type = P_NC_STATE;
	if (node)
		head->node_to = 1 << node->id;
	else
		head->node_to = hadmdev_get_connect_nodes(dev);

	/* 1:true 0:false */
	if (hadmdev_local_primary(dev))
		head->primary = 1;

	if (hadmdev_local_master(dev))
		head->master = 1;

	if (hadmdev_opened(dev))
		head->open = 1;

	if (hadm_queue_push(q, &pack->list) < 0) {
		pr_err("%s: push state packet faild.\n", __FUNCTION__);
		hdpacket_free(pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

int hadmdev_send_master_notify(struct hadmdev *dev)
{
	return hadmdev_send_node_state(dev, NULL);
}

int hadmdev_send_slaver_notify(struct hadmdev *dev)
{
	return hadmdev_send_node_state(dev, NULL);
}

struct hdpacket *hadmdev_create_site_state_packet(struct hadmdev *hadmdev)
{
	int nr_sites;
	size_t datalen;
	uint32_t node_to;
	int local_site_id;
	struct packet *head;
	struct hdpacket *pack;
	struct hadm_site *hadm_site;
	struct site_state_packet *ns_pack;

	nr_sites = atomic_read(&hadmdev->hadm_site_list_len);
	datalen = nr_sites * sizeof(struct site_state_packet);
	local_site_id = get_site_id();
	node_to = get_connected_sites(hadmdev);
	if (!node_to)
		return NULL;

	pack = site_hdpacket_alloc(GFP_KERNEL, datalen, HADM_DATA_NORMAL);
	if (!pack)
		return NULL;
	head = &pack->head;
	head->type = P_SC_STATE;
	head->dev_id = hadmdev->minor;
	head->node_to = node_to;
	head->site_state_num = nr_sites;
	head->bwr_seq = bwr_seq(hadmdev->bwr);
	head->uuid = bwr_uuid(hadmdev->bwr);

	ns_pack = (struct site_state_packet *)pack->data->buff;
	list_for_each_entry(hadm_site, &hadmdev->hadm_site_list, site) {
		hadm_site_state_pack(ns_pack, &hadm_site->s_state);
		ns_pack += 1;
	}

	return pack;
}

/* Just send state packet to connected nodes */
int hadmdev_send_primary_notify(struct hadmdev *dev)
{
	return hadmdev_send_node_state(dev, NULL);
}

int hadmdev_send_site_state(struct hadmdev *hadmdev)
{
	struct hdpacket *state_pack;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	state_pack = hadmdev_create_site_state_packet(hadmdev);
	if (!state_pack)
		return -ENOMEM;

	if (hadm_queue_push(q, &state_pack->list) < 0) {
		pr_err("%s: queue freezen", __FUNCTION__);
		hdpacket_free(state_pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

int hadmdev_packet_handler_type(int linktype, struct packet *pack)
{
	int handler_type = -1;
	int packet_type = pack->type;

	if (linktype == P_CTRL_TYPE) {
		if (packet_type >= P_SC_START
				&& packet_type <= P_SC_END)
			handler_type = SITE_CTRL_Q;
		else if (packet_type >= P_NC_START &&
				packet_type <= P_NC_END)
			handler_type = NODE_CTRL_Q;
	} else if (linktype == P_DATA_TYPE) {
		if (packet_type >= P_SD_START
				&& packet_type <= P_SD_END)
			handler_type = SITE_DATA_Q;
		else if (packet_type >= P_ND_START &&
				packet_type <= P_ND_END)
			handler_type = NODE_DATA_Q;
	}

	return handler_type;
}

#define MAX_RETRIES  10
int all_secondary_up2date(struct hadmdev * hadmdev)
{
	int retry=0;
	struct hadm_site *hadm_site;
	int node_not_uptodate=0;

	while(retry++<MAX_RETRIES) {
		node_not_uptodate=0;
		list_for_each_entry(hadm_site, &hadmdev->hadm_site_list, site) {
			if(C_SYNC==hadm_site_get(hadm_site,SECONDARY_STATE,S_CSTATE)) {
				node_not_uptodate++;
				if(is_uptodate(hadmdev->bwr,hadm_site->id)) {
					node_not_uptodate--;
				}
			}
		}
		if(node_not_uptodate==0)
			return 1;
		msleep(1000);
	}

	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)
void hadm_flush_device(struct block_device *bdev)
{
	//blkdev_issue_flush(bdev, GFP_KERNEL, NULL);
	//invalidate_inode_pages2(bdev->bd_inode->i_mapping);
}
#else
void hadm_flush_device(struct block_device *bdev)
{
	//blkdev_issue_flush(bdev, NULL);
	//invalidate_inode_pages2(bdev->bd_inode->i_mapping);
}
#endif

int hadmdev_sbio_add(struct hadmdev *dev, struct sbio *sbio)
{
	return hadm_queue_work_push(dev->queues[SBIO_Q], &sbio->list);
}

struct sbio *hadmdev_sbio_search(struct hadmdev *dev, sector_t dev_sector)
{
	unsigned long flags;
	struct sbio *sbio;
	struct sbio *result = NULL;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	spin_lock_irqsave(&q->lock, flags);
	list_for_each_entry_reverse(sbio, &q->head, list) {
		if (sbio->bio->bi_sector == dev_sector) {
			result = sbio;
			break;
		}
	}
	spin_unlock_irqrestore(&q->lock, flags);

	return result;
}

struct sbio *hadmdev_sbio_search_pop(struct hadmdev *dev, sector_t dev_sector)
{
	unsigned long flags;
	struct sbio *sbio;
	struct sbio *result = NULL;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	spin_lock_irqsave(&q->lock, flags);
	list_for_each_entry_reverse(sbio, &q->head, list) {
		if (sbio->bio->bi_sector == dev_sector) {
			list_del_init(&sbio->list);
			q->len--;
			if (waitqueue_active(&q->push_waitqueue))
				wake_up(&q->push_waitqueue);

			result = sbio;
			break;
		}
	}
	spin_unlock_irqrestore(&q->lock, flags);

	return result;
}

int hadmdev_sbio_clear(struct hadmdev *dev)
{
	unsigned long flags;
	struct sbio *sbio;
	struct sbio *tmp;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	spin_lock_irqsave(&q->lock, flags);
	list_for_each_entry_safe(sbio, tmp, &q->head, list) {
		bio_endio(sbio->bio, -EIO);
		list_del_init(&sbio->list);
		sbio_free(sbio);
	}
	spin_unlock_irqrestore(&q->lock, flags);

	return 0;
}

/* slaver became master */
int __hadmdev_sbio_list_submit(struct hadmdev *dev)
{
	//unsigned long flags;
	struct sbio *sbio;
	struct sbio *tmp;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	/* called after became master, so no others will modify this queue */
	//spin_lock_irqsave(&q->lock, flags);
	list_for_each_entry_safe(sbio, tmp, &q->head, list) {
		hadmdev_submit_master_bio(dev, sbio->bio);
		list_del_init(&sbio->list);
		sbio_free(sbio);
	}
	//spin_unlock_irqrestore(&q->lock, flags);

	return 0;
}

int hadmdev_sbio_list_send(struct hadmdev *dev)
{
	unsigned long flags;
	struct sbio *sbio;
	struct sbio *tmp;
	struct list_head send_list;
	struct hadm_queue *q = dev->queues[SBIO_Q];

	spin_lock_irqsave(&q->lock, flags);
	list_cut_position(&send_list, &q->head, q->head.prev);
	spin_unlock_irqrestore(&q->lock, flags);

	list_for_each_entry_safe(sbio, tmp, &send_list, list) {
		hadmdev_sbio_send(dev, sbio);
		list_del_init(&sbio->list);
		sbio_free(sbio);
	}

	return 0;
}

int hadmdev_sbio_send(struct hadmdev *dev, struct sbio *sbio)
{
	int ret;
	int idx, vcnt;
	struct bio_vec *bvec;
	struct packet *head;
	struct hdpacket *pack;
	struct hadm_node *master;
	struct bio *bio = sbio->bio;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	master = hadmdev_get_master(dev);
	if (unlikely(!master)) {
		pr_err("%s: master disconnect", __FUNCTION__);
		return -EKMOD_NONODE;
	}

	if (bio_data_dir(bio) == READ)
		vcnt = 0;
	else
		vcnt = bio->bi_vcnt;
	pack = node_hdpacket_alloc(GFP_KERNEL, vcnt, HADM_DATA_PAGE);
	if (!pack) {
		pr_err("%s: pack create faild.", __FUNCTION__);
		return -ENOMEM;
	}
	head = &pack->head;
	head->node_to = 1 << master->id;
	head->type = P_ND_SBIO;

	head->dev_sector = bio->bi_sector;
	head->bi_flags = bio->bi_flags & HADM_BIO_FLAGS_MASK;
	head->bi_rw = bio->bi_rw;
	head->bi_size = bio->bi_size;

	if (bio_data_dir(bio) == WRITE) {
		for (idx = 0; idx < vcnt; idx++) {
			bvec = &sbio->bio->bi_io_vec[idx];
			if (bvec->bv_offset || bvec->bv_len != PAGE_SIZE)
				pr_info("%s: unregular page.offset:%d. len:%d.\n",
						__FUNCTION__, bvec->bv_offset, bvec->bv_len);

			get_page(bvec->bv_page);
			ret = hdpacket_add_page(pack, bvec->bv_page, bvec->bv_offset,
					bvec->bv_len);
			if (ret < 0) {
				pr_err("%s: add page data failed.%d\n",
						__FUNCTION__, ret);
				goto free_pack;
			}
		}
	}

	ret = hadm_queue_push(q, &pack->list);
	if (ret < 0)
		goto free_pack;

	return 0;

free_pack:
	hdpacket_free(pack);
	return ret;
}

void hadmdev_sbio_packet_end(struct hadmdev *dev,
		struct hdpacket *sbio_pack, int err)
{
	struct hadm_queue *q = dev->queues[SLAVER_SBIO_Q];

	if (sbio_pack->head.bi_rw & WRITE) {
		/* FIXME clear here or before send? IRQ */
		hdpacket_clear_data(sbio_pack);
	}

	if (hadm_queue_push_nowait(q, &sbio_pack->list) < 0) {
		/* we guarentee the size by peer node
		 * q->maxlen = MAX_NODES * dev->sbio_queue->max_len
		 * */
		pr_err("%s: add sbio reply packet failed.\n", __func__);
		hdpacket_free(sbio_pack);
	}
}
