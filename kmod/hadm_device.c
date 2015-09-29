#define pr_fmt(fmt) "hadm_device: " fmt

#include <linux/blkdev.h>
#include <linux/module.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "hadm_socket.h"
#include "hadm_packet.h"
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

void hadmdev_list_add(struct hadmdev *dev, struct hadm_node *hadm_node)
{
	spin_lock(&dev->hadm_node_list_lock);
	list_add_tail(&hadm_node->node, &dev->hadm_node_list);
	atomic_inc(&dev->hadm_node_list_len);
	spin_unlock(&dev->hadm_node_list_lock);
}

void hadmdev_list_del(struct hadmdev *dev, struct hadm_node *hadm_node)
{
	spin_lock(&dev->hadm_node_list_lock);
	list_del(&hadm_node->node);
	atomic_dec(&dev->hadm_node_list_len);
	spin_unlock(&dev->hadm_node_list_lock);
}

void set_io_fail_flag(struct block_device *bdev)
{
	struct hadmdev *dev;

	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		if (dev->bwr_bdev == bdev) {
			hadmdev_set_error(dev, __BWR_ERR);
			return ;
		} else if (dev->bdev == bdev) {
			hadmdev_set_error(dev, __BDEV_ERR);
			return ;
		}
	}
	pr_warn("%s:no device io flag is set.\n",__FUNCTION__);
}


int hadmdev_get_nr_dbm_node(struct hadmdev *dev)
{
	struct hadm_node *hadm_node;
	int nr_node, dstate, local_node_id;

	nr_node = 0;
	local_node_id = get_node_id();
	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		if (hadm_node->id == local_node_id)
			continue;
		dstate = hadm_node_get(hadm_node, SECONDARY_STATE, S_DSTATE);
		if (dstate == D_INCONSISTENT)
			nr_node += 1;
	}

	return nr_node;
}

uint32_t get_hs_nodes(struct hadmdev *dev)
{
	unsigned long node_to;
	struct hadm_node *hadm_node;

	node_to = 0;
	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		if (hadm_node->id == g_hadm->local_node_id)
			continue;
		if (hadm_node_get(hadm_node, SECONDARY_STATE, S_HANDSHAKE)
				== HS_SUCCESS)
			set_bit(hadm_node->id, &node_to);
	}

	return node_to;
}

struct hadm_node *hadmdev_get_primary(struct hadmdev *dev)
{
	struct hadm_node *primary;

	spin_lock(&dev->primary_lock);
	primary = dev->primary;
	spin_unlock(&dev->primary_lock);

	return primary;
}

int hadmdev_local_primary(struct hadmdev *dev)
{
	int ret;

	spin_lock(&dev->primary_lock);
	ret = dev->primary == dev->local;
	spin_unlock(&dev->primary_lock);

	return ret;
}

/* 只允许清空primary，或者在没有primary的情况下设置primary */
int hadmdev_set_primary(struct hadmdev *dev, struct hadm_node *primary)
{
	int ret = 0;

	spin_lock(&dev->primary_lock);
	if (!dev->primary || !primary)
		dev->primary = primary;
	else
		ret = -1;
	spin_unlock(&dev->primary_lock);

	return ret;
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

int get_nr_primary(struct hadmdev *hadmdev)
{
	struct hadm_node *hadm_node;
	int role, nr_primary, state;

	nr_primary = 0;
	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		state = !hadm_node_get(hadm_node, PRIMARY_STATE, S_INVALID)
			? PRIMARY_STATE : SECONDARY_STATE;
		role = hadm_node_get(hadm_node, state, S_ROLE);
		if (role == R_PRIMARY)
			nr_primary += 1;
	}

	return nr_primary;
}

int be_primary(int dev_id,int force)
{
	struct hadmdev *hadmdev;
	struct hadm_node *runnode;
	unsigned long flags;
	char name[0x0f];
	int local_node_id, nr_bit, data_state, dstate;
	int i=0;
	int len;

	hadmdev = find_hadmdev_by_minor(dev_id);
	if (hadmdev == NULL) {
		return -EKMOD_NODEV;
	}

	if (hadmdev->bwr->mem_meta.disk_state != D_CONSISTENT) {
		return -EKMOD_BAD_DSTATE;		/* FIXME BAD_DSTATE ? */
	}

	if(hadmdev->primary && !force)
	{
		return -EKMOD_LOCAL_ROLE;
	}
    /**stop p_data io thread in secondary,  if exists**/
#if 0
	if(hadmdev->p_data_io_thread) {
		hadm_thread_stop(hadmdev->p_data_io_thread);
		hadm_thread_free(&hadmdev->p_data_io_thread);
	}
#endif
	while((len = hadm_queue_len(hadmdev->bio_wrapper_queue[HADM_IO_WRITE]))>0){
		pr_info("%s: waiting all previous primary data write to disk, data remain %d blocks in bio_queue.\n", __FUNCTION__, len);
		if(hadmdev_error(hadmdev)){
			return -EIO;
		}
		msleep(2000);
	}
	set_disk_ro(hadmdev->disk,false);
	hadm_node_set(hadmdev->local, SECONDARY_STATE, S_ROLE, R_PRIMARY);
	hadmdev_set_primary(hadmdev, hadmdev->local);
	set_local_primary(hadmdev, get_node_id(), jiffies);
	buffer_set_io_completed_seq(hadmdev->buffer, bwr_seq(hadmdev->bwr));
	buffer_set_tail_seq(hadmdev->buffer, bwr_seq(hadmdev->bwr));

	/* initialize each node state */
	/* require two lock:
	 * hadmdev->hadm_node_list_lock
	 *	node->s_state.lock
	 */
	local_node_id = get_node_id();
	spin_lock(&hadmdev->hadm_node_list_lock);
	list_for_each_entry(runnode, &hadmdev->hadm_node_list, node) {
		if (runnode->id == local_node_id)
			continue;
		nr_bit = atomic_read(&runnode->dbm->nr_bit);
		spin_lock_irqsave(&runnode->s_state.lock, flags);
		data_state = nr_bit > 0 ? DATA_DBM : DATA_CONSISTENT;
		dstate =  nr_bit > 0 ? D_INCONSISTENT : D_CONSISTENT;
		__hadm_node_set(&runnode->s_state, S_DATA_STATE, data_state);
		__hadm_node_set(&runnode->s_state, S_DSTATE, dstate);
		__hadm_node_set(&runnode->s_state, S_CSTATE, C_STOPPED);
		runnode->conf.real_protocol = PROTO_ASYNC;
		spin_unlock_irqrestore(&runnode->s_state.lock, flags);
		pr_info("%s: init node %d's state, dbm->nr_bit=%d, dstate=%d\n",
				__FUNCTION__, runnode->id, nr_bit, dstate);
	}
	spin_unlock(&hadmdev->hadm_node_list_lock);
	for(i=0; i<HADMDEV_THREAD_NUM; i++) {
		if(hadmdev_threads[i].primary_only && ! hadmdev_threads[i].disabled)
		{
			snprintf(name,0x0f,"%s%02d",hadmdev_threads[i].name,hadmdev->minor);
			hadm_thread_init(hadmdev->worker_thread[i],name,hadmdev_threads[i].func,(void *)hadmdev,NULL);
			hadm_thread_run(hadmdev->worker_thread[i]);
		}
	}

	return 0;
}

int be_secondary(int dev_id, int force)
{
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	int role,error;
	int i=0;

	pr_info("set device %d to secondary , force=%d\n", dev_id, force);

	hadmdev = find_hadmdev_by_minor(dev_id);
	if (hadmdev == NULL) {
		pr_err("%s no such device.\n", __FUNCTION__);
		error = -EKMOD_NODEV;
		return error;
	}

	role = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		pr_err("%s Not primary.\n", __FUNCTION__);
		error = -EKMOD_NOT_PRIMARY;
		return error;
	}

	mutex_lock(&hadmdev->lock);
	if (atomic_read(&hadmdev->openers) > 0) {
		pr_err("%s device is inuse(eg: mount).\n", __FUNCTION__);
		error = -EKMOD_INUSE;
		mutex_unlock(&hadmdev->lock);
		return error;
	}
	set_disk_ro(hadmdev->disk,true);
	if(!force&&!all_secondary_up2date(hadmdev))
	{
		pr_err("%s remain not uptodate node(no force model).\n", __FUNCTION__);
		error = -EKMOD_INSYNC;
		mutex_unlock(&hadmdev->lock);
		return error;
	}

	hadmdev_set_primary(hadmdev, NULL);
	hadm_node_set(hadmdev->local, SECONDARY_STATE, S_ROLE, R_SECONDARY);
	mutex_unlock(&hadmdev->lock);

	hadmdev_send_node_state(hadmdev);

	for(i=0;i<HADMDEV_THREAD_NUM;i++) {
		if(hadmdev_threads[i].primary_only) {
			hadm_thread_stop(hadmdev->worker_thread[i]);
			hadm_thread_join(hadmdev->worker_thread[i]);
		}
	}
	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		hadm_thread_stop(hadm_node->delta_sync);
		hadm_thread_join(hadm_node->delta_sync);
		hadm_thread_free(&hadm_node->delta_sync);
		hadm_node_set(hadm_node, SECONDARY_STATE, S_HANDSHAKE, HS_FAIL);
	}
	clear_data_buffer(hadmdev->buffer);
	return 0;

}


int hadmdev_send_node_state(struct hadmdev *hadmdev)
{
	struct packet *state_pack;

	state_pack = packet_alloc_node_state_packet(hadmdev);
	if (state_pack == NULL || IS_ERR(state_pack))
		return -ENOMEM;
	packet_send(state_pack);

	return 0;
}

void hadmdev_put(struct hadmdev *dev)
{
	struct hadm_node *hadm_node, *tmp;
	int i;

	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		hadm_node_set(hadm_node, SECONDARY_STATE, S_HANDSHAKE, HS_FAIL);
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
		hadm_thread_stop(hadm_node->delta_sync);
		hadm_thread_join(hadm_node->delta_sync);
		hadm_thread_free(&hadm_node->delta_sync);
	}


	for (i = 0; i < P_HANDLER_NUM; i++) {
		hadm_queue_freeze_all(dev->p_receiver_queue[i]);
		hadm_queue_freeze_all(dev->p_sender_queue[i]);
	}

	for(i=0; i < HADMDEV_THREAD_NUM; i++) {
		hadm_thread_stop(dev->worker_thread[i]);
	}
	for(i=0; i < HADMDEV_THREAD_NUM; i++) {
		hadm_thread_join(dev->worker_thread[i]);
	}


	hadm_detach_device(dev);
	//hadm_node_set(dev->local, SECONDARY_STATE, S_DEV_STATE, DEV_DOWN);

	free_bwr(dev->bwr);
	dev->bwr = NULL;

	list_for_each_entry_safe(hadm_node, tmp, &dev->hadm_node_list, node) {
		list_del(&hadm_node->node);
		hadm_node_free(hadm_node);
	}
	for(i=0; i < HADMDEV_THREAD_NUM; i++) {
		hadm_thread_free(&dev->worker_thread[i]);
	}


	for(i=0;i<2;i++) {
		hadm_pack_queue_clean(dev->p_receiver_queue[i]);
		hadm_queue_free(dev->p_receiver_queue[i]);
		hadm_pack_queue_clean(dev->p_sender_queue[i]);
		hadm_queue_free(dev->p_sender_queue[i]);

	}
	free_data_buffer(dev->buffer);

	kfree(dev);
}

struct hadmdev *hadmdev_alloc(int gfp_mask)
{
	struct hadmdev *dev;
	int i;
	char name[MAX_QUEUE_NAME];
	/**TODO exceptions**/

	dev = kzalloc(sizeof(*dev), gfp_mask);
	if (dev == NULL)
		return ERR_PTR(-ENOMEM);
	memset(dev, 0, sizeof(*dev));

	dev->bwr = bwr_alloc(sizeof(struct bwr), GFP_KERNEL);
	dev->bwr->hadmdev = dev;

	for (i = 0; i < HADM_IO_DIR_NUM; i++) {
		memset(name, 0, MAX_QUEUE_NAME);
		snprintf(name, MAX_QUEUE_NAME, "BWrapper_%s_queue",
				i == HADM_IO_READ ? "read" : "write");
		dev->bio_wrapper_queue[i] = hadm_queue_create(name, MAX_BIO_QUEUE_SIZE);
	}
	dev->buffer = init_data_buffer(MAX_BWR_CACHE_SIZE, dev);	/* warning:  256(max bio page) <= buffer->max_size < bwr disk size */

	for (i = 0; i < P_HANDLER_NUM; i++) {
		snprintf(name, MAX_QUEUE_NAME, "%s_recvq%02d",
			 (i == P_CTRL_WORKER) ? "ctrl" : "data", dev->minor);
		dev->p_receiver_queue[i] = hadm_queue_create(name, MAX_QUEUE_LEN);
		snprintf(name, MAX_QUEUE_NAME, "%s_sendq%02d",
			 (i == P_CTRL_WORKER) ? "ctrl" : "data", dev->minor);
		dev->p_sender_queue[i] = hadm_queue_create(name, MAX_QUEUE_LEN);

	}
	/**
	 *因为在up的时候是先分配内存，然后init bwr，最后启动线程
	 *如果init bwr失败，需要stop线程，这时候thread只是alloc，并没有
	 *init，rmmod就会有问题
	 */
	for (i = 0; i< HADMDEV_THREAD_NUM; i++) {
		dev->worker_thread[i] = NULL;
	}

	/* Primary related threads */


	dev->primary = NULL;
	dev->minor = 0;
	dev->state = 0;
	INIT_LIST_HEAD(&dev->node);
	INIT_LIST_HEAD(&dev->hadm_node_list);
	atomic_set(&dev->hadm_node_list_len, 0);
	atomic_set(&dev->openers, 0);
	atomic_set(&dev->bwr_io_pending, 0);
	atomic_set(&dev->async_io_pending[READ], 0);
	atomic_set(&dev->async_io_pending[WRITE], 0);
	spin_lock_init(&dev->hadm_node_list_lock);
	mutex_init(&dev->lock);
	spin_lock_init(&dev->primary_lock);

	return dev;
}

struct hadm_thread_info hadmdev_threads[] = {
	[P_CTRL_TYPE] = { p_ctrl_worker_run, "ctrl_worker", 0, 0},
	[P_DATA_TYPE] = { p_data_worker_run, "data_worker", 0, 0},
	[BIO_RD_HANDLER] = {bio_read_handler_run, "biord", 1, 0},
	[BIO_WR_HANDLER] = {bio_write_handler_run, "biowr", 0, 0},
	[LOCAL_SYNC_HANDLER] = {sync_local_thread, "lsync", 0, 0},
	[REMOTE_SYNC_HANDLER] = {sync_remote_thread, "rsync", 1, 0},
	[DBM_SYNC_HANDLER] = {sync_dbm_thread, "dbmsync", 1, 0},
};

int hadmdev_init(struct hadmdev *dev)
{
	char name[0x0f];
	int i=0;

	if (dev->local == NULL || IS_ERR(dev->local)) {
		pr_err("hadmdev_init: minor %d don't have a local node\n", dev->minor);
		return -ENODEV;
	}
	for(i=0; i < HADMDEV_THREAD_NUM; i++) {
		dev->worker_thread[i] = hadm_thread_alloc();
		if(!hadmdev_threads[i].primary_only && !hadmdev_threads[i].disabled){
			snprintf(name,0x0f,"%s%02d",hadmdev_threads[i].name,dev->minor);
			hadm_thread_init(dev->worker_thread[i],name,hadmdev_threads[i].func,(void *)dev,NULL);
			hadm_thread_run(dev->worker_thread[i]);
		}

	}
	return 0;
}

static int hadmdev_open(struct block_device *bdev, fmode_t mode)
{
	int role, ret = 0;
	struct hadmdev *dev;

	dev = bdev->bd_disk->private_data;

	mutex_lock(&dev->lock);
	role = hadm_node_get(dev->local, SECONDARY_STATE, S_ROLE);
	if (role == R_SECONDARY)
		ret = -EPERM;
	/* role == R_PRIMARY || (role == R_SECONDARY && (mode & FMOD_READ)) */
	if (ret == 0)
		atomic_inc(&dev->openers);
	mutex_unlock(&dev->lock);

	return ret;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
static int hadmdev_release(struct gendisk *gd, fmode_t mode)
#else
static void hadmdev_release(struct gendisk *gd, fmode_t mode)
#endif
{
	struct hadmdev *dev;

	dev = gd->private_data;
	atomic_dec(&dev->openers);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(3,5,0)
	return 0;
#endif
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
	struct block_device *bdev;

	hadm_node_set(dev->local, SECONDARY_STATE, S_ROLE, R_SECONDARY);

	bdev = blkdev_get_by_path(low_disk_name, HADMDEV_MODE, dev);
	if (IS_ERR(bdev)) {
		pr_err("hadm_attach_device: open %s failed\n", low_disk_name);
		ret = -EBUSY;
		goto err_bdev;
	}
	dev->bdev = bdev;

	q = blk_alloc_queue(GFP_KERNEL);
	if (!q) {
		ret = -ENOMEM;
		goto err_queue;
	}
	blk_queue_make_request(q, hadmdev_make_request);
	/**
	 *应该禁掉的是bwr的merge func
	 */
//	blk_queue_merge_bvec(q, NULL);
	dev->rq = q;

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
	dev->disk = d;
	/**align disk to 16M to avoid dbm overflow**/
	dev->bdev_disk_size = (i_size_read(bdev->bd_inode)>>24)<<15;
	set_capacity(dev->disk,dev->bdev_disk_size);

	add_disk(dev->disk);
	pr_info("%s attach to %s(bdev=%p), minor=%d, size=%llu(sectors)*512, queue(%p)->merge_bvec_fn = %p\n",
		dev->name, low_disk_name, dev->bdev, minor,dev->bdev_disk_size, q, q->merge_bvec_fn);
	return 0;

err_disk:
	blk_cleanup_queue(q);
err_queue:
	blkdev_put(bdev, HADMDEV_MODE);
err_bdev:
	unregister_blkdev(major, virtual_device_name);
	return ret;
}

void hadm_detach_device(struct hadmdev *dev)
{
	if (dev == NULL || IS_ERR(dev))
		return;
	if (dev->local == NULL || IS_ERR(dev->local))
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
		blkdev_put(dev->bdev, HADMDEV_MODE);
		dev->bdev = NULL;
	}

	if (dev->bwr_bdev != NULL && !IS_ERR(dev->bwr_bdev)) {
		blkdev_put(dev->bwr_bdev, BWRDEV_MODE);
		dev->bwr_bdev = NULL;
	}

}

#define MAX_RETRIES  60

int all_secondary_up2date(struct hadmdev * hadmdev)
{
	int retry=0;
	struct hadm_node *hadm_node;
	int node_not_uptodate = 0;

	while(retry++ < MAX_RETRIES) {
		node_not_uptodate = 0;
		list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
			if(C_STOPPED != hadm_node_get(hadm_node, SECONDARY_STATE,S_CSTATE)) {
				node_not_uptodate ++;
				if(is_uptodate(hadmdev->bwr, hadm_node->id) &&
						atomic_read(&hadm_node->dbm->nr_bit) == 0) {
					node_not_uptodate --;
				}
			}
		}
		if(node_not_uptodate == 0)
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
