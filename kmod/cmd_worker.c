#define pr_fmt(fmt) "cmd_worker: " fmt

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/list.h>

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_node.h"
#include "hadm_packet.h"
#include "hadm_socket.h"
#include "hadm_thread.h"

#include "dbm.h"
#include "fullsync.h"
#include "bwr.h"
#include "utils.h"
#include "primary_info.h"
#include "bio_handler.h"
#include "node_syncer.h"
#include "buffer.h"
#include "p_worker.h"

static int be_secondary(int dev_id,int force);
static int __response(struct socket *to, int type, int dev_id, int error)
{
	int ret;
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q;

	pack = hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack)
		return -ENOMEM;
	pack->private = to;

	head = &pack->head;
	head->type = type;
	head->dev_id = dev_id;
	head->errcode = error;

	q = g_hadm->p_sender_queue[P_CMD_TYPE];
	ret = hadm_queue_push(q, &pack->list);
	if (ret < 0) {
		if (ret == -EHADM_QUEUE_FREEZE)
			pr_err("%s: queue freezen", __FUNCTION__);
		hadm_socket_close(to);
		hadm_socket_release(to);
		hdpacket_free(pack);
	}

	return ret;
}

static struct hadmdev *cmd_worker_config_create_hadm_struct(struct hdpacket *pack)
{
	int err = 0;
	int local_site_id;
	uint64_t bwr_max_sector;
	struct config *cfg;
	struct res_config *res_cfg;
	struct hadmdev *dev = NULL;
	struct conf_packet *conf_pack = (struct conf_packet *)pack->data->buff;
	struct site_config *site_cfg;

	cfg = unpack_config(conf_pack);
	pr_config(cfg);

	local_site_id = cfg->local_site_id;
	g_hadm->local_site_id = local_site_id;
	g_hadm->local_node_id = cfg->local_node_id;

	/* 每次只config一个设备 */
	res_cfg = find_resource(cfg, pack->head.dev_id);
	if (!res_cfg) {
		pr_err("%s: no local_site node in resource map\n", __func__);
		goto done;
	}

	pr_info("%s get resource:%s id:%d|data_len:%llu|meta_offset:%llu|"
			"dbm_offset:%llu|dbm_size:%llu|bwr_offset:%llu|"
			"bwr_disk_size:%llu|runsite_num:%d.\n",
			__FUNCTION__, res_cfg->name, res_cfg->id,
			res_cfg->data_len, res_cfg->meta_offset,
			res_cfg->dbm_offset, res_cfg->dbm_size,
			res_cfg->bwr_offset, res_cfg->bwr_disk_size,
			res_cfg->runsite_num);

	dev = hadmdev_alloc(GFP_KERNEL);
	if (!dev) {
		pr_err("%s: alloc hadmdev failed.\n", __func__);
		goto done;
	}
	dev->minor = res_cfg->id;
	strncpy(dev->name, res_cfg->name, sizeof(dev->name));

	err = hadmdev_create_site_list(dev, cfg);
	if (err < 0) {
		pr_err("%s: create site list failed.\n", __func__);
		goto done;
	}

	site_cfg = find_site(cfg, local_site_id);
	if (!site_cfg) {
		err = -EKMOD_NONODE;
		pr_err("%s: can not find local site.\n", __func__);
		goto done;
	}
	err = hadmdev_create_node_list(dev, site_cfg);
	if (err < 0) {
		pr_err("%s create node list faild.\n", __func__);
		goto done;
	}

	err = hadm_attach_device(dev, g_hadm->major, dev->minor,
			dev->name, dev->local_site->conf.disk);
	if (err < 0) {
		pr_err("%s attach device failed.\n", __func__);
		goto done;
	}

	bwr_max_sector = res_cfg->bwr_offset + res_cfg->data_len;
	err = bwr_init(dev, bwr_max_sector,  res_cfg->bwr_disk_size,
		       res_cfg->meta_offset, res_cfg->dbm_offset, res_cfg->bwr_offset);
	if (err < 0) {
		pr_err("%s: create bwr failed.\n", __func__);
		goto done;
	}

	/*
	meta = &dev->bwr->mem_meta;
	dev->local_site->s_state.d_state = dev->bwr->disk_meta.disk_state;
	if (meta->head[hadm_site->id] == INVALID_SECTOR) {
		meta->head[hadm_site->id] = meta->bwr_start;
	}

	hadm_site->s_state.snd_ack_head = meta->head[hadm_site->id];
	hadm_site_set(hadm_site, SECONDARY_STATE,
		      S_SND_HEAD, meta->head[hadm_site->id]);
	pr_info("%s: site%d BWR head init to %llu\n", __FUNCTION__,
		hadm_site->id, (unsigned long long)meta->head[hadm_site->id]);

	for (i = 0; i < res_cfg->runsite_num; i++) {
		runsite_config = &res_cfg->runsites[i];
		if (runsite_config->id == local_site_id)
			continue;
		site_cfg = get_site_by_id(runsite_config->id, config);
		hadm_site = hadm_site_create(dev,
					     runsite_config->id, runsite_config->proto,
					     runsite_config->disk, runsite_config->bwr_disk);
		memcpy(hadm_site->conf.name, site_cfg->name, strlen(site_cfg->name));
		memcpy(hadm_site->conf.ipaddr, site_cfg->ipaddr, strlen(site_cfg->ipaddr));
		hadmdev_site_add(dev, hadm_site);
		if (meta->head[hadm_site->id] == INVALID_SECTOR) {
			meta->head[hadm_site->id] = meta->bwr_start;
		}
		hadm_site->s_state.snd_ack_head = meta->head[hadm_site->id];
		hadm_site_set(hadm_site, SECONDARY_STATE,
			      S_SND_HEAD, meta->head[hadm_site->id]);
		pr_info("%s: node %d BWR head init to %llu, node cstate:%d dstate:%d.\n", __FUNCTION__,
			hadm_site->id, (unsigned long long)meta->head[hadm_site->id],
			hadm_site_get(hadm_site, SECONDARY_STATE, S_CSTATE),
			hadm_site_get(hadm_site, SECONDARY_STATE, S_DATA_STATE));
		dbm = dbm_create(
			dev->bwr_bdev, res_cfg->dbm_offset, hadm_site,
			dev->bdev_disk_size << HADM_SECTOR_SHIFT, GFP_NOWAIT);
		if (hadm_site->dbm == NULL || IS_ERR(hadm_site->dbm)) {
			pr_err("create node %d dbm failed\n", hadm_site->id);
			err = -ENOMEM;
			goto config_done;
		}
	}

	*/
	hadmdev_init(dev);
	hadm_list_add(g_hadm, dev);

done:
	free_config(cfg);
	if (err) {
		hadmdev_put(dev);
		dev = NULL;
	}
	return dev;
}

static struct hdpacket *__cmd_worker_status__primary(struct hadm_site *local_site, int datalen, int accept)
{
	struct hdpacket *status_pack;
	struct packet *head;
	struct site_state_packet *ns_pack;
	struct hadm_site *runsite;
	struct hadm_site_state *state;

	/*
	 * 注意： hdpacket 的包头和数据是分离的，不是平坦的模型。也就是 header
	 * 和 data 的指针可能指向内存中不是连续的区域。在发送的时候，只要将
	 * header 和 data 的内存拷贝成平坦的形式，就可以保证对端收到的包是平坦连
	 * 续的。
	 *
	 * 这个事情是由内核做的，我们只要告诉它，希望拷贝的数据都在哪里就可以了。
	 */

	status_pack = site_hdpacket_alloc(GFP_KERNEL, datalen, HADM_DATA_NORMAL);
	if (status_pack == NULL)
		return NULL;

	/* 1. 设置 header */
	head = &status_pack->head;
	head->type = P_STATUS_ACK;
	head->dev_id = local_site->hadmdev->minor;
	head->site_state_num = atomic_read(&local_site->hadmdev->hadm_site_list_len);

	if (!accept) {
		head->uuid = local_site->hadmdev->bwr->mem_meta.local_primary.uuid;
		head->bwr_seq = bwr_seq(local_site->hadmdev->bwr);
	} else {
		head->uuid = local_site->hadmdev->primary->p_state.uuid;
		head->bwr_seq = local_site->hadmdev->primary->p_state.bwr_seq;
	}

	/* 2. 设置数据 */
	ns_pack = (struct site_state_packet *)status_pack->data->buff;
	list_for_each_entry(runsite, &local_site->hadmdev->hadm_site_list, site) {
		state = accept ? &runsite->p_state : &runsite->s_state;
		hadm_site_state_pack(ns_pack, state);
		ns_pack += 1;
	}

	return status_pack;
}

static struct hdpacket *__cmd_worker_status__standalone(struct hadm_site *local_site, int datalen)
{
	struct hdpacket *status_pack;
	struct packet *head;
	struct site_state_packet *ns_pack;

	status_pack = site_hdpacket_alloc(GFP_KERNEL, datalen, HADM_DATA_NORMAL);
	if (status_pack == NULL)
		return NULL;

	head = &status_pack->head;
	head->type = P_STATUS_ACK;
	head->dev_id = local_site->hadmdev->minor;
	head->site_state_num = 1;

	ns_pack = (struct site_state_packet *)status_pack->data->buff;
	hadm_site_state_pack(ns_pack, &local_site->s_state);

	return status_pack;
}

static struct hdpacket *__cmd_worker_status__alloc_packet(struct hadm_site *local_site)
{
	struct hdpacket *status_pack;
	size_t datalen;
	int primary_id;

	primary_id = hadmdev_get_primary_id(local_site->hadmdev);
	if (primary_id == local_site->id) {
		datalen = sizeof(struct site_state_packet) * atomic_read(&local_site->hadmdev->hadm_site_list_len);
		status_pack = __cmd_worker_status__primary(local_site, datalen, 0);
	} else if (primary_id != INVALID_ID) {
		datalen = sizeof(struct site_state_packet) * atomic_read(&local_site->hadmdev->hadm_site_list_len);
		status_pack = __cmd_worker_status__primary(local_site, datalen, 1);
	} else /* primary_id != local_site->id && primary_id == INVALID_ID */ {
		datalen = sizeof(struct site_state_packet);
		status_pack = __cmd_worker_status__standalone(local_site, datalen);
	}

	return status_pack;
}

static int cmd_worker_status(void *private)
{
	struct hdpacket *ev_node = private;
	struct hdpacket *status_pack;
	struct packet *head;
	struct hadmdev *hadmdev;
	struct socket *sock = ev_node->private;
	struct hadm_queue *queue;
	int ret;

	head = &ev_node->head;

	hadmdev = find_hadmdev_by_minor(head->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("cmd_worker_status: no device %d\n", head->dev_id);
		ret = -EKMOD_NODEV;
		goto err;
	}

	if (!hadmdev_local_master(hadmdev)) {
		pr_err("%s: not master, not implement.\n", __func__);
		ret = -EKMOD_NOT_SUPPORT;
		goto err;
	}

	status_pack = __cmd_worker_status__alloc_packet(hadmdev->local_site);
	if (status_pack == NULL) {
		pr_err("%s: no memory\n", __FUNCTION__);
		ret = -ENOMEM;
		goto err;
	}
	status_pack->private = sock;

	queue = g_hadm->p_sender_queue[P_CMD_TYPE];
	ret = hadm_queue_push(queue, &status_pack->list);
	if (ret == -EHADM_QUEUE_FREEZE) {
		hadm_socket_close(sock);
		hadm_socket_release(sock);
		hdpacket_free(status_pack);
	}

	return 0;
err:
	__response(sock, P_STATUS, head->dev_id, ret);
	return 0;
}

static int cmd_worker_up(void *private)
{
	int error = 0;
	struct hadmdev *hadmdev;
	struct hdpacket *ev_node = private;
	struct packet *head = &ev_node->head;

	hadmdev = find_hadmdev_by_minor(head->dev_id);
	if (hadmdev != NULL) {
		error = -EKMOD_ALREADY_CONFIG;
		goto gen_pack;
	}

	hadmdev = cmd_worker_config_create_hadm_struct(ev_node);
	if( IS_ERR_OR_NULL (hadmdev) ) {
		error=-EKMOD_NODEV;
		goto gen_pack;
	} else {
		pr_info("init device %d's config successed, now device num = %d\n",
				head->dev_id, atomic_read(&g_hadm->dev_list_len));
	}

	hadm_thread_start(hadmdev->threads[NODE_CTRL_WORKER]);
	hadm_thread_start(hadmdev->threads[NODE_DATA_WORKER]);

	hadm_site_set(hadmdev->local_site, SECONDARY_STATE, S_DEV_STATE, DEV_UP);

gen_pack:
	__response(ev_node->private, P_UP, head->dev_id, error);
	return 0;
}

static int cmd_worker_down(void *private)
{
	int state, error = 0;
	struct hadmdev *hadmdev;
	struct hdpacket *notify;
	struct hdpacket *ev_node = private;
	struct packet *head = &ev_node->head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	hadmdev = find_hadmdev_by_minor(head->dev_id);
	if (hadmdev == NULL) {
		pr_err("cmd_worker_down: no device %d\n", head->dev_id);
		error = -EKMOD_NODEV;
	} else {
		state = hadm_site_get(hadmdev->local_site, SECONDARY_STATE, S_DEV_STATE);
		if (state == DEV_DOWN) {
			error = -EKMOD_ALREADY_DOWN;
		} else if (state == DEV_UP) {
			be_secondary(hadmdev->minor,0);
			/* NOTE */
			notify = hadmdev_create_site_state_packet(hadmdev);
			if (notify) {
				notify->head.type = P_SC_DEVDOWN;
				hadm_list_del(g_hadm,hadmdev);
				hadmdev_put(hadmdev);
				if (hadm_queue_push(q, &notify->list) < 0) {
					error = -EHADM_QUEUE_FREEZE;
					hdpacket_free(notify);
				}
			}
		} else {
			pr_err("cmd_worker_down: unknown hadmdev state: %d\n", state);
			error = -EKMOD_UNKNOWN_STATE;
		}
	}

	__response(ev_node->private, P_DOWN, head->dev_id, error);
	return 0;
}

struct hadm_thread_info io_threads[] = {
	[BIO_RD_HANDLER]={bio_read_handler_run, "biord"},
	[BIO_WR_HANDLER]={bio_write_handler_run,"biowr"},
	[LOCAL_SYNC_HANDLER]={sync_local_thread,"lsync"},
	[REMOTE_SYNC_HANDLER]={sync_remote_thread,"rsync"},
	[DBM_SYNC_HANDLER]={sync_dbm_thread,"dbmsync"},
};

static int be_primary(int dev_id,int force)
{
	struct hadmdev *hadmdev;
	struct hadm_site *runsite;
	unsigned long flags;
	int local_node_id, nr_bit, data_state;

	hadmdev = find_hadmdev_by_minor(dev_id);
	if (hadmdev == NULL) {
		return -EKMOD_NODEV;
	}

	if (hadmdev->bwr->mem_meta.disk_state != D_CONSISTENT) {
		return -EKMOD_BAD_DSTATE;		/* FIXME BAD_DSTATE ? */
	}

	if (!hadmdev_local_master(hadmdev))
		return -EKMOD_NOT_SUPPORT;

	if(hadmdev->primary&&!force)
	{
		return -EKMOD_LOCAL_ROLE;
	}

	/* FIXME: how to set master */
	//hadmdev_set_master(hadmdev, hadmdev->local_node);

	hadmdev_start_io_threads(hadmdev);

	set_disk_ro(hadmdev->disk,false);
	hadm_site_set(hadmdev->local_site, SECONDARY_STATE, S_ROLE, R_PRIMARY);
	hadmdev_set_primary(hadmdev, hadmdev->local_site);
	set_local_primary(hadmdev, get_site_id(), jiffies);
	buffer_set_tail_seq(hadmdev->buffer, bwr_seq(hadmdev->bwr));

	/* initialize each node state */
	/* require two lock:
	 * hadmdev->hadm_site_list_lock
	 *	node->s_state.lock
	 */
	/* FIXME: Do we really need hadm_site/node_list_lock? */
	local_node_id = get_site_id();
	spin_lock(&hadmdev->hadm_site_list_lock);
	list_for_each_entry(runsite, &hadmdev->hadm_site_list, site) {
		if (runsite->id == local_node_id)
			continue;
		nr_bit = atomic_read(&runsite->dbm->nr_bit);
		spin_lock_irqsave(&runsite->s_state.lock, flags);
		data_state = nr_bit > 0 ? DATA_DBM : DATA_CONSISTENT;
		__hadm_site_set(&runsite->s_state, S_DATA_STATE, data_state);
		__hadm_site_set(&runsite->s_state, S_CSTATE, C_STOPPED);
		runsite->conf.real_protocol = PROTO_ASYNC;
		spin_unlock_irqrestore(&runsite->s_state.lock, flags);
	}
	spin_unlock(&hadmdev->hadm_site_list_lock);

	/* iff a master node can become primary */
	//if (hadmdev_local_master(hadmdev))
	hadmdev_send_primary_notify(hadmdev);

	/*
	for(i=0;i<IO_HANDLER_NUM;i++) {
		char name[0x0f];
		snprintf(name,0x0f,"%s%02d",io_threads[i].name,hadmdev->minor);
		hadmdev->io_handler_thread[i]=hadm_thread_alloc();
		hadm_thread_init(hadmdev->io_handler_thread[i],name,io_threads[i].func,hadmdev,NULL);
		hadm_thread_start(hadmdev->io_handler_thread[i]);
	}
	*/

	//hadm_thread_init(hadmdev->sbio_thread, "sbio_t", sbio_worker, hadmdev, NULL);
	//hadm_thread_start(hadmdev->sbio_thread);

	return 0;
}

static int cmd_worker_primary(void *private)
{
	int  error;
	struct hdpacket *pack = private;

	error = be_primary(pack->head.dev_id, 0);
	__response(pack->private, P_PRIMARY, pack->head.dev_id, error);

	return error;
}

static int cmd_worker_forceprimary(void *private)
{

	struct hdpacket *ev_node = private;
	int ret = 0, error = 0;

	error=be_primary(ev_node->head.dev_id,1);
	ret=error?-1:0;
	__response(ev_node->private, P_PRIMARY, ev_node->head.dev_id, error);

	return ret;
}

static int be_secondary(int dev_id,int force)
{
	struct hadmdev *hadmdev;
	struct hadm_site *hadm_site;
	struct hadm_node *hadm_node;
	int role,error;

	pr_info("set device %d to secondary , force=%d\n", dev_id, force);

	hadmdev = find_hadmdev_by_minor(dev_id);
	if (hadmdev == NULL) {
		pr_err("%s no such device.\n", __FUNCTION__);
		error = -EKMOD_NODEV;
		return error;
	}

	role = hadm_site_get(hadmdev->local_site, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		pr_err("%s Not primary.\n", __FUNCTION__);
		error = -EKMOD_NOT_PRIMARY;
		return error;
	}

	if (!hadmdev_local_master(hadmdev)) {
		pr_err("%s: Not master.\n", __func__);
		return -EKMOD_NOT_SUPPORT;
	}

	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		if (hadm_node_open(hadm_node)) {
			pr_err("%s: device is inuse by node%d.\n", __func__,
					hadm_node->id);
			return -EKMOD_INUSE;
		}
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
		error = -EKMOD_INUSE;
		error = EKMOD_PEER_BWR_NOT_EMPTY;
		mutex_unlock(&hadmdev->lock);
		return error;
	}

	hadmdev_set_primary(hadmdev, NULL);
	hadm_site_set(hadmdev->local_site, SECONDARY_STATE, S_ROLE, R_SECONDARY);
	mutex_unlock(&hadmdev->lock);

	if (hadmdev_local_master(hadmdev)) {
		hadmdev_wait_io_finish(hadmdev);
		hadmdev_stop_io_threads(hadmdev);
		clear_data_buffer(hadmdev->buffer);
	}

	/*
	for(i=0;i<IO_HANDLER_NUM;i++) {
		hadm_thread_stop(hadmdev->io_handler_thread[i]);
		hadm_thread_free(&hadmdev->io_handler_thread[i]);
	}
	*/
	/* FIXME: clear queue */
	//hadm_thread_stop(hadmdev->sbio_thread);

	list_for_each_entry(hadm_site, &hadmdev->hadm_site_list, site) {
		hadm_thread_stop(hadm_site->delta_sync);
		hadm_thread_free(&hadm_site->delta_sync);
		hadm_site_set(hadm_site, SECONDARY_STATE, S_HANDSHAKE, HS_FAIL);
	}

	hadmdev_send_site_state(hadmdev);
	hadmdev_send_node_state(hadmdev, NULL);
	return 0;
}

/* NOTE: 现在只允许本身作为primary的时候调用这个命令 */
static int cmd_worker_secondary(void *private)
{
	struct hdpacket *ev_node = private;
	int  error = 0;

	error=be_secondary(ev_node->head.dev_id,0);

	__response(ev_node->private, P_SECONDARY, ev_node->head.dev_id, error);
	return 0;
}

static int cmd_worker_forcesecondary(void *private)
{

	struct hdpacket *ev_node = private;
	int  error = 0;

	error=be_secondary(ev_node->head.dev_id,0);

	__response(ev_node->private, P_SECONDARY, ev_node->head.dev_id, error);
	return 0;
}

static int cmd_worker_master(void *private)
{
	int err;
	struct hadmdev *dev;
	struct hdpacket *pkt = private;
	struct packet *head = &pkt->head;

	err = 0;
	dev = find_hadmdev_by_minor(head->dev_id);
	if (!dev) {
		err = -EKMOD_NODEV;
		goto out;
	}

	/* site内master的唯一由外部保证，如HA */
	err = hadmdev_set_master(dev, dev->local_node);
	if (err != 0) {
		err = -EKMOD_MASTER_EXIST;
		goto out;
	}

	err = load_bwr_meta(dev->bwr);
	if (err < 0) {
		pr_err("%s: load bwr meta failed.\n", __func__);
		goto out;
	}

	err = hadmdev_site_list_init(dev);
	if (err < 0) {
		pr_err("%s: site list init failed.\n", __func__);
		goto out;
	}

	/* hadmdev_start_master_worker() */
	hadm_queue_unfreeze_all(dev->queues[SITE_DATA_Q]);
	hadm_queue_unfreeze_all(dev->queues[SITE_CTRL_Q]);
	hadm_thread_start(dev->threads[SITE_CTRL_WORKER]);
	hadm_thread_start(dev->threads[SITE_DATA_WORKER]);

	/* 在这里不保证尚未完成的sbio与新发下去的bio之间的顺序关系 */
	if (hadmdev_local_primary(dev)) {
		__hadmdev_sbio_list_submit(dev);
		//hadm_thread_start(dev->threads[LOCAL_SYNC_HANDLER]);
		//hadm_thread_start(dev->threads[REMOTE_SYNC_HANDLER]);
		//hadm_thread_start(dev->threads[SLAVER_BIO_HANDLER]);
		//hadm_thread_start(dev->threads[BIO_RD_HANDLER]);
		//hadm_thread_start(dev->threads[BIO_WR_HANDLER]);
		hadmdev_start_io_threads(dev);
		buffer_set_tail_seq(dev->buffer, bwr_seq(dev->bwr));
	};

	hadmdev_send_master_notify(dev);
out:
	__response(pkt->private, P_MASTER, head->dev_id, err);
	return 0;
}

static int cmd_worker_slaver(void *private)
{
	int err;
	struct hadmdev *dev;
	struct hdpacket *pkt = private;
	struct packet *head = &pkt->head;

	err = 0;
	dev = find_hadmdev_by_minor(head->dev_id);
	if (!dev) {
		err = -EKMOD_NODEV;
		goto out;
	}

	if (!hadmdev_local_master(dev)) {
		err = -EKMOD_NOT_SUPPORT;
		goto out;
	}


	hadmdev_set_master(dev, NULL);
	hadmdev_send_slaver_notify(dev);

	hadmdev_stop_site_all(dev);
	//hadmdev_clean_site_pack(dev);
	//hadm_queue_freeze_all(dev->queues[NODE_DATA_Q]);
	//hdpacket_queue_clean(dev->queues[NODE_DATA_Q]);

	if (hadmdev_local_primary(dev)) {
		hadmdev_wait_io_finish(dev);
		hadmdev_stop_io_threads(dev);
		clear_data_buffer(dev->buffer);
	}

	sync_bwr_meta(dev->bwr);
	//bwr_sync_meta(dev->bwr);
out:
	__response(pkt->private, P_SLAVER, head->dev_id, err);
	return 0;
}

static int cmd_worker_dbm_sync(uint8_t pack_type,struct hdpacket *ev_node)
{
	int error = 0, role;
	struct hadmdev *hadmdev;
	struct hadm_site *hadm_site;
	struct hdpacket *req;
	struct packet *rhead;
	struct packet *head = &ev_node->head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	hadmdev = find_hadmdev_by_minor(head->dev_id);
	if (!hadmdev) {
		pr_err("cmd_worker_cmsync: no device %d\n", head->dev_id);
		return -EKMOD_NODEV;
	}
	role = hadm_site_get(hadmdev->local_site, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		error = -EKMOD_LOCAL_ROLE;
		goto done;
	}

	hadm_site = find_hadm_site_by_id(hadmdev, head->node_to);
	if (!hadm_site) {
		pr_err("cmd_worker_dbm_sync: no node %d\n", head->node_to);
		error = -EKMOD_NONODE;
		goto done;
	}
	if(hadm_site->delta_sync&&hadm_thread_get_state(hadm_site->delta_sync)==HADM_THREAD_RUN) {
		pr_err("cmd_worker_dbm_sync:a delta_sync thread has been already started for node %d\n",head->node_to);
		error = -EKMOD_INUSE;
		goto done;
	}
	req = site_hdpacket_alloc(GFP_KERNEL, sizeof(struct bwr_meta), HADM_DATA_NORMAL);
	if (!req) {
		pr_err("cmd_worker_cmsync: no memory\n");
		error = -ENOMEM;
		goto done;
	}

	rhead = &req->head;
	switch(pack_type)
	{
		case P_DELTA_SYNC:
			rhead->type = P_SD_DSYNC_REQ;
			break;
		case P_CMSYNC:
			rhead->type = P_SD_DBM_REQ;
			break;
		case P_FULLSYNC:
			rhead->type = P_SD_FSYNC_REQ;
			break;
		default:
			error=-EINVAL;
			goto done;
	}

	rhead->node_to = (1 << head->node_to);
	rhead->dev_id = head->dev_id;
	memcpy(req->data->buff, &hadmdev->bwr->mem_meta, sizeof(struct bwr_meta));

	if (hadm_queue_push(q, &req->list) < 0) {
		error = -EKMOD_SEND_FAIL;
		hdpacket_free(req);
	}

done:
	__response(ev_node->private, P_DELTA_SYNC, head->dev_id, error);
	return 0;
}

static int cmd_worker_delta_sync(void *private)
{
	return cmd_worker_dbm_sync(P_DELTA_SYNC,(struct hdpacket *)private);
}

/*
 * 只允许 Primary 到 Secondary 的数据传输，也就是说，cmsync 能够成功的前提是，本
 * 地是 Primary，对端是 Secondary。
 */
static int cmd_worker_cmsync(void *private)
{
	return cmd_worker_dbm_sync(P_CMSYNC,(struct hdpacket *)private);
}

static int cmd_worker_fullsync(void *private)
{
	return cmd_worker_dbm_sync(P_FULLSYNC,(struct hdpacket *)private);
}

static struct packet_handler cmd_handler[] = {
	[P_STATUS] = {cmd_worker_status},

	[P_UP] = {cmd_worker_up},
	[P_DOWN] = {cmd_worker_down},
	[P_PRIMARY] = {cmd_worker_primary},
	[P_FORCEPRIMARY] = {cmd_worker_forceprimary},
	[P_FORCESECONDARY] = {cmd_worker_forcesecondary},
	[P_SECONDARY] = {cmd_worker_secondary},
	[P_MASTER] = {cmd_worker_master},
	[P_SLAVER] = {cmd_worker_slaver},

	[P_DELTA_SYNC] = {cmd_worker_delta_sync},
	[P_CMSYNC] = {cmd_worker_cmsync},
	[P_FULLSYNC] = {cmd_worker_fullsync},

	[P_CMD_END] = { NULL}
};

struct packet_handler *get_cmd_handler(void)
{
	return cmd_handler;
}
