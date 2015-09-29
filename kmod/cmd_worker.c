#define pr_fmt(fmt) "cmd_worker: " fmt

#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/list.h>

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
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

static int __response(struct socket *to, int type, int dev_id, int error)
{
	struct packet *response_pack;
	struct hadm_pack_node *cmd_node;

	response_pack = packet_alloc(0, GFP_KERNEL);
	if (response_pack == NULL || IS_ERR(response_pack))
		return -ENOMEM;
	packet_init(response_pack, type, dev_id, 0, 0, 0, 0, 0, error);

	cmd_node = hadm_pack_node_create(response_pack, to);
	if (cmd_node == NULL || IS_ERR(cmd_node)) {
		packet_free(response_pack);
		return -ENOMEM;
	}

	/* in case queue was freezed */
	{
		int ret;

		ret = hadm_queue_push(g_hadm->cmd_sender_queue, &cmd_node->q_node);
		if (ret == -EHADM_QUEUE_FREEZE) {
			hadm_socket_close(cmd_node->sock);
			hadm_socket_release(cmd_node->sock);
			hadm_pack_node_free(cmd_node);
		}
	}

	return 0;
}

static struct hadmdev *cmd_worker_config_create_hadm_struct(struct packet *pack)
{
	int i, local_node_id, err = 0;
	struct conf_packet *conf_pack;
	struct node_config *node_cfg;
	struct config *config;
	struct res_config *res_config = NULL;
	struct runnode_config *runnode_config;
	struct hadmdev *hadmdev = NULL;
	struct hadm_node *hadm_node;
	struct bwr_meta *meta;
	uint64_t bwr_max_sector;
	int dev_id=pack->dev_id;

	conf_pack = (struct conf_packet *)pack->data;
	config = unpack_config(conf_pack);

	dump_config(__func__, config);

	local_node_id = get_node_id();

	/* 每次只config一个设备 */
	res_config = NULL;
	for (i = 0; i < config->res_num; i++) {
		res_config = &config->res[i];
		if (dev_id == res_config->id)
			break;
	}
	if (res_config == NULL) {
		pr_err("no local node in resource map\n");
		goto config_done;
	}

	hadmdev = hadmdev_alloc(GFP_KERNEL);
	if (hadmdev == NULL || IS_ERR(hadmdev)){
		goto config_done;
	}
	hadmdev->minor = res_config->id;
	snprintf(hadmdev->name, MAX_NAME_LEN, "%s", res_config->name);
	meta = &hadmdev->bwr->mem_meta;

	/*
	 * 对于每个设备（hadm0）来说，它需要先创建从本地节点开始创建可运
	 * 行节点。这意味着，对于 0 节点来说，循环的运行应该是 0,1,2,3。
	 * 而对于 1 节点来说，循环的运行顺序应该是 1,2,3,0 或者是
	 * 1,0,2,3。总之，本地节点应该首先创建，因为其他节点创建 dbm
	 * 的时候，依赖本地节点创建的 BWR。
	 */

	/* 首先创建本地节点 */
	runnode_config = NULL;
	for (i = 0; i < res_config->runnode_num; i++) {
		runnode_config = &res_config->runnodes[i];
		if (runnode_config->id == get_kmod_id())
			break;
	}
	BUG_ON(runnode_config->id != get_kmod_id());

	node_cfg = get_node_by_id(runnode_config->id, config);
	hadm_node = hadm_node_create(hadmdev, node_cfg->server_id,
			runnode_config->id, runnode_config->proto);
	memcpy(hadm_node->conf.hostname, node_cfg->hostname, strlen(node_cfg->hostname));
	hadmdev_list_add(hadmdev, hadm_node);
	hadmdev->local = hadm_node;
	if (meta->head[hadm_node->id] == INVALID_SECTOR) {
		meta->head[hadm_node->id] = meta->bwr_start;
	}
	hadm_node->s_state.snd_ack_head = meta->head[hadm_node->id];
	hadm_node_set(hadm_node, SECONDARY_STATE,
		      S_SND_HEAD, meta->head[hadm_node->id]);
	pr_info("%s: node %d BWR head init to %llu\n", __FUNCTION__,
		hadm_node->id, (unsigned long long)meta->head[hadm_node->id]);
	err = hadm_attach_device(hadmdev, g_hadm->major, hadmdev->minor,
				 hadmdev->name, runnode_config->disk);
	if (err)
		goto config_done;
	bwr_max_sector = res_config->bwr_offset + res_config->data_len;
	err = bwr_init(hadmdev, runnode_config->bwr_disk, bwr_max_sector,  res_config->bwr_disk_size,
		       res_config->meta_offset, res_config->dbm_offset, res_config->bwr_offset);
	if (err) {
		goto config_done;
	}
	pr_info("%s:node %d BWR start_sector = %llu, max_sector = %llu, max_size = %llu, disk_size = %llu\n",
			__FUNCTION__, hadm_node->id,
			(unsigned long long)hadmdev->bwr->start_sector,
			(unsigned long long)hadmdev->bwr->max_sector,
			(unsigned long long)hadmdev->bwr->max_size,
			(unsigned long long)hadmdev->bwr->disk_size);
	hadmdev->local->s_state.d_state = hadmdev->bwr->disk_meta.disk_state;

	/* 然后是其他节点 */
	for (i = 0; i < res_config->runnode_num; i++) {
		runnode_config = &res_config->runnodes[i];
		if (runnode_config->id == get_kmod_id())
			continue;
		node_cfg = get_node_by_id(runnode_config->id, config);
		hadm_node = find_hadm_node_by_id(hadmdev, node_cfg->server_id);
		if (hadm_node) {
			pr_info("%s exist, server_id:%d|kmod id:%d\n", __func__, node_cfg->server_id, runnode_config->id);
			continue;
		}

		hadm_node = hadm_node_create(hadmdev, node_cfg->server_id,
					     //runnode_config->id, runnode_config->proto);
					     INVALID_ID, runnode_config->proto);
		hadmdev_list_add(hadmdev, hadm_node);
		if (meta->head[hadm_node->id] == INVALID_SECTOR) {
			meta->head[hadm_node->id] = meta->bwr_start;
		}
		hadm_node->s_state.snd_ack_head = meta->head[hadm_node->id];
		hadm_node_set(hadm_node, SECONDARY_STATE,
			      S_SND_HEAD, meta->head[hadm_node->id]);
		pr_info("%s: node %d BWR head init to %llu, node cstate:%d dstate:%d.\n", __FUNCTION__,
			hadm_node->id, (unsigned long long)meta->head[hadm_node->id],
			(int)hadm_node_get(hadm_node, SECONDARY_STATE, S_CSTATE),
			(int)hadm_node_get(hadm_node, SECONDARY_STATE, S_DATA_STATE));
		hadm_node->dbm = dbm_create(
			hadmdev->bwr_bdev, res_config->dbm_offset, hadm_node,
			hadmdev->bdev_disk_size << HADM_SECTOR_SHIFT, GFP_NOWAIT);
		if (hadm_node->dbm == NULL || IS_ERR(hadm_node->dbm)) {
			pr_err("create node %d dbm failed\n", hadm_node->id);
			err = -ENOMEM;
			goto config_done;
		}
	}
	sync_disk_meta(hadmdev->bwr);
	hadmdev_init(hadmdev);
	hadm_list_add(g_hadm, hadmdev);

config_done:
	free_config(config);
	if(err) {
		hadmdev_put(hadmdev);
		hadmdev = ERR_PTR(err);
	}
	return hadmdev;
}

static struct packet *__cmd_worker_status__primary(struct hadm_node *local, int datalen, int accept)
{
	struct packet *status_pack;
	struct node_state_packet *ns_pack;
	struct hadm_node *runnode;
	struct hadm_node_state *state;
	int nr_nodes;

	nr_nodes = atomic_read(&local->hadmdev->hadm_node_list_len);

	status_pack = packet_alloc(datalen, GFP_KERNEL);
	if (status_pack == NULL || IS_ERR(status_pack))
		return status_pack;
	packet_init(status_pack, P_STATUS_ACK, local->hadmdev->minor, 0, 0, 0, 0, nr_nodes, 0);

	if (!accept) {
		status_pack->uuid = local->hadmdev->bwr->mem_meta.local_primary.uuid;
		status_pack->bwr_seq = bwr_seq(local->hadmdev->bwr);
	} else {
		status_pack->uuid = local->hadmdev->primary->p_state.uuid;
		status_pack->bwr_seq = local->hadmdev->primary->p_state.bwr_seq;
	}

	ns_pack = (struct node_state_packet *)status_pack->data;
	list_for_each_entry(runnode, &local->hadmdev->hadm_node_list, node) {
		state = accept ? &runnode->p_state : &runnode->s_state;
		hadm_node_state_pack(ns_pack, state);
		ns_pack += 1;
	}

	return status_pack;
}

static struct packet *__cmd_worker_status__standalone(struct hadm_node *local, int datalen)
{
	struct packet *status_pack;
	struct node_state_packet *ns_pack;

	status_pack = packet_alloc(datalen, GFP_KERNEL);
	if (status_pack == NULL || IS_ERR(status_pack))
		return status_pack;
	packet_init(status_pack, P_STATUS_ACK, local->hadmdev->minor, 0, 0, 0, 0, 1, 0);

	ns_pack = (struct node_state_packet *)status_pack->data;
	hadm_node_state_pack(ns_pack, &local->s_state);

	return status_pack;
}

static struct packet *__cmd_worker_status__alloc_packet(struct hadm_node *local)
{
	struct packet *status_pack;
	size_t datalen;
	int primary_id;

	primary_id = hadmdev_get_primary_id(local->hadmdev);
	if (primary_id == local->id) {
		datalen = sizeof(struct node_state_packet) * atomic_read(&local->hadmdev->hadm_node_list_len);
		status_pack = __cmd_worker_status__primary(local, datalen, 0);
	} else if (primary_id != INVALID_ID) {
		datalen = sizeof(struct node_state_packet) * atomic_read(&local->hadmdev->hadm_node_list_len);
		status_pack = __cmd_worker_status__primary(local, datalen, 1);
	} else /* primary_id != local->id && primary_id == INVALID_ID */ {
		datalen = sizeof(struct node_state_packet);
		status_pack = __cmd_worker_status__standalone(local, datalen);
	}

	return status_pack;
}

static int cmd_worker_status(void *private)
{
	struct hadm_pack_node *ev_node = private;
	struct packet *recv_pack, *status_pack;
	struct hadm_pack_node *s_node;
	struct hadmdev *hadmdev;

	recv_pack = ev_node->pack;
	if (recv_pack->magic != MAGIC) {
		pr_err("cmd_worker_status: wrong packet\n");
		dump_packet("cmd_worker_status", recv_pack);
		return 0;
	}

	hadmdev = find_hadmdev_by_minor(recv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("cmd_worker_status: no device %d\n", recv_pack->dev_id);
		__response(ev_node->sock, P_STATUS, recv_pack->dev_id, -EKMOD_NODEV);
		return 0;
	}

	status_pack = __cmd_worker_status__alloc_packet(hadmdev->local);
	if (status_pack == NULL || IS_ERR(status_pack)) {
		pr_err("%s: no memory\n", __FUNCTION__);
		__response(ev_node->sock, P_STATUS, recv_pack->dev_id, -ENOMEM);
		return 0;
	}

	s_node = hadm_pack_node_create(status_pack,ev_node->sock);
	if (s_node == NULL || IS_ERR(s_node)) {
		pr_err("cmd_worker_status: no memory\n");
		packet_free(status_pack);
		return 0;
	}

	/* in case queue was freezed */
	{
		int ret;

		ret = hadm_queue_push(g_hadm->cmd_sender_queue, &s_node->q_node);
		if (ret == -EHADM_QUEUE_FREEZE) {
			hadm_socket_close(s_node->sock);
			hadm_socket_release(s_node->sock);
			hadm_pack_node_free(s_node);
		}
	}

	return 0;
}

static int cmd_worker_init(void *private)
{
	int err = 0;
	struct hadmdev *hadmdev = NULL;
	struct hadm_pack_node *ev_node = private;

	hadmdev = find_hadmdev_by_minor(ev_node->pack->dev_id);
	if (hadmdev)
		err = -EKMOD_ALREADY_CONFIG;

	__response(ev_node->sock, P_INIT, ev_node->pack->dev_id, err);
	return 0;
}

static int cmd_worker_up(void *private)
{
	struct hadm_pack_node *ev_node = private;
	struct hadmdev *hadmdev = NULL;
	int dev_id = ev_node->pack->dev_id;
	struct conf_packet *conf_pack;
	int error = 0;

	if (ev_node->pack->magic != MAGIC || ev_node->pack->len <= 0) {
		pr_err("cmd_worker_up: receive wrong packet\n");
		dump_packet("cmd_worker_up", ev_node->pack);
		error = -EINVAL;
		goto gen_pack;
	}

	if (hadm_devs_empty(g_hadm)) {
		conf_pack = (struct conf_packet *)ev_node->pack->data;
		hadm_reconfig(g_hadm, NULL, NULL, conf_pack->local_server_id,
				conf_pack->local_node_id);
	}
	hadmdev = find_hadmdev_by_minor(ev_node->pack->dev_id);
	if (hadmdev != NULL) {
		error = -EKMOD_ALREADY_CONFIG;
		goto gen_pack;
	}
	hadmdev = cmd_worker_config_create_hadm_struct(ev_node->pack);
	if( IS_ERR_OR_NULL (hadmdev) ) {
		error = PTR_ERR(hadmdev);
		goto gen_pack;
	} else {
		pr_info("init device %d's config successed, now device num = %d\n",
				dev_id, atomic_read(&g_hadm->dev_list_len));
	}


	hadm_node_set(hadmdev->local, SECONDARY_STATE, S_DEV_STATE, DEV_UP);

gen_pack:
	__response(ev_node->sock, P_UP, ev_node->pack->dev_id, error);
	return 0;
}

// CMD的处理非并发
static int cmd_worker_down(void *private)
{
	int err = 0;
	struct packet *notify;
	struct hadmdev *hadmdev;
	struct hadm_node *primary;
	struct hadm_pack_node *ev_node = private;

	hadmdev = find_hadmdev_by_minor(ev_node->pack->dev_id);
	if (!hadmdev) {
		pr_err("cmd_worker_down: no device or not up already: %d\n",
				ev_node->pack->dev_id);
		err = -EKMOD_NODEV;
		goto out;
	}

	if (hadmdev_local_primary(hadmdev)) {
		pr_err("%s: can not down primary node.\n", __func__);
		err = -EKMOD_NOT_SUPPORT;
		goto out;
	}

	primary = hadmdev_get_primary(hadmdev);
	if (primary) {
		notify = packet_alloc_for_node(0, GFP_KERNEL, primary);
		if (!notify) {
			pr_err("%s alloc notify packet failed.\n", __func__);
			err = -ENOMEM;
			goto out;
		}
		notify->type = P_DEV_DOWN_NOTIFY;
		notify->dev_id = hadmdev->minor;
		if (packet_send(notify) < 0) {
			pr_err("%s send dev down notify failed.\n", __func__);
			packet_free(notify);
			err = -EKMOD_SEND_FAIL;
			goto out;
		}
	}
	//down之前，禁止再发送META包，并等待p_send_queue为0，这是为了确保DOWN的信息发送到对端
	hadm_queue_freeze_push(hadmdev->p_sender_queue[P_CTRL_TYPE]);

	if(wait_event_timeout(g_hadm->queue_event,
			hadm_queue_len(hadmdev->p_sender_queue[P_CTRL_TYPE]) == 0 || 
			!hadm_net_connected(g_hadm->ctrl_net), msecs_to_jiffies(10000)) == 0){
		pr_warn("hadm%d is down, but there are meta data not sent. meta sender queue len %d\n", 
				hadmdev->minor, hadm_queue_len(hadmdev->p_sender_queue[P_CTRL_TYPE]) );
	}


	hadm_list_del(g_hadm, hadmdev);

	hadmdev_put(hadmdev);
out:
	__response(ev_node->sock, P_DOWN, ev_node->pack->dev_id, err);
	return err;
}

static int cmd_worker_primary(void *private)
{
	struct hadm_pack_node *ev_node = private;
	struct packet *recv_pack;
	int  error = 0;

	recv_pack = ev_node->pack;
	error=be_primary(recv_pack->dev_id,0);
	__response(ev_node->sock, P_PRIMARY, recv_pack->dev_id, error);
	return error;
}

static int cmd_worker_forceprimary(void *private)
{

	struct hadm_pack_node *ev_node = private;
	struct packet *recv_pack;
	int ret = 0, error = 0;

	recv_pack = ev_node->pack;
	error=be_primary(recv_pack->dev_id,1);
	ret=error?-1:0;
	__response(ev_node->sock, P_PRIMARY, recv_pack->dev_id, error);

	return ret;
}


/* NOTE: 现在只允许本身作为primary的时候调用这个命令 */
static int cmd_worker_secondary(void *private)
{
	struct hadm_pack_node *ev_node = private;
	struct packet *rcv_pack;
	int  error = 0;

	rcv_pack = ev_node->pack;
	error=be_secondary(rcv_pack->dev_id,0);

	__response(ev_node->sock, P_SECONDARY, rcv_pack->dev_id, error);
	return 0;
}

static int cmd_worker_forcesecondary(void *private)
{

	struct hadm_pack_node *ev_node = private;
	struct packet *rcv_pack;
	int  error = 0;

	rcv_pack = ev_node->pack;
	error=be_secondary(rcv_pack->dev_id,0);

	__response(ev_node->sock, P_SECONDARY, rcv_pack->dev_id, error);
	return 0;
}

static int cmd_worker_dbm_sync(uint8_t pack_type,struct hadm_pack_node *ev_node)
{
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct packet *req;
	int error = 0, role;

	hadmdev = find_hadmdev_by_minor(ev_node->pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("cmd_worker_cmsync: no device %d\n", ev_node->pack->dev_id);
		return -EKMOD_NODEV;
	}
	role = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		error = -EKMOD_LOCAL_ROLE;
		goto done;
	}

	hadm_node = find_hadm_node_by_id(hadmdev, ev_node->pack->node_to);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("cmd_worker_dbm_sync: no node %d\n", ev_node->pack->node_to);
		error = -EKMOD_NONODE;
		goto done;
	}
	if(hadm_node->delta_sync &&
			hadm_thread_get_state(hadm_node->delta_sync) == HADM_THREAD_RUN) {
		pr_err("cmd_worker_dbm_sync:a delta_sync thread has been already started for node %d\n",ev_node->pack->node_to);
		error = -EKMOD_INUSE;
		goto done;
	}
	req = packet_alloc(sizeof(struct bwr_meta), GFP_KERNEL);
	if (req == NULL || IS_ERR(req)) {
		pr_err("cmd_worker_cmsync: no memory\n");
		error = -ENOMEM;
		goto done;
	}
	switch(pack_type)
	{
		case P_DELTA_SYNC:
			req->type = P_DELTA_SYNC_REQ;
			req->kmod_to = (1 << hadm_node->kmod_id);
			break;
		case P_CMSYNC:
			req->type = P_DBM_REQ;
			req->kmod_to = -1;
			break;
		case P_FULLSYNC:
			req->type = P_FULLSYNC_REQ;
			req->kmod_to = -1;
			break;
		default:
			error=-EINVAL;
			goto done;
	}
	set_bit(ev_node->pack->node_to, (unsigned long *)&req->node_to);
	req->dev_id = ev_node->pack->dev_id;
	memcpy(req->data, &hadmdev->bwr->mem_meta, sizeof(struct bwr_meta));
	error = packet_send(req);
	if (error < 0)
		error = -EKMOD_SEND_FAIL;
done:
	__response(ev_node->sock, P_DELTA_SYNC, ev_node->pack->dev_id, error);
	return 0;
}

static int cmd_worker_delta_sync(void *private)
{
	return cmd_worker_dbm_sync(P_DELTA_SYNC,(struct hadm_pack_node *)private);
}

/*
 * 只允许 Primary 到 Secondary 的数据传输，也就是说，cmsync 能够成功的前提是，本
 * 地是 Primary，对端是 Secondary。
 */
static int cmd_worker_cmsync(void *private)
{
	return cmd_worker_dbm_sync(P_CMSYNC,(struct hadm_pack_node *)private);
}

static int cmd_worker_fullsync(void *private)
{
	return cmd_worker_dbm_sync(P_FULLSYNC,(struct hadm_pack_node *)private);
}

static struct packet_handler cmd_handler[] = {
	[P_STATUS] = {cmd_worker_status},

	[P_INIT] = {cmd_worker_init},
	[P_UP] = {cmd_worker_up},
	[P_DOWN] = {cmd_worker_down},
	[P_PRIMARY] = {cmd_worker_primary},
	[P_FORCEPRIMARY] = {cmd_worker_forceprimary},
	[P_FORCESECONDARY] = {cmd_worker_forcesecondary},
	[P_SECONDARY] = {cmd_worker_secondary},

	[P_DELTA_SYNC] = {cmd_worker_delta_sync},
	[P_CMSYNC] = {cmd_worker_cmsync},
	[P_FULLSYNC] = {cmd_worker_fullsync},

	[P_LOCAL_END] = { NULL}
};

/* valid type: 1, otherwise: 0 */
static int __cmd_worker_valid_type(int type)
{
	return P_LOCAL_START<type&&type<P_LOCAL_END;
}

packet_handler_t get_cmd_worker_handler(int type)
{
	if(__cmd_worker_valid_type(type))
		return cmd_handler[type].func;
	else
		return NULL;
}
