#define pr_fmt(fmt) "packet_handler: " fmt

#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>

#define USE_HADM_STR_ERRNO

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_node.h"
#include "hadm_packet.h"
#include "hadm_socket.h"
#include "hadm_thread.h"

#include "bio_handler.h"
#include "dbm.h"
#include "fullsync.h"
#include "bwr.h"
#include "primary_info.h"
#include "p_worker.h"

#include "../include/common_string.h"

/* TODO */
static int __do_device_handshake_ack(struct hadmdev *hadmdev,
				     struct hdpacket *orig, int error)
{
	struct hdpacket *ack_pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	if(error)
		pr_info("[3]%s: error: %d(%s)\n", __FUNCTION__,-error, hadm_str_errno[-error]);

	ack_pack = hadmdev_create_site_state_packet(hadmdev);
	if (!ack_pack) {
		pr_err("__do_device_handshake_ack: no memory\n");
		return -ENOMEM;
	}

	head = &ack_pack->head;
	head->type = P_SC_HS_ACK;
	head->errcode = error;
	head->node_to = (1 << orig->head.node_from);

	if (hadm_queue_push(q, &ack_pack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack_pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __check_handshake(struct primary_info *remote_info, struct bwr_meta *local_meta)
{
	int ret = 0;

	if (local_meta->local_primary.uuid == remote_info->uuid) {
		ret = HS_OK;
		if (remote_info->bwr_seq)
			ret |= HS_SETHEAD;
		else
			ret |= HS_DBM;
		if (remote_info->last_page_damaged)
			ret |= HS_SETBM;
	} else if (local_meta->last_primary.uuid == remote_info->uuid &&
			local_meta->last_primary.bwr_seq == remote_info->bwr_seq) {
		ret = HS_OK;
		if (remote_info->last_page_damaged ||
				local_meta->last_primary.last_page_damaged)
			ret |= HS_SETBM;
	}

	return ret;
}

static int __do_handshake(struct hadm_site *peer, struct bwr_meta *remote_meta,
		struct bwr_meta *local_meta)
{
	int ret = 0;
	unsigned long flags;
	struct primary_info *remote_info = NULL;

	pr_info("remote_meta: lastp id:uuid:seq(%d:%llu:%llu).\n"
			"local_sitep id:uuid:seq(%d:%llu:%llu).\n",
			remote_meta->last_primary.id,
			remote_meta->last_primary.uuid,
			remote_meta->last_primary.bwr_seq,
			remote_meta->local_primary.id,
			remote_meta->local_primary.uuid,
			remote_meta->local_primary.bwr_seq);

	if (remote_meta->local_primary.id != INVALID_ID)
		remote_info = &remote_meta->local_primary;
	else if (remote_meta->last_primary.id != INVALID_ID)
		remote_info = &remote_meta->last_primary;
	else /* remote_meta->local_primary.id == INVALID_ID &&
	      * remote_meta->last_primary.id == INVALID_ID */
		/* remote_info = NULL; */;

	if (remote_info != NULL) {
		ret = __check_handshake(remote_info, local_meta);
		if (!ret)
			if (remote_meta->local_primary.id != INVALID_ID &&
					remote_meta->local_primary.bwr_seq == 1 &&
					remote_meta->last_primary.id != INVALID_ID) {
				remote_info = &remote_meta->last_primary;
				ret = __check_handshake(remote_info, local_meta);
			}
	}

	if (ret & HS_OK) {
		/* require two lock
		 * node_s_state.lock
		 *	bwr lock
		 */
		if (ret & HS_SETBM ||
				ret & HS_DBM) {
			spin_lock_irqsave(&peer->s_state.lock, flags);
			if (__hadm_site_get(&peer->s_state, S_DATA_STATE) != DATA_DBM) {
				__hadm_site_set(&peer->s_state, S_DATA_STATE, DATA_DBM);
				__hadm_site_set(&peer->s_state, S_DSTATE, D_INCONSISTENT);

			}
			spin_unlock_irqrestore(&peer->s_state.lock, flags);
			if (ret & HS_SETBM)
				dbm_set_sector(peer->dbm, remote_info->last_page);
			pr_info("hs ok & setbm\n");
		}
		if (ret & HS_SETHEAD) {
			spin_lock_irqsave(&peer->s_state.lock, flags);
			if (__hadm_site_get(&peer->s_state, S_DATA_STATE) != DATA_DBM) {
				pr_info("node is consistent, try update head.\n"
						"(%llu:%llu), set head to %llu.\n",
						peer->hadmdev->bwr->mem_meta.head[peer->id],
						remote_meta->last_primary.bwr_seq,
						seq_to_bwr(remote_info->bwr_seq, peer->hadmdev->bwr));
				bwr_set_site_head(peer->hadmdev->bwr, peer->id,
						seq_to_bwr(remote_info->bwr_seq, peer->hadmdev->bwr));
			}
			spin_unlock_irqrestore(&peer->s_state.lock, flags);
			pr_info("hs ok & sethead\n");

		}
	} else {
		if (check_split_brain(local_meta, remote_meta)) {
			hadm_site_set(peer, SECONDARY_STATE, S_DATA_STATE, DATA_SPLITBRAIN);
			ret = HS_SPLITBRAIN;
		} else {
			hadm_site_set(peer, SECONDARY_STATE, S_DATA_STATE, DATA_CORRUPT);
			ret = HS_FULLSYNC;
		}
	}

	return ret;
}

/* 只有主节点才处理握手包 */
static int p_handshake(struct hadmdev *dev, struct hdpacket *node)
{
	int role, ret;
	struct hadm_site *peer;
	struct bwr_meta *remote_meta, *local_meta;
	struct packet *head = &node->head;

	pr_info("[2]%s: node %d\n", __FUNCTION__, head->node_from);

	/* role == R_PRIMARY */
	role = hadm_site_get(dev->local_site, SECONDARY_STATE, S_ROLE);
	if (role == R_SECONDARY) {
		ret = -EKMOD_REMOTE_ROLE;
		goto response;
	}
	peer = find_hadm_site_by_id(dev, head->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}

	local_meta = (struct bwr_meta *)&dev->bwr->disk_meta;
	remote_meta = (struct bwr_meta *)node->data->buff;
	ret = __do_handshake(peer, remote_meta, local_meta);
	pr_info("get check_handshake %d\n", ret);
	ret = ret & HS_OK ? 0 : -EKMOD_UNKNOWN_STATE;
response:
	__do_device_handshake_ack(dev, node, ret);
done:
	return ret;
}

int send_startrep(int dev_id, uint32_t site_id)
{
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pr_info("[5]%s\n", __FUNCTION__);

	pack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack)
		return -ENOMEM;
	head = &pack->head;
	head->dev_id = dev_id ;
	head->type = P_SC_STARTREP;
	head->node_from = get_site_id();
	head->node_to = (1 << site_id);

	if (hadm_queue_push(q, &pack->list) < 0) {
		pr_err("%s: push ctrl queue failed.\n", __FUNCTION__);
		hdpacket_free(pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

/*
 * Secondary 节点在收到 ACK 之后，需要发送一个 P_STARTREP 包到 Primary 节点
 * 从节点，这时候主节点比较适合发送的时机是在发送 P_HANDSHAKE_ACK 到从节点的时候。
 * 那么对从节点来说，就会出现竞争的情况，在从节点没有改变状态之前，有可能就会收
 * 到 P_SD_DATA 的包，那么它只能丢弃掉这个包，因为它的状态还是 C_CONFIG 而不是
 * C_READY。
 *
 * 2. 在三个节点的情况下，有两个 Primary 节点和一个 Secondary 节点。如果
 * Secondary 和两个 Primary 节点都握手成功（这是有可能发生的）。如果 Secondary
 * 节点不发送 P_STARTREP 包告诉 Primary 节点它接受了哪个节点作为它的主节点，那么
 * 对于两个主节点来说，两个都会认为和这个 Secondary 节点握手成功。从而两个
 * Primary 节点都向 Secondary 节点发送数据，而对于 Secondary 节点来说，它将会丢
 * 弃一个 Primary 节点发送过来的数据，从而导致这个 Primary 节点对它产生了 dbm。
 */
static int p_handshake_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *primary_node;
	struct packet *head = &pack->head;

	pr_info("[4]%s: node %d\n", __FUNCTION__, head->node_from);

	if (head->errcode != 0) {
		pr_err("%s: packet errcode %d.\n", __FUNCTION__, head->errcode);
		return -1;
	}

	primary_node = find_hadm_site_by_id(dev, head->node_from);
	if (hadmdev_set_primary(dev, primary_node) != 0) {
		if (hadmdev_get_primary_id(dev) != head->node_from) {
			pr_warn("%s: Sorry, I accepted node %d as primary\n", __FUNCTION__, dev->primary->id);
		}
		return -1;
	}

	hadm_site_set(primary_node,SECONDARY_STATE,S_HANDSHAKE,HS_SUCCESS);
	send_startrep(dev->minor, head->node_from);
	return 0;
}

static int p_startrep(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *peer;
	struct packet *head = &pack->head;
	int role, ret = 0;
	int data_state;
	unsigned long flags;
	struct bwr *bwr;

	pr_info("[6]%s\n", __FUNCTION__);

	role = hadm_site_get(dev->local_site, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		pr_info("%s: local_site is NOT primary\n", __FUNCTION__);
		ret = -EINVAL;
		goto done;
	}

	peer = find_hadm_site_by_id(dev, head->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}
	data_state=hadm_site_get(peer,SECONDARY_STATE,S_DATA_STATE);
	if(data_state==DATA_CONSISTENT){
		pr_info("%s node %d's dstate is D_CONSISTENT\n",__FUNCTION__,peer->id);
		bwr = dev->bwr;
		write_lock_irqsave(&bwr->lock, flags);
		if (bwr->mem_meta.tail == bwr->mem_meta.head[peer->id] &&
				atomic_read(&peer->dbm->nr_bit) == 0) {
			pr_info("%s node %d already uptodate, tp: %u -> %u.\n",
					__FUNCTION__,
					peer->id,
					peer->conf.real_protocol,
					peer->conf.protocol);
			peer->conf.real_protocol = peer->conf.protocol;
		}
		write_unlock_irqrestore(&bwr->lock, flags);

		spin_lock_irqsave(&peer->s_state.lock, flags);
		//__hadm_site_test_and_set(&peer->s_state, S_CSTATE, C_STOPPED, C_SYNC);
		__hadm_site_set(&peer->s_state, S_CSTATE, C_SYNC);
		__hadm_site_set(&peer->s_state, S_HANDSHAKE, HS_SUCCESS);
		__hadm_site_reset_send_head(peer);
		spin_unlock_irqrestore(&peer->s_state.lock, flags);
	}
	else{
		pr_info("%s node %d is D_INCONSISTENT, create delta_sync thread\n",__FUNCTION__,peer->id);
		spin_lock_irqsave(&peer->s_state.lock, flags);
		__hadm_site_set(&peer->s_state, S_CSTATE,C_DELTA_SYNC_DBM);
		__hadm_site_set(&peer->s_state, S_HANDSHAKE, HS_SUCCESS);
		__hadm_site_reset_send_head(peer);
		spin_unlock_irqrestore(&peer->s_state.lock, flags);
		create_dbm_sync_thread(P_DELTA_SYNC,peer);
	}

done:
	return ret;
}

static int __p_node_conn_state__disconnect_action(struct hadm_site *hadm_site)
{
	disconnect_site(hadm_site);
	return 0;
}

static int __do_device_handshake(struct hadmdev *hadmdev, int node_id)
{
	int datalen;
	struct hdpacket *pack;
	struct packet *head;
	struct bwr_meta *meta;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pr_info("[1]%s\n", __FUNCTION__);

	datalen = sizeof(struct bwr_meta);
	pack = site_hdpacket_alloc(GFP_KERNEL, datalen, HADM_DATA_NORMAL);
	if (!pack) {
		pr_err("%s: no memory\n", __FUNCTION__);
		return -ENOMEM;
	}
	head = &pack->head;
	head->type = P_SC_HS;
	head->dev_id = hadmdev->minor;
	head->node_to = (1 << node_id);

	meta = (struct bwr_meta *)pack->data->buff;
	memcpy(meta, &hadmdev->bwr->disk_meta, datalen);

	if (hadm_queue_push(q, &pack->list) < 0) {
		pr_err("%s: push ctrl queue failed.\n", __FUNCTION__);
		hdpacket_free(pack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __do_send_status(struct hadmdev *dev, int node_id)
{
	struct hdpacket *pkt;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pkt = hadmdev_create_site_state_packet(dev);
	if (!pkt) {
		pr_err("%s: create packet failed.\n", __FUNCTION__);
		return -ENOMEM;
	}

	head = &pkt->head;
	head->type = P_SC_STATE;
	head->dev_id = dev->minor;
	head->node_to = (1 << node_id);

	if (hadm_queue_push(q, &pkt->list) < 0) {
		pr_err("%s: push ctrl queue failed.\n", __FUNCTION__);
		hdpacket_free(pkt);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __do_probe_primary(struct hadmdev *dev, int node_id)
{
	struct hdpacket *pkt;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pkt = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pkt) {
		pr_err("%s: create pkt faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	head = &pkt->head;
	head->type = P_SC_PRI_PRO;
	head->dev_id = dev->minor;
	head->node_to = (1 << node_id);

	if (hadm_queue_push(q, &pkt->list) < 0) {
		pr_err("%s: push ctrl queue failed.\n", __FUNCTION__);
		hdpacket_free(pkt);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __p_node_conn_state__connect_action(struct hadm_site *hadm_site)
{
	struct hadmdev *hadmdev;
	int r_handshake, primary_id;

	hadmdev = hadm_site->hadmdev;
	hadm_site_set(hadm_site, SECONDARY_STATE, S_NSTATE, N_CONNECT);

	primary_id = hadmdev_get_primary_id(hadmdev);
	r_handshake = hadm_site_get(hadm_site, SECONDARY_STATE, S_HANDSHAKE);

	/*
	 * 如果一个节点连接上来了，如果是本节点是从节点，那么发送握手包。如果本
	 * 节点是主节点，那么将会发送 2 种类型的包：一种是节点状态包，一种是主节
	 * 点探测包。
	 *
	 * 握手包和主节点探测包都只有主节点才响应，而节点状态包只有从节点才会保
	 * 存起来，主节点应该丢弃掉这个包。
	 */

	/* 本节点是从节点 */
	if (primary_id == INVALID_ID && r_handshake != HS_SUCCESS) {
		pr_info("node %d connect, do device %d handshake\n",
			hadm_site->id, hadmdev->minor);
		__do_device_handshake(hadmdev, hadm_site->id);
	}

	/* 本节点是主节点 */
	else if (primary_id == get_site_id()) {
		if (r_handshake == HS_SUCCESS)
			__do_send_status(hadmdev, hadm_site->id);
		else
			__do_probe_primary(hadmdev, hadm_site->id);
	}

	return 0;
}

static int p_site_conn_state(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *hadm_site;
	int dev_state, r_nstate, local_site_id;

	dev_state = hadm_site_get(dev->local_site, SECONDARY_STATE, S_DEV_STATE);
	if (dev_state == DEV_DOWN)
		goto done;
	if(io_failed(dev)) {
		goto done;
	}

	local_site_id = get_site_id();
	list_for_each_entry(hadm_site, &dev->hadm_site_list, site) {
		if (hadm_site->id == local_site_id)
			continue;
		r_nstate = ((1 << hadm_site->id) & head->node_to) ?
			N_CONNECT : N_DISCONNECT;
		if (r_nstate == N_DISCONNECT) {
			__p_node_conn_state__disconnect_action(hadm_site);
		} else /* r_nstate == N_CONNECT */ {
			__p_node_conn_state__connect_action(hadm_site);
		}
	}

done:
	return 0;
}

/* 只有主节点才会响应探测包 */
static int p_primary_probe(struct hadmdev *dev, struct hdpacket *orig)
{
	int ret = 0, role;
	struct hdpacket *ack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	role = hadm_site_get(dev->local_site, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		return -EINVAL;
	}

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!ack) {
		pr_err("%s: alloc ack packet faild.\n", __FUNCTION__);
		return -ENOMEM;
	}

	head = &ack->head;
	head->type = P_SC_PRI_PRO_ACK;
	head->dev_id = orig->head.dev_id;
	head->node_to = (1 << orig->head.node_from);

	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ctrl queue failed.\n", __FUNCTION__);
		hdpacket_free(ack);
		return -EHADM_QUEUE_FREEZE;
	}

	return ret;
}

static int p_primary_probe_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *peer;
	int ret = 0;

	peer = find_hadm_site_by_id(dev, head->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}

	hadm_site_set(peer, SECONDARY_STATE, S_DATA_STATE, DATA_SPLITBRAIN);

done:
	return ret;
}

static int __p_dev_down_notify__peer_secondary_action(struct hadmdev *dev, struct hdpacket *pack)
{
	int cstate;
	struct hdpacket *ack;
	struct hadm_site *peer;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	head = &pack->head;
	peer = find_hadm_site_by_id(dev, head->node_from);
	if (!peer) {
		pr_err("%s: can not find peer node(id:%d).\n",
				__FUNCTION__, head->node_from);
		return -EKMOD_NONODE;
	}

	hadm_site_set(peer, SECONDARY_STATE, S_DEV_STATE, DEV_DOWN);
	cstate = hadm_site_get(peer, SECONDARY_STATE, S_CSTATE);
	if (cstate == C_SYNC)
		cstate = C_STOPPED;
	else
		/* unchanged */;
	hadm_site_set(peer, SECONDARY_STATE, S_CSTATE, cstate);
	hadm_site_set(peer, SECONDARY_STATE, S_HANDSHAKE, DEVICE_NOT_HANDSHAKE);

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!ack) {
		pr_err("%s: alloc ack packet failed.\n", __FUNCTION__);
		return -ENOMEM;
	}
	head = &ack->head;
	head->type = P_SC_DEVDOWN_ACK;
	head->dev_id = pack->head.dev_id;
	head->node_to = (1 << pack->head.node_from);

	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int p_dev_down_notify(struct hadmdev *dev, struct hdpacket *node)
{
	struct site_state_packet *remote_state;
	int r_role;

	remote_state = site_state_packet_entry(node, node->head.node_from);
	r_role = remote_state->role;
	if (r_role == R_PRIMARY) {
		/* primary down */
	} else {
		/* secondary down */
		__p_dev_down_notify__peer_secondary_action(dev, node);
	}

	return 0;
}

/* FIXME */
static int p_dev_down_notify_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *runsite;

	/* everything back to C_CONFIG state */
	hadm_detach_device(dev);
	list_for_each_entry(runsite, &dev->hadm_site_list, site) {
		hadm_site_set(runsite, PRIMARY_STATE, S_INVALID, 1);
		hadm_site_set(runsite, SECONDARY_STATE, S_HANDSHAKE, DEVICE_NOT_HANDSHAKE);
	}
	hadm_site_set(dev->local_site, SECONDARY_STATE, S_DEV_STATE, DEV_DOWN);

	return 0;
}

static int __p_site_state__primary_action(struct hdpacket *pack, struct hadmdev *dev)
{
	struct hadm_site *runsite;
	struct site_state_packet *ns_pack;

	spin_lock(&dev->hadm_site_list_lock);
	list_for_each_entry(runsite, &dev->hadm_site_list, site) {
		ns_pack = site_state_packet_entry(pack, runsite->id);
		if (ns_pack)
			hadm_site_state_unpack(&runsite->p_state, ns_pack);
		if (pack->head.node_from == runsite->id) {
			runsite->p_state.uuid = pack->head.uuid;
			runsite->p_state.bwr_seq = pack->head.bwr_seq;
		}
	}
	spin_unlock(&dev->hadm_site_list_lock);

	return 0;
}

static int __p_site_state__secondary_action(struct hdpacket *pack, struct hadmdev *dev)
{
	struct hadm_site *hadm_site=find_hadm_site_by_id(dev,pack->head.node_from);
	if(dev->primary && dev->primary->id==hadm_site->id) {
		pr_info("primary node %d is change to secondary\n",
				hadm_site->id);

		hadmdev_set_primary(dev, NULL);
		hadm_site_set(hadm_site,SECONDARY_STATE,S_HANDSHAKE,HS_FAIL);
	}
	return 0;
}

/*
 * 之后从节点会收到 P_NODE_STATE 的包。根据发送节点的 role 来决定做什么操作。如
 * 果发送节点是 Primary 的话，那么就将主节点发送过来的状态保存下来；如果发送节点
 * 是 Secondary 的话，那么就说明发送节点由主节点变为了从节点，那么它需要放弃掉这
 * 个主节点。
 */
static int p_site_state(struct hadmdev *dev, struct hdpacket *node)
{
	struct packet *head = &node->head;
	struct site_state_packet *ns_pack;
	int primary_id, ret = 0;

	ns_pack = site_state_packet_entry(node, head->node_from);
	if (ns_pack == NULL || IS_ERR(ns_pack)) {
		pr_err("%s: no remote node %d\n",
		       __FUNCTION__, head->node_from);
		ret = -EINVAL;
		goto done;
	}
	primary_id = hadmdev_get_primary_id(dev);
	if (primary_id != head->node_from) {
		pr_info("%s: node %d is NOT my primary\n",
			__FUNCTION__, head->node_from);
		ret = -EINVAL;
		goto done;
	}
	if (ns_pack->role == R_PRIMARY) {
		__p_site_state__primary_action(node, dev);
	}
	else {
		__p_site_state__secondary_action(node, dev);
	}

done:
	/* Don't send P_NODE_STATE_ACK, do we need it? */
	return ret;
}

static int p_site_state_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	return 0;
}

static struct device_handler p_functions[] = {
	[P_SC_CONN_STATE] = { p_site_conn_state },
	[P_SC_HS] = { p_handshake },
	[P_SC_HS_ACK] = { p_handshake_ack },
	[P_SC_DEVDOWN] = { p_dev_down_notify },
	[P_SC_DEVDOWN_ACK] = { p_dev_down_notify_ack },
	[P_SC_STARTREP] = { p_startrep },
	[P_SC_STATE] = { p_site_state },
	[P_SC_STATE_ACK] = { p_site_state_ack },
	[P_SC_PRI_PRO] = { p_primary_probe },
	[P_SC_PRI_PRO_ACK] = { p_primary_probe_ack },
	//[P_SC_END] = { NULL }
};

struct device_handler *get_site_ctrl_handler()
{
	return p_functions;
}
