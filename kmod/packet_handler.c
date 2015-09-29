#define pr_fmt(fmt) "packet_handler: " fmt

#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/kthread.h>

#define USE_HADM_STR_ERRNO

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
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

static int __do_device_handshake_ack(struct hadmdev *hadmdev,
				     struct packet *orig, int error)
{
	struct packet *ack_pack;

	if(error)
		pr_info("[3]%s: hadm%d error: %d(%s)\n", __FUNCTION__,
                        hadmdev->minor,
                        -error, hadm_str_errno[-error]);

	ack_pack = packet_alloc(0, GFP_KERNEL);
	if (!ack_pack) {
		pr_err("__do_device_handshake_ack hadm%d: no memory\n", hadmdev->minor);
		return -ENOMEM;
	}

	ack_pack->type = P_HANDSHAKE_ACK;
	ack_pack->dev_id = hadmdev->minor;
	ack_pack->node_to = (1 << orig->node_from);
	ack_pack->kmod_to = (1 << orig->kmod_from);
	ack_pack->uuid = bwr_get_uuid(hadmdev->bwr);
	ack_pack->errcode = error;

	packet_send(ack_pack);
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
		/**
		 *这种情况是本地的last_primary和对端的local_primary相同，表明，本地上次
		 *是对端节点的primary，并且up2date。这时候对端可以正常作为本地节点的secondary。
		 */
		ret = HS_OK;
		/**
		 *但是，如果本地节点曾经出现lpd，表明对端节点在作为primary的时候，
		 *最后一个block数据没有同步到本地节点，所以这时候对端节点的这个block
		 *需要重传，因为本地可能已经写入新的数据，所以这个时候需要进行delta_sync
		 */
		if (remote_info->last_page_damaged ||
				local_meta->last_primary.last_page_damaged)
			ret |= HS_DBM| HS_SETBM;
	}

	return ret;
}

static int __do_handshake(struct hadm_node *peer, struct bwr_meta *remote_meta,
		struct bwr_meta *local_meta)
{
	int ret = 0;
	//unsigned long flags;
	struct primary_info *remote_info = NULL;
	int local_node_id = get_node_id() ;
	int d_state, c_state, data_state, n_state;
	int h_state;
    int hadm_id = peer->hadmdev->minor;
	h_state = __hadm_node_get(&peer->s_state, S_HANDSHAKE);
	pr_info("hadm%d local_meta(node id %d): lastp id:uuid:seq:lpd(%d:%llu:%llu:%d).localp id:uuid:seq(%d:%llu:%llu).\n",
                    hadm_id,
                    local_node_id,
                    local_meta->last_primary.id,
                    local_meta->last_primary.uuid,
                    local_meta->last_primary.bwr_seq,
                    local_meta->last_primary.last_page_damaged,
                    local_meta->local_primary.id,
                    local_meta->local_primary.uuid,
                    local_meta->local_primary.bwr_seq);
	pr_info("hadm%d remote_meta(node id %d): lastp id:uuid:seq:lpd(%d:%llu:%llu:%d).localp id:uuid:seq(%d:%llu:%llu).\n",
                    hadm_id,
                    peer->id,
                    remote_meta->last_primary.id,
                    remote_meta->last_primary.uuid,
                    remote_meta->last_primary.bwr_seq,
                    remote_meta->last_primary.last_page_damaged,
                    remote_meta->local_primary.id,
                    remote_meta->local_primary.uuid,
                    remote_meta->local_primary.bwr_seq);

	d_state = __hadm_node_get(&peer->s_state, S_DSTATE);
	c_state = __hadm_node_get(&peer->s_state, S_CSTATE);
	data_state = __hadm_node_get(&peer->s_state, S_DATA_STATE);
	n_state = __hadm_node_get(&peer->s_state, S_NSTATE);

#if 0
	data_state = hadm_node_get(peer, SECONDARY_STATE, S_DATA_STATE);
	pr_info("%s: before remote node %d 's state: d_state = %d, c_state = %d, data_state = %d\n",
			__FUNCTION__,
			peer->id,
			d_state, c_state, data_state);
#endif

	pr_info("%s: before remote node %d 's hadm%d state: d_state = %s, c_state = %s, data_state = %s, h_state = %d, n_state=%d\n",
			__FUNCTION__,
			peer->id,
            hadm_id,
			dstate_name[d_state], cstate_name[c_state], datastate_name[data_state], h_state, n_state);
	/**
	if(h_state == HS_SUCCESS) {
		pr_info("duplicate handshake for node %d\n", peer->id);
		return -EKMOD_DUP_HS;
	}
	**/

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
	/**
	 *这里用data_state，而不是disk_state，因为本地记录
	 *的其他节点的disk_state可能为FAIL
	 */
	if(data_state != DATA_CONSISTENT) {
		ret |= HS_DBM;
	}

	if (ret & HS_OK) {
		/* require two lock
		 * node_s_state.lock
		 *	bwr lock
		 */
		/**
		 *如果握手成功，对端的状态为HS_OK|HS_SET_HEAD，但是本地有bitmap
		 *仍然按HS_DBM处理。
		 *
		 *
		 */
		if(atomic_read(&peer->dbm->nr_bit) > 0) {
			ret |= HS_DBM;
		}
		if (ret & HS_DBM ) {
			__hadm_node_set(&peer->s_state, S_DATA_STATE, DATA_DBM);
			__hadm_node_set(&peer->s_state, S_DSTATE, D_INCONSISTENT);

			if (ret & HS_SETBM)
				dbm_set_sector(peer->dbm, remote_info->last_page);
			pr_info("hadm%d hs ok & setbm\n", hadm_id);
		}else if (ret & HS_SETHEAD) {
			/**
			 *如果对端节点作为本地节点的secondary，重连时发现其last page damaged
			 *这时候，对端节点记录的最后一个sequence需要重新传输
			 */
			__hadm_node_set(&peer->s_state, S_DATA_STATE, DATA_CONSISTENT);
			__hadm_node_set(&peer->s_state, S_DSTATE, D_CONSISTENT);
			/**
			 *head的数据是没有发送到对端的数据，所以head应该对应着bwr_seq+1
			 */
			/**FIX ME : maybe lock problem**/
			if(ret & HS_SETBM && remote_info->bwr_seq > 1) {
				remote_info->bwr_seq--;

			}
			bwr_set_node_head(peer->hadmdev->bwr, peer->id,
					seq_to_bwr(remote_info->bwr_seq + 1, peer->hadmdev->bwr), 0);
			/**
			read_lock_irqsave(&peer->hadmdev->bwr->lock, flags);
			__hadm_node_reset_send_head(peer);
			read_unlock_irqrestore(&peer->hadmdev->bwr->lock, flags);
			**/
			pr_info("hadm%d node %d is consistent, try update head.\n"
					"(%llu:%llu), set head to %llu, snd_head %llu.\n",
                    hadm_id,
					peer->id,
					peer->hadmdev->bwr->mem_meta.head[peer->id],
					remote_meta->last_primary.bwr_seq,
					seq_to_bwr(remote_info->bwr_seq + 1, peer->hadmdev->bwr),
					peer->s_state.snd_head);
			pr_info("hadm%d hs ok & sethead\n", hadm_id);

		}
	} else {
		if (check_split_brain(local_meta, remote_meta)) {
			__hadm_node_set(&peer->s_state, S_DATA_STATE, DATA_SPLITBRAIN);
			ret = HS_SPLITBRAIN;
		} else {
			__hadm_node_set(&peer->s_state, S_DATA_STATE, DATA_CORRUPT);
			ret = HS_FULLSYNC;
		}
	}
	pr_info("hadm%d do handshake with node %d , ret = %d\n", hadm_id, peer->id, ret);
	d_state = __hadm_node_get(&peer->s_state, S_DSTATE);
	c_state = __hadm_node_get(&peer->s_state, S_CSTATE);
	data_state = __hadm_node_get(&peer->s_state, S_DATA_STATE);

	pr_info("%s: after handshake remote node %d 's hadm%d state: d_state = %s, c_state = %s, data_state = %s\n",
			__FUNCTION__,
			peer->id,
            hadm_id,
			dstate_name[d_state], cstate_name[c_state], datastate_name[data_state]);

	return ret & HS_OK ? 0: -EKMOD_UNKNOWN_STATE;
}

/* 只有主节点才处理握手包 */
static int p_handshake(void *arg)
{
	struct hadm_pack_node *node=(struct hadm_pack_node *)arg;
	struct packet *pack=node->pack;
	struct hadmdev *hadmdev;

	struct hadm_node *peer;
	struct bwr_meta *remote_meta, *local_meta;
	int role, ret;
	unsigned long flags;

	pr_info("[2]%s: hadm%d, node %d\n", __FUNCTION__, pack->dev_id, pack->node_from);

	hadmdev = find_hadmdev_by_minor(pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_handshake: can't find device %d\n", pack->dev_id);
		ret = -ENODEV;
		goto done;
	}
	/* role == R_PRIMARY */
	role = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_ROLE);
	if (role == R_SECONDARY) {
		ret = -EKMOD_REMOTE_ROLE;
		goto response;
	}
	peer = find_hadm_node_by_id(hadmdev, pack->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: hadm%d no node %d\n", __FUNCTION__, pack->dev_id, pack->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}

	local_meta = (struct bwr_meta *)&hadmdev->bwr->disk_meta;
	remote_meta = (struct bwr_meta *)pack->data;
	/**
	 *如果secondary节点先启动，将会持续发送handshake包，这样
	 *__do_handshake 会被执行多次，从而触发备机多次startrep操作
	 */
	spin_lock_irqsave(&peer->s_state.lock, flags);
	ret = __do_handshake(peer, remote_meta, local_meta);
	spin_unlock_irqrestore(&peer->s_state.lock, flags);
	pr_info("hadm%d get check_handshake %d with node %d\n",
                    pack->dev_id, ret, peer->id);
response:
	__do_device_handshake_ack(hadmdev, pack, ret);
done:
	return ret;
}

int send_startrep(int dev_id, struct hadm_node *node)
{
	struct packet *pack;

	pr_info("[5]%s hadm%d\n", __FUNCTION__, node->hadmdev->minor);

	pack = packet_alloc_for_node(0, GFP_KERNEL, node);
	if (!pack)
		return -ENOMEM;
	pack->dev_id = dev_id ;
	pack->type = P_STARTREP;

	packet_send(pack);
	return 0;
}

/*
 * Secondary 节点在收到 ACK 之后，需要发送一个 P_STARTREP 包到 Primary 节点
 * 从节点，这时候主节点比较适合发送的时机是在发送 P_HANDSHAKE_ACK 到从节点的时候。
 * 那么对从节点来说，就会出现竞争的情况，在从节点没有改变状态之前，有可能就会收
 * 到 P_DATA 的包，那么它只能丢弃掉这个包，因为它的状态还是 C_CONFIG 而不是
 * C_READY。
 *
 * 2. 在三个节点的情况下，有两个 Primary 节点和一个 Secondary 节点。如果
 * Secondary 和两个 Primary 节点都握手成功（这是有可能发生的）。如果 Secondary
 * 节点不发送 P_STARTREP 包告诉 Primary 节点它接受了哪个节点作为它的主节点，那么
 * 对于两个主节点来说，两个都会认为和这个 Secondary 节点握手成功。从而两个
 * Primary 节点都向 Secondary 节点发送数据，而对于 Secondary 节点来说，它将会丢
 * 弃一个 Primary 节点发送过来的数据，从而导致这个 Primary 节点对它产生了 dbm。
 */
static int p_handshake_ack(void *arg)
{
	struct hadm_pack_node *pnode;
	struct packet *recv_pack;
	struct hadm_node *primary_node;
	struct hadmdev *hadmdev;
	unsigned long flags;

	pnode = (struct hadm_pack_node *)arg;
	recv_pack = pnode->pack;

	pr_info("[4]%s: hadm%d node %d\n",
                    __FUNCTION__, recv_pack->dev_id, recv_pack->node_from);

	hadmdev = find_hadmdev_by_minor(recv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_handshake_ack: no device %d\n", recv_pack->dev_id);
		return -ENODEV;
	}

	if (recv_pack->errcode != 0) {
		pr_err("%s: hadm%d packet errcode %d.\n",
                        __FUNCTION__, recv_pack->dev_id, recv_pack->errcode);
		return -1;
	}

	primary_node = find_hadm_node_by_id(hadmdev, recv_pack->node_from);
	if (hadmdev_set_primary(hadmdev, primary_node) < 0) {
		if (hadmdev_get_primary_id(hadmdev) != recv_pack->node_from) {
			pr_warn("%s: Sorry, I(hadm%d) accepted node %d as primary\n",
                            __FUNCTION__, hadmdev->minor, hadmdev->primary->id);
			return -1;
		}
	}
	spin_lock_irqsave(&primary_node->s_state.lock, flags);
	if(__hadm_node_get(&primary_node->s_state, S_HANDSHAKE) != HS_SUCCESS) {
		pr_info("%s: hadm%d handshake success with node %d, accept it as my primary.\n",
				__FUNCTION__, hadmdev->minor, primary_node->id);
		primary_node->kmod_id = recv_pack->kmod_from;
		__hadm_node_set(&primary_node->s_state,S_HANDSHAKE,HS_SUCCESS);
		spin_unlock_irqrestore(&primary_node->s_state.lock, flags);
		set_last_primary(hadmdev->bwr, recv_pack->node_from, recv_pack->uuid);
		send_startrep(hadmdev->minor, primary_node);
	}else {
		spin_unlock_irqrestore(&primary_node->s_state.lock, flags);
	}
	//pr_info("%s:", __FUNCTION__);
	//bwr_dump(hadmdev->bwr);
	return 0;
}

static int p_startrep(void *arg)
{
	struct hadmdev *hadmdev;
	struct hadm_node *peer;
	struct hadm_pack_node *node = arg;
	struct packet *pack = node->pack;
	int role, ret = 0;
	int data_state;
	unsigned long flags;
	struct bwr *bwr;

	pr_info("[6] hadm%d %s\n", pack->dev_id , __FUNCTION__);

	hadmdev = find_hadmdev_by_minor(pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, pack->dev_id);
		ret=-ENODEV;
		goto done;
	}

	role = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		pr_info("%s: local is NOT hadm%d primary\n", __FUNCTION__, hadmdev->minor);
		ret = -EINVAL;
		goto done;
	}

	peer = find_hadm_node_by_id(hadmdev, pack->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: hadm%d no node %d\n", __FUNCTION__, pack->dev_id, pack->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}
	peer->kmod_id = pack->kmod_from;
	data_state = hadm_node_get(peer,SECONDARY_STATE,S_DATA_STATE);
	if(data_state == DATA_CONSISTENT){
		pr_info("%s node %d's hadm%d dstate is D_CONSISTENT\n",
                        __FUNCTION__,peer->id, hadmdev->minor);
		bwr = hadmdev->bwr;
		write_lock_irqsave(&bwr->lock, flags);
		if (bwr->mem_meta.tail == bwr->mem_meta.head[peer->id] &&
				atomic_read(&peer->dbm->nr_bit) == 0) {
			pr_info("%s hadm%d node %d already uptodate, tp: %u -> %u.\n",
					__FUNCTION__,
                    hadmdev->minor,
					peer->id,
					peer->conf.real_protocol,
					peer->conf.protocol);
			peer->conf.real_protocol = peer->conf.protocol;
		}else {
			pr_info("start replication hadm%d to node %d, head = %llu\n",
					hadmdev->minor, peer->id, (unsigned long long)bwr->mem_meta.head[peer->id]);
		}
		write_unlock_irqrestore(&bwr->lock, flags);

		spin_lock_irqsave(&peer->s_state.lock, flags);
		__hadm_node_test_and_set(&peer->s_state, S_CSTATE, C_STOPPED, C_SYNC);
		__hadm_node_set(&peer->s_state, S_HANDSHAKE, HS_SUCCESS);
		spin_unlock_irqrestore(&peer->s_state.lock, flags);
	}
	else{
		pr_info("%s hadm%d node %d is %s , create delta_sync thread\n",
				__FUNCTION__, hadmdev->minor, peer->id, datastate_name[data_state]);
		spin_lock_irqsave(&peer->s_state.lock, flags);
		__hadm_node_set(&peer->s_state, S_CSTATE,C_DELTA_SYNC_DBM);
		__hadm_node_set(&peer->s_state, S_HANDSHAKE, HS_SUCCESS);
		spin_unlock_irqrestore(&peer->s_state.lock, flags);
		create_dbm_sync_thread(P_DELTA_SYNC,peer);
	}

done:
	return ret;
}

static int __p_node_conn_state__disconnect_action(struct hadm_node *hadm_node)
{
	disconnect_node(hadm_node);
	return 0;
}

static int __do_device_handshake(struct hadmdev *hadmdev, struct hadm_node *node)
{
	struct packet *pack;
	struct bwr_meta *meta;

	pr_info("[1]%s:hadm%d\n",  __FUNCTION__, hadmdev->minor);

	pack = packet_alloc(sizeof(struct bwr_meta), GFP_KERNEL);
	if (!pack) {
		pr_err("%s: no memory\n", __FUNCTION__);
		return -ENOMEM;
	}
	pack->type = P_HANDSHAKE;
	pack->dev_id = hadmdev->minor;
	pack->node_to = (1 << node->id);
	pack->kmod_to = -1;	//FIXME or macro like MAX_KMOD_ID?
	meta = (struct bwr_meta *)pack->data;
	memcpy(meta, &hadmdev->bwr->disk_meta, sizeof(struct bwr_meta));

	packet_send(pack);
	return 0;
}

static int __do_send_status(struct hadmdev *dev, struct hadm_node *node)
{
	struct packet *pkt;

	pkt = packet_alloc_node_state_packet(dev);
	if (!pkt) {
		pr_err("%s: alloc packet failed.\n", __func__);
		return -ENOMEM;
	}

	pkt->type = P_NODE_STATE;
	pkt->dev_id = dev->minor;
	pkt->node_to = (1 << node->id);
	pkt->kmod_to = (1 << node->kmod_id);

	packet_send(pkt);
	return 0;
}

static int __do_probe_primary(struct hadmdev *dev, struct hadm_node *node)
{
	struct packet *pkt;

	pkt = packet_alloc(0, GFP_KERNEL);
	if (!pkt) {
		pr_err("%s: alloc packet failed.\n", __func__);
		return -ENOMEM;
	}

	pkt->type = P_PRIMARY_PROBE;
	pkt->dev_id = dev->minor;
	pkt->node_to = 0, set_bit(node->id, (unsigned long *)&pkt->node_to);
	pkt->kmod_to = -1;

	packet_send(pkt);
	return 0;
}

static int __p_node_conn_state__connect_action(struct hadm_node *hadm_node)
{
	struct hadmdev *hadmdev;
	int r_handshake, primary_id;
	uint32_t p_data_len, io_queue_len;

	hadmdev = hadm_node->hadmdev;
	if(hadm_node_get(hadm_node, SECONDARY_STATE, S_NSTATE) != N_CONNECT) {
		pr_info("hadm%d node %d connected.\n", hadm_node->hadmdev->minor, hadm_node->id);
		hadm_node_set(hadm_node, SECONDARY_STATE, S_NSTATE, N_CONNECT);
	}

	primary_id = hadmdev_get_primary_id(hadmdev);
	r_handshake = hadm_node_get(hadm_node, SECONDARY_STATE, S_HANDSHAKE);

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
		/**
		 *当备机网络闪断时，备机在bio_wrapper_queue的数据尚未完全写入到bwr中
		 *或者p_data queue里仍然有数据，这时候需要等待这些数据写入到磁盘再握手。
		 *这些数据大概有64m+64m，是否需要清除，待定
		 */
		p_data_len = hadm_queue_len(hadmdev->p_receiver_queue[P_DATA_TYPE]);
		io_queue_len = hadm_queue_len(hadmdev->bio_wrapper_queue[HADM_IO_WRITE]);
		if(p_data_len == 0 && io_queue_len == 0 ){
			pr_info("node %d connect, do device %d handshake\n",
				hadm_node->id, hadmdev->minor);
			__do_device_handshake(hadmdev, hadm_node);
		}else{
			pr_info("There are still data in network buffer(%u) or  not written to bwr(%u).  do device %d handshake with node %d is pending.\n",
					p_data_len, io_queue_len, hadmdev->minor, hadm_node->id);


		}
	}

	/* 本节点是主节点 */
	else if (primary_id == get_node_id()) {
		if (r_handshake == HS_SUCCESS)
			__do_send_status(hadmdev, hadm_node);
		else
			__do_probe_primary(hadmdev, hadm_node);
	}

	return 0;
}

static int p_node_conn_state(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pack = node->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	int dev_state, r_nstate, local_node_id;

	hadmdev = find_hadmdev_by_minor(pack->dev_id);
	if (hadmdev == NULL) {
		pr_err("p_node_conn_state: no device %d\n", pack->dev_id);
		dump_packet("  ", pack);
		goto done;
	}

	dev_state = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_DEV_STATE);
	if (dev_state == DEV_DOWN)
		goto done;
	if(hadmdev_error(hadmdev)) {
		goto done;
	}

	local_node_id = get_node_id();
	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		if (hadm_node->id == local_node_id)
			continue;
		r_nstate = ((1 << hadm_node->id) & pack->node_to) ?
			N_CONNECT : N_DISCONNECT;
		if (r_nstate == N_DISCONNECT) {
			__p_node_conn_state__disconnect_action(hadm_node);
		} else /* r_nstate == N_CONNECT */ {
			__p_node_conn_state__connect_action(hadm_node);
		}
	}

done:
	return 0;
}

/* 只有主节点才会响应探测包 */
static int p_primary_probe(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *orig, *ack;
	struct hadmdev *dev;
	int ret = 0, role;

	orig = node->pack;

	dev = find_hadmdev_by_minor(orig->dev_id);
	if (dev == NULL || IS_ERR(dev)) {
		ret = -ENODEV;
		goto done;
	}

	role = hadm_node_get(dev->local, SECONDARY_STATE, S_ROLE);
	if (role != R_PRIMARY) {
		ret = -EINVAL;
		goto done;
	}

	ack = packet_alloc(0, GFP_KERNEL);
	ack->type = P_PRIMARY_PROBE_ACK;
	ack->dev_id = node->pack->dev_id;
	ack->node_to = 0, set_bit(orig->node_from, (unsigned long *)&ack->node_to);
	ack->kmod_to = orig->kmod_from;
	packet_send(ack);

done:
	return ret;
}

static int p_primary_probe_ack(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pkt = node->pack;
	struct hadmdev *dev;
	struct hadm_node *peer;
	int ret = 0;

	dev = find_hadmdev_by_minor(pkt->dev_id);
	if (dev == NULL || IS_ERR(dev)) {
		pr_err("%s: can't find device %d\n",
		       __FUNCTION__, pkt->dev_id);
		ret = -ENODEV;
		goto done;
	}

	peer = find_hadm_node_by_id(dev, pkt->node_from);
	if (peer == NULL || IS_ERR(peer)) {
		pr_err("%s: no node %d\n", __FUNCTION__, pkt->node_from);
		ret = -EKMOD_NONODE;
		goto done;
	}

	hadm_node_set(peer, SECONDARY_STATE, S_DATA_STATE, DATA_SPLITBRAIN);

done:
	return ret;
}

static int p_kmod_disconn(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pkt = node->pack;
	struct hadmdev *dev;
	struct hadm_node *peer;
	int ret = 0;

	dev = find_hadmdev_by_minor(pkt->dev_id);
	if (dev == NULL || IS_ERR(dev)) {
		pr_err("%s: can't find device %d\n",
		       __FUNCTION__, pkt->dev_id);
		ret = -ENODEV;
		goto done;
	}

	peer = find_hadm_node_by_id(dev, pkt->node_from);
	if (!peer)
		goto done;

	if (pkt->kmod_from == INVALID_ID ||
			pkt->kmod_from == peer->kmod_id)
		disconnect_node(peer);
done:
	return ret;
}

/* FIXME down需要进行哪些动作？
 */
static int p_dev_down_notify(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pack = node->pack;
	struct hadm_node *hadm_node = NULL;
	struct hadmdev *hadmdev = NULL;

	pr_info("receive hadm%d dev down from node %d(server %d)\n", 
			pack->dev_id, pack->kmod_from, pack->node_from);
	hadmdev = find_hadmdev_by_minor(pack->dev_id);	
	if(hadmdev == NULL){
		return -EKMOD_NODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, pack->node_from);
	if(hadm_node == NULL){
		return -EKMOD_NONODE;
	}
	if (hadm_node == hadmdev->primary) {
		pr_err("ERROR: %s recv dev down notify from primary node", __func__);
		/* primary down */
	} else {
		disconnect_node(hadm_node);
		/* secondary down */
	}

	return 0;
}

static int p_dev_down_notify_ack(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pack = node->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *runnode;

	hadmdev = find_hadmdev_by_minor(pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_dev_down_notify_ack: no device %d\n", pack->dev_id);
		return -ENODEV;
	}

	/* everything back to C_CONFIG state */
	hadm_detach_device(hadmdev);
	list_for_each_entry(runnode, &hadmdev->hadm_node_list, node) {
		hadm_node_set(runnode, PRIMARY_STATE, S_INVALID, 1);
		hadm_node_set(runnode, SECONDARY_STATE, S_HANDSHAKE, DEVICE_NOT_HANDSHAKE);
	}
	hadm_node_set(hadmdev->local, SECONDARY_STATE, S_DEV_STATE, DEV_DOWN);

	return 0;
}

static int __p_node_state__primary_action(struct packet *pack, struct hadmdev *dev)
{
	struct hadm_node *runnode;
	struct node_state_packet *ns_pack;

	spin_lock(&dev->hadm_node_list_lock);
	list_for_each_entry(runnode, &dev->hadm_node_list, node) {
		ns_pack = node_state_packet_entry(pack, runnode->id);
		if (ns_pack)
			hadm_node_state_unpack(&runnode->p_state, ns_pack);
		if (pack->node_from == runnode->id) {
			runnode->p_state.uuid = pack->uuid;
			runnode->p_state.bwr_seq = pack->bwr_seq;
		}
	}
	spin_unlock(&dev->hadm_node_list_lock);

	return 0;
}

static int __p_node_state__secondary_action(struct packet *pack, struct hadmdev *dev)
{
	struct hadm_node *hadm_node=find_hadm_node_by_id(dev,pack->node_from);
	if(dev->primary && dev->primary->id==hadm_node->id) {
		pr_info("hadm%d primary node %d is change to secondary\n",
				dev->minor, hadm_node->id);

		hadmdev_set_primary(dev, NULL);
		hadm_node_set(hadm_node,SECONDARY_STATE,S_HANDSHAKE,HS_FAIL);
	}
	return 0;
}

/*
 * 之后从节点会收到 P_NODE_STATE 的包。根据发送节点的 role 来决定做什么操作。如
 * 果发送节点是 Primary 的话，那么就将主节点发送过来的状态保存下来；如果发送节点
 * 是 Secondary 的话，那么就说明发送节点由主节点变为了从节点，那么它需要放弃掉这
 * 个主节点。
 */
static int p_node_state(void *arg)
{
	struct hadm_pack_node *node = arg;
	struct packet *pack = node->pack;
	struct node_state_packet *ns_pack;
	struct hadmdev *dev;
	int primary_id, ret = 0;

	dev = find_hadmdev_by_minor(pack->dev_id);
	if (dev == NULL || IS_ERR(dev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, pack->dev_id);
		ret = -ENODEV;
		goto done;
	}

	ns_pack = node_state_packet_entry(pack, pack->node_from);
	if (ns_pack == NULL || IS_ERR(ns_pack)) {
		pr_err("%s: no remote node %d\n",
		       __FUNCTION__, pack->node_from);
		ret = -EINVAL;
		goto done;
	}
	primary_id = hadmdev_get_primary_id(dev);
	if (primary_id != INVALID_ID && primary_id != pack->node_from) {
		pr_info("%s: node %d is NOT my primary\n",
			__FUNCTION__, pack->node_from);
		ret = -EINVAL;
		goto done;
	}
	if (ns_pack->role == R_PRIMARY) {
		__p_node_state__primary_action(pack, dev);
	}
	else {
		__p_node_state__secondary_action(pack, dev);
	}

done:
	/* Don't send P_NODE_STATE_ACK, do we need it? */
	return ret;
}

static int p_node_state_ack(void *arg)
{
	return 0;
}

static struct packet_handler  p_functions[] = {
	[P_NODE_CONN_STATE] = { p_node_conn_state },
	[P_HANDSHAKE] = { p_handshake },
	[P_HANDSHAKE_ACK] = { p_handshake_ack },
	[P_DEV_DOWN_NOTIFY] = { p_dev_down_notify },
	[P_DEV_DOWN_NOTIFY_ACK] = { p_dev_down_notify_ack },
	[P_STARTREP] = { p_startrep },
	[P_NODE_STATE] = { p_node_state },
	[P_NODE_STATE_ACK] = { p_node_state_ack },
	[P_PRIMARY_PROBE] = { p_primary_probe },
	[P_PRIMARY_PROBE_ACK] = { p_primary_probe_ack },
	[P_KMOD_DISCONN] = {p_kmod_disconn },
	[P_CTRL_END] = { NULL }
};

packet_handler_t get_ctrl_worker_handler(int type)
{
	if(P_CTRL_START<type&&type<P_CTRL_END) {
		return p_functions[type].func;
	} else {
		return NULL;
	}
}
