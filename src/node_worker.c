/*
 * meta 和 data 的处理流程基本上是一样的，除了 meta 需要特殊处理 P_META_PING 和
 * P_META_PING_ACK，但还是把 meta 和 data 的处理分成独立的处理流程，而不是使用一
 * 个统一的流程。这样破坏了 DRI 原则，但这样做更直接，也更容易理解，毕竟只有两种
 * 情况，可能更容易维护。如果以后有确切的需要把它们合并，那么就合并吧。
 */

#include "common.h"

static int transfer_data_to_local(struct node *node, struct packet *pkt)
{
	struct daemon *daemon;
	struct device_list *dev_list;
	struct device *dev;

	daemon = node->daemon;
	dev_list = daemon->dev_list;
	dev = find_device(dev_list, pkt->dev_id);
	if (!dev) {
		log_error("no device %d while transfer data to local", pkt->dev_id);
		log_packet_header(pkt, packet_log_error);
		free_packet(pkt);
		return -1;
	}

	if(dev_put_data_packet(dev, pkt) < 0){
		log_error("failed to put packet into device %d", dev->id);
		log_packet_header(pkt, packet_log_error);
		free_packet(pkt);
		dev_del_data_event(dev);
	}

	return 0;
}

static int transfer_meta_to_local(struct node *node, struct packet *pkt)
{
	struct daemon *daemon;
	struct device_list *dev_list;
	struct device *dev;

	daemon = node->daemon;
	dev_list = daemon->dev_list;
	dev = find_device(dev_list, pkt->dev_id);
	if (!dev) {
		log_error("no device %d while transfer meta to local", pkt->dev_id);
		log_packet_header(pkt, packet_log_error);
		free_packet(pkt);
		return -1;
	}

	if(dev_put_meta_packet(dev, pkt) < 0){
		free_packet(pkt);
		dev_del_meta_event(dev);
		return -1;
	}

	return 0;
}

static int transfer_data_compress(struct node *node, struct packet *pkt)
{
	struct z_packet *z_pkt;
	int ret;

	z_pkt = pack_z_packet(pkt);
	if (!z_pkt) {
		log_error("compress node %d packet failed", node->id);
		return -1;
	}

	ret = z_packet_send(node->dfd, z_pkt);
	if (ret <= 0) {
		log_error("send data zpacket to node %d (%s) failed", node->id, node->remote_ip);
		//node_del_data_event(node);
		return -1;
	}

	free_z_packet(z_pkt);
	return ret;
}

static int transfer_meta_compress(struct node *node, struct packet *pkt)
{
	struct z_packet *z_pkt;
	int ret;

	z_pkt = pack_z_packet(pkt);
	if (!z_pkt) {
		log_error("compress node %d packet failed", node->id);
		return -1;
	}

	ret = z_packet_send(node->mfd, z_pkt);
	if (ret <= 0) {
		log_error("send meta zpacket to node %d (%s) failed", node->id, node->remote_ip);
		//node_del_meta_event(node);
		return -1;
	}

	free_z_packet(z_pkt);
	return ret;
}

static int transfer_data_no_compress(struct node *node, struct packet *pkt)
{
	int ret;

	ret = packet_send(node->dfd, pkt);
	if (ret <= 0) {
		log_error("send data packet to node %d (%s) failed", node->id, node->remote_ip);
		log_packet_header(pkt, packet_log_error);
		//node_del_data_event(node);
		return -1;
	}
}

static int transfer_meta_no_compress(struct node *node, struct packet *pkt)
{
	int ret;

	ret = packet_send(node->mfd, pkt);
	if (ret <= 0) {
		log_error("send meta packet to node %d (%s) failed", node->id, node->remote_ip);
		log_packet_header(pkt, packet_log_error);
		//node_del_meta_event(node);
		return -1;
	}
}

static int transfer_data_to_remote(struct node *node, struct packet *pkt)
{
	int ret;

#ifdef HADM_COMPRESS
	ret = transfer_data_compress(node, pkt);
#else
	ret = transfer_data_no_compress(node, pkt);
#endif

	return ret;
}

static int transfer_meta_to_remote(struct node *node, struct packet *pkt)
{
	int ret;

#ifdef HADM_COMPRESS
	ret = transfer_meta_compress(node, pkt);
#else
	ret = transfer_meta_no_compress(node, pkt);
#endif

	return ret;
}

static int transfer_data(struct node *node, struct packet *pkt)
{
	struct daemon *daemon;
	struct node_list *node_list;
	struct node *local_node;
	int ret = 0;

	daemon = node->daemon;
	node_list = daemon->node_list;
	local_node = node_list->nodes[node_list->local_node_id];
	if (local_node->id == node->id){
		ret = transfer_data_to_local(node, pkt);
	}
	else {
		ret = transfer_data_to_remote(node, pkt);
		free_packet(pkt);
	}

	return ret;
}

static int transfer_meta(struct node *node, struct packet *pkt)
{
	struct daemon *daemon;
	struct node_list *node_list;
	struct node *local_node;
	int ret = 0;

	daemon = node->daemon;
	node_list = daemon->node_list;
	local_node = node_list->nodes[node_list->local_node_id];
	if (local_node->id == node->id)
		ret = transfer_meta_to_local(node, pkt);
	else {
		ret = transfer_meta_to_remote(node, pkt);
		free_packet(pkt);
	}

	return ret;
}

int node_data_worker_function(void *data)
{
	struct thread *thr;
	struct node *node;
	struct packet *pkt;

	thr = (struct thread *)data;
	node = (struct node *)thr->data;

	while (thr->state == THREAD_RUN) {
		pkt = node_get_data_packet(node);
		if (!pkt)
			continue;
		while (node->data_conn_state == NODE_DFD_DISCONNECTED)
			sleep(CONNECT_TIMER_TIMEOUT);
		transfer_data(node, pkt);
		//free_packet(pkt);
	}

	return 0;
}

int node_meta_worker_function(void *data)
{
	struct thread *thr;
	struct node *node;
	struct packet *pkt;

	thr = (struct thread *)data;
	node = (struct node *)thr->data;

	while (thr->state == THREAD_RUN) {
		pkt = node_get_meta_packet(node);
		if (!pkt)
			continue;
		while (node->meta_conn_state == NODE_MFD_DISCONNECTED)
			sleep(CONNECT_TIMER_TIMEOUT);
		transfer_meta(node, pkt);
		//free_packet(pkt);
	}

	return 0;
}

int w_node_meta_ping_action(struct node *node, struct packet *orig_pkt)
{
	struct packet *pkt;
	struct daemon *daemon;
	struct node *local_node;

	daemon = node->daemon;
	local_node = daemon->local_node;

	pkt = alloc_packet0();
	if(pkt == NULL) {
		goto err;
	}

	pkt->type = P_META_PING_ACK;
	pkt->node_from = local_node->id;
	packet_set_node_to(node->id, pkt);

	free_packet(orig_pkt);

	return node_put_meta_packet(node, pkt);

err:
	free_packet(orig_pkt);

	return -1;
}

int w_node_meta_ping_ack_action(struct node *node, struct packet *orig_pkt)
{
	if(--node->ping < 0) {
		node->ping = 0;
	}

	free_packet(orig_pkt);

	return 0;
}

int w_node_meta_common_action(struct node *node, struct packet *orig_pkt)
{
	struct daemon *daemon;
	struct device_list *dev_list;
	struct device *dev;
	struct packet *pkt;
	int i, ret = 0;

	daemon = node->daemon;
	dev_list = daemon->dev_list;

	for (i = 0; i < dev_list->dev_num; i++) {
		dev = dev_list->devs[i];
		if (!device_is_target(dev, orig_pkt->kmod_to))
			continue;
		if (!device_want_recv(dev))
			continue;
		pkt = packet_clone(orig_pkt);
		if (!pkt) {
			log_error("send to kmod node %d failed: no memory", dev->id);
			ret = -1;
			goto out;
		}
		ret = dev_put_meta_packet(dev, pkt);
		if (ret < 0) {
			log_warn("kmod node %d meta queue is NOT start", dev->id);
			free_packet(pkt);
			ret = -1;
			goto out;
		}
	}

out:
	free_packet(orig_pkt);
	return ret;
}

struct node_packet_handler node_meta_action[] = {
	[P_META_PING] = {w_node_meta_ping_action},
	[P_META_PING_ACK] = {w_node_meta_ping_ack_action},
	[P_CTRL_END] = {NULL}
};

int node_meta_packet_handler(struct node *node, struct packet *orig_pkt)
{
	int type;

	type = orig_pkt->type;
	if (!node_meta_action[type].action) {
		return w_node_meta_common_action(node, orig_pkt);
	} else {
		return node_meta_action[type].action(node, orig_pkt);
	}
}
