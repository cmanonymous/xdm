#include "common.h"

int node_worker_function(void *data)
{
	struct thread *thr;
	struct node *node;
	struct packet *pkt;

	thr = (struct thread *)data;
	node = (struct node *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = node_get_work_packet(node);

		if(pkt == NULL) {
			continue;
		}

		if (P_CTRL_START < pkt->type && pkt->type < P_CTRL_END) {
			node_meta_packet_handler(node, pkt);
		} else if (P_DATA_START < pkt->type && pkt->type < P_DATA_END) {
			node_data_packet_handler(node, pkt);
		} else {
			log_debug("%s:unknown packet %s\n", __FUNCTION__, packet_name[pkt->type]);
		}
	}

	return 0;
}

struct node_packet_handler node_data_action[] = {
	[P_DATA_START] = {NULL},
	[P_DATA_END] = {NULL},
};

struct node_packet_handler node_meta_action[] = {
	[P_CTRL_START] = {NULL},
	[P_SC_PING] = {w_node_meta_ping_action},
	[P_NC_PING] = {w_node_meta_ping_action},
	[P_SC_PING_ACK] = {w_node_meta_ping_ack_action},
	[P_NC_PING_ACK] = {w_node_meta_ping_ack_action},
	[P_CTRL_END] = {NULL}
};

int node_data_worker_function(void *data)
{
	struct thread *thr;
	struct node *node;
	int ret;
	struct packet *pkt;
#ifdef HADM_COMPRESS
	struct z_packet *z_pkt
#endif

	thr = (struct thread *)data;
	node = (struct node *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = node_get_data_packet(node);

		if(pkt == NULL) {
			continue;
		}

		while(node->data_conn_state == NODE_DFD_DISCONNECTED) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

#ifdef HADM_COMPRESS
		z_pkt = pack_z_packet(pkt);
		if(z_pkt == NULL) {
			free_packet(pkt);
			continue;
		}

		ret = z_packet_send(node->dfd, z_pkt);
		free_z_packet(z_pkt);
#else
		ret = packet_send(node->dfd, pkt);

		log_debug(">>>>> send data packet to %s %d (%s), ret = %d", node_type_name[node->type], node->id, node->remote_ip, ret);
		log_packet_header(pkt);
#endif

		if(ret <= 0) {
			node_del_data_event(node);
		}

		free_packet(pkt);
	}

	return 0;
}

int node_meta_worker_function(void *data)
{
	struct thread *thr;
	struct node *node;
	int ret;
	struct packet *pkt;
#ifdef HADM_COMPRESS
	struct z_packet *z_pkt
#endif

	thr = (struct thread *)data;
	node = (struct node *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = node_get_meta_packet(node);

		if(pkt == NULL) {
			continue;
		}

		while(node->meta_conn_state == NODE_MFD_DISCONNECTED) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

#ifdef HADM_COMPRESS
		z_pkt = pack_z_packet(pkt);
		if(z_pkt == NULL) {
			free_packet(pkt);
			continue;
		}

		ret = z_packet_send(node->mfd, z_pkt);
		free_z_packet(z_pkt);
#else
		ret = packet_send(node->mfd, pkt);

		log_debug(">>>>> send meta packet to %s %d (%s), ret = %d", node_type_name[node->type], node->id, node->remote_ip, ret);
		log_packet_header(pkt);
#endif

		if(ret <= 0) {
			node_del_meta_event(node);
		}

		free_packet(pkt);
	}

	return 0;
}

int w_node_meta_ping_action(struct node *node, struct packet *orig_pkt)
{
	struct packet *pkt;
	struct daemon *daemon;
	int node_from;
	int packet_type;

	daemon = node->daemon;
	if (node->type == LOCAL_NODE) {
		node_from = daemon->local_node->id;
		packet_type = P_NC_PING_ACK;
	} else {
		node_from = daemon->local_site_id;
		packet_type = P_SC_PING_ACK;
	}

	pkt = alloc_packet0();
	if(pkt == NULL) {
		goto err;
	}

	pkt->type = packet_type;
	pkt->node_from = node_from;
	packet_set_node_to(node->id, pkt);

	free_packet(orig_pkt);

	return node_put_meta_packet(node, pkt);

err:
	free_packet(orig_pkt);

	return -1;
}

int w_node_meta_ping_ack_action(struct node *node, struct packet *orig_pkt)
{

	node->ping_count--;
	if (node->ping_count < 0) {
		node->ping_count = 0;
	}

	free_packet(orig_pkt);

	return 0;
}

int node_data_packet_handler(struct node *node, struct packet *orig_pkt)
{
	int type;

	type = orig_pkt->type;
	if(node_data_action[type].action != NULL) {
		return node_data_action[type].action(node, orig_pkt);
	} else {
		return w_node_data_common_action(node,orig_pkt);
	}
}

int node_meta_packet_handler(struct node *node, struct packet *orig_pkt)
{
	int type;

	type = orig_pkt->type;
	if(node_meta_action[type].action != NULL) {
		return node_meta_action[type].action(node, orig_pkt);
	} else {
		return w_node_meta_common_action(node,orig_pkt);
	}

}

int w_node_data_common_action(struct node *node, struct packet *orig_pkt)
{
	struct daemon *daemon;
	struct device *dev;

	daemon = node->daemon;
	dev = daemon->dev;

	return dev_put_data_packet(dev, orig_pkt);
}

int w_node_meta_common_action(struct node *node, struct packet *orig_pkt)
{
	struct daemon *daemon;
	struct device *dev;

	daemon = node->daemon;
	dev = daemon->dev;

	return dev_put_meta_packet(dev, orig_pkt);
}
