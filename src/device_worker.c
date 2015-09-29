#include "common.h"

int device_worker_function(void *data)
{
	struct thread *thr;
	struct device *dev;
	struct packet *pkt;

	thr = (struct thread *)data;
	dev = (struct device *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = dev_get_work_packet(dev);

		if(pkt == NULL) {
			continue;
		}

		if(P_CTRL_START < pkt->type && pkt->type < P_CTRL_END) {
			device_meta_packet_handler(dev, pkt);
		} else if(P_DATA_START < pkt->type && pkt->type < P_DATA_END) {
			device_data_packet_handler(dev, pkt);
		} else {
			log_debug("%s: unknown packet %s\n", __FUNCTION__, packet_name[pkt->type]);
		}
	}

	return 0;
}

struct device_packet_handler dev_data_action[] = {
	[P_DATA_START] = {NULL},
	[P_DATA_END] = {NULL}
};

struct device_packet_handler dev_meta_action[] = {
	[P_CTRL_START] = {NULL},
	[P_CTRL_END] = { NULL },
};

int device_data_worker_function(void *data)
{
	struct thread *thr;
	struct device *dev;
	struct packet *pkt;
	int ret;

	thr = (struct thread *)data;
	dev = (struct device *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = dev_get_data_packet(dev);

		if(pkt == NULL) {
			continue;
		}

		while(dev->dfd < 0) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

		ret = packet_send(dev->dfd, pkt);

		log_debug(">>>>> send data packet to kernel dev , ret = %d",  ret);
		log_packet_header(pkt);

		if(ret <= 0) {
			dev_del_data_event(dev);
		}

		free_packet(pkt);
	}

	return 0;
}

int device_meta_worker_function(void *data)
{
	struct thread *thr;
	struct device *dev;
	struct packet *pkt;
	int ret;

	thr = (struct thread *)data;
	dev = (struct device *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = dev_get_meta_packet(dev);

		if(pkt == NULL) {
			continue;
		}

		while(dev->mfd < 0) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

		ret = packet_send(dev->mfd, pkt);

		log_debug(">>>>> send meta packet to kernel dev, ret = %d", ret);
		log_packet_header(pkt);

		if(ret <= 0) {
			dev_del_meta_event(dev);
		}

		free_packet(pkt);
	}

	return 0;
}

int device_data_packet_handler(struct device *dev, struct packet *orig_pkt)
{
	int type;

	type = orig_pkt->type;

	if(dev_data_action[type].action != NULL) {
		return dev_data_action[type].action(dev, orig_pkt);
	} else {
		return w_dev_data_common_action(dev, orig_pkt);
	}
}

int device_meta_packet_handler(struct device *dev, struct packet *orig_pkt)
{
	int type;

	type = orig_pkt->type;

	if(dev_meta_action[type].action != NULL) {
		return dev_meta_action[type].action(dev, orig_pkt);
	} else {
		return w_dev_meta_common_action(dev, orig_pkt);
	}
}

int w_dev_data_common_action(struct device *dev, struct packet *orig_pkt)
{
	int type;
	struct daemon *daemon;
	struct node_list *node_list;
	struct node *node;
	struct packet *pkt;
	int idx;

	daemon = dev->daemon;
	type = get_packet_node_type(orig_pkt);
	if(type == SITE_NODE) {
		pthread_spin_lock(&daemon->rnode_list_lock);
		node_list = daemon->rnode_list;
		pthread_spin_unlock(&daemon->rnode_list_lock);
	} else {
		node_list = daemon->lnode_list;
	}

	for(idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];

		if(packet_test_node_to(node->id, orig_pkt)) {
			pkt = packet_clone(orig_pkt);
			if(pkt == NULL) {
				continue;
			}

			node_put_data_packet(node, pkt);
		}
	}

	free_packet(orig_pkt);

	return 0;
}

int w_dev_meta_common_action(struct device *dev, struct packet *orig_pkt)
{
	int type;
	struct daemon *daemon;
	struct node_list *node_list;
	struct node *node;
	struct packet *pkt;
	int idx;

	daemon = dev->daemon;
	type = get_packet_node_type(orig_pkt);
	if (type == SITE_NODE) {
		pthread_spin_lock(&daemon->rnode_list_lock);
		node_list = daemon->rnode_list;
		pthread_spin_unlock(&daemon->rnode_list_lock);
	} else {
		node_list = daemon->lnode_list;
	}

	for(idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];

		if(packet_test_node_to(node->id, orig_pkt)) {
			pkt = packet_clone(orig_pkt);
			if(pkt == NULL) {
				continue;
			}

			node_put_meta_packet(node, pkt);
		}
	}

	free_packet(orig_pkt);

	return 0;
}
