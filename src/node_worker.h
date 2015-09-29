#ifndef __NODE_WORKER_H__
#define __NODE_WORKER_H__

struct node_packet_handler {
	    int (*action)(struct node *node, struct packet *orig_pkt);
};

int node_worker_function(void *data);

int node_data_worker_function(void *data);

int node_meta_worker_function(void *data);

int w_node_meta_ping_action(struct node *node, struct packet *orig_pkt);

int w_node_meta_ping_ack_action(struct node *node, struct packet *orig_pkt);

int node_data_packet_handler(struct node *node, struct packet *orig_pkt);

int node_meta_packet_handler(struct node *node, struct packet *orig_pkt);

int w_node_data_common_action(struct node *node, struct packet *orig_pkt);

int w_node_meta_common_action(struct node *node, struct packet *orig_pkt);

#endif // __NODE_WORKER_H__
