#ifndef __NODE_H__
#define __NODE_H__

#include "common.h"

struct node {
	int id;
	uint32_t share_node_bits;
	char hostname[MAX_HOSTNAME_LEN];
	char local_ip[MAX_IPADDR_LEN];
	char remote_ip[MAX_IPADDR_LEN];
	char local_port[MAX_PORT_LEN];
	char remote_port[MAX_PORT_LEN];
	int dfd;
	int data_conn_state;
	int mfd;
	int meta_conn_state;
	struct daemon *daemon;
	struct event *data_event;
	event_handler data_handler;
	struct event *meta_event;
	event_handler meta_handler;
	struct queue *data_q;
	struct queue *meta_q;
	struct queue *work_q;
	struct thread *data_worker;
	struct thread *meta_worker;
	struct thread *worker;
	struct timer *ping_timer;
	pthread_spinlock_t spinlock;
	int ping;
};

struct node_list {
	int local_node_id;
	int max_num;
	int node_num;
	struct node **nodes;
	int ping;
	int pingtimeout;
};

struct node *alloc_node();

void free_node(struct node *node);

struct node *make_node(int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port);

int node_connect(int link, struct node *local_node, struct node *remote_node);

int node_data_connect(struct node *local_node, struct node *remote_node);

int node_meta_connect(struct node *local_node, struct node *remote_node);

int node_make_server(struct node *node);

int node_add_data_event(struct node *node, struct daemon *daemon);

void node_del_data_event(struct node *node);

int node_add_meta_event(struct node *node, struct daemon *daemon);

void node_del_meta_event(struct node *node);

int node_add_ping_timer(struct node *node, struct daemon *daemon);

struct node_list *alloc_node_list(int node_num);

struct node_list *create_node_list(int node_num);

void free_node_list(struct node_list *node_list);

struct node_list *init_node_list(struct daemon *daemon, struct config *cfg);

void node_list_set_node(struct node_list *node_list, int idx, struct node * node);

void node_list_run(struct node_list *node_list);

void node_data_handler(evutil_socket_t fd, short event, void *args);

void node_meta_handler(evutil_socket_t fd, short event, void *args);

void node_set_daemon(struct node *node, struct daemon *daemon);

void ping_timer_cb(evutil_socket_t fd, short event, void *args);

int node_put_data_packet(struct node *node, struct packet *pkt);

struct packet *node_get_data_packet(struct node *node);

int node_put_meta_packet(struct node *node, struct packet *pkt);

int node_put_data_packet_force(struct node *node, struct packet *pkt,
		cb_fn *callback, void *data);

struct packet *node_get_meta_packet(struct node *node);

int node_is_target(struct node *node, int node_to);

int node_available(struct node *node);

int node_disconnect(struct node *node);

void pr_node(struct node *node);

void pr_node_list(struct node_list *node_list);

#endif // __NODE_H__
