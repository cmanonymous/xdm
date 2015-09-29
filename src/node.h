#ifndef __NODE_H__
#define __NODE_H__

#include "common.h"

enum node_property {
	LOG_OWNER = 0,
};

struct node {
	int id;
	int type;					/* remote node or local node */
	int sfd;
	char hostname[MAX_HOSTNAME_LEN];
	char local_ip[MAX_IPADDR_LEN];
	char remote_ip[MAX_IPADDR_LEN];
	char local_port[MAX_PORT_LEN];
	char remote_port[MAX_PORT_LEN];
	struct daemon *daemon;

	int dfd;
	int data_conn_state;
	struct event *data_event;
	event_handler data_handler;

	int mfd;
	int meta_conn_state;
	struct event *meta_event;
	event_handler meta_handler;

	struct queue *data_q;
	struct queue *meta_q;
	struct queue *work_q;
	struct thread *data_worker;
	struct thread *meta_worker;
	struct thread *worker;

	struct timer *ping_timer;
	int ping_timer_timeout;	/* ping in conf */
	int max_ping_count;	/* pingtimeout in conf */
	int ping_count;

	pthread_spinlock_t spinlock;
};

struct node_list {
	int local_node_id;
	int max_num;
	int node_num;
	struct node **nodes;
};

struct node *alloc_node();

void free_node(struct node *node);

int init_node(struct node *node, int type, int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port,
		int ping_timer_timeout, int max_ping_count);

struct node *make_node(int type, int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port,
		int ping_timer_timeout, int max_ping_count);

int node_logowner(struct resource *resource);

int node_handshake(int link, struct node *local_node, struct node *remote_node);

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

struct node_list *init_lnode_list(struct daemon *daemon, struct config *cfg);

void node_list_run(struct node_list *node_list);

void node_data_handler(evutil_socket_t fd, short event, void *args);

void node_meta_handler(evutil_socket_t fd, short event, void *args);

void node_set_daemon(struct node *node, struct daemon *daemon);

void ping_timer_cb(evutil_socket_t fd, short event, void *args);

int node_put_work_packet(struct node *node, struct packet *pkt);

struct packet *node_get_work_packet(struct node *node);

int node_put_data_packet(struct node *node, struct packet *pkt);

struct packet *node_get_data_packet(struct node *node);

int node_put_meta_packet(struct node *node, struct packet *pkt);

struct packet *node_get_meta_packet(struct node *node);

int node_list_put(struct node_list *list, struct node *node);

void log_node(struct node *node);

#endif // __NODE_H__
