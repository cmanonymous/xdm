#include "common.h"

#define NODE_DATA_LINK 0
#define NODE_META_LINK 1
#define SOCK_TIMEOUT 3

struct node *alloc_node()
{
	struct node *node;

	node = malloc(sizeof(struct node));
	if(node == NULL) {
		return NULL;
	}

	memset(node, 0, sizeof(struct node));
	node->dfd = -1;
	node->data_conn_state = NODE_DFD_DISCONNECTED;
	node->mfd = -1;
	node->meta_conn_state = NODE_MFD_DISCONNECTED;
	pthread_spin_init(&node->spinlock, PTHREAD_PROCESS_PRIVATE);

	return node;
}

void free_node(struct node *node)
{
	if (node) {
		free_thread(node->worker);
		free_thread(node->meta_worker);
		free_thread(node->data_worker);
		free_queue(node->work_q);
		free_queue(node->data_q);
		free_queue(node->meta_q);
	}
	free(node);
}

int init_node(struct node *node, int type, int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port,
		int ping_timer_timeout, int max_ping_count)
{
	struct queue *q;
	struct thread *thr;
	char name[MAX_NAME_LEN];

	memset(node, 0, sizeof(struct node));
	node->dfd = -1;
	node->data_conn_state = NODE_DFD_DISCONNECTED;
	node->mfd = -1;
	node->meta_conn_state = NODE_MFD_DISCONNECTED;
	pthread_spin_init(&node->spinlock, PTHREAD_PROCESS_PRIVATE);

	node->id = id;
	node->type = type;
	node->sfd = -1;
	strncpy(node->hostname, hostname, MAX_HOSTNAME_LEN);
	strncpy(node->local_ip, local_ip, MAX_IPADDR_LEN);
	strncpy(node->remote_ip, remote_ip, MAX_IPADDR_LEN);
	strncpy(node->local_port, local_port, MAX_PORT_LEN);
	strncpy(node->remote_port, remote_port, MAX_PORT_LEN);
	node->data_handler = node_data_handler;
	node->meta_handler = node_meta_handler;
	node->ping_timer_timeout = ping_timer_timeout;
	node->max_ping_count = max_ping_count;

	q = init_queue();
	if (!q)
		return -1;
	node->data_q = q;

	q = init_queue();
	if (!q)
		goto err_free_data_q;
	node->meta_q = q;

	q = init_queue();
	if (!q)
		goto err_free_meta_q;
	node->work_q = q;

	snprintf(name, sizeof(name), "%s%d:data_worker", node_type_name[node->type], node->id);
	thr = create_thread(name, "node_data_worker_function", node_data_worker_function, node);
	if (!thr)
		goto err_free_work_q;
	node->data_worker = thr;

	snprintf(name, sizeof(name), "%s%d:meta_worker", node_type_name[node->type], node->id);
	thr = create_thread(name, "node_meta_worker_function", node_meta_worker_function, node);
	if (!thr)
		goto err_free_data_thread;
	node->meta_worker = thr;

	snprintf(name, sizeof(name), "%s%d:worker", node_type_name[node->type], node->id);
	thr = create_thread(name, "node_worker_function", node_worker_function, node);
	if (!thr)
		goto err_free_meta_thread;
	node->worker = thr;

	return 0;

err_free_meta_thread:
	free_thread(node->meta_worker);
err_free_data_thread:
	free_thread(node->data_worker);
err_free_work_q:
	free_queue(node->work_q);
err_free_data_q:
	free_queue(node->data_q);
err_free_meta_q:
	free_queue(node->meta_q);
	return -1;
}

struct node *make_node(int type, int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port,
		int ping_timer_timeout, int max_ping_count)
{
	struct node *node;
	int ret;

	node = alloc_node();
	if(node == NULL) {
		return NULL;
	}
	ret = init_node(node, type, id, hostname,
			local_ip, remote_ip, local_port, remote_port,
			ping_timer_timeout, max_ping_count);
	if (ret < 0)
		goto err_free_node;

	return node;

err_free_node:
	free_node(node);
	return NULL;
}

int node_handshake(int link, struct node *local_node, struct node *remote_node)
{
	int fd;
	struct sock_packet *sock_pkt;

	if(link == NODE_DATA_LINK) {
		sock_pkt = create_sock_packet(DATA_HANDSHAKE, local_node->id, remote_node->type, remote_node->local_ip);
		fd = remote_node->dfd;
	} else if(link == NODE_META_LINK) {
		sock_pkt = create_sock_packet(META_HANDSHAKE, local_node->id, remote_node->type, remote_node->local_ip);
		fd = remote_node->mfd;
	} else {
		return -1;
	}

	if(sock_pkt == NULL) {
		return -1;
	}

	sock_clear_nonblock(fd);
	sock_packet_send(fd, sock_pkt);
	free_sock_packet(sock_pkt);

	return 0;
}

int node_connect(int link, struct node *local_node, struct node *remote_node)
{
	int *fdp;
	int sock;
	struct sockaddr remote_addr;
	struct sock_packet *sock_pkt;

	fdp = link == NODE_DATA_LINK ? &remote_node->dfd : &remote_node->mfd;

	if (*fdp < 0) {
		sock = sock_create();
		if (sock < 0)
			return -1;
		if (sock_set_nonblock(sock) < 0)
			return -1;
		*fdp = sock;
	}

	if (sock_get_addr(remote_node->remote_ip, remote_node->remote_port, &remote_addr) < 0) {
		return -1;
	}

	return sock_connect(*fdp, &remote_addr);
}

int node_data_handshake(struct node *local_node, struct node *remote_node)
{
	return node_handshake(NODE_DATA_LINK, local_node, remote_node);
}

int node_meta_handshake(struct node *local_node, struct node *remote_node)
{
	return node_handshake(NODE_META_LINK, local_node, remote_node);
}

int node_data_connect(struct node *local_node, struct node *remote_node)
{
	return node_connect(NODE_DATA_LINK, local_node, remote_node);
}

int node_meta_connect(struct node *local_node, struct node *remote_node)
{
	return node_connect(NODE_META_LINK, local_node, remote_node);
}

int node_make_server(struct node *node)
{
	char ipaddr[MAX_IPADDR_LEN];

	snprintf(ipaddr, sizeof(ipaddr), "%s", node->type == SITE_NODE ? "0.0.0.0" : node->remote_ip);

	return make_server(ipaddr, node->remote_port);
}

int node_add_data_event(struct node *node, struct daemon *daemon)
{
	struct event *data_event;

	if(node->data_conn_state == NODE_DFD_DISCONNECTED
			|| node->data_event != NULL) {
		return -1;
	}

	data_event = event_new(daemon->event_base, node->dfd, EV_READ | EV_PERSIST, node->data_handler, node);
	if(data_event == NULL) {
		return -1;
	}

	if(event_add(data_event, NULL)) {
		event_free(data_event);
		return -1;
	}

	node->data_event = data_event;

	return 0;
}

void node_del_data_event(struct node *node)
{
	int ret;

	shutdown(node->dfd, SHUT_RDWR);
	sock_close(node->dfd);
	node->dfd = -1;
	node->data_conn_state = NODE_DFD_DISCONNECTED;
	node->ping_count = 0;

	ret = pthread_spin_trylock(&node->spinlock);
	if(ret != 0) {
		return;
	}

	if(node->data_event == NULL) {
		goto err;
	}

	event_free(node->data_event);
	node->data_event = NULL;

	pthread_spin_unlock(&node->spinlock);

	clean_packet_queue(node->data_q);

	return;

err:
	pthread_spin_unlock(&node->spinlock);
}

int node_add_meta_event(struct node *node, struct daemon *daemon)
{
	struct event *meta_event;

	if(node->meta_conn_state == NODE_MFD_DISCONNECTED
			|| node->meta_event != NULL) {
		return -1;
	}

	meta_event = event_new(daemon->event_base, node->mfd, EV_READ | EV_PERSIST, node->meta_handler, node);
	if(meta_event == NULL) {
		return -1;
	}

	if(event_add(meta_event, NULL)) {
		event_free(meta_event);
		return -1;
	}

	node->meta_event = meta_event;

	return 0;
}

void node_del_meta_event(struct node *node)
{
	int ret;

	shutdown(node->mfd, SHUT_RDWR);
	sock_close(node->mfd);
	node->mfd = -1;
	node->meta_conn_state = NODE_MFD_DISCONNECTED;
	node->ping_count = 0;

	ret = pthread_spin_trylock(&node->spinlock);
	if(ret != 0) {
		return;
	}

	if(node->meta_event == NULL) {
		goto err;
	}

	event_free(node->meta_event);
	node->meta_event = NULL;

	pthread_spin_unlock(&node->spinlock);

	clean_packet_queue(node->meta_q);

	return;

err:
	pthread_spin_unlock(&node->spinlock);
}

int node_add_ping_timer(struct node *node, struct daemon *daemon)
{
	struct timer *ping_timer;
	struct node_list *node_list;
	struct timer_base *tb;
	char name[MAX_NAME_LEN];

	tb = daemon->timer_base;

	if (node->type == LOCAL_NODE) {
		node_list = daemon->lnode_list;
	} else /* node->type == SITE_NODE */ {
		pthread_spin_lock(&daemon->rnode_list_lock);
		node_list = daemon->rnode_list;
		pthread_spin_unlock(&daemon->rnode_list_lock);
	}

	if(node->ping_timer != NULL) {
		timer_add_tb(tb, node->ping_timer);
		return 0;
	}

	snprintf(name, sizeof(name), "%s%d:ping_timer", node_type_name[node->type], node->id);
	ping_timer = create_timer(name, node->ping_timer_timeout, ping_timer_cb, node);
	if(ping_timer == NULL) {
		return -1;
	}

	node->ping_timer = ping_timer;
	timer_add_tb(tb, node->ping_timer);

	return  0;
}

struct node_list *alloc_node_list(int node_num)
{
	struct node_list *node_list;
	struct node **nodes;

	node_list = malloc(sizeof(struct node_list));
	if(node_list == NULL) {
		return NULL;
	}

	memset(node_list, 0, sizeof(struct node_list));
	node_list->local_node_id = -1;
	node_list->max_num = node_num;
	node_list->node_num = 0;

	nodes = malloc(node_num * sizeof(struct node *));
	if(nodes == NULL) {
		free(node_list);
		return NULL;
	}

	memset(nodes, 0, node_num * sizeof(struct node *));
	node_list->nodes = nodes;

	return node_list;
}

struct node_list *create_node_list(int node_num)
{
	return alloc_node_list(node_num);
}

void node_list_clean_up(struct node_list *list)
{
	if (list) {
		free(list->nodes);
		free(list);
	}
}

void free_node_list(struct node_list *node_list)
{
	int idx;

	for(idx = 0; idx < node_list->node_num; idx++) {
		if(node_list->nodes[idx]) {
			free_node(node_list->nodes[idx]);
		}
	}

	free(node_list->nodes);
	free(node_list);
}

/*
 * node_logowner: 判断节点是不是 resource 的 logowner
 *
 * 什么是 logowner 节点？
 *
 * 一个设备（resource）可以运行在多个 site 中，这些可运行的 site 叫做 runsite，
 * 在每个 runsite 里面，resource 可以运行在多个节点中，这些节点是 runsite 所有节
 * 点的一个子集。这些节点中只有一个具有写入设备（resource）的权限，这个节点就叫
 * 做 logowner。
 *
 * logowner 节点具有浮动 IP，也就是说，它除了具有本地节点的 IP 之外，还有一个标
 * 识 logowner 节点的 IP。比如，resource 在一个 site 运行的浮动 IP 是
 * 192.168.2.100，这个 site 里面有两个节点：
 *
 *     node0: 192.168.1.2
 *     node1: 192.168.1.3
 *
 * 那么，如果 node0 是 logowner 节点，那么 site 里面这两个节点的 IP 分别是：
 *
 *     node0: 192.168.1.2, 192.168.2.100
 *     node1: 192.168.1.3
 *
 * 如果 node1 是 logowner 节点，那么 site 里面这两个节点的 IP 分别是：
 *
 *     node0: 192.168.1.2
 *     node1: 192.168.1.3, 192.168.2.10
 *
 * 判断的依据是，节点的所有 IP 是否有一个是 resource 运行在本地 site 的 IP。
 *
 * return:
 *     0 - not log owner
 *     1 - yes, it is log owner
 */
int node_logowner(struct resource *resource)
{
	struct ip_list *list;
	int i, j;
	int ret = 0;

	list = create_ip_list(16);
	if (!list)
		return 0;

	init_ip_list(list);
	for (i = 0; i < list->inuse; i++) {
		struct ip *ip;

		ip = &list->ips[i];
		if (!strncmp(ip->addr, resource->local_site->remote_ip, strlen(ip->addr))) {
			ret = 1;
			break;
		}
	}

	free_ip_list(list);
	return ret;
}

/*
 * logowner_in: 判断节点是不是 resource 列表中某一个 resource 的 logowner
 *
 * return:
 *     0 - not log owner
 *     1 - at least one resource logowner
 */
int logowner_in(struct resource_list *list)
{
	int i;
	int ret = 0;

	for (i = 0; i < list->nr; i++) {
		struct resource *resource;

		resource = list->resources[i];
		ret |= node_logowner(resource);
		if (ret)
			break;
	}

	return ret;
}

struct node_list *init_lnode_list(struct daemon *daemon, struct config *cfg)
{
	int idx;
	struct node_list *node_list;
	struct node *node;
	struct site_config *site_cfg;
	struct node_config *node_cfg;

	site_cfg = &cfg->sites[cfg->local_site_id];
	node_list = create_node_list(site_cfg->node_num);
	if(node_list == NULL) {
		return NULL;
	}

	for (idx = 0; idx < site_cfg->node_num; idx++) {
		node_cfg = &site_cfg->nodes[idx];
		node = make_node(LOCAL_NODE, node_cfg->id, node_cfg->hostname,
				 cfg->serverip, node_cfg->ipaddr, cfg->serverport, node_cfg->port,
				 cfg->pingtimeout, cfg->maxpingcount);
		if(node == NULL) {
			goto err;
		}

		node_set_daemon(node, daemon);
		node_list_put(node_list, node);
		if (node->id == cfg->local_node_id)
			node_list->local_node_id = idx;
	}

	return node_list;

err:
	free_node_list(node_list);
	return NULL;
}

int node_list_resize(struct node_list *list)
{
	struct node **nodes;
	struct node **tmp;
	int size;

	size = list->max_num + (list->max_num * 3) / 2;
	nodes = calloc(size, sizeof(*nodes));
	if (nodes == NULL)
		return -1;
	list->max_num = size;

	tmp = list->nodes;
	memcpy(nodes, tmp, list->node_num * sizeof(*nodes));

	list->nodes = nodes;
	free(tmp);

	return 0;
}

int node_list_put(struct node_list *list, struct node *node)
{
	list->nodes[list->node_num] = node;
	list->node_num += 1;

	return (list->node_num == list->max_num) ? node_list_resize(list) : 0;
}

void node_list_run(struct node_list *node_list)
{
	int idx;
	struct node *node;

	for(idx = 0; idx < node_list->node_num; idx++) {
		if(idx == node_list->local_node_id) {
			continue;
		}

		node = node_list->nodes[idx];
		thread_run(node->data_worker);
		thread_run(node->meta_worker);
		thread_run(node->worker);
	}
}

void node_data_handler(evutil_socket_t fd, short event, void *args)
{
	struct node *node;
	struct daemon *daemon;
	struct device *dev;
#ifdef HADM_COMPRESS
	struct z_packet *pkt;
#else
	struct packet *pkt;
#endif

	node = (struct node *)args;
	daemon = node->daemon;
	dev = daemon->dev;

#ifdef HADM_COMPRESS
	pkt = z_packet_recv(node->dfd);
#else
	pkt = packet_recv(node->dfd);
#endif

	if(pkt == NULL) {
		node_del_data_event(node);
	} else {
#ifdef HADM_COMPRESS
		node_put_work_packet(node, unpack_z_packet(pkt));
		free_z_packet(pkt);
#else
		log_debug("<<<<< recv data packet from %s %d (%s)", node_type_name[pkt->node_type], pkt->node_from, node->remote_ip);
		log_packet_header(pkt);

		node_put_work_packet(node, pkt);
#endif
	}
}

void node_meta_handler(evutil_socket_t fd, short event, void *args)
{
	struct node *node;
#ifdef HADM_COMPRESS
	struct z_packet *pkt
#else
	struct packet *pkt;
#endif

	node = (struct node *)args;

#ifdef HADM_COMPRESS
	pkt = z_packet_recv(node->mfd);
#else
	pkt = packet_recv(node->mfd);
#endif

	if(pkt == NULL) {
		node_del_meta_event(node);
	} else {
#ifdef HADM_COMPRESS
		node_put_work_packet(node, unpack_z_packet(pkt));
		free_z_packet(pkt);
#else
		log_debug("<<<<< recv meta packet from %s %d (%s)", node_type_name[pkt->node_type], pkt->node_from, node->remote_ip);
		log_packet_header(pkt);

		node_put_work_packet(node, pkt);
#endif
	}
}

void node_set_daemon(struct node *node, struct daemon *daemon)
{
	node->daemon = daemon;
}

void ping_timer_cb(evutil_socket_t fd, short event, void *args)
{
	struct node *node;
	struct node_list *node_list;
	struct daemon *daemon;
	struct packet *pkt;
	int packet_type;
	int node_from;

	node = (struct node *)args;
	daemon = node->daemon;
	if (node->type == LOCAL_NODE) {
		node_list = daemon->lnode_list;
		node_from = daemon->local_node->id;
		packet_type = P_NC_PING;
	} else {
		pthread_spin_lock(&daemon->rnode_list_lock);
		node_list = daemon->rnode_list;
		pthread_spin_unlock(&daemon->rnode_list_lock);
		node_from = daemon->local_site_id;
		packet_type = P_SC_PING;
	}

	if(node->meta_conn_state == NODE_MFD_DISCONNECTED) {
		return;
	}

	if (node->ping_count >= node->max_ping_count) {
		node_del_data_event(node);
		node_del_meta_event(node);

		return;
	}

	pkt = alloc_packet0();
	pkt->type = packet_type;
	pkt->node_type = node->type;
	pkt->node_from = node_from;
	packet_set_node_to(node->id, pkt);

	node->ping_count++;
	node_put_meta_packet(node, pkt);

	timer_add_tb(daemon->timer_base, node->ping_timer);
}

int node_put_work_packet(struct node *node, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, node->work_q);
}

struct packet *node_get_work_packet(struct node *node)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(node->work_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

int node_put_data_packet(struct node *node, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, node->data_q);
}

struct packet *node_get_data_packet(struct node *node)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(node->data_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

int node_put_meta_packet(struct node *node, struct packet *pkt)
{
	struct entry *e;

	if (!pkt->node_to)
		return -1;
	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	return queue_put(e, node->meta_q);
}

struct packet *node_get_meta_packet(struct node *node)
{
	struct entry *e;
	struct packet *pkt;

	e = queue_get(node->meta_q);
	if(e == NULL) {
		return NULL;
	}

	pkt = (struct packet *)e->data;
	free_entry(e);

	return pkt;
}

void log_node(struct node *node)
{
	log_debug("NODE: |id:%d|type:%s|hostname:%s|local_ip:%s|local_port:%s|remote_ip:%s|remote_port:%s|dfd:%d,%s|mfd:%d,%s|pingcount:%d|",
		  node->id, node_type_name[node->type], node->hostname,
		  node->local_ip, node->local_port, node->remote_ip, node->remote_port,
		  node->dfd, link_state_name[node->data_conn_state],
		  node->mfd, link_state_name[node->meta_conn_state],
		  node->ping_count);
}

void pr_node_list(struct node_list *list)
{
	int i;

	printf("node_list:\n");
	printf("\tlocal_node_id: %d\n", list->local_node_id);
	printf("\tmax_num: %d\n", list->max_num);
	printf("\tnode_num: %d\n", list->node_num);
	for (i = 0; i < list->node_num; i++) {
		struct node *node;

		node = list->nodes[i];
		printf("\tnode:\n");
		printf("\t\tid: %d\n", node->id);
		printf("\t\thostname: %s\n", node->hostname);
		printf("\t\tremote_ip: %s, remote_port: %s\n", node->remote_ip, node->remote_port);
	}
}
