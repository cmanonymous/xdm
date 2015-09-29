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
	free(node);
}

/* target: 1, otherwise: 0 */
int node_is_target(struct node *node, int node_to)
{
	//return !!(node->share_node_bits & node_to);
	return !!((1 << node->id) & node_to);
}

int node_available(struct node *node)
{
	return node->dfd > 0 && node->mfd > 0;
}

int node_disconnect(struct node *node)
{
	int i, ret;
	struct device *dev;
	struct packet *pkt, *notify;
	struct daemon *daemon = node->daemon;

	log_error("%s: disconnect node %d\n", __func__, node->id);
	pkt = alloc_packet0();
	if (!pkt) {
		log_error("Error: %s alloc packet failed", __func__);
		return -ENOMEM;
	}
	pkt->type = P_KMOD_DISCONN;
	pkt->dev_id = MAX_DEVICES;
	pkt->node_from = node->id;
	pkt->kmod_from = INVALID_ID;	//FIXME 是否导入了不一致?
	pkt->node_to = daemon->local_node->id;

	for (i = 0; i < daemon->dev_list->dev_num; i++) {
		dev = daemon->dev_list->devs[i];
		if (!device_want_recv(dev))
			continue;
		notify = packet_clone(pkt);
		if (!notify) {
			log_error("alloc disconnect notify packet failed.");
			ret = -ENOMEM;
			goto out;
		}
		notify->kmod_to = (1 << dev->id);
		ret = dev_put_meta_packet(dev, notify);
		if (ret < 0) {
			log_error("Error: put meta packet failed.");
			goto out;
		}

	}
out:
	free_packet(pkt);
	return ret;

}

struct node *make_node(int id, const char *hostname,
		const char *local_ip, const char *remote_ip,
		const char *local_port, const char *remote_port)
{
	struct node *node;
	struct queue *q;
	struct thread *thr;

	node = alloc_node();
	if(node == NULL) {
		return NULL;
	}

	node->id = id;
	strncpy(node->hostname, hostname, MAX_HOSTNAME_LEN);
	strncpy(node->local_ip, local_ip, MAX_IPADDR_LEN);
	strncpy(node->remote_ip, remote_ip, MAX_IPADDR_LEN);
	strncpy(node->local_port, local_port, MAX_PORT_LEN);
	strncpy(node->remote_port, remote_port, MAX_PORT_LEN);
	node->data_handler = node_data_handler;
	node->meta_handler = node_meta_handler;

	q = init_queue();
	if(q == NULL) {
		free_node(node);
		return NULL;
	}
	node->data_q = q;

	q = init_queue();
	if(q == NULL) {
		free_queue(node->data_q);
		free_node(node);
		return NULL;
	}
	node->meta_q = q;

	q = init_queue();
	if(q == NULL) {
		free_queue(node->data_q);
		free_queue(node->meta_q);
		free_node(node);
		return NULL;
	}
	node->work_q = q;

	thr = create_thread(node_data_worker_function, node);
	if(thr == NULL) {
		goto err_data;
	}
	node->data_worker = thr;

	thr = create_thread(node_meta_worker_function, node);
	if(thr == NULL) {
		goto err_meta;
	}
	node->meta_worker = thr;

	return node;

err_worker:
	free_thread(node->meta_worker);

err_meta:
	free_thread(node->data_worker);

err_data:
	free_queue(node->data_q);
	free_queue(node->meta_q);
	free_node(node);

	return NULL;
}

int node_connect(int link, struct node *local_node, struct node *remote_node)
{
	int fd;
	int ret;
	struct sockaddr local_addr;
	struct sockaddr remote_addr;
	struct sock_packet *sock_pkt;

	fd_set rset;
	fd_set wset;
	struct timeval tv;
	int error;
	int len;

	if(link == NODE_DATA_LINK
			&& remote_node->data_conn_state == NODE_DFD_CONNECTED) {
		return 0;
	}

	if(link == NODE_META_LINK
			&& remote_node->meta_conn_state == NODE_MFD_CONNECTED) {
		return 0;
	}

	fd = sock_create();
	if(fd < 0) {
		return -1;
	}

	if(sock_get_addr(local_node->remote_ip, NULL, &local_addr) < 0) {
		goto err;
	}

	if(sock_get_addr(remote_node->remote_ip, remote_node->remote_port, &remote_addr) < 0) {
		goto err;
	}

	if(sock_bind(fd, &local_addr) < 0) {
		goto err;
	}

	sock_set_nonblock(fd);
	ret = sock_connect(fd, &remote_addr);

	if(ret < 0 && errno != EINPROGRESS) {
		goto err;
	} else if(ret == 0) {
		goto done;
	} else {
		FD_ZERO(&rset);
		FD_SET(fd, &rset);
		wset = rset;

		tv.tv_sec = SOCK_TIMEOUT;
		tv.tv_usec = 0;

		ret = select(SELECT_MAX_FDS, &rset, &wset, NULL, &tv);
		if(ret <= 0) {
			goto err;
		}

		error = 0;
		len = sizeof(int);
		if(FD_ISSET(fd, &rset) || FD_ISSET(fd, &wset)) {
			if(getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &len) < 0) {
				goto err;
			}
		}

		if(error) {
			goto err;
		}

		goto done;
	}

done:
	if(link == NODE_DATA_LINK) {
		sock_pkt = create_sock_packet(local_node->id, DATA_HANDSHAKE);
	} else if(link == NODE_META_LINK) {
		sock_pkt = create_sock_packet(local_node->id, META_HANDSHAKE);
	} else {
		goto err;
	}

	if(sock_pkt == NULL) {
		goto err;
	}

	sock_clear_nonblock(fd);
	sock_packet_send(fd, sock_pkt);
	free_sock_packet(sock_pkt);

	if(link == NODE_DATA_LINK) {
		remote_node->dfd = fd;
	} else if(link == NODE_META_LINK) {
		remote_node->mfd = fd;
	}

	return 0;

err:
	sock_close(fd);
	return -1;
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
	return make_server(node->remote_ip, node->remote_port);
}

int node_add_data_event(struct node *node, struct daemon *daemon)
{
	struct event *data_event;

	log_error("%s: add data event for node %d", __func__, node->id);
	if(node->data_conn_state == NODE_DFD_DISCONNECTED
			|| node->data_event != NULL) {
		log_error("Error: %s node %d add data event failed(conn:%d|event:%p)",
				__func__, node->id, node->data_conn_state, node->data_event);
		return -1;
	}

	data_event = event_new(daemon->event_base, node->dfd, EV_READ, node->data_handler, node);
	if(data_event == NULL) {
		log_error("Error: %s alloc event failed", __func__);
		return -1;
	}

	node->data_event = data_event;

	if(event_add(data_event, NULL)) {
		log_error("Error: %s add event failed", __func__);
		event_free(data_event);
		node->data_event = NULL;
		return -1;
	}

	// sock_set_nonblock(node->dfd);

	return 0;
}

void node_del_data_event(struct node *node)
{
	int ret;

	log_error("%s: del data event for node %d", __func__, node->id);
	ret = pthread_spin_trylock(&node->spinlock);
	if(ret != 0) {
		log_error("%s: del data event get lock failed", __func__);
		return;
	}

	if(node->data_event == NULL) {
		log_error("%s: null data_event for node %d, cancel", __func__, node->id);
		goto err;
	}

	shutdown(node->dfd, SHUT_RDWR);
	sock_close(node->dfd);
	node->dfd = -1;
	node->data_conn_state = NODE_DFD_DISCONNECTED;

	event_free(node->data_event);
	node->data_event = NULL;

	pthread_spin_unlock(&node->spinlock);

	clean_packet_queue(node->data_q);

	node_disconnect(node);

	return;

err:
	pthread_spin_unlock(&node->spinlock);
}

int node_add_meta_event(struct node *node, struct daemon *daemon)
{
	struct event *meta_event;

	log_error("%s: node %d", __func__, node->id);
	if(node->meta_conn_state == NODE_MFD_DISCONNECTED
			|| node->meta_event != NULL) {
		log_error("Error: %s (conn:%d|meta_event:%p)", __func__,
				node->meta_conn_state, node->meta_event);
		return -1;
	}

	meta_event = event_new(daemon->event_base, node->mfd, EV_READ, node->meta_handler, node);
	if(meta_event == NULL) {
		log_error("Error: %s alloc event failed", __func__);
		return -1;
	}

	node->meta_event = meta_event;

	if(event_add(meta_event, NULL)) {
		log_error("Error: %s add event failed", __func__);
		event_free(meta_event);
		node->meta_event = NULL;
		return -1;
	}

	// sock_set_nonblock(node->mfd);

	return 0;
}

void node_del_meta_event(struct node *node)
{
	int ret;

	log_error("%s: node %d", __func__, node->id);
	ret = pthread_spin_trylock(&node->spinlock);
	if(ret != 0) {
		log_error("Error: %s try lock failed", __func__);
		return;
	}

	if(node->meta_event == NULL) {
		log_error("Error: %s null meta event", __func__);
		goto err;
	}

	shutdown(node->mfd, SHUT_RDWR);
	sock_close(node->mfd);
	node->mfd = -1;
	node->meta_conn_state = NODE_MFD_DISCONNECTED;
	node->ping = 0;

	event_free(node->meta_event);
	node->meta_event = NULL;

	pthread_spin_unlock(&node->spinlock);

	clean_packet_queue(node->meta_q);

	node_disconnect(node);

	return;

err:
	pthread_spin_unlock(&node->spinlock);
}

int node_add_ping_timer(struct node *node, struct daemon *daemon)
{
	struct timer *ping_timer;
	struct node_list *node_list;
	struct timer_base *tb;

	tb = daemon->timer_base;
	node_list = daemon->node_list;

	if(node->ping_timer != NULL) {
		timer_add_tb(tb, node->ping_timer);
		return 0;
	}

	ping_timer = create_timer(node_list->ping, ping_timer_cb, node);
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

void node_list_set_local(struct node_list *node_list)
{
	struct ip_list *ip_list;
	int i, j;

	ip_list = create_ip_list(3);
	if (!ip_list) {
		log_error("failed to create IP list");
		return;
	}

	init_ip_list(ip_list);

	for (i = 0; i < node_list->node_num; i++) {
		struct node *node;

		node = node_list->nodes[i];
		for (j = 0; j < ip_list->inuse; j++) {
			struct ip *ip;

			ip = &ip_list->ips[j];
			if (!strcmp(node->local_ip, ip->addr)) {
				node_list->local_node_id = i;
				break;
			}
		}
	}

	free_ip_list(ip_list);
}

static void node_set_share_node_bits(struct node *node, struct config *cfg)
{
	struct node_config *node_cfg;
	int i;

	for (i = 0; i < cfg->node_num; i++) {
		node_cfg = &cfg->nodes[i];
		if (node_cfg->server_id == node->id)
			node->share_node_bits |= 1 << node_cfg->id;
	}
}

struct node_list *init_node_list(struct daemon *daemon, struct config *cfg)
{
	struct node_list *node_list;
	struct server_config *server_cfg;
	struct node *node;
	int idx;

	node_list = create_node_list(cfg->server_num);
	if (!node_list) {
		log_error("failed to create %d server nodes", cfg->server_num);
		return NULL;
	}

	node_list->ping = cfg->ping;
	node_list->pingtimeout = cfg->pingtimeout;

	for (idx = 0; idx < cfg->server_num; idx++) {
		server_cfg = &cfg->servers[idx];
		node = make_node(server_cfg->id, "server",
				 server_cfg->localipaddr, server_cfg->remoteipaddr,
				 server_cfg->localport, server_cfg->remoteport);
		if (!node) {
			log_error("failed to create node %d", server_cfg->id);
			goto err;
		}

		node_set_daemon(node, daemon);
		node_set_share_node_bits(node, cfg);
		node_list_put(node_list, node);
	}
	node_list_set_local(node_list);
	if (node_list->local_node_id < 0) {
		log_error("can not find local node ip");
		goto err;
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

/*
 * 本地 server 节点的线程也需要启动，因为本地节点需要把其他的 kmod 节点数据转发
 * 到共享这个 server 节点的其他 kmod 节点中
 */
void node_list_run(struct node_list *node_list)
{
	int idx;
	struct node *node;

	for(idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];
		thread_run(node->data_worker);
		thread_run(node->meta_worker);
	}
}

static struct packet *handler_recv(int fd)
{
	struct packet *pkt = NULL;

#ifdef HADM_COMPRESS
	{
		struct z_packet *z_pkt;
		z_pkt = z_packet_recv(fd);
		if (!z_pkt)
			goto out;
		pkt = unpack_z_packet(z_pkt);
		free_z_packet(z_pkt);
	}
#else
	pkt = packet_recv(fd);
#endif

	return pkt;
}

static void node_data_handle_force_cb(void *data)
{
	struct node *node = data;

	if (!node->data_event)
		return;

	log_error("%s: resume force add event for node %d", __func__, node->id);
	if (event_add(node->data_event, NULL) < 0) {
		log_error("failed to add data event on node %d", node->id);
		node_del_data_event(node);
	}
}

/* 从对端 server 的 data 链路收到数据，把它放到对应的 kmod 节点中 */
void node_data_handler(evutil_socket_t fd, short event, void *args)
{
	struct node *node;
	struct daemon *daemon;
	struct device_list *dev_list;
	struct device *dev;
	struct packet *pkt;
	struct packet *pkt_clone;
	int i, ret, full;
	cb_fn *cb;

	node = (struct node *)args;
	daemon = node->daemon;
	dev_list = daemon->dev_list;

	pkt = handler_recv(node->dfd);
	if (!pkt) {
		node_del_data_event(node);
		log_error("receive data from server node %d failed", node->id);
		return;
	}

	/* FIXME 如果某个device的queue满了，在这里就会等待，从而造成两个问题：
	 *	1. 这是event的call back函数，如果等待会造成event base的阻塞
	 *	2. 单个device队列满而影响到所有其它device，不公平
	 * 是否可以这样？
	 *   提前获取队列一个空位，如果失败的话，直接返回，
	 *   当队列有剩余空间时再加入该event
	 * 但是，device互相影响的问题还是没能解决，满了直接断连？
	 */
	full = 0;
	for (i = 0; i < dev_list->dev_num; i++) {
		//FIXME 查找效率很低，可考虑序号对应下标，并且判读是否是只有单个device
		dev = dev_list->devs[i];
		if (!device_is_target(dev, pkt->kmod_to))
			continue;
		if (!device_want_recv(dev))
			continue;
		pkt_clone = packet_clone(pkt);
		if (!pkt_clone) {
			log_error("send to kmod node %d failed: no memory", dev->id);
			free_packet(pkt_clone);
			goto out;
		}
		cb = full ? NULL : node_data_handle_force_cb;
		ret = dev_put_data_packet_force(dev, pkt_clone, cb, node);
		if (ret < 0) {
			log_error("kmod node %d data queue is NOT start", dev->id);
			goto out;
		} else if (ret > 0) {
			log_info("%s force handle for node %d", __func__, node->id);
			full = 1;
		}
	}

out:
	free_packet(pkt);
	if (!full) {
		ret = event_add(node->data_event, NULL);
		if (ret < 0) {
			log_error("failed to add data event on node %d", node->id);
			node_del_data_event(node);
		}
	}
}

void node_meta_handler(evutil_socket_t fd, short event, void *args)
{
	struct node *node;
	struct daemon *daemon;
	struct device_list *dev_list;
	struct device *dev;
	struct packet *pkt;
	struct packet *pkt_clone;
	int i, ret;

	node = (struct node *)args;
	daemon = node->daemon;
	dev_list = daemon->dev_list;

	pkt = handler_recv(node->mfd);
	if (!pkt) {
		log_error("failed to receive meta from server node %d on mfd %d",
			  node->id, node->mfd);
		node_del_meta_event(node);
		return;
	}

	ret = node_meta_packet_handler(node, pkt);
	if (ret < 0) {
		log_warn("WARNING: handle packet %s return %d",
			 packet_name[pkt->type], ret);
	}

out:
	ret = event_add(node->meta_event, NULL);
	if (ret < 0) {
		log_error("failed to add data event on node %d", node->id);
		node_del_meta_event(node);
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
	struct node *local_node;
	struct daemon *daemon;
	struct packet *pkt;

	node = (struct node *)args;
	daemon = node->daemon;
	node_list = daemon->node_list;
	local_node = daemon->local_node;

	if(node->meta_conn_state == NODE_MFD_DISCONNECTED) {
		return;
	}

	if(node->ping >= node_list->pingtimeout) {
		log_error("Error: %s node %d ping reach timeout count",
				__func__, node->id);
		node_del_data_event(node);
		node_del_meta_event(node);

		return;
	}

	pkt = alloc_packet0();
	pkt->type = P_META_PING;
	pkt->node_from = local_node->id;
	packet_set_node_to(node->id, pkt);

	node->ping++;
	if(node_put_meta_packet(node, pkt) < 0){
		log_error("Error: %s node %d meta queue push failed.\n",
				__func__, node->id);
		free_packet(pkt);
		node_del_data_event(node);
		node_del_meta_event(node);

		return;

	}

	timer_add_tb(daemon->timer_base, node->ping_timer);
}

int node_put_data_packet_force(struct node *node, struct packet *pkt,
		cb_fn *callback, void *data)
{
	int ret;
	struct entry *e;

	e = create_cb_entry(pkt, callback, data);
	if (!e)
		return -1;
	ret = queue_put_force(e, node->data_q);
	if (ret < 0)
		free_entry(e);

	return ret;
}

int node_put_data_packet(struct node *node, struct packet *pkt)
{
	struct entry *e;

	e = create_entry(pkt);
	if(e == NULL) {
		return -1;
	}

	if(queue_put(e, node->data_q) < 0){
		free_entry(e);
		return -1;
	}
	return 0;
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

	e = create_entry(pkt);
	if(e == NULL) {
		log_error("Error: %s node %d alloc entry failed",
				__func__, node->id);
		return -1;
	}

	if(queue_put(e, node->meta_q) < 0){
		free_entry(e);
		return -1;
	}
	return 0;
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

void pr_node(struct node *node)
{
	printf("\tid: %d\n", node->id);
	printf("\tshare_node_bits: 0x%x\n", node->share_node_bits);
	printf("\thostname: %s\n", node->hostname);
	printf("\tlocalip: %s, localport: %s\n", node->local_ip, node->local_port);
	printf("\tremoteip: %s, remoteport: %s\n", node->remote_ip, node->remote_port);
	printf("\tdfd: %d(%s), mfd: %d(%s)\n", node->dfd, connect_state[node->data_conn_state],
	       node->mfd, connect_state[node->meta_conn_state]);
	printf("\tping: %d\n", node->ping);
}

void pr_node_list(struct node_list *node_list)
{
	int i;

	printf("local_node_id: %d\n", node_list->local_node_id);
	printf("ping: %d, pingtimeout: %d\n", node_list->ping, node_list->pingtimeout);
	printf("max_num: %d, node_num: %d\n", node_list->max_num, node_list->node_num);

	printf("nodes:\n");
	for (i = 0; i < node_list->node_num; i++) {
		struct node *node;

		node = node_list->nodes[i];
		pr_node(node);
		printf("\n");
	}
}
