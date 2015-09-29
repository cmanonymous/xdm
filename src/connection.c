#include "common.h"

#define CONNECT_TRY 4
#define CONNECT_TRY_TIME 1
#define SERVER_WAIT_TIMEOUT 5
#define CONNECT_TIMEOUT 10

int check_all_connected(struct node_list *node_list)
{
	int i;
	int ret = 1;
	struct node *node;

	for(i = 0; i < node_list->node_num; i++) {
		if(i == node_list->local_node_id) {
			continue;
		}

		node = node_list->nodes[i];
		ret = (node->data_conn_state == NODE_DFD_CONNECTED)
			&& (node->meta_conn_state == NODE_MFD_CONNECTED)
			&& ret;
	}

	return ret;
}

void clean_connection(struct node_list *node_list)
{
	int idx;
	struct node *node;

	if (!node_list)
		return;

	for(idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];
		if(idx == node_list->local_node_id) {
			if (node->sfd) {
				sock_close(node->sfd);
				node->sfd = -1;
			}
			continue;
		}


		if(node->data_conn_state == NODE_DFD_DISCONNECTED
				|| node->meta_conn_state == NODE_MFD_DISCONNECTED) {
			if(node->dfd >= 0) {
				node_del_data_event(node);
			}

			if(node->mfd >= 0) {
				node_del_meta_event(node);
			}
		}
	}
}

static int client_connect_server(struct node *client, struct node *server, fd_set *rfds)
{
	int ret = 0;

	if (server->data_conn_state == NODE_DFD_DISCONNECTED) {

		log_debug("data link try to connect %s %d (%s:%s)",
				node_type_name[server->type], server->id,
				server->remote_ip, server->remote_port);

		ret = node_data_connect(client, server);
		if (ret < 0) {
			log_debug("data link connect %s %d failed, give up meta link",
					node_type_name[server->type], server->id);
			goto done;
		}

		ret = node_data_handshake(client, server);
		if (ret < 0) {
			log_debug("data link handshake %s %d failed, close dfd and give up meta link",
					node_type_name[server->type], server->id,
					server->remote_ip, server->remote_port);
			sock_close(server->dfd);
			server->dfd = -1;
			goto done;
		}

		FD_SET(server->dfd, rfds);
	}

	if (server->meta_conn_state == NODE_MFD_DISCONNECTED) {

		log_debug("meta link try to connect %s %d (%s:%s)",
				node_type_name[server->type], server->id,
				server->remote_ip, server->remote_port);

		ret = node_meta_connect(client, server);
		if (ret < 0) {
			log_debug("meta link connect %s %d failed",
					node_type_name[server->type], server->id);
			goto done;
		}

		ret = node_meta_handshake(client, server);
		if (ret < 0) {
			log_debug("meta link handshake %s %d failed, close mfd",
					node_type_name[server->type], server->id);
			sock_close(server->mfd);
			server->mfd = -1;
			goto done;
		}

		FD_SET(server->mfd, rfds);
	}

done:
	return ret;
}

static void client_connect_server_list(struct node_list *node_list, fd_set *rfds)
{
	int idx;
	struct node *client;
	struct node *server;

	client = node_list->nodes[node_list->local_node_id];

	for (idx = 0; idx < node_list->node_num; idx++) {
		server = node_list->nodes[idx];
		if (client->id <= server->id)
			continue;
		client_connect_server(client, server, rfds);
	}
}

static struct node *find_client(struct node_list *node_list, struct sock_packet *sock_pkt)
{
	int idx;
	struct node *local_node;
	struct node *client;
	char *client_ip;

	local_node = node_list->nodes[node_list->local_node_id];

	for (idx = 0; idx < node_list->node_num; idx++) {
		client = node_list->nodes[idx];
		if (client->id == local_node->id)
			continue;
		if (client->id != sock_pkt->node_id)
			continue;
		if (sock_pkt->node_type == LOCAL_NODE)
			break;
		if (sock_pkt->node_type == SITE_NODE) {
			if (!strncmp(sock_pkt->ipaddr, client->remote_ip, strlen(client->remote_ip)))
				break;
		}
	}

	if (idx == node_list->node_num)
		client = NULL;

	return client;
}

static int server_response_client(int sfd, struct node_list *node_list)
{
	socklen_t addrlen;
	struct sockaddr client_addr;
	struct sock_packet sock_pkt;
	struct node *client;
	struct node *local_node;
	int fd;
	int ret;

	local_node = node_list->nodes[node_list->local_node_id];

	addrlen = sizeof(struct sockaddr);
	fd = sock_accept(sfd, &client_addr, &addrlen);
	memset(&sock_pkt, 0, sizeof(struct sock_packet));
	ret = sock_packet_recv(fd, &sock_pkt);
	if (ret <= 0) {
		sock_close(fd);
		return -1;
	}

	log_sock_packet(&sock_pkt);

	client = find_client(node_list, &sock_pkt);
	if (!client)
		return -1;

	if (sock_pkt.type == DATA_HANDSHAKE && client->dfd < 0) {
		client->dfd = fd;
		client->data_conn_state = NODE_DFD_CONNECTED;

		memset(&sock_pkt, 0, sizeof(struct sock_packet));
		sock_pkt.node_id = local_node->id;
		sock_pkt.type = DATA_HANDSHAKE_ACK;
		sock_packet_send(client->dfd, &sock_pkt);

		log_info("%s %d (%s:%s) data link connected",
				node_type_name[client->type], client->id,
				client->remote_ip, client->remote_port);
	} else if (sock_pkt.type == META_HANDSHAKE && client->mfd < 0) {
		client->mfd = fd;
		client->meta_conn_state = NODE_MFD_CONNECTED;

		memset(&sock_pkt, 0, sizeof(struct sock_packet));
		sock_pkt.node_id = local_node->id;
		sock_pkt.type = META_HANDSHAKE_ACK;
		sock_packet_send(client->mfd, &sock_pkt);

		log_info("%s %d (%s:%s) meta link connected",
				node_type_name[client->type], client->id,
				client->remote_ip, client->remote_port);
	} else {
		log_info("%s %d (%s:%s) connected failed, type:%s, dfd:%d mfd:%d.",
				node_type_name[client->type], client->id,
				client->remote_ip, client->remote_port,
				sock_pkt.type == DATA_HANDSHAKE ? "data handshake" : "meta handshake",
				client->dfd, client->mfd);
		sock_close(fd);
	}

	if (client->data_conn_state == NODE_DFD_CONNECTED &&
			client->meta_conn_state == NODE_MFD_CONNECTED) {
		client->ping_count = 0;
		node_add_data_event(client, client->daemon);
		node_add_meta_event(client, client->daemon);
		node_add_ping_timer(client, client->daemon);
	}

	return 0;
}

static int client_accept_server(struct node_list *node_list, fd_set *rfds, fd_set *iter)
{
	int idx;
	int ret;
	int nr_connected_links;
	struct node *server;
	struct node *local_node;
	struct sock_packet sock_pkt;

	local_node = node_list->nodes[node_list->local_node_id];
	nr_connected_links = 0;

	for(idx = 0; idx < node_list->node_num; idx++) {
		server = node_list->nodes[idx];
		if (local_node->id == server->id)
			continue;

		if (server->dfd >= 0 && FD_ISSET(server->dfd, iter)) {
			FD_CLR(server->dfd, rfds);
			memset(&sock_pkt, 0, sizeof(struct sock_packet));
			ret = sock_packet_recv(server->dfd, &sock_pkt);

			if (ret > 0 && sock_pkt.type == DATA_HANDSHAKE_ACK) {
				log_info("data link connect to %s %d (%s:%s)",
						node_type_name[server->type], server->id,
						server->remote_ip, server->remote_port);
				server->data_conn_state = NODE_DFD_CONNECTED;
				nr_connected_links += 1;
			} else {
				log_info("data link failed connect to %s %d (%s:%s)",
						node_type_name[server->type], server->id,
						server->remote_ip, server->remote_port);
				sock_close(server->dfd);
				server->dfd = -1;
				server->data_conn_state = NODE_DFD_DISCONNECTED;
			}
		}

		if (server->mfd >= 0 && FD_ISSET(server->mfd, iter)) {
			FD_CLR(server->mfd, rfds);
			memset(&sock_pkt, 0, sizeof(struct sock_packet));
			ret = sock_packet_recv(server->mfd, &sock_pkt);

			if (ret > 0 && sock_pkt.type == META_HANDSHAKE_ACK) {
				log_info("meta link connect to node %d (%s:%s)",
						server->id, server->remote_ip, server->remote_port);
				server->meta_conn_state = NODE_MFD_CONNECTED;
				nr_connected_links += 1;
			} else {
				log_info("meta link failed connect to node %d (%s:%s)",
						server->id, server->remote_ip, server->remote_port);
				sock_close(server->mfd);
				server->mfd = -1;
				server->meta_conn_state = NODE_MFD_DISCONNECTED;
			}
		}

		if (server->data_conn_state == NODE_DFD_CONNECTED &&
				server->meta_conn_state == NODE_MFD_CONNECTED) {
			server->ping_count = 0;
			node_add_data_event(server, server->daemon);
			node_add_meta_event(server, server->daemon);
			node_add_ping_timer(server, server->daemon);
		}
	}

	return nr_connected_links;
}

static void connect_set_up(struct node_list *node_list, fd_set *rfds, fd_set *wfds)
{
	int idx, fd, ret;
	struct node *node, *local_node;

	local_node = node_list->nodes[node_list->local_node_id];
	for (idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];
		if (node->id > local_node->id)
			continue;
		else if (node->id == local_node->id) {
			if (node->sfd < 0) {
				node->sfd = node_make_server(node);
				if (node->sfd < 0) {
					log_error("ERROR: %s %d: unable to create listen fd on %s:%s",
							node_type_name[node->type], node->id,
							node->type == SITE_NODE ? "0.0.0.0" : node->remote_ip,
							node->remote_port);
					continue;
				}
				FD_SET(node->sfd, rfds);
			} else {
				if (!FD_ISSET(node->sfd, rfds)) {
					log_error("%s sfd is exist, but not in rfds.", __func__);
					FD_SET(node->sfd, rfds);
				}
			}
		} else {
			if (node->dfd < 0) {
				ret = node_data_connect(local_node, node);
				if (ret < 0) {
					if (ret == -EINPROGRESS) {
						FD_SET(node->dfd, wfds);
					} else
						log_error("ERROR: unable connect to server %d", ret);
				} else {
					ret = node_data_handshake(local_node, node);
					if (ret < 0) {
						log_error("%s data handshake.", __func__);
						sock_close(node->dfd);
						node->dfd = -1;
						continue;
					}
					FD_SET(node->dfd, rfds);
				}
			} else {
				if (node->data_conn_state != NODE_DFD_CONNECTED)
					if (!FD_ISSET(node->dfd, rfds)
							&& !FD_ISSET(node->dfd, wfds))
						log_error("%s node%d dfd is exist, but not set in fds.",
								__func__, node->id);
			}

			if (node->mfd < 0) {
				ret = node_meta_connect(local_node, node);
				if (ret < 0) {
					if (ret == -EINPROGRESS) {
						FD_SET(node->mfd, wfds);
					} else {
						log_error("ERROR: unable connect to server");
					}
				} else {
					ret = node_meta_handshake(local_node, node);
					if (ret < 0) {
						log_error("%s meta handshake.", __func__);
						sock_close(node->mfd);
						node->mfd = -1;
						continue;
					}
					FD_SET(node->mfd, rfds);
				}
			} else {
				if (node->meta_conn_state != NODE_MFD_CONNECTED)
					if (!FD_ISSET(node->mfd, rfds)
							&& !FD_ISSET(node->mfd, wfds))
						log_error("%s node%d mfd is exist, but not in fds.",
								__func__, node->id);
			}

		}
	}
}

static int client_do_handshake(struct node_list *node_list, fd_set *rfds, fd_set *wfds, fd_set *iter)
{
	int val, nr;
	int idx, ret;
	socklen_t size;
	struct node *node;
	struct node *local_node;

	nr = 0;
	local_node = node_list->nodes[node_list->local_node_id];
	for (idx = 0; idx < node_list->node_num; idx++) {
		node = node_list->nodes[idx];
		if (node->dfd > 0 && FD_ISSET(node->dfd, iter)) {
			FD_CLR(node->dfd, wfds);
			size = sizeof(val);
			ret = getsockopt(node->dfd, SOL_SOCKET, SO_ERROR, &val, &size);
			if (ret < 0 || val) {
				log_error("node%d get connect result failed.(ret:%d|err:%d|val:%d)",
						node->id, ret, errno, val);
				sock_close(node->dfd);
				node->dfd = -1;
			} else {
				ret = node_data_handshake(local_node, node);
				if (ret < 0) {
					log_error("%s data handshake.", __func__);
					sock_close(node->dfd);
					node->dfd = -1;
				} else {
					nr++;
					FD_SET(node->dfd, rfds);
				}
			}
		}

		if (node->mfd > 0 && FD_ISSET(node->mfd, iter)) {
			FD_CLR(node->mfd, wfds);
			ret = getsockopt(node->mfd, SOL_SOCKET, SO_ERROR, &val, &size);
			if (ret < 0 || val) {
				log_error("node%d get connect result failed.(ret:%d|err:%d|val:%d)",
						node->id, ret, errno, val);
				sock_close(node->mfd);
				node->mfd = -1;
			} else {
				ret = node_meta_handshake(local_node, node);
				if (ret < 0) {
					log_error("%s data handshake.", __func__);
					sock_close(node->mfd);
					node->mfd = -1;
				} else {
					nr++;
					FD_SET(node->mfd, rfds);
				}
			}
		}
	}

	return nr;
}

int node_list_do_connect(struct node_list *node_list)
{
	struct node *local_node;
	int ret, sfd, nfds, nsuccess;
	fd_set rfds, wfds;
	fd_set rfds_iter, wfds_iter;
	struct timeval tv;
	int n_try = 0;
	int sec = CONNECT_TRY_TIME;

	clean_connection(node_list);
	local_node = node_list->nodes[node_list->local_node_id];
	FD_ZERO(&rfds);
	FD_ZERO(&wfds);

	while(1) {
		log_info("%s %d waits for connection",
				node_type_name[local_node->type], local_node->id);
		connect_set_up(node_list, &rfds, &wfds);

		rfds_iter = rfds;
		wfds_iter = wfds;
		tv.tv_sec = sec;
		tv.tv_usec = 0;
		nsuccess = 0;
		nfds = select(SELECT_MAX_FDS, &rfds_iter, &wfds_iter, NULL, &tv);
		if (nfds > 0) {
			if(local_node->sfd > 0 &&
					FD_ISSET(local_node->sfd, &rfds_iter)) {
				ret = server_response_client(local_node->sfd, node_list);
				if (ret == 0)
					nsuccess++;
			}

			nsuccess += client_do_handshake(node_list, &rfds, &wfds, &wfds_iter);
			nsuccess += client_accept_server(node_list, &rfds, &rfds_iter);
		}

		if(!nfds || !nsuccess) {
			n_try += 1;
			sec <<= 1;
			if(n_try > CONNECT_TRY) {
				break;
			}
		}

		if((ret = check_all_connected(node_list))) {
			log_info("all %ss connected!", node_type_name[local_node->type]);
			break;
		}
	}

	clean_connection(node_list);

	return ret;
}

int node_connect_function(void *data)
{
	struct thread *thr;
	struct daemon *daemon;
	struct node_list *node_list;

	thr = (struct thread *)data;
	daemon = (struct daemon *)thr->data;
	node_list = daemon->lnode_list;
	clean_connection(node_list);

	return node_list_connect(node_list);
}

/*
 * 需要连接的 site 从 resource_list 中过滤出来
 *
 * 真正的实体 site 结构在每个 resource 中，每个 resource 结构有一个它需要连接的
 * site 的列表。
 */
int site_connect_function(void *data)
{
	struct thread *thr;
	struct daemon *daemon;
	struct node_list *node_list;

	thr = (struct thread *)data;
	daemon = (struct daemon *)thr->data;

	pthread_spin_lock(&daemon->rnode_list_lock);
	node_list = daemon->rnode_list;
	pthread_spin_unlock(&daemon->rnode_list_lock);
	clean_connection(node_list);

	return node_list_connect(node_list);
}

int node_list_connect(struct node_list *node_list)
{
	struct node *node;
	int idx;

	if (!node_list)
		return -1;

	if (!check_all_connected(node_list)) {
		log_debug("%s try connect nodes", __FUNCTION__);
		node_list_do_connect(node_list);
	}

	return 0;
}

static int connect_nodes_and_notify_kmod(struct daemon *daemon)
{
	struct node_list *node_list;
	struct packet *pkt;
	struct device *dev;
	int i;

	dev = daemon->dev;
	node_list = daemon->lnode_list;

	if (!check_all_connected(node_list))
		if (daemon->local_connect_thread->state == THREAD_STOP)
			thread_run(daemon->local_connect_thread);

	pkt = alloc_packet0();
	if (!pkt) {
		log_error("ERROR: no memory");
		return -1;
	}
	pkt->type = P_NC_CONN_STATE;
	pkt->node_type = LOCAL_NODE;
	pkt->node_from = daemon->local_node->id;
	pkt->dev_id = MAX_DEVICES; /* all devices */
	for (i = 0; i < node_list->node_num; i++) {
		struct node *node;

		if (i == node_list->local_node_id)
			continue;
		node = node_list->nodes[i];
		if (node->data_conn_state == NODE_DFD_CONNECTED &&
				node->meta_conn_state == NODE_MFD_CONNECTED)
			packet_set_node_to(node->id, pkt);
	}

	dev_put_meta_packet(dev, pkt);

	return 0;
}

static int connect_sites_and_notify_kmod(struct daemon *daemon)
{
	int log_owner;
	struct device *dev;

	dev = daemon->dev;

	log_owner = logowner_in(daemon->resource_list);
	if (log_owner) {
		struct resource_list *resource_list;
		struct node_list *node_list;

		resource_list = daemon->resource_list;

		pthread_spin_lock(&daemon->rnode_list_lock);

		node_list = daemon->rnode_list;
		node_list_clean_up(node_list);
		node_list = filter_from(resource_list);
		daemon->rnode_list = node_list;
		if (!node_list) {
			log_error("ERROR: failed to filter out node list from resource list");
			pthread_spin_unlock(&daemon->rnode_list_lock);
			return -1;
		}

		pthread_spin_unlock(&daemon->rnode_list_lock);

		node_list_run(node_list);

		if (!check_all_connected(node_list))
			if (daemon->remote_connect_thread->state == THREAD_STOP)
				thread_run(daemon->remote_connect_thread);
	}

	notify_all(dev, daemon->resource_list);

	return 0;
}

void connect_timer_cb(evutil_socket_t fd, short event, void *args)
{
	struct timer_base *tb;
	struct daemon *daemon;
	int ret;

	tb = (struct timer_base *)args;
	daemon = tb->daemon;

	connect_nodes_and_notify_kmod(daemon);
	connect_sites_and_notify_kmod(daemon);

	timer_add_tb(tb, tb->connect_timer);
}
