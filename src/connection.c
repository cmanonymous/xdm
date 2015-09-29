#include "common.h"

#define CONNECT_TRY 3
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

	for(idx = 0; idx < node_list->node_num; idx++) {
		if(idx == node_list->local_node_id) {
			continue;
		}

		node = node_list->nodes[idx];

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

int node_list_connect(struct node_list *node_list)
{
	int fd;
	int sfd = -1;
	int try;
	int idx;
	int ret;
	struct node *node;
	struct node *local_node;
	struct sockaddr remote_addr;
	struct sock_packet sock_pkt;
	socklen_t addrlen;
	fd_set rfds;
	int nfds;
	int timeused = 0;
	struct timeval tv;

	local_node = node_list->nodes[node_list->local_node_id];

	while(1) {
		for(try = 0; try < CONNECT_TRY; try++) {
			for(idx = 0; idx < node_list->node_num; idx++) {
				if(idx == local_node->id) {
					continue;
				}

				node = node_list->nodes[idx];
				if(node->data_conn_state == NODE_DFD_DISCONNECTED
						&& node->dfd < 0) {
					log_debug("data link try to connect to node %d (%s)", node->id, node->remote_ip);
					node_data_connect(local_node, node);
				}

				if(node->meta_conn_state == NODE_MFD_DISCONNECTED
						&& node->mfd < 0) {
					log_debug("meta link try to connect to node %d (%s)", node->id, node->remote_ip);
					node_meta_connect(local_node, node);
				}
			}

			sleep(CONNECT_TRY_TIME);
		}


		if((ret = check_all_connected(node_list))) {
			log_info("all nodes connected");
			break;
		}

		if(sfd < 0) {
			sfd = node_make_server(local_node);
			if(sfd < 0) {
				clean_connection(node_list);
				break;
			}
		}

		FD_ZERO(&rfds);
		FD_SET(sfd, &rfds);

		for(idx = 0; idx < node_list->node_num; idx++) {
			if(idx == local_node->id) {
				continue;
			}

			node = node_list->nodes[idx];
			if(node->data_conn_state == NODE_DFD_DISCONNECTED
					&& node->dfd >= 0) {
				FD_SET(node->dfd, &rfds);
			}

			if(node->meta_conn_state == NODE_MFD_DISCONNECTED
					&& node->mfd >= 0) {
				FD_SET(node->mfd, &rfds);
			}
		}

		tv.tv_sec = SERVER_WAIT_TIMEOUT + random() % 5;
		tv.tv_usec = 0;

		log_info("server (%s:%s) waits for connection", local_node->remote_ip, local_node->remote_port);

		nfds = select(SELECT_MAX_FDS, &rfds, NULL, NULL, &tv);
		if(nfds == 0) {
			timeused += SERVER_WAIT_TIMEOUT;
			if(timeused >= CONNECT_TIMEOUT) {
				clean_connection(node_list);
				sock_close(sfd);
				sfd = -1;
				break;
			}
		} else if(nfds > 0) {
			if(FD_ISSET(sfd, &rfds)) {
				addrlen = sizeof(struct sockaddr);
				fd = sock_accept(sfd, &remote_addr, &addrlen);
				memset(&sock_pkt, 0, sizeof(struct sock_packet));
				ret = sock_packet_recv(fd, &sock_pkt);

				for(idx = 0; idx < node_list->node_num; idx++) {
					if(idx == local_node->id) {
						continue;
					}

					node = node_list->nodes[idx];
					if(ret <= 0) {
						log_error("Error: %s server recv client failed %s", __func__, strerror(errno));
						sock_close(fd);
						break;
					} else if(node->id == sock_pkt.node_id) {
						if(sock_pkt.type == DATA_HANDSHAKE && node->dfd < 0) {
							node->dfd = fd;
							node->data_conn_state = NODE_DFD_CONNECTED;

							memset(&sock_pkt, 0, sizeof(struct sock_packet));
							sock_pkt.node_id = local_node->id;
							sock_pkt.type = DATA_HANDSHAKE_ACK;
							sock_packet_send(node->dfd, &sock_pkt);
							log_info("node %d (%s) data link connected", node->id, node->remote_ip);
						} else if(sock_pkt.type == META_HANDSHAKE && node->mfd < 0) {
							node->mfd = fd;
							node->meta_conn_state = NODE_MFD_CONNECTED;

							memset(&sock_pkt, 0, sizeof(struct sock_packet));
							sock_pkt.node_id = local_node->id;
							sock_pkt.type = META_HANDSHAKE_ACK;
							sock_packet_send(node->mfd, &sock_pkt);
							log_info("node %d (%s) meta link connected", node->id, node->remote_ip);
						} else {
							sock_close(fd);
						}
					}
				}
			} else {
				for(idx = 0; idx < node_list->node_num; idx++) {
					if(idx == local_node->id) {
						continue;
					}

					node = node_list->nodes[idx];
					if(node->dfd >= 0 && FD_ISSET(node->dfd, &rfds)) {
						memset(&sock_pkt, 0, sizeof(struct sock_packet));
						ret = sock_packet_recv(node->dfd, &sock_pkt);

						if(ret > 0 && sock_pkt.type == DATA_HANDSHAKE_ACK) {
							log_info("data link connect to node %d (%s)", node->id, node->remote_ip);
							node->data_conn_state = NODE_DFD_CONNECTED;
						} else {
							if (ret <= 0)
								log_error("Error: %s recv data hs ack for node %d failed %s",
										__func__, node->id, strerror(errno));
							else
								log_error("Error: %s recv data hs ack for node %d wrong type: %d",
										__func__, node->id, sock_pkt.type);
							sock_close(node->dfd);
							node->dfd = -1;
							node->data_conn_state = NODE_DFD_DISCONNECTED;
						}
					}

					if(node->mfd >= 0 && FD_ISSET(node->mfd, &rfds)) {
						memset(&sock_pkt, 0, sizeof(struct sock_packet));
						ret = sock_packet_recv(node->mfd, &sock_pkt);

						if(ret > 0 && sock_pkt.type == META_HANDSHAKE_ACK) {
							log_info("meta link connect to node %d (%s)", node->id, node->remote_ip);
							node->meta_conn_state = NODE_MFD_CONNECTED;
						} else {
							if (ret <= 0)
								log_error("Error: %s recv data hs ack for node %d failed %s",
										__func__, node->id, strerror(errno));
							else
								log_error("Error: %s recv data hs ack for node %d wrong type: %d",
										__func__, node->id, sock_pkt.type);

							sock_close(node->mfd);
							node->mfd = -1;
							node->meta_conn_state = NODE_MFD_DISCONNECTED;
						}
					}
				}
			}
		}

		sock_close(sfd);
		sfd = -1;

		if((ret = check_all_connected(node_list))) {
			log_info("all nodes connected!");
			break;
		}
	}

	return ret;
}

int connect_function(void *data)
{
	struct thread *thr;
	struct daemon *daemon;
	struct node_list *node_list;
	struct node *node;
	int idx;

	thr = (struct thread *)data;
	daemon = (struct daemon *)thr->data;
	node_list = daemon->node_list;

	clean_connection(node_list);
	node_list_connect(node_list);

	for(idx = 0; idx < node_list->node_num; idx++) {
		if(idx == node_list->local_node_id) {
			continue;
		}

		node = node_list->nodes[idx];
		if(node->data_conn_state == NODE_DFD_CONNECTED
				&& node->meta_conn_state == NODE_MFD_CONNECTED) {
			node->ping = 0;
			node_add_data_event(node, daemon);
			node_add_meta_event(node, daemon);
			node_add_ping_timer(node, daemon);
		}
	}

	return 0;
}

static void notify_kmod(struct daemon *daemon, struct device *dev)
{
	struct packet *pkt;
	struct node_list *node_list;
	struct node *local_node;
	int i;

	node_list = daemon->node_list;
	local_node = daemon->local_node;

	pkt = alloc_packet0();
	if (!pkt) {
		log_error("%s: kmod node %d: no memory", __func__, dev->id);
		return;
	}

	pkt->type = P_NODE_CONN_STATE;
	pkt->dev_id = MAX_DEVICES; /* 通知 kmod 节点的所有设备 */
	pkt->node_from = daemon->local_node->id;
	pkt->node_to = pkt->kmod_to = 0;
	for (i = 0; i < node_list->node_num; i++) {
		struct node *node;

		node = node_list->nodes[i];
        /**
         *这里node_to应该是server id，对应到kmod的hadm_node_list
         */
		if (node->data_conn_state == NODE_DFD_CONNECTED &&
		    node->meta_conn_state == NODE_MFD_CONNECTED){
			pkt->node_to |= 1 << node->id;
		}
	}

	if(dev_put_meta_packet(dev, pkt) < 0){
		free_packet(pkt);
		dev_del_meta_event(dev);
	}
}

void connect_timer_cb(evutil_socket_t fd, short event, void *args)
{
	struct timer_base *tb;
	struct daemon *daemon;
	struct node_list *node_list;
	struct device_list *dev_list;
	int i;

	tb = (struct timer_base *)args;
	daemon = tb->daemon;
	node_list = daemon->node_list;
	dev_list = daemon->dev_list;

	if (!check_all_connected(daemon->node_list)) {
		if (daemon->connect_thread->state == THREAD_STOP)
			thread_run(daemon->connect_thread);
	}

	for (i = 0; i < dev_list->dev_num; i++) {
		struct device *dev;

		dev = dev_list->devs[i];
		notify_kmod(daemon, dev);
	}

	timer_add_tb(tb, tb->connect_timer);
}
