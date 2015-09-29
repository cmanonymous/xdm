#include "common.h"

struct daemon *alloc_daemon()
{
	struct daemon *daemon;

	daemon = malloc(sizeof(struct daemon));
	if(daemon == NULL) {
		return NULL;
	}

	memset(daemon, 0, sizeof(struct daemon));
	daemon->local_fd = -1;

	return daemon;
}

struct daemon *create_daemon(struct config *cfg)
{
	struct daemon *daemon;
	struct node_list *node_list;
	struct device_list *dev_list;

	daemon = alloc_daemon();
	if(daemon == NULL) {
		return NULL;
	}

	node_list = init_node_list(daemon, cfg);
	if(node_list == NULL) {
		goto err_node_list;
	}
	daemon->node_list = node_list;

	dev_list = init_device_list(daemon, cfg);
	if (!dev_list) {
		log_error("ERROR: no memory init device list");
		goto err_dev_list;
	}
	daemon->dev_list = dev_list;

	daemon->local_node = node_list->nodes[node_list->local_node_id];
	daemon->local_handler = local_handler;

	return daemon;

err_dev_list:
	free_node_list(node_list);
err_node_list:
	free(daemon);
	return NULL;
}

int init_daemon(struct daemon *daemon)
{
	int fd;
	struct node *local_node;
	struct event_base *event_base;
	struct event *local_event;
	struct thread *thread;
	struct timer_base *timer_base;

	local_node = daemon->local_node;
	fd = make_server(local_node->local_ip, local_node->local_port);
	if(fd < 0) {
		log_error("make server (%s:%s) failed", local_node->local_ip, local_node->local_port);
		return -1;
	}
	daemon->local_fd = fd;

	evthread_use_pthreads();

	event_base = event_base_new();
	if(event_base == NULL) {
		return -1;
	}
	daemon->event_base = event_base;

	local_event = event_new(event_base, daemon->local_fd, EV_READ | EV_PERSIST, daemon->local_handler, daemon);
	if(local_event == NULL) {
		goto err;
	}

	if(event_add(local_event, NULL) < 0) {
		event_free(local_event);
		goto err;
	}

	daemon->local_event = local_event;

	thread = create_thread(connect_function, daemon);
	if(thread == NULL) {
		goto err;
	}
	daemon->connect_thread = thread;

	timer_base = init_timer_base(daemon);
	daemon->timer_base = timer_base;

	return 0;

err:
	event_base_free(event_base);
	daemon->event_base = NULL;
	sock_close(fd);
	daemon->local_fd = -1;

	return -1;
}

int daemon_run(struct daemon *daemon)
{
	thread_run(daemon->connect_thread);
	timer_base_run(daemon->timer_base);

	device_list_run(daemon->dev_list);
	node_list_run(daemon->node_list);

	return event_base_dispatch(daemon->event_base);
}

void local_handler(evutil_socket_t fd, short event, void *args)
{
	int cfd;
	struct daemon *daemon;
	struct event *ev;
	struct packet *pkt;
	struct packet *pkt_ack;
	struct device_list *dev_list;
	struct device *dev;

	daemon = (struct daemon *)args;
	dev_list = daemon->dev_list;

	cfd = sock_accept(daemon->local_fd, NULL, NULL);
	if(cfd < 0) {
		return;
	}

	pkt = packet_recv(cfd);
	if(pkt == NULL) {
		sock_close(cfd);
		return;
	}
	dev = find_device(dev_list, pkt->kmod_from);
	if (!dev) {
		log_error("ERROR: Can not find kmod on node %d", pkt->kmod_from);
		goto err;
	}

	if(pkt->type == P_KERN_HANDSHAKE_D) {
		if(dev->dfd < 0 && dev->data_event == NULL) {
			pkt_ack = alloc_packet0();
			if(pkt_ack == NULL) {
				goto err;
			}

			dev->dfd = cfd;
			pkt_ack->dev_id = pkt->dev_id;
			pkt_ack->type = P_KERN_HANDSHAKE_D_ACK;
			packet_send(dev->dfd, pkt_ack);
			log_info("data link handshake from kernel");

			ev = event_new(daemon->event_base, dev->dfd, EV_READ, dev->data_handler, dev);
			if(ev == NULL) {
				free_packet(pkt_ack);
				dev->dfd = -1;
				goto err;
			}

			dev->data_event = ev;
			if(event_add(ev, NULL) < 0) {
				event_free(ev);
				free_packet(pkt_ack);
				dev->dfd = -1;
				dev->data_event = NULL;
				goto err;
			}

			free_packet(pkt_ack);
		} else {
			sock_close(cfd);
			//dev_del_data_event(dev);
		}
	} else if(pkt->type == P_KERN_HANDSHAKE_M) {
		if(dev->mfd < 0 && dev->meta_event == NULL) {
			pkt_ack = alloc_packet0();
			if(pkt_ack == NULL) {
				free_packet(pkt);
				goto err;
			}

			dev->mfd = cfd;
			pkt_ack->dev_id = pkt->dev_id;
			pkt_ack->type = P_KERN_HANDSHAKE_M_ACK;
			packet_send(dev->mfd, pkt_ack);
			log_info("data link handshake from kernel");

			ev = event_new(daemon->event_base, dev->mfd, EV_READ, dev->meta_handler, dev);
			if(ev == NULL) {
				free_packet(pkt_ack);
				dev->mfd = -1;
				goto err;
			}

			dev->meta_event = ev;
			if(event_add(ev, NULL) < 0) {
				event_free(ev);
				free_packet(pkt_ack);
				dev->mfd = -1;
				dev->meta_event = NULL;
				goto err;
			}

			free_packet(pkt_ack);
		} else {
			sock_close(cfd);
			//dev_del_meta_event(dev);
		}
	} else {
		sock_close(cfd);
	}

	free_packet(pkt);
	return;

err:
	free_packet(pkt);
	sock_close(cfd);
}

void dev_data_force_handle_cb(void *data)
{
	struct device *dev = data;

	if (!dev->data_event)
		return;
	log_debug("%s: force resume for dev %d", __func__, dev->id);
	if (event_add(dev->data_event, NULL) < 0) {
		log_error("failed to add data event on kmod %d", dev->id);
		dev_del_data_event(dev);
	}
}

/* 从 kmod 节点收到的数据，需要把它挂入到对应的 servr 节点中 */
void kern_data_handler(evutil_socket_t fd, short event, void *args)
{
	struct daemon *daemon;
	struct device *dev;
	struct node_list *node_list;
	struct node *node;
	struct packet *pkt, *pkt_clone;
	int i, ret, full;
	cb_fn *cb;

	dev = (struct device *)args;
	daemon = dev->daemon;
	node_list = daemon->node_list;

	pkt = packet_recv(dev->dfd);
	if (!pkt) {
		log_error("failed to receive data from kmod %d on fd %d", dev->id, dev->dfd);
		dev_del_data_event(dev);
		return;
	}

	full = 0;
	for (i = 0; i < node_list->node_num; i++) {
		node = node_list->nodes[i];
		if (!node_is_target(node, pkt->node_to))
			continue;
		/* 我们希望kmod之间的连接是可靠连接，一个基本的要求就是连接正常时不能丢包。
		 * 而kmod之间的连接经过了两个proxy server,这就要求这些中间节点维持这些可靠性。
		 * 现在，由于节点的连接与发给kmod的conn_state包之间存在时延，在节点断开后快速
		 * 建立连接的情况下，kmod对此是无感知的, 也就有可能出现丢包的情况。
		 * 因此为简化处理，当中间出现断连时，就给kmod发送断连包, 丢弃已存在的包
		 */
		if (!node_available(node))
			continue;
		pkt_clone = packet_clone(pkt);
		if (!pkt_clone) {
			log_error("Do NOT send data packet to server %d: no memory", node->id);
			goto out;
		}
		cb = full ? NULL : dev_data_force_handle_cb;
		ret = node_put_data_packet_force(node, pkt_clone, cb, dev);
		if (ret < 0) {
			log_error("node %d data queue is NOT start", node->id);
			dev_del_data_event(dev);
			free_packet(pkt);
			return;
		} else if (ret > 0) {
			log_info("%s: force handle for dev %d", __func__, dev->id);
			full = 1;
		}

	}

out:
	free_packet(pkt);
	if (!full) {
		ret = event_add(dev->data_event, NULL);
		if (ret < 0) {
			log_error("failed to add data event on kmod %d", dev->id);
			dev_del_data_event(dev);
		}
	}
}

void kern_meta_handler(evutil_socket_t fd, short event, void *args)
{
	struct daemon *daemon;
	struct device *dev;
	struct node_list *node_list;
	struct node *node;
	struct packet *pkt, *pkt_clone;
	int i, ret;

	dev = (struct device *)args;
	daemon = dev->daemon;
	node_list = daemon->node_list;

	pkt = packet_recv(dev->mfd);
	if (!pkt) {
		log_error("failed to receive meta from kmod %d on fd %d", dev->id, dev->mfd);
		dev_del_meta_event(dev);
		return;
	}

	for (i = 0; i < node_list->node_num; i++) {
		node = node_list->nodes[i];
		if (!node_is_target(node, pkt->node_to))
			continue;
		if (!node_available(node))
			continue;
		pkt_clone = packet_clone(pkt);
		if (!pkt_clone) {
			log_warn("Do NOT send meta packet to server %d: no memory", node->id);
			goto out;
		}
		ret = node_put_meta_packet(node, pkt_clone);
		if (ret < 0) {
			log_error("node %d data queue is NOT start", node->id);
			dev_del_meta_event(dev);
			free_packet(pkt);
			return;
		}
	}

out:
	free_packet(pkt);
add_pending_event:
	ret = event_add(dev->meta_event, NULL);
	if (ret < 0) {
		log_error("failed to add meta event on kmod %d", dev->id);
		dev_del_meta_event(dev);
	}
}

struct timer_base *init_timer_base(struct daemon *daemon)
{
	struct timer_base *tb;
	struct event_base *event_base;
	struct thread *thread;
	struct timer *timer;

	tb = malloc(sizeof(struct timer_base));
	if(tb == NULL) {
		return NULL;
	}

	memset(tb, 0, sizeof(struct timer_base));

	tb->daemon = daemon;

	event_base = event_base_new();
	if(event_base == NULL) {
		goto err_event_base;
	}
	tb->event_base = event_base;

	thread = create_thread(timer_function, tb);
	if(thread == NULL) {
		goto err_thread;
	}
	tb->timer_thread = thread;

	timer = create_timer(CONNECT_TIMER_TIMEOUT, connect_timer_cb, tb);
	if(timer == NULL) {
		goto err_conn_timer;
	}
	tb->connect_timer = timer;

	return tb;

err_kmod_timer:
	free_timer(tb->connect_timer);

err_conn_timer:
	free_thread(thread);

err_thread:
	event_base_free(event_base);

err_event_base:
	free(tb);

	return NULL;
}

void timer_base_run(struct timer_base *tb)
{
	timer_add_tb(tb, tb->connect_timer);
	thread_run(tb->timer_thread);
}

int timer_function(void *data)
{
	struct thread *thr;
	struct timer_base *tb;

	thr = (struct thread *)data;
	tb = thr->data;

	return event_base_dispatch(tb->event_base);
}
