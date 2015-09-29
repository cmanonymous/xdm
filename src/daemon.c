#include "common.h"

#define KMOD_CHECK_TIMEOUT 1

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
	struct node_list *lnode_list;
	struct resource_list *resource_list;
	struct device *dev;

	daemon = alloc_daemon();
	if(daemon == NULL) {
		return NULL;
	}
	daemon->local_site_id = cfg->local_site_id;
	daemon->rnode_list = NULL;
	pthread_spin_init(&daemon->rnode_list_lock, PTHREAD_PROCESS_PRIVATE);

	resource_list = init_resource_list(daemon, cfg);
	if (resource_list == NULL)
		goto err_free_daemon;
	daemon->resource_list = resource_list;

	lnode_list = init_lnode_list(daemon, cfg);
	if(lnode_list == NULL) {
		goto err_lnode_list;
	}
	daemon->lnode_list = lnode_list;

	dev = init_device(daemon, cfg);
	if(dev == NULL) {
		goto err_dev;
	}
	daemon->dev = dev;

	daemon->local_node = lnode_list->nodes[lnode_list->local_node_id];
	daemon->local_handler = local_handler;

	return daemon;

err_dev:
	free_node_list(lnode_list);
err_lnode_list:
	free_resource_list(resource_list);
err_free_daemon:
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
	char name[MAX_NAME_LEN];

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

	thread = create_thread("daemon:local_connect", "node_connect_function", node_connect_function, daemon);
	if(thread == NULL) {
		goto err;
	}
	daemon->local_connect_thread = thread;

	thread = create_thread("daemon:remote_connect", "site_connect_function", site_connect_function, daemon);
	if(thread == NULL) {
		goto err;
	}
	daemon->remote_connect_thread = thread;

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
	thread_run(daemon->local_connect_thread);
	timer_base_run(daemon->timer_base);

	device_run(daemon->dev);
	node_list_run(daemon->lnode_list);

	return event_base_dispatch(daemon->event_base);
}

void local_handler(evutil_socket_t fd, short event, void *args)
{
	int cfd;
	struct daemon *daemon;
	struct event *ev;
	struct packet *pkt;
	struct packet *pkt_ack;
	struct device *dev;

	daemon = (struct daemon *)args;
	dev = daemon->dev;

	cfd = sock_accept(daemon->local_fd, NULL, NULL);
	if(cfd < 0) {
		return;
	}

	pkt = packet_recv(cfd);
	if(pkt == NULL) {
		sock_close(cfd);
		return;
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

			ev = event_new(daemon->event_base, dev->dfd, EV_READ | EV_PERSIST, dev->data_handler, dev);
			if(ev == NULL) {
				free_packet(pkt_ack);
				dev->dfd = -1;
				goto err;
			}

			if(event_add(ev, NULL) < 0) {
				event_free(ev);
				free_packet(pkt_ack);
				dev->dfd = -1;
				goto err;
			}

			dev->data_event = ev;
			free_packet(pkt_ack);
		} else {
			sock_close(cfd);
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

			ev = event_new(daemon->event_base, dev->mfd, EV_READ | EV_PERSIST, dev->meta_handler, dev);
			if(ev == NULL) {
				free_packet(pkt_ack);
				dev->mfd = -1;
				goto err;
			}

			if(event_add(ev, NULL) < 0) {
				event_free(ev);
				free_packet(pkt_ack);
				dev->mfd = -1;
				goto err;
			}

			dev->meta_event = ev;
			free_packet(pkt_ack);
		} else {
			sock_close(cfd);
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

void kern_data_handler(evutil_socket_t fd, short event, void *args)
{
	struct device *dev;
	struct packet *pkt;

	dev = (struct device *)args;

	pkt = packet_recv(dev->dfd);
	if(pkt == NULL) {
		dev_del_data_event(dev);
	} else {
		log_debug("<<<<< recv data packet from kernel");
		log_packet_header(pkt);

		dev_put_work_packet(dev, pkt);
	}
}

void kern_meta_handler(evutil_socket_t fd, short event, void *args)
{
	struct device *dev;
	struct packet *pkt;

	dev = (struct device *)args;

	pkt = packet_recv(dev->mfd);
	if(pkt == NULL) {
		dev_del_meta_event(dev);
	} else {
		log_debug("<<<<< recv meta packet from kernel");
		log_packet_header(pkt);

		dev_put_work_packet(dev, pkt);
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

	thread = create_thread("daemon:timer_thread", "timer_function", timer_function, tb);
	if(thread == NULL) {
		goto err_thread;
	}
	tb->timer_thread = thread;

	timer = create_timer("connect_timer", CONNECT_TIMER_TIMEOUT, connect_timer_cb, tb);
	if(timer == NULL) {
		goto err_conn_timer;
	}
	tb->connect_timer = timer;

	timer = create_timer("kmod_check_timer", KMOD_CHECK_TIMEOUT, kmod_check_timer_cb, tb);
	if(timer == NULL) {
		goto err_kmod_timer;
	}
	tb->kmod_check_timer = timer;

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
	timer_add_tb(tb, tb->kmod_check_timer);
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

void kmod_check_timer_cb(evutil_socket_t fd, short event, void *args)
{
	struct timer_base *tb;

	tb = (struct timer_base *)args;

	if(!check_module()) {
		log_error("hadm_kmod removed, hadm_server quit!");
		exit(EXIT_FAILURE);
	}

	timer_add_tb(tb, tb->kmod_check_timer);
}
