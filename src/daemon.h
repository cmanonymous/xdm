#ifndef __DAEMON_H__
#define __DAEMON_H__

struct timer_base {
	struct daemon *daemon;
	struct thread *timer_thread;
	struct event_base *event_base;
	struct timer *connect_timer;
	struct timer *kmod_check_timer;
};

struct daemon {
	int local_site_id;
	struct node *local_node;

	struct node_list *lnode_list;
	struct resource_list *resource_list;
	struct node_list *rnode_list;
	pthread_spinlock_t rnode_list_lock;

	struct device *dev;
	struct event_base *event_base;
	int local_fd;
	struct event *local_event;
	event_handler local_handler;

	struct thread *local_connect_thread;
	struct thread *remote_connect_thread;
	struct timer_base *timer_base;
};

struct daemon *alloc_daemon();

struct daemon *create_daemon(struct config *cfg);

int init_daemon(struct daemon *daemon);

int daemon_run(struct daemon *daemon);

void local_handler(evutil_socket_t fd, short event, void *args);

void kern_data_handler(evutil_socket_t fd, short event, void *args);

void kern_meta_handler(evutil_socket_t fd, short event, void *args);

struct timer_base *init_timer_base(struct daemon *daemon);

void timer_base_run(struct timer_base *tb);

int timer_function(void *data);

void kmod_check_timer_cb(evutil_socket_t fd, short event, void *args);

#endif // __DAEMON_H__
