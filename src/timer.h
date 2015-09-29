#ifndef __TIMER_H__
#define __TIMER_H__

struct timer {
	struct event *timer_event;
	struct timeval timeout;
	event_handler timer_handler;
	void *data;
};

struct timer *alloc_timer();

struct timer *create_timer(int timeout, event_handler timer_handler, void *data);

void free_timer(struct timer *timer);

int timer_add(struct daemon *daemon, struct timer *timer);

int timer_del(struct timer *timer);

#endif // __TIMER_H__
