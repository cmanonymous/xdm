#include "common.h"

struct timer *alloc_timer()
{
	struct timer *timer;

	timer = malloc(sizeof(struct timer));
	if(timer == NULL) {
		return NULL;
	}

	memset(timer, 0, sizeof(struct timer));

	return timer;
}

struct timer *create_timer(int timeout, event_handler timer_handler, void *data)
{
	struct timer *timer;

	timer = alloc_timer();
	if(timer == NULL) {
		return NULL;
	}

	timer->timeout.tv_sec = timeout;
	timer->timer_handler = timer_handler;
	timer->data = data;

	return timer;
}

void free_timer(struct timer *timer)
{
	if(timer->timer_event != NULL) {
		evtimer_del(timer->timer_event);
		event_free(timer->timer_event);
	}

	free(timer);
}

int timer_add(struct daemon *daemon, struct timer *timer)
{
	struct event *ev;
	int ret;

	if(timer->timer_event) {
		event_free(timer->timer_event);
		timer->timer_event = NULL;
	}

	ev = evtimer_new(daemon->event_base, timer->timer_handler, timer->data);
	if(ev == NULL) {
		return -1;
	}

	timer->timer_event = ev;

	ret = evtimer_add(timer->timer_event, &timer->timeout);

	if(ret < 0) {
		event_free(ev);
	}

	return ret;
}

int timer_del(struct timer *timer)
{
	return evtimer_del(timer->timer_event);
}

int timer_add_tb(struct timer_base *tb, struct timer *timer)
{
	struct event *ev;
	int ret;
	if(timer->timer_event) {
		event_free(timer->timer_event);
		timer->timer_event = NULL;
	}

	ev = evtimer_new(tb->event_base, timer->timer_handler, timer->data);
	if(ev == NULL) {
		return -1;
	}

	timer->timer_event = ev;

	ret = evtimer_add(timer->timer_event, &timer->timeout);

	if(ret < 0) {
		event_free(ev);
	}

	return ret;
}

