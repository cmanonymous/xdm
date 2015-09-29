#include "common.h"
#include "queue.h"

struct entry *alloc_entry()
{
	struct entry *e;

	e = malloc(sizeof(struct entry));
	if(e == NULL) {
		return NULL;
	}

	memset(e, 0, sizeof(struct entry));
	INIT_LIST_HEAD(&e->list);

	return e;
}

struct entry *create_entry(void *data)
{
	struct entry *e;

	e = alloc_entry();
	if(e == NULL) {
		return e;
	}

	e->data = data;

	return e;
}

void free_entry(struct entry *e)
{
	free(e);
}

struct queue *init_queue_timeout(int max_size, long timeout)
{
	struct queue *q;

	q = malloc(sizeof(struct queue));
	if(q == NULL) {
		return NULL;
	}

	memset(q, 0, sizeof(struct queue));

	INIT_LIST_HEAD(&q->head);
	q->size = 0;
	q->max_size = max_size;
	q->timeout = timeout;
	q->run = QUEUE_START;

	pthread_mutex_init(&q->mutex, NULL);
	pthread_cond_init(&q->cond, NULL);

	return q;
}

struct queue *init_queue()
{
	return init_queue_timeout(DEF_MAX_SIZE, DEF_TIMEOUT);
}

void free_queue(struct queue *q)
{
	struct list_head *pos;
	struct list_head *next;
	struct entry *e;

	list_for_each_safe(pos, next, &q->head) {
		list_del(pos);
		e = list_entry(pos, struct entry, list);
		free_entry(e);
	}

	pthread_mutex_destroy(&q->mutex);
	pthread_cond_destroy(&q->cond);

	free(q);
}

void queue_stop(struct queue *q)
{
	q->run = QUEUE_STOP;
}

int queue_put(struct entry *e, struct queue *q)
{
	int ret = 0;

retry:
	pthread_mutex_lock(&q->mutex);

	if(q->size + 1> q->max_size) {
		if(q->run == QUEUE_START) {
			pthread_mutex_unlock(&q->mutex);
			sleep(1);
			goto retry;
		}else{
			pthread_mutex_unlock(&q->mutex);
			return -1;
		}
	}

	list_add_tail(&e->list, &q->head);
	q->size++;

	if(q->size == 1) {
		pthread_cond_signal(&q->cond);
	}

	pthread_mutex_unlock(&q->mutex);

	return ret;
}

struct entry *queue_get(struct queue *q)
{
	struct entry *e;
	struct timespec ts;

	pthread_mutex_lock(&q->mutex);

	while(q->size == 0 && q->run == QUEUE_START) {
		make_timespec(q->timeout, &ts);
		pthread_cond_timedwait(&q->cond, &q->mutex, &ts);
	}

	if(q->size == 0) {
		e = NULL;
		goto out;
	}


	e = list_first_entry(&q->head, struct entry, list);
	list_del((&q->head)->next);
	q->size--;

out:
	pthread_mutex_unlock(&q->mutex);

	return e;
}

int queue_size(struct queue *q)
{
	/*
	int size = 0;
	struct list_head *pos;

	list_for_each(pos, &q->head) {
		size++;
	}
	*/

	return q->size;
}

int is_queue_empty(struct queue *q)
{
	return q->size == 0;
}

void clean_packet_queue(struct queue *q)
{
	// FIXME: may cause memory bug

	/*
	struct list_head *pos;
	struct list_head *next;
	struct entry *e;
	struct packet *pkt;

	pthread_mutex_lock(&q->mutex);

	list_for_each_safe(pos, next, &q->head) {
		list_del(pos);
		e = list_entry(pos, struct entry, list);
		pkt = (struct packet *)e->data;
		free_packet(pkt);
		free_entry(e);
	}

	pthread_mutex_unlock(&q->mutex);
	*/
}
