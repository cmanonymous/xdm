#include "common.h"
#include "queue.h"

struct entry *alloc_entry()
{
	struct entry *e;

	e = malloc(sizeof(struct entry));
	if(e == NULL) {
		log_error("Error: %s failed", __func__);
		return NULL;
	}

	memset(e, 0, sizeof(struct entry));
	INIT_LIST_HEAD(&e->list);

	return e;
}

struct entry *create_cb_entry(void *data, cb_fn *callback, void *cb_data)
{
	struct entry *e;

	e = create_entry(data);
	if (e) {
		e->cb = callback;
		e->cb_data = cb_data;
	}

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
	INIT_LIST_HEAD(&q->wait_list);
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

	list_for_each_safe(pos, next, &q->wait_list) {
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

/*
 * force put @e into @q, if @q is full, insert into q->wait_list
 * return 0 if @q is not full and insert properly, 1 if @q is full
 *        < 0 for error
 */
int queue_put_force(struct entry *e, struct queue *q)
{
	int ret = 0;
	struct list_head *head;

	pthread_mutex_lock(&q->mutex);

	if (q->run != QUEUE_START) {
		ret = -1;
		goto out;
	}

	if (q->size < q->max_size) {
		head = &q->head;
	} else {
		head = &q->wait_list;
		ret = 1;
	}

	list_add_tail(&e->list, head);
	q->size++;

	if(q->size == 1) {
		pthread_cond_signal(&q->cond);
	}

out:
	pthread_mutex_unlock(&q->mutex);

	return ret;
}

static int __queue_put(struct entry *e, struct queue *q, int block)
{
	int ret = 0;

retry:
	pthread_mutex_lock(&q->mutex);

	if(q->size + 1> q->max_size) {
		if(q->run == QUEUE_START
				&& block) {
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

// out:
	pthread_mutex_unlock(&q->mutex);

	return ret;
}

static struct entry *__queue_get(struct queue *q, int block)
{
	struct entry *e, *wait_e;
	struct timespec ts;
	struct list_head *head;

	pthread_mutex_lock(&q->mutex);

	while(q->size == 0 && q->run == QUEUE_START && block) {
		make_timespec(q->timeout, &ts);
		pthread_cond_timedwait(&q->cond, &q->mutex, &ts);
	}

	if(q->size == 0) {
		e = NULL;
		goto out;
	}

	if (list_empty(&q->head)) {
		log_error("Error: %s try get entry from empty list(len:%d)",
				__func__, q->size);
		e = NULL;
		goto out;
	}

	head = &q->head;
	e = list_first_entry(head, struct entry, list);
	list_del(head->next);
	q->size--;

	//将wait_list的元素插入到队尾
	if (!list_empty(&q->wait_list)) {
		head = &q->wait_list;
		wait_e = list_first_entry(head, struct entry, list);
		if (wait_e->cb)
			wait_e->cb(wait_e->cb_data);
		list_del(head->next);

		list_add_tail(&wait_e->list, &q->head);
	}

out:
	pthread_mutex_unlock(&q->mutex);

	return e;
}

int queue_put(struct entry *e, struct queue *q)
{
	return __queue_put(e, q, 1);
}

int queue_put_nonblock(struct entry *e, struct queue *q)
{
	return __queue_put(e, q, 0);
}

struct entry *queue_get(struct queue *q)
{
	return __queue_get(q, 1);
}

struct entry *queue_get_nonblock(struct queue *q)
{
	return __queue_get(q, 0);
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
	int ret;

	pthread_mutex_lock(&q->mutex);
	ret = q->size == 0;
	pthread_mutex_unlock(&q->mutex);

	return ret;
}

int is_queue_full(struct queue *q)
{
	int ret;

	pthread_mutex_lock(&q->mutex);
	ret = q->size == q->max_size;
	pthread_mutex_unlock(&q->mutex);

	return ret;
}


void clean_packet_queue(struct queue *q)
{
	// FIXME: may cause memory bug
	struct list_head *pos, *next;
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

	list_for_each_safe(pos, next, &q->wait_list) {
		list_del(pos);
		e = list_entry(pos, struct entry, list);
		if (e->cb)
			e->cb(e->cb_data);
		pkt = (struct packet *)e->data;
		free_packet(pkt);
		free_entry(e);
	}
	q->size = 0;

	pthread_mutex_unlock(&q->mutex);
}
