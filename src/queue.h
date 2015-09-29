#ifndef __QUEUE_H__
#define __QUEUE_H__

#include "list.h"

#define DEF_MAX_SIZE 16384 
#define DEF_TIMEOUT 1000

typedef void (cb_fn)(void *);

enum {
	QUEUE_STOP,
	QUEUE_START
};

struct entry {
	struct list_head list;
	void *data;
	cb_fn *cb;
	void *cb_data;
};

struct queue {
	struct list_head head;
	struct list_head wait_list;
	int size;
	int max_size;
	long timeout;
	int run;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct entry *alloc_entry();

struct entry *create_entry(void *data);

struct entry *create_cb_entry(void *data, cb_fn *callback, void *cb_data);

void free_entry(struct entry *e);

struct queue *init_queue_timeout(int max_size, long timeout);

struct queue *init_queue();

void free_queue(struct queue *q);

void queue_stop(struct queue *q);

int queue_put(struct entry *e, struct queue *q);

int queue_put_nonblock(struct entry *e, struct queue *q);

int queue_put_force(struct entry *e, struct queue *q);

struct entry *queue_get(struct queue *q);

struct entry *queue_get_nonblock(struct queue *q);

int queue_size(struct queue *q);

int is_queue_empty(struct queue *q);

int is_queue_full(struct queue *q);

void clean_packet_queue(struct queue *q);

#endif // __QUEUE_H__
