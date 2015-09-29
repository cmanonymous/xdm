#ifndef __QUEUE_H__
#define __QUEUE_H__

#include "list.h"

#define DEF_MAX_SIZE 16384
#define DEF_TIMEOUT 1000

enum {
	QUEUE_STOP,
	QUEUE_START
};

struct entry {
	struct list_head list;
	void *data;
};

struct queue {
	struct list_head head;
	int size;
	int max_size;
	long timeout;
	int run;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
};

struct entry *alloc_entry();

struct entry *create_entry(void *data);

void free_entry(struct entry *e);

struct queue *init_queue_timeout(int max_size, long timeout);

struct queue *init_queue();

void free_queue(struct queue *q);

void queue_stop(struct queue *q);

int queue_put(struct entry *e, struct queue *q);

struct entry *queue_get(struct queue *q);

int queue_size(struct queue *q);

int is_queue_empty(struct queue *q);

void clean_packet_queue(struct queue *q);

#endif // __QUEUE_H__
