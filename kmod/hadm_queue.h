#ifndef HADM_QUEUE_H
#define HADM_QUEUE_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/completion.h>

enum {
	HADM_QUEUE_PUSH_FREEZE = 1,
	HADM_QUEUE_POP_FREEZE = 2,
};

enum hadm_queue_flag {
	__hq_inwork,
};

#define MAX_QUEUE_NAME 0x20
#define MAX_QUEUE_LEN (16384)

struct hadm_queue {
	struct list_head head;
	spinlock_t lock;
	unsigned long flags;
	struct semaphore sema;
	struct list_head *last_handled;

	char name[MAX_QUEUE_NAME];
	uint32_t maxlen;
	uint32_t len;
	uint32_t disable;

	wait_queue_head_t empty_waitqueue;
	wait_queue_head_t push_waitqueue;
	wait_queue_head_t pop_waitqueue;
};

struct hadm_queue_info {
	char *name;
	uint32_t len;
	void (*free)(struct hadm_queue *);
};

#define set_hadm_queue_inwork(q) set_bit(__hq_inwork, &(q)->flags)
#define clear_hadm_queue_inwork(q) clear_bit(__hq_inwork, &(q)->flags)
#define hadm_queue_inwork(q) test_bit(__hq_inwork, &(q)->flags)

#define hadm_queue_entry(ptr, type, member) list_entry(ptr, type, member)
#define hadm_queue_pop_entry_common(q, type, member, timeout) ({		\
	void *_node = (void *)hadm_queue_pop_common(q, timeout);	\
	IS_ERR_OR_NULL(_node) ? (type *)_node : list_entry(_node, type, member);	\
	})

#define hadm_queue_pop_entry_timeout(ptr, type, member, timeout)\
	hadm_queue_pop_entry_common(ptr, type, member, timeout)
#define hadm_queue_pop_entry(ptr, type, member) \
	hadm_queue_pop_entry_common(ptr, type, member, MAX_SCHEDULE_TIMEOUT)
#define hadm_queue_pop_entry_nowait(ptr, type, member) \
	hadm_queue_pop_entry_common(ptr, type, member, 0)

#define __hadm_queue_pop_entry(q, type, member) \
	list_entry(__hadm_queue_pop_common(q), type, member)

enum push_ret_t {
	EHADM_QUEUE_PUSH_FAIL = 1,
	EHADM_QUEUE_FREEZE = 2,
};

extern struct hadm_queue *hadm_queue_alloc(void);
extern struct hadm_queue *hadm_queue_create(char *name, uint32_t maxlen);
extern void hadm_queue_init(struct hadm_queue *q, char *name, uint32_t maxlen);
extern void hadm_queue_free(struct hadm_queue *q);

/* hadm_packet.c */
extern void hdpacket_queue_clean(struct hadm_queue *q);
extern void hdpacket_queue_clean_careful(struct hadm_queue *q);
extern void hdpacket_queue_free(struct hadm_queue *q);

extern int hadm_queue_empty(struct hadm_queue *q);
extern int hadm_queue_full(struct hadm_queue *q);
extern void hadm_queue_try_wait_empty(struct hadm_queue *q);

extern void hadm_queue_freeze(struct hadm_queue *q, int which);
extern void hadm_queue_freeze_push(struct hadm_queue *q);
extern void hadm_queue_freeze_pop(struct hadm_queue *q);
extern void hadm_queue_freeze_all(struct hadm_queue *q);
extern void hadm_queue_unfreeze(struct hadm_queue *q, int which);
extern void hadm_queue_unfreeze_push(struct hadm_queue *q);
extern void hadm_queue_unfreeze_pop(struct hadm_queue *q);
extern void hadm_queue_unfreeze_all(struct hadm_queue *q);

extern int hadm_queue_push(struct hadm_queue *q, struct list_head *n);
extern int hadm_queue_push_nowait(struct hadm_queue *q, struct list_head *n);
extern int hadm_queue_push_timeout(struct hadm_queue *q, struct list_head *n, unsigned int timeout);
extern int hadm_queue_work_push(struct hadm_queue *q, struct list_head *n);

extern struct list_head *hadm_queue_pop_common(struct hadm_queue *q,
					      long timeout);
extern struct list_head *__hadm_queue_pop_common(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop_nowait(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop_timeout(struct hadm_queue *q, unsigned int timeout);

extern struct list_head *
hadm_queue_next_to_handle(struct hadm_queue *q, unsigned int timeout);

extern void hadm_queue_delete(struct hadm_queue *q, struct list_head *node);

/* no lock version */
extern int __hadm_queue_push(struct hadm_queue *q, struct list_head *n);
extern struct list_head *__hadm_queue_pop(struct hadm_queue *q);
#endif	/* HADM_QUEUE_H */
