#ifndef HADM_QUEUE_H
#define HADM_QUEUE_H

#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/completion.h>

enum {
	HADM_QUEUE_PUSH_FREEZE = 1,
	HADM_QUEUE_POP_FREEZE = 2,
};

#define MAX_QUEUE_NAME 0x20
#define MAX_QUEUE_LEN (16384)

struct hadm_queue {
	struct list_head head;
	spinlock_t lock;

	char name[MAX_QUEUE_NAME];
	uint32_t maxlen;
	uint32_t len;
	uint32_t reserved;
	uint32_t disable;
	uint32_t unused;
	void *private;

	wait_queue_head_t push_waitqueue;
	wait_queue_head_t pop_waitqueue;
};



enum push_ret_t {
	EHADM_QUEUE_PUSH_FAIL = 1,
	EHADM_QUEUE_FREEZE = 2,
};

#define hadm_queue_pop_entry_common(ptr, type, member, timeout) ({ \
		struct list_head *n = hadm_queue_pop_common(ptr, timeout); \
		type *t = n ? list_entry(n, type, member) : NULL; \
		t; })

#define hadm_queue_pop_entry_timeout(ptr, type, member, timeout) \
	hadm_queue_pop_entry_common(ptr, type, member, timeout)

#define hadm_queue_head(q, type, member) list_empty(&(q)->head) ? \
		NULL : list_first_entry(&(q)->head, type, member)


extern struct hadm_queue *hadm_queue_alloc(void);
extern struct hadm_queue *hadm_queue_create(char *name, uint32_t maxlen);
extern void hadm_queue_init(struct hadm_queue *q, char *name, uint32_t maxlen);
extern void hadm_queue_free(struct hadm_queue *q);
extern void hadm_queue_clean(struct hadm_queue *q);
#define hadm_queue_lock(queue, flags, irq_save)  do {\
	if(irq_save) { \
	       	spin_lock_irqsave(&queue->lock, flags) ; \
	}else {\
		spin_lock(&queue->lock); \
	}\
	}while(0) 


#define hadm_queue_unlock(queue, flags, irq_save)  do {\
	if(irq_save) { \
	       	spin_unlock_irqrestore(&queue->lock, flags) ; \
	}else {\
		spin_unlock(&queue->lock); \
	}\
	}while(0)


	


extern void hadm_queue_freeze(struct hadm_queue *q, int which);
extern void hadm_queue_freeze_push(struct hadm_queue *q);
extern void hadm_queue_freeze_pop(struct hadm_queue *q);
extern void hadm_queue_freeze_all(struct hadm_queue *q);

extern int hadm_queue_push(struct hadm_queue *q, struct list_head *n);
extern int hadm_queue_push_nowait(struct hadm_queue *q, struct list_head *n);
extern int hadm_queue_push_timeout(struct hadm_queue *q, struct list_head *n, unsigned int timeout);
extern int hadm_queue_wait_space_timeout(struct hadm_queue *q, uint32_t free_size, long timeout);
extern int hadm_queue_push_timeout_fn(struct hadm_queue *q, struct list_head *n, unsigned int timeout, int (*fn) (void *), void *arg);

extern struct list_head *hadm_queue_pop_common(struct hadm_queue *q,
					      long timeout);
extern struct list_head *__hadm_queue_pop_common(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop_nowait(struct hadm_queue *q);
extern struct list_head *hadm_queue_pop_timeout(struct hadm_queue *q, unsigned int timeout);

extern void __hadm_queue_del_node(struct hadm_queue *q, struct list_head *node);
extern void hadm_queue_del_node(struct hadm_queue *q, struct list_head *node);
extern int hadm_queue_wait_data_timeout(struct hadm_queue *q, long timeout);
extern int hadm_queue_next(struct hadm_queue *q, struct list_head **cur_node, struct list_head **next_node);
extern uint32_t hadm_queue_len(struct hadm_queue *q);
extern uint32_t hadm_queue_free_space(struct hadm_queue *q);
extern int hadm_queue_push_in_seq_timeout(struct hadm_queue *queue, struct list_head *node, 
		int (*seq_cmp_fn)(struct list_head *, struct list_head *), long timeout);
extern int hadm_queue_push_in_seq(struct hadm_queue *q, struct list_head *node, 
		int (*seq_cmp_fn)(struct list_head *, struct list_head *));
extern struct list_head *hadm_queue_pop_in_seq_timeout(struct hadm_queue *queue, 
		uint64_t (*get_seq_fn)(struct list_head *), uint64_t seq, long timeout);
int hadm_queue_almost_full(struct hadm_queue *q);

int hadm_queue_reserve_timeout(struct hadm_queue *q, uint32_t reserve, long timeout);
void hadm_queue_dump(const char *msg, struct hadm_queue *q);

#endif	/* HADM_QUEUE_H */
