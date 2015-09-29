#include <linux/module.h>

#include <linux/gfp.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/wait.h>

#include "hadm_queue.h"

void hadm_queue_freeze(struct hadm_queue *q, int which)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);

	q->disable |= which;

	if (which & HADM_QUEUE_PUSH_FREEZE) {
		while (waitqueue_active(&q->push_waitqueue))
			wake_up(&q->push_waitqueue);
	}

	if (which & HADM_QUEUE_POP_FREEZE) {
		while (waitqueue_active(&q->pop_waitqueue))
			wake_up(&q->pop_waitqueue);
	}

	spin_unlock_irqrestore(&q->lock, flags);
}

void hadm_queue_freeze_push(struct hadm_queue *q)
{
	hadm_queue_freeze(q, HADM_QUEUE_PUSH_FREEZE);
}

void hadm_queue_freeze_pop(struct hadm_queue *q)
{
	hadm_queue_freeze(q, HADM_QUEUE_POP_FREEZE);
}

void hadm_queue_freeze_all(struct hadm_queue *q)
{
	hadm_queue_freeze(q, HADM_QUEUE_PUSH_FREEZE | HADM_QUEUE_POP_FREEZE);
}

void hadm_queue_unfreeze(struct hadm_queue *q, int which)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	q->disable &= ~which;
	spin_unlock_irqrestore(&q->lock, flags);
}

void hadm_queue_unfreeze_push(struct hadm_queue *q)
{
	hadm_queue_unfreeze(q, HADM_QUEUE_PUSH_FREEZE);
}

void hadm_queue_unfreeze_pop(struct hadm_queue *q)
{
	hadm_queue_unfreeze(q, HADM_QUEUE_POP_FREEZE);
}

void hadm_queue_unfreeze_all(struct hadm_queue *q)
{
	hadm_queue_unfreeze(q, HADM_QUEUE_PUSH_FREEZE | HADM_QUEUE_POP_FREEZE);
}

struct hadm_queue *hadm_queue_alloc(void)
{
	struct hadm_queue *q;

	q = kzalloc(sizeof(struct hadm_queue), GFP_KERNEL);

	return q;
}

void hadm_queue_init(struct hadm_queue *q, char *name, uint32_t maxlen)
{
	INIT_LIST_HEAD(&q->head);
	spin_lock_init(&q->lock);
	sema_init(&q->sema, 0);

	snprintf(q->name,MAX_QUEUE_NAME, "%s", name);
	q->maxlen = maxlen;
	q->len = 0;
	q->disable = 0;
	q->last_handled = NULL;

	init_waitqueue_head(&q->empty_waitqueue);
	init_waitqueue_head(&q->push_waitqueue);
	init_waitqueue_head(&q->pop_waitqueue);
}

struct hadm_queue *hadm_queue_create(char *name,uint32_t maxlen)
{
	struct hadm_queue *q;

	q = hadm_queue_alloc();
	if (q != NULL && !IS_ERR(q))
		hadm_queue_init(q, name, maxlen);

	return q;
}

void hadm_queue_free(struct hadm_queue *q)
{
	if (!hadm_queue_empty(q))
		pr_err("%s: warning try free no-empty queue.\n", __func__);
	kfree(q);
}

int hadm_queue_empty(struct hadm_queue *q)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	ret = q->len == 0;
	spin_unlock_irqrestore(&q->lock, flags);

	return ret;
}

int hadm_queue_full(struct hadm_queue *q)
{
	int ret;
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	ret = q->len == q->maxlen;
	spin_unlock_irqrestore(&q->lock, flags);

	return ret;
}

void hadm_queue_try_wait_empty(struct hadm_queue *q)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	if (q->len) {
		DEFINE_WAIT(w);
		prepare_to_wait(&q->empty_waitqueue, &w, TASK_UNINTERRUPTIBLE);
		spin_unlock_irqrestore(&q->lock, flags);
		schedule();
		finish_wait(&q->empty_waitqueue, &w);
	} else
		spin_unlock_irqrestore(&q->lock, flags);
}

static int __hadm_queue_push_common(struct hadm_queue *q, struct list_head *n)
{
	list_add_tail(n, &q->head);
	q->len += 1;

	up(&q->sema);
	if (waitqueue_active(&q->pop_waitqueue))
		wake_up(&q->pop_waitqueue);

	return hadm_queue_inwork(q);
}

/*
 * hadm_queue_push_common -- 将一个队列节点 n 加入到队列 q 中
 *
 * @timeout 表示超时时间，它的单位是 jiffies。
 *
 * 如果超时参数 @timeout 设置为 MAX_SCHEDULE_TIMEOUT，那么表示如果不能马上插入队
 * 列，那么就一直等待直到插入成功为止；或者是队列被禁用。
 *
 * 如果超时参数 @timeout 设置为 0，那么表示如果不能马上插入队列，那么就返回
 * -EHADM_QUEUE_PUSH_FAIL。
 *
 * 如果超时参数 @timeout 设置为 (0, MAX_SCHEDULE_TIMEOUT)，那么表示如果不能马上
 * 插入队列，那么就等待指定的时间；如果超时了还不能插入队列，那么返回
 * -EHADM_QUEUE_PUSH_FAIL。
 *
 * 如果队列没有被禁用：如果插入成功，则返回队列的长度；如果不能插入（无论是超时，
 * 还是不等待），则返回 -EHADM_QUEUE_FAIL。如果队列被禁用，则返回 -EHADM_QUEUE_FREEZE。
 */

int hadm_queue_push_common(struct hadm_queue *q, struct list_head *n,
			   long timeout)
{
	int ret = -EHADM_QUEUE_PUSH_FAIL;
	unsigned long flags;

retry:
	spin_lock_irqsave(&q->lock, flags);

	if (q->disable & HADM_QUEUE_PUSH_FREEZE) {
		ret = -EHADM_QUEUE_FREEZE;
		goto done;
	}

	if (q->len == q->maxlen) {
		if (timeout > 0) {
			DEFINE_WAIT(w);
			prepare_to_wait_exclusive(&q->push_waitqueue, &w, TASK_UNINTERRUPTIBLE);
			spin_unlock_irqrestore(&q->lock, flags);
			timeout = schedule_timeout(timeout);
			finish_wait(&q->push_waitqueue, &w);
			goto retry;
		} else {	/* timeout */
			ret = -EHADM_QUEUE_PUSH_FAIL;
			goto done;
		}
	}

	ret = __hadm_queue_push_common(q, n);

done:
	spin_unlock_irqrestore(&q->lock, flags);
	return ret;
}

int hadm_queue_work_push(struct hadm_queue *q, struct list_head *n)
{
	return hadm_queue_push_common(q, n, MAX_SCHEDULE_TIMEOUT);
}

int hadm_queue_push(struct hadm_queue *q, struct list_head *n)
{
	return hadm_queue_push_common(q, n, MAX_SCHEDULE_TIMEOUT);
}

int hadm_queue_push_nowait(struct hadm_queue *q, struct list_head *n)
{
	return hadm_queue_push_common(q, n, 0);
}

int hadm_queue_push_timeout(struct hadm_queue *q, struct list_head *n,
			    unsigned int timeout)
{
	return hadm_queue_push_common(q, n, timeout);
}

/* export, cmd_worker needs it */
struct list_head *__hadm_queue_pop_common(struct hadm_queue *q)
{
	struct list_head *n = NULL;

	n = q->head.next;
	list_del(n);
	q->len -= 1;
	if (waitqueue_active(&q->push_waitqueue))
		wake_up(&q->push_waitqueue);

	if (!q->len && waitqueue_active(&q->empty_waitqueue))
		wake_up(&q->empty_waitqueue);

	return n;
}

/*
 * hadm_queue_pop_common -- 返回队列 @q 中的一个队列节点
 *
 * 如果队列已经禁用，那么就会立刻返回。
 *
 * 如果队列没有禁用，并且能够取得队列节点，那么就在队列中拆除这个节点，然后返回
 * 这个队列节点。
 *
 * 如果队列没有禁用，并且如果队列为空，那么将会由 @timeout 参数决定时候等待队列
 * 有节点可取：
 *
 *     1. timeout=0,表示调用者不希望等待
 *
 *     2. timeout=MAX_SCHEDULE_TIMEOUT，表示调用者希望一直等待直到队列有节点可取；
 *	  如果它醒来后发现队列被禁用了，则返回 ERR_PTR(-EHADM_QUEUE_FREEZE)
 *
 *     3. timeout=(0, MAX_SCHEDULE_TIMEOUT)，表示尝试在 @timeout 时间内取得队列
 *	  节点，如果不能取得队列节点，那么就返回 NULL 或者
 *	  ERR_PTR(-EHADM_QUEUE_FREEZE)。返回 ERR_PTR(-EHADM_QUEUE_FREEZE) 表示是
 *	  不能取得队列节点的原因是队列被禁用了。返回 NULL 表示在 @timeout 时间内，
 *	  队列中没有节点
 *
 * @timeout 的单位是 jiffies。
 *
 * 返回值：
 *
 *     1. 正常返回，返回的是队列节点的指针
 *     2. 取得队列节点失败，返回 NULL
 *     3. 队列被禁用，返回 ERR_PTR(-EHADM_QUEUE_FREEZE)
 */

struct list_head *hadm_queue_pop_common(struct hadm_queue *q,
					      long timeout)
{
	struct list_head *n = NULL;
	unsigned long flags;

retry:
	spin_lock_irqsave(&q->lock, flags);

	if (q->disable & HADM_QUEUE_POP_FREEZE) {
		n = ERR_PTR(-EHADM_QUEUE_FREEZE);
		goto done;
	}

	if (q->len == 0) {
		if (timeout > 0) {
			DEFINE_WAIT(w);
			prepare_to_wait_exclusive(&q->pop_waitqueue, &w, TASK_UNINTERRUPTIBLE);
			spin_unlock_irqrestore(&q->lock, flags);
			timeout = schedule_timeout(timeout);
			finish_wait(&q->pop_waitqueue, &w);
			goto retry;
		} else {	/* timeout */
			goto done;
		}
	}

	n = __hadm_queue_pop_common(q);

done:
	spin_unlock_irqrestore(&q->lock, flags);
	return n;
}

struct list_head *hadm_queue_pop(struct hadm_queue *q)
{
	return hadm_queue_pop_common(q, MAX_SCHEDULE_TIMEOUT);
}

struct list_head *hadm_queue_pop_nowait(struct hadm_queue *q)
{
	return hadm_queue_pop_common(q, 0);
}

struct list_head *hadm_queue_pop_timeout(struct hadm_queue *q,
					       unsigned int timeout)
{
	return hadm_queue_pop_common(q, timeout);
}

struct list_head *hadm_queue_next_to_handle(struct hadm_queue *q,
		unsigned int timeout)
{
	unsigned long flags;
	struct list_head *next;

	if (down_timeout(&q->sema, timeout) == -ETIME) {
		return NULL;
	}
	spin_lock_irqsave(&q->lock, flags);
	next = q->last_handled->next;
	q->last_handled = next;
	spin_unlock_irqrestore(&q->lock, flags);

	return next;
}

void hadm_queue_delete(struct hadm_queue *q, struct list_head *n)
{
	unsigned long flags;

	spin_lock_irqsave(&q->lock, flags);
	list_del(n);
	if (waitqueue_active(&q->push_waitqueue))
		wake_up(&q->push_waitqueue);
	spin_unlock_irqrestore(&q->lock, flags);
}

int __hadm_queue_push(struct hadm_queue *q, struct list_head *n)
{
	if (q->disable & HADM_QUEUE_PUSH_FREEZE)
		return -EHADM_QUEUE_FREEZE;
	if (q->len == q->maxlen)
		return -EAGAIN;
	return __hadm_queue_push_common(q, n);
}

struct list_head *__hadm_queue_pop(struct hadm_queue *q)
{
	if (q->disable & HADM_QUEUE_PUSH_FREEZE)
		return ERR_PTR(-EHADM_QUEUE_FREEZE);
	if (!q->len)
		return ERR_PTR(-EAGAIN);
	return __hadm_queue_pop_common(q);
}
