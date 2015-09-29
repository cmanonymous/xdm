#include <linux/slab.h>
#include <linux/kthread.h>

#include "hadm_def.h"
#include "hadm_thread.h"
#include "hadm_struct.h"

/**
 *线程的基本操作，线程分为4个状态
 *INIT：线程初始化，但没有运行
 *RUN： 线程运行
 *STOP： 中间状态，设置这个状态后，线程循环种植
 *EXIT： 线程停止
 */

struct hadm_thread *hadm_thread_alloc(void)
{
	struct hadm_thread *t;

	t = kzalloc(sizeof(struct hadm_thread), GFP_KERNEL);

	return t;
}

int hadm_thread_get_state(struct hadm_thread *t)
{
	int state;

	if (t == NULL || ! t->name[0] ) {
		return HADM_THREAD_EXIT;
	}

	if(!g_hadm->state) {
		return HADM_THREAD_EXIT;
	}

	mutex_lock(&t->mutex);
	state = t->state;
	mutex_unlock(&t->mutex);

	return state;
}

int hadm_thread_init(struct hadm_thread *t,
		     char *name, thread_func_t func, void *arg,
		     void *private)
{
	int namelen = strlen(name) + 1;
	int minlen = min(namelen, MAX_THREAD_NAME);

	mutex_init(&t->mutex);
	memcpy(t->name, name, minlen);
	t->state = HADM_THREAD_INIT;
	t->func = func;
	t->arg = arg;
	t->private = private;

	init_completion(&t->ev_exit);
	t->task = kthread_create(func, arg, "%s", t->name);
	if (t->task == NULL || IS_ERR(t->task)) {
		pr_err("%s: create %s thread failed\n", __FUNCTION__, t->name);
		return PTR_ERR(t->task);
	}

	return 0;
}

void hadm_thread_free(struct hadm_thread **t)
{
	if(*t){
		kfree(*t);
		*t=NULL;
	}
}

void hadm_thread_run(struct hadm_thread *t)
{
	if(!IS_ERR_OR_NULL(t)) {
		pr_info("thread %s is started\n",t->name);
		t->state = HADM_THREAD_RUN;
		wake_up_process(t->task); 
	}
}

void hadm_thread_stop(struct hadm_thread *t)
{
	if (!t || ! t->name[0] )
		return;

	mutex_lock(&t->mutex);
	if (t->state == HADM_THREAD_RUN) {
		pr_info("%s: stop thread %s, state = %d\n", __FUNCTION__, t->name, t->state);
		t->state = HADM_THREAD_STOP; /* 改变线程的状态使之退出 */
	//	wait_for_completion(&t->ev_exit);
	}
	mutex_unlock(&t->mutex);

}

void hadm_thread_join(struct hadm_thread *t)
{
	int state = hadm_thread_get_state(t);
	/**
	 *只有当线程处于RUN或者STOP状态时，才需要等待期退出
	 */
	if(state != HADM_THREAD_INIT && state != HADM_THREAD_EXIT) {
		wait_for_completion(&t->ev_exit);
		pr_info("%s: %s thread exited\n", __FUNCTION__, t->name);
	}
}

void hadm_thread_terminate(struct hadm_thread *t)
{
	if(t){
		mutex_lock(&t->mutex);
		pr_info("%s: %s thread will terminate from state %d\n", __FUNCTION__, t->name, t->state);
		t->state=HADM_THREAD_EXIT;
		mutex_unlock(&t->mutex);
		complete(&t->ev_exit);
	}
}
