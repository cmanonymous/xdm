#include <linux/slab.h>
#include <linux/kthread.h>

#include "hadm_def.h"
#include "hadm_thread.h"
#include "hadm_struct.h"

struct hadm_thread *hadm_thread_alloc(void)
{
	struct hadm_thread *t;

	t = kzalloc(sizeof(struct hadm_thread), GFP_KERNEL);

	return t;
}

int hadm_thread_get_state(struct hadm_thread *t)
{
	int state;

	if (t == NULL) {
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
	init_completion(&t->ev_exit);
	memcpy(t->name, name, minlen);
	t->state = HADM_THREAD_INIT;
	t->func = func;
	t->arg = arg;
	t->private = private;

	return 0;
}

void hadm_thread_free(struct hadm_thread **t)
{
	if(*t){
		kfree(*t);
		*t=NULL;
	}
}

int hadm_thread_wake_up(struct hadm_thread *t)
{
	if (t->state != HADM_THREAD_RUN) {
		//pr_err("%s: try wake up %d state hadm thread.\n",
				//__func__, t->state);
		return -1;
	}
	return wake_up_process(t->task);
}

int hadm_thread_start(struct hadm_thread *t)
{
	if (t->state != HADM_THREAD_STOP &&
			t->state != HADM_THREAD_INIT) {
		pr_err("%s: thread %s wrong state %d.\n", __func__, t->name,
				t->state);
		return -1;
	}

	t->task = kthread_create(t->func, t->arg, "%s", t->name);
	if (t->task == NULL || IS_ERR(t->task)) {
		pr_err("%s: create %s thread failed\n", __FUNCTION__, t->name);
		return -1;
	}
	pr_info("thread %s is started\n",t->name);
	t->state = HADM_THREAD_RUN;
	wake_up_process(t->task);

	return 0;

}

void hadm_thread_stop(struct hadm_thread *t)
{
	if (!t)
		return;

	if (t->state == HADM_THREAD_STOP) {
		return;
	} else if (t->state == HADM_THREAD_INIT) {
		t->state = HADM_THREAD_STOP;
	} else if (t->state == HADM_THREAD_RUN || t->state == HADM_THREAD_EXIT) {
		t->state = HADM_THREAD_STOP; /* 改变线程的状态使之退出 */
		hadm_thread_wake_up(t);
		wait_for_completion(&t->ev_exit);
	} else {
		pr_warn("%s: thread %s: unknown state: %d\n", __FUNCTION__, t->name, t->state);
		return;
	}

	pr_info("%s: %s thread exited\n", __FUNCTION__, t->name);
}

void hadm_thread_terminate(struct hadm_thread *t)
{
	if(t&&t->state==HADM_THREAD_RUN) {
		pr_info("%s: %s thread will terminate\n", __FUNCTION__, t->name);
		t->state=HADM_THREAD_EXIT;
		complete(&t->ev_exit);
	}
}
