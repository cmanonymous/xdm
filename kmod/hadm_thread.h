#ifndef HADM_THREAD_H
#define HADM_THREAD_H

#include <linux/sched.h>
#include <linux/completion.h>

typedef int (*thread_func_t)(void *);

/*
 * INIT >>hadm_thread_run>>> RUN >>hadm_thread_terminate>>> EXIT
 *  v                         v                              v
 *  v                         v                              v
 *  `>>>>>>>>>>>>>>>>>>hadm_thread_stop<<<<<<<<<<<<<<<<<<<<<</
 *                            v
 *                            v
 *                            v
 *                           STOP
 */

enum {
	HADM_THREAD_INIT,
	HADM_THREAD_RUN,
	HADM_THREAD_EXIT,
	HADM_THREAD_STOP,
};

#define MAX_THREAD_NAME 20

struct hadm_thread {
	struct mutex mutex;

	char name[MAX_THREAD_NAME];
	struct task_struct *task;
	thread_func_t func;
	void *arg;

	struct completion ev_exit;
	int state;

	void *private;
};

struct hadm_thread_info {
	thread_func_t func;
	char *name;
};

extern struct hadm_thread *hadm_thread_alloc(void);
extern int hadm_thread_init(struct hadm_thread *t, char *name, thread_func_t func, void *arg, void *private);
extern void hadm_thread_free(struct hadm_thread **t);

extern int hadm_thread_start(struct hadm_thread *t);
extern void hadm_thread_stop(struct hadm_thread *t);
extern int hadm_thread_wake_up(struct hadm_thread *t);
extern void hadm_thread_terminate(struct hadm_thread *t);
extern int hadm_thread_get_state(struct hadm_thread *t);

#endif	/* HADM_THREAD_H */
