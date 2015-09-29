#include "common.h"

void *thread_function(void *data)
{
	struct thread *thr;

	signal(SIGPIPE, SIG_IGN);

	thr = (struct thread *)data;
	log_info("thread %s try to run %s(pointer=%p, arg=%p)",
		 thr->name, thr->funcname, thr->function, thr->data);
	thr->function(data);

	log_info("thread %s finish %s(pointer=%p, arg=%p)",
		 thr->name, thr->funcname, thr->function, thr->data);
	thr->state = THREAD_STOP;

	return NULL;
}

struct thread *alloc_thread()
{
	struct thread *thr;

	thr = malloc(sizeof(struct thread));
	if(thr == NULL) {
		return NULL;
	}

	memset(thr, 0, sizeof(struct thread));
	thr->state = THREAD_STOP;

	return thr;
}

struct thread *create_thread(char *name, char *funcname, thread_fun function, void *data)
{
	struct thread *thr;

	thr = alloc_thread();
	if(thr == NULL) {
		return NULL;
	}

	thr->function = function;
	thr->data = data;
	snprintf(thr->name, sizeof(thr->name), "%s", name);
	snprintf(thr->funcname, sizeof(thr->funcname), "%s", funcname);

	log_info("create thread %s bind to function %s(pointer=%p, arg=%p)",
		 thr->name, thr->funcname, thr->function, thr->data);

	return thr;
}

void free_thread(struct thread *thr)
{
	free(thr);
}

int thread_run(struct thread *thr)
{
	int ret;

	if(thr->state == THREAD_RUN) {
		return 0;
	}

	thr->state = THREAD_RUN;
	ret = pthread_create(&thr->thr, NULL, thread_function, thr);
	if (ret < 0) {
		log_error("%s: create thread failed.(%d)",__func__, ret);
		thr->state = THREAD_STOP;
	}
	return ret;
}

int thread_stop(struct thread *thr)
{
	if(thr->state == THREAD_STOP) {
		return 0;
	}

	thr->state = THREAD_STOP;
	return pthread_join(thr->thr, NULL);
}
