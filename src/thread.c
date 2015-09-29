#include "common.h"

void *thread_function(void *data)
{
	struct thread *thr;

	signal(SIGPIPE, SIG_IGN);

	thr = (struct thread *)data;
	thr->function(data);

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

struct thread *create_thread(thread_fun function, void *data)
{
	struct thread *thr;

	thr = alloc_thread();
	if(thr == NULL) {
		return NULL;
	}

	thr->function = function;
	thr->data = data;

	return thr;
}

void free_thread(struct thread *thr)
{
	free(thr);
}

int thread_run(struct thread *thr)
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if(thr->state == THREAD_RUN) {
		return 0;
	}

	thr->state = THREAD_RUN;
	return pthread_create(&thr->thr, &attr, thread_function, thr);
}

int thread_stop(struct thread *thr)
{
	if(thr->state == THREAD_STOP) {
		return 0;
	}

	thr->state = THREAD_STOP;
	return pthread_join(thr->thr, NULL);
}
