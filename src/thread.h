#ifndef __THREAD_H__
#define __THREAD_H__

enum {
	THREAD_STOP,
	THREAD_RUN
};

typedef int (*thread_fun)(void *data);

struct thread {
	pthread_t thr;
	thread_fun function;
	void *data;
	int state;
	char name[MAX_NAME_LEN];
	char funcname[MAX_NAME_LEN];
};

void *thread_function(void *data);

struct thread *alloc_thread();

struct thread *create_thread(char *name, char *funcname, thread_fun function, void *data);

void free_thread(struct thread *thr);

int thread_run(struct thread *thr);

int thread_stop(struct thread *thr);

#endif // __THREAD_H__
