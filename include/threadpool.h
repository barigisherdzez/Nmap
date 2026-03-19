#ifndef THREADPOOL_H
#define THREADPOOL_H

#include "ft_nmap.h"
#include <pthread.h>

typedef struct s_job {
	void (*fn)(void *arg);
	void *arg;
	struct s_job *next;
} t_job;

typedef struct s_threadpool {
	pthread_t *threads;
	int        nthreads;

	pthread_mutex_t mtx;
	pthread_cond_t  cv;

	t_job     *head;
	t_job     *tail;
	bool       stop;

	size_t     pending;
	pthread_cond_t done_cv;
} t_threadpool;

int  tp_init(t_threadpool *tp, int nthreads);
int  tp_submit(t_threadpool *tp, void (*fn)(void*), void *arg);
void tp_wait(t_threadpool *tp);
void tp_destroy(t_threadpool *tp);

#endif