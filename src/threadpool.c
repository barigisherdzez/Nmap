#include "threadpool.h"

static void *worker(void *arg)
{
	t_threadpool *tp = (t_threadpool *)arg;

	while (1) {
		pthread_mutex_lock(&tp->mtx);
		while (!tp->stop && tp->head == NULL)
			pthread_cond_wait(&tp->cv, &tp->mtx);

		if (tp->stop && tp->head == NULL) {
			pthread_mutex_unlock(&tp->mtx);
			return NULL;
		}

		t_job *job = tp->head;
		tp->head = job->next;
		if (!tp->head) tp->tail = NULL;
		pthread_mutex_unlock(&tp->mtx);

		job->fn(job->arg);
		free(job);

		pthread_mutex_lock(&tp->mtx);
		if (tp->pending > 0) tp->pending--;
		if (tp->pending == 0)
			pthread_cond_broadcast(&tp->done_cv);
		pthread_mutex_unlock(&tp->mtx);
	}
}

int tp_init(t_threadpool *tp, int nthreads)
{
	memset(tp, 0, sizeof(*tp));
	if (nthreads < 1) nthreads = 1;

	tp->threads = calloc((size_t)nthreads, sizeof(pthread_t));
	if (!tp->threads) return -1;
	tp->nthreads = nthreads;

	if (pthread_mutex_init(&tp->mtx, NULL) != 0) return -1;
	if (pthread_cond_init(&tp->cv, NULL) != 0) return -1;
	if (pthread_cond_init(&tp->done_cv, NULL) != 0) return -1;

	for (int i = 0; i < nthreads; i++) {
		if (pthread_create(&tp->threads[i], NULL, worker, tp) != 0)
			return -1;
	}
	return 0;
}

int tp_submit(t_threadpool *tp, void (*fn)(void*), void *arg)
{
	t_job *j = calloc(1, sizeof(*j));
	if (!j) return -1;
	j->fn = fn;
	j->arg = arg;

	pthread_mutex_lock(&tp->mtx);
	if (tp->stop) {
		pthread_mutex_unlock(&tp->mtx);
		free(j);
		return -1;
	}
	if (tp->tail) tp->tail->next = j;
	else tp->head = j;
	tp->tail = j;
	tp->pending++;
	pthread_cond_signal(&tp->cv);
	pthread_mutex_unlock(&tp->mtx);
	return 0;
}

void tp_wait(t_threadpool *tp)
{
	pthread_mutex_lock(&tp->mtx);
	while (tp->pending != 0)
		pthread_cond_wait(&tp->done_cv, &tp->mtx);
	pthread_mutex_unlock(&tp->mtx);
}

void tp_destroy(t_threadpool *tp)
{
	pthread_mutex_lock(&tp->mtx);
	tp->stop = true;
	pthread_cond_broadcast(&tp->cv);
	pthread_mutex_unlock(&tp->mtx);

	for (int i = 0; i < tp->nthreads; i++)
		pthread_join(tp->threads[i], NULL);

	// cleanup remaining jobs
	t_job *cur = tp->head;
	while (cur) {
		t_job *n = cur->next;
		free(cur);
		cur = n;
	}

	pthread_mutex_destroy(&tp->mtx);
	pthread_cond_destroy(&tp->cv);
	pthread_cond_destroy(&tp->done_cv);

	free(tp->threads);
	memset(tp, 0, sizeof(*tp));
}