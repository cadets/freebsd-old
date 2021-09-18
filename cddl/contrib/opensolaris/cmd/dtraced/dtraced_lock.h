#ifndef _DTRACED_LOCK_H_
#define _DTRACED_LOCK_H_

#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>

#include "dtraced_errmsg.h"

typedef struct mutex {
	pthread_mutex_t _m;       /* pthread mutex */
	_Atomic pthread_t _owner; /* owner thread of _m */
	char _name[MAXPATHLEN];   /* name of the mutex */
	int _checkowner;          /* do we want to check who owns the mutex? */
#define CHECKOWNER_NO     0
#define CHECKOWNER_YES    1
} mutex_t;


#define OWNED(m)    (atomic_load(&(m)->_owner) == pthread_self())

#define SIGNAL(c)                                               \
	{                                                       \
		int err;                                        \
		err = pthread_cond_signal(c);                   \
		if (err != 0) {                                 \
			dump_errmsg("Failed to signal cv: %m"); \
		}                                               \
	}

#define WAIT(c, m)                                                \
	{                                                         \
		int err;                                          \
		err = pthread_cond_wait(c, m);                    \
		if (err != 0) {                                   \
			dump_errmsg("Failed to wait for cv: %m"); \
		}                                                 \
	}

#define BROADCAST(c)                                               \
	{                                                          \
		int err;                                           \
		err = pthread_cond_broadcast(c);                   \
		if (err != 0) {                                    \
			dump_errmsg("Failed to broadcast cv: %m"); \
		}                                                  \
	}

#define SEMWAIT(s)                                                  \
	{                                                           \
		int err;                                            \
		err = sem_wait(s);                                  \
		if (err != 0) {                                     \
			dump_errmsg("Failed to wait for sema: %m"); \
		}                                                   \
	}

#define SEMPOST(s)                                                  \
	{                                                           \
		int err;                                            \
		err = sem_post(s);                                  \
		if (err != 0) {                                     \
			dump_errmsg("Failed to post for sema: %m"); \
		}                                                   \
	}

void            LOCK(mutex_t *);
void            UNLOCK(mutex_t *);
int             mutex_destroy(mutex_t *);
pthread_mutex_t *pmutex_of(mutex_t *);
int             mutex_init(mutex_t *, const pthread_mutexattr_t *restrict,
    const char *, int);

#endif // _DTRACED_LOCK_H_
