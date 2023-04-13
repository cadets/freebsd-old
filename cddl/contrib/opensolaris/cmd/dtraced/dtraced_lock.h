/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

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

#define SIGNAL(c)                                                          \
	{                                                                  \
		int err;                                                   \
		err = pthread_cond_signal(c);                              \
		if (err != 0) {                                            \
			ERR("%d: %s(): Failed to signal cv: %s", __LINE__, \
			    __func__, strerror(err));                      \
		}                                                          \
	}

#define WAIT(c, m)                                                           \
	{                                                                    \
		int err;                                                     \
		err = pthread_cond_wait(c, m);                               \
		if (err != 0) {                                              \
			ERR("%d: %s(): Failed to wait for cv: %s", __LINE__, \
			    __func__, strerror(err));                        \
		}                                                            \
	}

#define BROADCAST(c)                                                          \
	{                                                                     \
		int err;                                                      \
		err = pthread_cond_broadcast(c);                              \
		if (err != 0) {                                               \
			ERR("%d: %s(): Failed to broadcast cv: %s", __LINE__, \
			    __func__, strerror(err));                         \
		}                                                             \
	}

#define SEMWAIT(s)                                                             \
	{                                                                      \
		int err;                                                       \
		err = sem_wait(s);                                             \
		if (err != 0) {                                                \
			ERR("%d: %s(): Failed to wait for sema: %m", __LINE__, \
			    __func__);                                         \
		}                                                              \
	}

#define SEMPOST(s)                                                             \
	{                                                                      \
		int err;                                                       \
		err = sem_post(s);                                             \
		if (err != 0) {                                                \
			ERR("%d: %s(): Failed to post for sema: %m", __LINE__, \
			    __func__);                                         \
		}                                                              \
	}

#if defined(DTRACED_DEBUG) || defined(DTRACED_ROBUST)
void            LOCK(mutex_t *);
void            UNLOCK(mutex_t *);
#else
#define LOCK(m)                                                             \
	{                                                                   \
		int err;                                                    \
		err = pthread_mutex_lock(pmutex_of(m));                     \
		if (err != 0) {                                             \
			ERR("%d: %s(): Failed to lock mutex: %s", __LINE__, \
			    __func__, strerror(err));                       \
		}                                                           \
	}

#define UNLOCK(m)                                                           \
	{                                                                   \
		int err;                                                    \
		err = pthread_mutex_unlock(pmutex_of(m));                   \
		if (err != 0) {                                             \
			ERR("%d: %s(): Failed to lock mutex: %s", __LINE__, \
			    __func__, strerror(err));                       \
		}                                                           \
	}
#endif /* DTRACED_DEBUG || DTRACED_ROBUST */

int             mutex_destroy(mutex_t *);
pthread_mutex_t *pmutex_of(mutex_t *);
int             mutex_init(mutex_t *, const pthread_mutexattr_t *restrict,
    const char *, int);

#endif // _DTRACED_LOCK_H_
