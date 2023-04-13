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

#include <sys/param.h>

#include <stdlib.h>
#include <string.h>

#include "dtraced_errmsg.h"
#include "dtraced_lock.h"

#if defined(DTRACED_DEBUG) || defined(DTRACED_ROBUST)
void
LOCK(mutex_t *m)
{
	int err;

	err = pthread_mutex_lock(&(m)->_m);
	if (err != 0) {
		ERR("%d: %s(): Failed to lock mutex: %s", __LINE__, __func__,
		    strerror(err));
		exit(EXIT_FAILURE);
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&(m)->_owner, pthread_self());
}

void
UNLOCK(mutex_t *m)
{
	int err;
	pthread_t self;

	if (m->_checkowner != CHECKOWNER_NO) {
		self = pthread_self();
		if (pthread_equal(atomic_load(&m->_owner), self) == 0) {
			ERR("%d: %s(): Attempted unlock of %s by thread %p (!= %p)",
			    __LINE__, __func__, m->_name, self,
			    atomic_load(&m->_owner));
			dump_backtrace();
			exit(EXIT_FAILURE);
		}
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&m->_owner, NULL);

	err = pthread_mutex_unlock(&(m)->_m);
	if (err != 0) {
		ERR("%d: %s(): Failed to unlock mutex: %s", __LINE__, __func__,
		    strerror(err));
		return;
	}

}
#endif

int
mutex_init(mutex_t *m, const pthread_mutexattr_t *restrict attr,
    const char *name, int checkowner)
{
	size_t l;

	assert(m != NULL);

	if (name == NULL)
		return (-1);

	l = strlcpy(m->_name, name, MAXPATHLEN);
	if (l >= MAXPATHLEN)
		return (-1);

	m->_checkowner = checkowner;

	atomic_store(&m->_owner, NULL);
	return (pthread_mutex_init(&m->_m, attr));
}

int
mutex_destroy(mutex_t *m)
{

	assert(atomic_load(&m->_owner) == NULL);
	return (pthread_mutex_destroy(&m->_m));
}

pthread_mutex_t *
pmutex_of(mutex_t *m)
{

	return (&m->_m);
}

