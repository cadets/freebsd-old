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

#include <sys/types.h>
#include <sys/wait.h>

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_chld.h"
#include "dtraced_lock.h"
#include "dtraced_state.h"

void *
manage_children(void *_s)
{
	struct dtraced_state *s = (struct dtraced_state *)_s;
	pidlist_t *kill_entry, *pe;
	int status;

	while (atomic_load(&s->shutdown) == 0) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		LOCK(&s->killcvmtx);
		LOCK(&s->kill_listmtx);
		while (dt_list_next(&s->kill_list) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			UNLOCK(&s->kill_listmtx);
			WAIT(&s->killcv, pmutex_of(&s->killcvmtx));
			LOCK(&s->kill_listmtx);
		}
		UNLOCK(&s->kill_listmtx);
		UNLOCK(&s->killcvmtx);

		if (atomic_load(&s->shutdown) == 1)
			pthread_exit(_s);

		LOCK(&s->pidlistmtx);
		LOCK(&s->kill_listmtx);
		kill_entry = dt_list_next(&s->kill_list);
		if (kill_entry == NULL) {
			fprintf(stderr, "kill message pulled from under us");
			UNLOCK(&s->kill_listmtx);
			continue;
		}

		dt_list_delete(&s->kill_list, kill_entry);
		UNLOCK(&s->kill_listmtx);

		for (pe = dt_list_next(&s->pidlist); pe; pe = dt_list_next(pe))
			if (pe->pid == kill_entry->pid)
				break;

		if (pe != NULL)
			dt_list_delete(&s->pidlist, pe);
		UNLOCK(&s->pidlistmtx);

		if (kill(kill_entry->pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH)
				ERR("%d: %s(): pid %d does not exist", __LINE__,
				    __func__, kill_entry->pid);
		}

		free(kill_entry);
	}

	return (_s);
}

void *
reap_children(void *_s)
{
	struct dtraced_state *s = _s;
	int status, rv;

	for (;;) {
		sleep(30);
		do {
			rv = waitpid(-1, &status, WNOHANG);
		} while (rv != -1 && rv != 0);

		if (atomic_load(&s->shutdown) != 0)
			pthread_exit(_s);
	}
}

