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
#include <sys/param.h>
#include <sys/event.h>
#include <sys/socket.h>

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_cleanupjob.h"
#include "dtraced_connection.h"
#include "dtraced_elfjob.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_killjob.h"
#include "dtraced_lock.h"
#include "dtraced_readjob.h"
#include "dtraced_sendinfojob.h"
#include "dtraced_state.h"

/*
 * NOTE: dispatch_event assumes that event has already been handled correctly in
 * the main loop.
 */
int
dispatch_event(struct dtraced_state *s, struct kevent *ev)
{
	struct dtraced_job *job = NULL; /* in case we free */
	dtraced_fd_t *dfd;

	if (ev->filter == EVFILT_READ) {
		dfd = ev->udata;
		fd_acquire(dfd);

		/*
		 * Read is a little bit more complicated than write, because we
		 * have to read in the actual event and put it in the
		 * /var/ddtrace/base directory for the directory monitoring
		 * kqueues to wake up and process it further.
		 */
		job = malloc(sizeof(struct dtraced_job));
		if (job == NULL) {
			ERR("%d: %s(): malloc() failed with: %m", __LINE__,
			    __func__);
			abort();
		}

		memset(job, 0, sizeof(struct dtraced_job));
		job->job = READ_DATA;
		job->connsockfd = dfd;

		LOCK(&s->dispatched_jobsmtx);
		dt_list_prepend(&s->dispatched_jobs, job);
		UNLOCK(&s->dispatched_jobsmtx);

		DEBUG("%d: %s(): Dispatching EVFILT_READ on %d", __LINE__,
		    __func__, ev->ident);
		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);

	} else if (ev->filter == EVFILT_WRITE) {
		/*
		 * Go through the joblist, and if we find a job which has our
		 * file descriptor as the destination, we put it in the dispatch
		 * list.
		 */
		for (job = dt_list_next(&s->joblist); job;
		     job = dt_list_next(job)) {
			dfd = job->connsockfd;
			if (dfd->fd == ev->ident) {
				dt_list_delete(&s->joblist, job);
				dt_list_append(&s->dispatched_jobs, job);
			}
		}

		/*
		 * Signal the workers to pick up our dispatched jobs.
		 */
		DEBUG("%d: %s(): Dispatching EVFILT_WRITE on %d", __LINE__,
		    __func__, ev->ident);
		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);
	} else {
		free(job);
		ERR("%d: %s(): Unexpected event flags: %d", __LINE__, __func__,
		    ev->flags);
		return (-1);
	}

	return (0);
}

void *
process_joblist(void *_s)
{
	int i;
	struct dtraced_job *curjob;
	struct dtraced_state *s = (struct dtraced_state *)_s;
	struct dtraced_job *job;
	const char *jobname[] = {
		[0]               = "NONE",
		[NOTIFY_ELFWRITE] = "NOTIFY_ELFWRITE",
		[KILL]            = "KILL",
		[READ_DATA]       = "READ_DATA",
		[CLEANUP]         = "CLEANUP",
		[SEND_INFO]       = "SEND_INFO"
	};

	while (atomic_load(&s->shutdown) == 0) {
		LOCK(&s->joblistcvmtx);
		while (dt_list_next(&s->dispatched_jobs) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			WAIT(&s->joblistcv, pmutex_of(&s->joblistcvmtx));
		}
		UNLOCK(&s->joblistcvmtx);
		if (atomic_load(&s->shutdown) == 1)
			break;

		LOCK(&s->dispatched_jobsmtx);
		curjob = dt_list_next(&s->dispatched_jobs);
		if (curjob == NULL) {
			/*
			 * It is possible that another thread already picked
			 * this job up, in which case we simply loop again.
			 */
			UNLOCK(&s->dispatched_jobsmtx);
			continue;
		}

		dt_list_delete(&s->dispatched_jobs, curjob);
		UNLOCK(&s->dispatched_jobsmtx);

		if (curjob->job >= 0 && curjob->job <= JOB_LAST)
			DEBUG("%d: %s(): Job: %s", __LINE__, __func__,
			    jobname[curjob->job]);
		else
			ERR("%d: %s(): Job %u out of bounds", __LINE__,
			    __func__, curjob->job);

		switch (curjob->job) {
		case READ_DATA:
			handle_read_data(s, curjob);
			break;

		case KILL:
			handle_kill(s, curjob);
			break;

		case NOTIFY_ELFWRITE:
			handle_elfwrite(s, curjob);
			break;

		case CLEANUP:
			handle_cleanup(s, curjob);
			break;

		case SEND_INFO:
			handle_sendinfo(s, curjob);
			break;

		default:
			ERR("%d: %s(): Unknown job: %d", __LINE__, __func__,
			    curjob->job);
			abort();
		}

		free(curjob);
	}

	pthread_exit(s);
}

