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
#include "dtraced_state.h"

/*
 * NOTE: dispatch_event assumes that event has already been handled correctly in
 * the main loop.
 */
int
dispatch_event(struct dtd_state *s, struct kevent *ev)
{
	struct dtd_joblist *job;
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
		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			dump_errmsg("malloc() failed with: %m");
			abort();
		}

		job->job = READ_DATA;
		job->connsockfd = dfd;

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		dump_debugmsg("Dispatching EVFILT_READ on %d", ev->ident);
		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);

	} else if (ev->filter == EVFILT_WRITE) {
		/*
		 * Because we are in a state where we know that:
		 *  (1) There is a consumer waiting for an event and we can
		 *      write to
		 * and
		 *  (2) We have said event
		 *
		 * we can signal the condition variable and rely on one of our
		 * workers to pick up and process the event.
		 */
		dump_debugmsg("Dispatching EVFILT_WRITE on %d", ev->ident);
		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);
	} else {
		free(job);
		dump_errmsg("unexpected event flags: %d", ev->flags);
		return (-1);
	}

	return (0);
}

void *
process_joblist(void *_s)
{
	int i;
	struct dtd_joblist *curjob;
	struct dtd_state *s = (struct dtd_state *)_s;
	struct dtd_joblist *job;
	const char *jobname[] = {
		[0]               = "NONE",
		[NOTIFY_ELFWRITE] = "NOTIFY_ELFWRITE",
		[KILL]            = "KILL",
		[READ_DATA]       = "READ_DATA",
		[CLEANUP]         = "CLEANUP"
	};

	while (atomic_load(&s->shutdown) == 0) {
		LOCK(&s->joblistcvmtx);
		LOCK(&s->joblistmtx);
		while (dt_list_next(&s->joblist) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			UNLOCK(&s->joblistmtx);
			WAIT(&s->joblistcv, pmutex_of(&s->joblistcvmtx));
			LOCK(&s->joblistmtx);
		}
		UNLOCK(&s->joblistmtx);
		UNLOCK(&s->joblistcvmtx);
		if (atomic_load(&s->shutdown) == 1)
			break;


		LOCK(&s->joblistmtx);
		curjob = dt_list_next(&s->joblist);
		if (curjob == NULL) {
			/*
			 * It is possible that another thread already picked
			 * this job up, in which case we simply loop again.
			 */
			UNLOCK(&s->joblistmtx);
			continue;
		}

		dt_list_delete(&s->joblist, curjob);
		UNLOCK(&s->joblistmtx);

		if (curjob->job >= 0 && curjob->job <= JOB_LAST)
			dump_debugmsg("Job: %s", jobname[curjob->job]);
		else
			dump_errmsg("Job %u out of bounds", curjob->job);

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

		default:
			dump_errmsg("Unknown job: %d", curjob->job);
			abort();
		}

		free(curjob);
	}

	pthread_exit(s);
}

