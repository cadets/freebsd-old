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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <pthread_np.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_chld.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_state.h"

static int
setup_threads(struct dtraced_state *s)
{
	int err;
	pthread_t *threads;
	size_t i;

	threads = malloc(sizeof(pthread_t) * s->threadpool_size);
	if (threads == NULL) {
		ERR("%d: %s(): Failed to allocate thread array", __LINE__,
		    __func__);
		return (-1);
	}
	memset(threads, 0, sizeof(pthread_t) * s->threadpool_size);

	for (i = 0; i < s->threadpool_size; i++) {
		err = pthread_create(&threads[i], NULL, process_joblist, s);
		if (err != 0) {
			ERR("%d: %s(): Failed to create a new thread: %m",
			    __LINE__, __func__);
			return (-1);
		}
	}

	s->workers = threads;

	sem_init(&s->socksema, 0, 0);

	if (s->ctrlmachine == 0) {
		err = pthread_create(
		    &s->dtt_listentd, NULL, listen_dttransport, s);
		if (err != 0) {
			ERR("%d: %s(): Failed to create the dttransport thread: %m",
			    __LINE__, __func__);
			return (-1);
		}

		/*
		 * The socket can't be connected at this point because
		 * accept_subs is not running. Need a semaphore.
		 */
		err = pthread_create(
		    &s->dtt_writetd, NULL, write_dttransport, s);
		if (err != 0) {
			ERR("%d: %s(): Failed to create the dttransport thread: %m",
			    __LINE__, __func__);
			return (-1);
		}
	}

	err = pthread_create(&s->socktd, NULL, process_consumers, s);
	if (err != 0) {
		ERR("%d: %s(): Failed to create the socket thread: %m",
		    __LINE__, __func__);
		return (-1);
	}

	err = pthread_create(&s->inboundtd, NULL, listen_dir, s->inbounddir);
	if (err != 0) {
		ERR("%d: %s(): Failed to create inbound listening thread: %m",
		    __LINE__, __func__);
		return (-1);
	}

	err = pthread_create(&s->basetd, NULL, listen_dir, s->basedir);
	if (err != 0) {
		ERR("%d: %s(): Failed to create base listening thread: %m",
		    __LINE__, __func__);
		return (-1);
	}

	err = pthread_create(&s->killtd, NULL, manage_children, s);
	if (err != 0) {
		ERR("%d: %s(): Failed to create a child management thread: %m",
		    __LINE__, __func__);
		return (-1);
	}

	err = pthread_create(&s->reaptd, NULL, reap_children, s);
	if (err != 0) {
		ERR("%d: %s(): Failed to create reaper thread: %m", __LINE__,
		    __func__);
		return (-1);
	}

	err = pthread_create(&s->closetd, NULL, close_filedescs, s);
	if (err != 0) {
		ERR("%d: %s(): Failed to create filedesc closing thread: %m",
		    __LINE__, __func__);
		return (-1);
	}

	return (0);
}

int
init_state(struct dtraced_state *s, int ctrlmachine, int nosha, int n_threads,
    const char **argv)
{
	int err;

	memset(s, 0, sizeof(struct dtraced_state));
	s->argv = argv;
	s->sockfd = -1;
	s->ctrlmachine = ctrlmachine;
	s->nosha = nosha;
	s->threadpool_size = n_threads;

	if ((err = mutex_init(
	    &s->socklistmtx, NULL, "socklist", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create sock list mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->sockmtx, NULL, "socket", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create socket mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistcvmtx, NULL, "joblist condvar", CHECKOWNER_NO)) != 0) {
		ERR("%d: %s(): Failed to create joblist condvar mutex: %m",
		    __LINE__, __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistmtx, NULL, "joblist", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create joblist mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->dispatched_jobsmtx, NULL, "joblist", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create joblist mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->kill_listmtx, NULL, "kill list", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create kill list mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->pidlistmtx, NULL, "pidlist", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create pidlist mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->killcvmtx, NULL, "", CHECKOWNER_NO)) != 0) {
		ERR("%d: %s(): Failed to create kill condvar mutex: %m",
		    __LINE__, __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->identlistmtx, NULL, "", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create identlist mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = mutex_init(
	    &s->deadfdsmtx, NULL, "", CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create deadfds mutex: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if ((err = pthread_cond_init(&s->killcv, NULL)) != 0) {
		ERR("%d: %s(): Failed to create kill list condvar: %m",
		    __LINE__, __func__);
		return (-1);
	}

	if ((err = pthread_cond_init(&s->joblistcv, NULL)) != 0) {
		ERR("%d: %s(): Failed to create joblist condvar: %m", __LINE__,
		    __func__);
		return (-1);
	}

	if (s->ctrlmachine == 0) {
		/* We close dttransport on exec. */
		s->dtt_fd = open("/dev/dttransport", O_RDWR | O_CLOEXEC);
		if (s->dtt_fd == -1) {
			ERR("%d: %s(): Failed to open /dev/dttransport: %m",
			    __LINE__, __func__);
			return (-1);
		}
	}

	s->outbounddir = dtd_mkdir(DTRACED_OUTBOUNDDIR, &process_outbound);
	if (s->outbounddir == NULL) {
		ERR("%d: %s(): Failed creating outbound directory: %m",
		    __LINE__, __func__);
		return (-1);
	}

	s->inbounddir = dtd_mkdir(DTRACED_INBOUNDDIR, &process_inbound);
	if (s->inbounddir == NULL) {
		ERR("%d: %s(): Failed creating inbound directory: %m", __LINE__,
		    __func__);
		return (-1);
	}

	s->basedir = dtd_mkdir(DTRACED_BASEDIR, &process_base);
	if (s->basedir == NULL) {
		ERR("%d: %s(): Failed creating base directory: %m", __LINE__,
		    __func__);
		return (-1);
	}

	s->outbounddir->state = s;
	s->inbounddir->state = s;
	s->basedir->state = s;

	if ((err = setup_sockfd(s)) != 0) {
		ERR("%d: %s(): Failed to set up the socket", __LINE__,
		    __func__);
		return (-1);
	}

	err = file_foreach(s->outbounddir->dir,
	    populate_existing, s->outbounddir);
	if (err != 0) {
		ERR("%d: %s(): Failed to populate outbound existing files",
		    __LINE__, __func__);
		return (-1);
	}

	err = file_foreach(s->inbounddir->dir,
	    populate_existing, s->inbounddir);
	if (err != 0) {
		ERR("%d: %s(): Failed to populate inbound existing files",
		    __LINE__, __func__);
		return (-1);
	}

	err = file_foreach(s->basedir->dir, populate_existing, s->basedir);
	if (err != 0) {
		ERR("%d: %s(): Failed to populate base existing files",
		    __LINE__, __func__);
		return (-1);
	}

	err = setup_threads(s);
	if (err != 0) {
		ERR("%d: %s(): Failed to set up threads", __LINE__, __func__);
		return (-1);
	}

	return (0);
}

int
destroy_state(struct dtraced_state *s)
{
	int err;
	size_t i;
	struct dtraced_job *j, *next;
	struct dtraced_state *retval;
	struct timespec ts;

	/*
	 * Timespec for join timeout.
	 */
	memset(&ts, 0, sizeof(ts));
	ts.tv_sec = 5;

	/*
	 * Give all the threads a chance to stop, but we don't really care if
	 * the call fails. We're simply going to exit anyway. pthread_kill() can
	 * only give us an ESRCH (which means the thread's already gone and we
	 * don't care), or EINVAL for an invalid signal, which we never send.
	 * Therefore, we can safely just ignore all of the return codes and
	 * expect the pthread_timedjoin_np() to behave sanely. If our thread is
	 * stuck and doesn't join in time, we simply report the error and
	 * continue destroying the other threads. We are exiting after this, so
	 * it's unlikely that a stuck thread is going to cause more chaos than
	 * it already has.
	 */
	(void) pthread_kill(s->socktd, SIGTERM);
	if (pthread_timedjoin_np(s->socktd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): socktd join timed out", __LINE__, __func__);
		abort();
	}

	(void) pthread_kill(s->dtt_listentd, SIGTERM);
	if (pthread_timedjoin_np(s->dtt_listentd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): dtt_listentd join timed out", __LINE__,
		    __func__);
		abort();
	}

	(void) pthread_kill(s->dtt_writetd, SIGTERM);
	if (pthread_timedjoin_np(s->dtt_writetd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): dtt_writetd join timed out", __LINE__,
		    __func__);
		abort();
	}

	(void) pthread_kill(s->inboundtd, SIGTERM);
	if (pthread_timedjoin_np(s->inboundtd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): inboundtd join timed out", __LINE__,
		    __func__);
		abort();
	}

	(void) pthread_kill(s->basetd, SIGTERM);
	if (pthread_timedjoin_np(s->basetd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): basetd join timed out", __LINE__,
		    __func__);
		abort();
	}

	LOCK(&s->joblistcvmtx);
	BROADCAST(&s->joblistcv);
	UNLOCK(&s->joblistcvmtx);

	for (i = 0; i < s->threadpool_size; i++) {
		if (pthread_timedjoin_np(s->workers[i],
		    (void **)&retval, &ts) == ETIMEDOUT) {
			ERR("%d: %s(): worker %ju join timed out", __LINE__,
			    __func__, (uintmax_t)i);
			abort();
		}
	}

	(void) pthread_kill(s->killtd, SIGTERM);
	if (pthread_timedjoin_np(s->killtd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): killtd join timed out", __LINE__,
		    __func__);
		abort();
	}

	(void) pthread_kill(s->reaptd, SIGTERM);
	if (pthread_timedjoin_np(s->reaptd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): reaptd join timed out", __LINE__,
		    __func__);
		abort();
	}

	(void) pthread_kill(s->closetd, SIGTERM);
	if (pthread_timedjoin_np(s->closetd,
	    (void **)&retval, &ts) == ETIMEDOUT) {
		ERR("%d: %s(): closetd join timed out", __LINE__,
		    __func__);
		abort();
	}

	LOCK(&s->joblistmtx);
	for (j = dt_list_next(&s->joblist); j; j = next) {
		next = dt_list_next(j);
		free(j);
	}
	UNLOCK(&s->joblistmtx);

	(void) mutex_destroy(&s->socklistmtx);
	(void) mutex_destroy(&s->sockmtx);
	(void) mutex_destroy(&s->joblistcvmtx);
	(void) mutex_destroy(&s->joblistmtx);
	(void) mutex_destroy(&s->kill_listmtx);
	(void) mutex_destroy(&s->killcvmtx);
	(void) mutex_destroy(&s->deadfdsmtx);
	(void) pthread_cond_destroy(&s->killcv);
	(void) pthread_cond_destroy(&s->joblistcv);

	dtd_closedir(s->outbounddir);
	dtd_closedir(s->inbounddir);
	dtd_closedir(s->basedir);

	sem_destroy(&s->socksema);

	destroy_sockfd(s);
	s->sockfd = -1;

	free(s->workers);

	if (s->ctrlmachine == 0) {
		close(s->dtt_fd);
		s->dtt_fd = -1;
	}

	return (0);
}
