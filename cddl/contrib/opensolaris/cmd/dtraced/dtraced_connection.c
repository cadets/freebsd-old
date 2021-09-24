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
#include <sys/un.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define DTRACED_BACKLOG_SIZE    4

static int
accept_new_connection(struct dtd_state *s)
{
	int connsockfd;
	int on = 1;
	int kq = s->kq_hdl;
	struct dtd_fdlist *fde;
	dtd_initmsg_t initmsg;
	struct kevent change_event[4];

	memset(&initmsg, 0, sizeof(initmsg));

	connsockfd = accept(s->sockfd, NULL, 0);
	if (connsockfd == -1) {
		dump_errmsg("accept() failed: %m");
		return (-1);
	}

	if (setsockopt(connsockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))) {
		close(connsockfd);
		dump_errmsg("setsockopt() failed: %m");
		return (-1);
	}

	initmsg.kind = DTRACED_KIND_DTRACED;
	if (send(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		dump_errmsg("send() initmsg to connsockfd failed: %m");
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	if (recv(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		dump_errmsg("recv() get initmsg failed: %m");
		return (-1);
	}

	fde = malloc(sizeof(struct dtd_fdlist));
	if (fde == NULL) {
		dump_errmsg("malloc() failed with: %m");
		abort();
	}

	memset(fde, 0, sizeof(struct dtd_fdlist));
	fde->fd = connsockfd;
	fde->kind = initmsg.kind;
	fde->subs = initmsg.subs;

	EV_SET(change_event, connsockfd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, fde);
	if (kevent(kq, change_event, 1, NULL, 0, NULL) < 0) {
		close(connsockfd);
		free(fde);
		dump_errmsg("kevent() adding new connection failed: %m");
		return (-1);
	}

	EV_SET(change_event, connsockfd, EVFILT_WRITE,
	    EV_ADD | EV_ENABLE, 0, 0, fde);
	if (kevent(kq, change_event, 1, NULL, 0, NULL) < 0) {
		close(connsockfd);
		free(fde);
		dump_errmsg("kevent() adding new connection failed: %m");
		return (-1);
	}

	dump_debugmsg("Accepted (%d, %x, %x)", fde->fd, fde->kind,
	    fde->subs);
	LOCK(&s->socklistmtx);
	dt_list_append(&s->sockfds, fde);
	UNLOCK(&s->socklistmtx);

	return (0);
}

void *
process_consumers(void *_s)
{
	int err;
	int on = 1;
	int new_events;
	__cleanup(closefd_generic) int kq = -1;
	int efd;
	int dispatch;
	size_t i;
	struct dtd_fdlist *udata_fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	struct dtd_joblist *jle;

	struct kevent change_event[4], event[4];

	dispatch = 0;

	/*
	 * Sanity checks on the state.
	 */
	if (s == NULL)
		pthread_exit(NULL);

	if (s->socktd == NULL)
		pthread_exit(NULL);

	if (s->sockfd == -1)
		pthread_exit(NULL);

	err = listen(s->sockfd, DTRACED_BACKLOG_SIZE);
	if (err != 0) {
		dump_errmsg("Failed to listen on %d: %m", s->sockfd);
		pthread_exit(NULL);
	}

	kq = kqueue();
	if (kq == -1) {
		dump_errmsg("Failed to create dtraced socket kqueue: %m");
		pthread_exit(NULL);
	}

	EV_SET(
	    change_event, s->sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	if (kevent(kq, change_event, 1, NULL, 0, NULL)) {
		dump_errmsg("Failed to register listening socket kevent: %m");
		close(kq);
		pthread_exit(NULL);
	}

	s->kq_hdl = kq;
	SEMPOST(&s->socksema);

	while (atomic_load(&s->shutdown) == 0) {
		new_events = kevent(kq, NULL, 0, event, 1, NULL);
		if (new_events == -1) {
			/*
			 * Because kevent failed, we are no longer reliably able
			 * to accept any new connections, therefore the daemon
			 * must exit and report an error.
			 */
			dump_errmsg("kevent() failed with %m");
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		for (i = 0; i < new_events; i++) {
			efd = event[i].ident;

			if (event[i].flags & EV_ERROR) {
				/*
				 * XXX: We could add some checks here to make
				 * sure we're not doing something bad and
				 * segfaulting.
				 */
				LOCK(&s->socklistmtx);
				dt_list_delete(&s->sockfds, event[i].udata);
				UNLOCK(&s->socklistmtx);
				free(event[i].udata);
				close(efd);
				dump_errmsg("event error: %m");
				continue;
			}

			if (event[i].flags & EV_EOF) {
				LOCK(&s->socklistmtx);
				dt_list_delete(&s->sockfds, event[i].udata);
				UNLOCK(&s->socklistmtx);
				free(event[i].udata);

				close(efd);
				continue;
			}

			if (efd == s->sockfd) {
				/*
				 * New connection incoming
				 */
				if (accept_new_connection(s))
					pthread_exit(NULL);
				continue;
			}

			if (event[i].filter == EVFILT_READ) {
				/*
				 * assert that we are in a sane state.
				 */
				udata_fde = event[i].udata;
				assert(udata_fde->fd == efd);

				/*
				 * Disable the EVFILT_READ event so we don't get
				 * spammed by it.
				 */
				EV_SET(change_event, event[i].ident, EVFILT_READ,
				    EV_DISABLE, 0, 0, event[i].udata);
				if (kevent(s->kq_hdl, change_event, 1, NULL, 0,
					NULL)) {
					dump_errmsg("kevent() failed with: %m");
					pthread_exit(NULL);
				}

				/*
				 * If efd did not state it ever wants READDATA
				 * to work on dtraced, we will simply ignore
				 * it and report a warning.
				 */
				if ((udata_fde->subs & DTD_SUB_READDATA) == 0) {
					dump_warnmsg(
					    "socket %d tried to READDATA, but "
					    "is not subscribed (%lx)",
					    efd, udata_fde->subs);
					continue;
				}

				if (dispatch_event(s, &event[i])) {
					dump_errmsg("dispatch_event() failed");
					pthread_exit(NULL);
				}

				continue;
			}

			if (event[i].filter == EVFILT_WRITE) {
				EV_SET(change_event, efd, EVFILT_WRITE,
				    EV_DISABLE, 0, 0, event[i].udata);
				if (kevent(
				    kq, change_event, 1, NULL, 0, NULL)) {
					dump_errmsg("kevent() failed with: %m");
					pthread_exit(NULL);
				}

				dispatch = 0;

				LOCK(&s->joblistmtx);
				for (jle = dt_list_next(&s->joblist); jle;
				     jle = dt_list_next(jle))
					if (jle->connsockfd == efd) {
						/*
						 * Short sanity check before we
						 * say that we should dispatch
						 * the event.
						 */
						udata_fde = event[i].udata;
						assert(udata_fde->fd == efd);
						dispatch = 1;
					}
				UNLOCK(&s->joblistmtx);

				/*
				 * If we have a job to dispatch to the socket,
				 * we tell a worker thread to actually do the
				 * action.
				 */
				if (dispatch != 0) {
					if (dispatch_event(s, &event[i])) {
						dump_errmsg(
						    "dispatch_event() failed");
						pthread_exit(NULL);
					}

					continue;
				}
			}
		}
	}

	pthread_exit(s);
}

int
setup_sockfd(struct dtd_state *s)
{
	int err;
	struct sockaddr_un addr;
	size_t l;
	
	s->sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s->sockfd == -1) {
		dump_errmsg("Failed to create unix: %m");
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		dump_errmsg("Failed to copy %s into sockaddr (%zu)",
		    DTRACED_SOCKPATH, l);
		close(s->sockfd);
		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
		if (err != 0)
			dump_errmsg("Failed to destroy sockmtx: %m");

		return (-1);
	}

	if (remove(DTRACED_SOCKPATH) != 0) {
		if (errno != ENOENT) {
			dump_errmsg("Failed to remove %s: %m",
			    DTRACED_SOCKPATH);
			return (-1);
		}
	}

	err = bind(s->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		dump_errmsg("Failed to bind to %d: %m", s->sockfd);
		close(s->sockfd);
		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
		if (err != 0)
			dump_errmsg("Failed to destroy sockmtx: %m");

		return (-1);
	}

	return (0);
}

int
destroy_sockfd(struct dtd_state *s)
{
	int err;

	if (close(s->sockfd) != 0) {
		dump_errmsg("Failed to close %d: %m", s->sockfd);
		return (-1);
	}

	s->sockfd = -1;

	if (remove(DTRACED_SOCKPATH) != 0)
		dump_errmsg("Failed to remove %s: %m", DTRACED_SOCKPATH);

	return (0);
}

