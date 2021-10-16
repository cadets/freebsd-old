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

#include <sys/socket.h>

#include <dt_list.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_readjob.h"
#include "dtraced_state.h"

static int
handle_elfmsg(struct dtd_state *s, dtraced_hdr_t *h,
    unsigned char *buf, size_t bsize)
{
	dtd_dir_t *dir;
	identlist_t *newident;

	dump_debugmsg("        ELF file");

	if (strcmp(DTRACED_MSG_LOC(*h), "base") == 0)
		dir = s->basedir;
	else if (strcmp(DTRACED_MSG_LOC(*h), "outbound") == 0)
		dir = s->outbounddir;
	else if (strcmp(DTRACED_MSG_LOC(*h), "inbound") == 0)
		dir = s->inbounddir;
	else
		dir = NULL;

	if (dir == NULL) {
		dump_errmsg("unrecognized location: %s", DTRACED_MSG_LOC(*h));
		return (-1);
	}

	if (s->ctrlmachine == 0) {
		newident = malloc(sizeof(identlist_t));
		if (newident == NULL) {
			dump_errmsg("Failed to allocate new"
				    " identifier: %m");
			abort();
		}

		if (DTRACED_MSG_IDENT_PRESENT(*h)) {
			memcpy(newident->ident, DTRACED_MSG_IDENT(*h),
			    DTRACED_PROGIDENTLEN);

			LOCK(&s->identlistmtx);
			dt_list_append(&s->identlist, newident);
			UNLOCK(&s->identlistmtx);
		}
	}

	if (write_data(dir, buf, bsize))
		dump_errmsg("write_data() failed");

	return (0);
}

static int
handle_killmsg(struct dtd_state *s, dtraced_hdr_t *h)
{
	dtraced_fd_t *dfd = NULL;
	struct dtd_joblist *job;

	dump_debugmsg("        KILL (%d)", DTRACED_MSG_KILLPID(*h));

	/*
	 * We enqueue a KILL message in the joblist
	 * (another thread will simply pick this up). We
	 * need to only do it for FORWARDERs.
	 */
	LOCK(&s->socklistmtx);
	for (dfd = dt_list_next(&s->sockfds); dfd; dfd = dt_list_next(dfd)) {
		fd_acquire(dfd);
		if (dfd->kind != DTRACED_KIND_FORWARDER) {
			fd_release(dfd);
			continue;
		}

		if ((dfd->subs & DTD_SUB_KILL) == 0) {
			fd_release(dfd);
			continue;
		}

		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			dump_errmsg("malloc() failed with: %m");
			abort();
		}

		memset(job, 0, sizeof(struct dtd_joblist));

		job->job = KILL;
		job->connsockfd = dfd;
		job->j.kill.pid = DTRACED_MSG_KILLPID(*h);
		job->j.kill.vmid = DTRACED_MSG_KILLVMID(*h);

		dump_debugmsg("        kill %d to %d",
		    DTRACED_MSG_KILLPID(*h), dfd->fd);

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);
	}
	UNLOCK(&s->socklistmtx);

	return (0);
}

static int
handle_cleanupmsg(struct dtd_state *s, dtraced_hdr_t *h)
{
	size_t n_entries, nbytes, len, i, j;
	ssize_t r;
	char *buf, *_buf;
	struct dtd_joblist *job;
	dtraced_fd_t *dfd;

	/* XXX: Would be nice if __cleanup() did everything. */
	__cleanup(freep) char **entries = NULL;

	n_entries = DTRACED_MSG_NUMENTRIES(*h);
	entries = malloc(n_entries * sizeof(char *));
	if (entries == NULL)
		abort();

	memset(entries, 0, sizeof(char *) * n_entries);

	for (dfd = dt_list_next(&s->sockfds); dfd; dfd = dt_list_next(dfd)) {
		fd_acquire(dfd);
		if (dfd->kind != DTRACED_KIND_FORWARDER) {
			fd_release(dfd);
			continue;
		}

		if ((dfd->subs & DTD_SUB_CLEANUP) == 0) {
			fd_release(dfd);
			continue;
		}

		for (i = 0; i < n_entries; i++) {
			if (recv(dfd->fd, &len, sizeof(len), 0) < 0) {
				dump_errmsg("recv() failed with: %m");
				for (j = 0; j < i; j++)
					free(entries[j]);
				return (-1);
			}

			buf = malloc(len);
			if (buf == NULL)
				abort();

			_buf = buf;
			nbytes = len;
			while ((r = recv(dfd->fd, _buf, nbytes, 0)) != nbytes) {
				if (r < 0) {
					dump_errmsg("recv() failed with: %m");
					for (j = 0; j < i; j++)
						free(entries[j]);
					free(buf);
					return (-1);
				}

				assert(r != 0);

				_buf += r;
				nbytes -= r;
			}

			buf[len - 1] = '\0';
			entries[i] = buf;
		}

		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL)
			abort();

		memset(job, 0, sizeof(struct dtd_joblist));

		/*
		 * Prepare the job.
		 */
		job->job = CLEANUP;
		job->connsockfd = dfd;
		job->j.cleanup.n_entries = n_entries;
		job->j.cleanup.entries = malloc(sizeof(char *) * n_entries);
		if (job->j.cleanup.entries == NULL)
			abort();

		memset(job->j.cleanup.entries, 0, sizeof(char *) * n_entries);

		for (i = 0; i < n_entries; i++) {
			job->j.cleanup.entries[i] = strdup(entries[i]);
			if (job->j.cleanup.entries[i] == NULL)
				abort();
		}

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);
	}

	for (i = 0; i < n_entries; i++)
		free(entries[i]);

	return (0);
}

void
handle_read_data(struct dtd_state *s, struct dtd_joblist *curjob)
{
	int fd, err;
	__cleanup(releasefd) dtraced_fd_t *dfd = curjob->connsockfd;
	size_t nbytes, totalbytes;
	ssize_t r;
	char *_buf;
	dtraced_hdr_t header;
	__cleanup(freep) char *buf = NULL;

	fd = dfd->fd;
	nbytes = 0;
	totalbytes = 0;

	if ((r = recv(fd, &totalbytes, sizeof(totalbytes), 0)) < 0) {
		dump_errmsg("recv() failed with: %m");
		return;
	}

	assert(r == sizeof(totalbytes));
	dump_debugmsg("    %zu bytes from %d", totalbytes, fd);

	nbytes = totalbytes;

	buf = malloc(nbytes);
	if (buf == NULL) {
		dump_errmsg("malloc() failed with: %m");
		abort();
	}

	_buf = buf;
	while ((r = recv(fd, _buf, nbytes, 0)) != nbytes) {
		if (r < 0) {
			dump_errmsg("recv() failed with: %m");
			buf = NULL;
			return;
		}

		assert(r != 0);

		_buf += r;
		nbytes -= r;
	}

	if (r < 0) {
		if (send_nak(fd) < 0) {
			dump_errmsg("send_nak() failed with: %m");
			return;
		}

		/*
		 * We are done receiving the data and nothing
		 * failed, re-enable the event and keep going.
		 */
		if (reenable_fd(s->kq_hdl, fd, EVFILT_READ)) {
			dump_errmsg("reenable_fd() failed with: %m");
			return;
		}
	}

	nbytes = totalbytes;
	_buf = buf;

	/*
	 * We now have our data (ELF file) in buf. Create an ELF
	 * file in /var/ddtrace/base. This will kick off the
	 * listen_dir thread for process_base.
	 */

	memcpy(&header, buf, DTRACED_MSGHDRSIZE);
	switch (DTRACED_MSG_TYPE(header)) {
	case DTRACED_MSG_ELF:
		_buf += DTRACED_MSGHDRSIZE;
		nbytes -= DTRACED_MSGHDRSIZE;
		err = handle_elfmsg(s, &header, _buf, nbytes);
		break;

	case DTRACED_MSG_KILL:
		err = handle_killmsg(s, &header);
		break;

	case DTRACED_MSG_CLEANUP:
		err = handle_cleanupmsg(s, &header);
		break;

	default:
		dump_errmsg("Unknown message: %d", DTRACED_MSG_TYPE(header));
		err = 1;
	}

	if (err == 0) {
		if (send_ack(fd) < 0) {
			dump_errmsg("send_ack() failed with: %m");
			return;
		}
	} else {
		if (send_nak(fd) < 0) {
			dump_errmsg("send_nak() failed with: %m");
			return;
		}
	}

	/*
	 * We are done receiving the data and nothing
	 * failed, re-enable the event and keep going.
	 */
	if (reenable_fd(s->kq_hdl, fd, EVFILT_READ))
		dump_errmsg("reenable_fd() failed with: %m");
}
