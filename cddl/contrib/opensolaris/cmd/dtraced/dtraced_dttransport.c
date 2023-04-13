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
#include <sys/socket.h>
#include <sys/un.h>

#include <dttransport.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_chld.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

static size_t dirlen;

static void
dtt_elf(struct dtraced_state *s, dtt_entry_t *e)
{
	static int fd = 0;
	static char *elf = NULL;
	static char *path = NULL;
	static size_t len = 0;
	static size_t offs = 0;
	char donepath[MAXPATHLEN] = { 0 };
	size_t donepathlen;
	char msg[128] = { 0 };

	if (fd == -1)
		return;

retry:
	/*
	 * At this point we have the /var/ddtrace/inbound
	 * open and created, so we can just create new files in
	 * it without too much worry of failure because
	 * directory does not exist.
	 */
	if (fd == 0) {
		LOCK(&s->inbounddir->dirmtx);
		path = gen_filename(s->inbounddir->dirpath);
		UNLOCK(&s->inbounddir->dirmtx);

		if (path == NULL) {
			ERR("%d: %s(): gen_filename() failed with %s", __LINE__,
			    __func__, strerror(errno));
			goto retry;
		}
		fd = open(path, O_CREAT | O_WRONLY, 0600);

		if (fd == -1) {
			ERR("%d: %s(): Failed to open %s: %m", __LINE__,
			    __func__, path);
			return;
		}

		elf = malloc(e->u.elf.totallen);
		if (elf == NULL) {
			ERR("%d: %s(): Failed to malloc elf: %m", __LINE__,
			    __func__);
			abort();
		}

		memset(elf, 0, e->u.elf.totallen);
		len = e->u.elf.totallen;
	}

	assert(offs < len && "Assertion happens if file was not created");
	if (offs + e->u.elf.len > len) {
		ERR("%d: %s(): offs + elflen (%zu) > len (%zu)", __LINE__,
		    __func__, offs + e->u.elf.len, len);
		return;
	}

	assert(offs + e->u.elf.len <= len &&
	    "Assertion happens if ELF segment length is too long");
	memcpy(elf + offs, e->u.elf.data, e->u.elf.len);
	offs += e->u.elf.len;

	if (e->u.elf.hasmore == 0) {
		if (write(fd, elf, len) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			ERR("%d: %s(): Failed to write data to %s: %m",
			    __LINE__, __func__, path);
		}

		donepathlen = strlen(path) - 1;
		assert(donepathlen < MAXPATHLEN);
		memset(donepath, 0, donepathlen);
		memcpy(donepath, path, dirlen);
		memcpy(donepath + dirlen, path + dirlen + 1,
		    donepathlen - dirlen);

		if (rename(path, donepath)) {
			ERR("%d: %s(): Failed to move %s to %s: %m", __LINE__,
			    __func__, path, donepath);
		}

		free(elf);
		close(fd);
		free(path);
		fd = 0;
		offs = 0;
		len = 0;
		path = NULL;
	}
}

static void
dtt_kill(struct dtraced_state *s, dtt_entry_t *e)
{
	pidlist_t *kill_entry;

	kill_entry = malloc(sizeof(pidlist_t));
	if (kill_entry == NULL) {
		ERR("%d: %s(): failed to malloc kill_entry: %m", __LINE__,
		    __func__);
		abort();
	}

	kill_entry->pid = e->u.kill.pid;
	LOCK(&s->kill_listmtx);
	dt_list_append(&s->kill_list, kill_entry);
	UNLOCK(&s->kill_listmtx);

	LOCK(&s->killcvmtx);
	SIGNAL(&s->killcv);
	UNLOCK(&s->killcvmtx);
}

static void
dtt_cleanup(struct dtraced_state *s, dtt_entry_t *e)
{
	struct dtraced_job *job;
	pidlist_t *pe;
	size_t i;

	/* Clean up all of the dtraced state */
	DEBUG("%d: %s(): Got cleanup message.", __LINE__, __func__);

	LOCK(&s->joblistmtx);
	while (job = dt_list_next(&s->joblist)) {
		dt_list_delete(&s->joblist, job);
		switch (job->job) {
		case READ_DATA:
			fd_release(job->connsockfd);
			break;

		case KILL:
			fd_release(job->connsockfd);
			break;

		case NOTIFY_ELFWRITE:
			fd_release(job->connsockfd);
			break;

		case CLEANUP:
			fd_release(job->connsockfd);
			for (i = 0; i < job->j.cleanup.n_entries; i++)
				free(job->j.cleanup.entries[i]);
			free(job->j.cleanup.entries);
			break;

		default:
			ERR("%d: %s(): Unknown job: %d", __LINE__, __func__,
			    job->job);
		}
		free(job);
	}
	UNLOCK(&s->joblistmtx);

	LOCK(&s->pidlistmtx);
	while (pe = dt_list_next(&s->pidlist)) {
		dt_list_delete(&s->pidlist, pe);
		(void)kill(pe->pid, SIGKILL);
		free(pe);
	}
	UNLOCK(&s->pidlistmtx);

#ifdef notyet /* XXX(dstolfa): We probably want this later on. */
	/* Re-exec ourselves to ensure full cleanup. */
	execve(s->argv[0], (char *const *)s->argv, NULL);
#endif
}

static int
setup_connection(struct dtraced_state *s)
{
	dtd_initmsg_t initmsg;
	struct sockaddr_un addr;
	int sockfd;
	size_t l;

	memset(&initmsg, 0, sizeof(initmsg));

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		ERR("%d: %s(): Failed creating a socket: %m", __LINE__,
		    __func__);
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		ERR("%d: %s(): Failed setting addr.sun_path to /var/ddtrace/sub.sock",
		    __LINE__, __func__);
		close(sockfd);
		return (-1);
	}

	SEMWAIT(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		ERR("%d: %s(): connect to /var/ddtrace/sub.sock failed: %m",
		    __LINE__, __func__);
		close(sockfd);
		return (-1);
	}

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		close(sockfd);
		return (-1);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		ERR("%d: %s(): Expected dtraced kind, got %d", __LINE__,
		    __func__, initmsg.kind);
		close(sockfd);
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	snprintf(initmsg.ident, DTRACED_FDIDENTLEN, "dtraced-dttransport-%d", getpid());

	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		ERR("%d: %s(): Failed to write initmsg to sockfd: %m", __LINE__,
		    __func__);
		close(sockfd);
		return (-1);
	}

	return (sockfd);
}

/*
 * Runs in its own thread. Reads ELF files from dttransport and puts them in
 * the inbound directory.
 */
void *
listen_dttransport(void *_s)
{
	int err;
	struct dtraced_state *s = (struct dtraced_state *)_s;
	dtt_entry_t e;
	uintptr_t aux1, aux2;

	err = 0;

	LOCK(&s->inbounddir->dirmtx);
	dirlen = strlen(s->inbounddir->dirpath);
	UNLOCK(&s->inbounddir->dirmtx);

	while (atomic_load(&s->shutdown) == 0) {
		if (read(s->dtt_fd, &e, sizeof(e)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			ERR("%d: %s(): Failed to read an entry: %m", __LINE__,
			    __func__);
			continue;
		}

		switch (e.event_kind) {
		case DTT_ELF:
			dtt_elf(s, &e);
			break;

		case DTT_KILL:
			dtt_kill(s, &e);
			break;

		case DTT_CLEANUP_DTRACED:
			dtt_cleanup(s, &e);
			break;

		default:
			ERR("%d: %s(): got unknown event (%d) from dttransport",
			    __LINE__, __func__, e.event_kind);
			break;
		}
	}

	pthread_exit(s);
}

void *
write_dttransport(void *_s)
{
	ssize_t rval;
	__cleanup(closefd_generic) int sockfd = -1;
	struct dtraced_state *s = (struct dtraced_state *)_s;
	dtt_entry_t e;
	size_t lentoread, len, totallen;
	uint32_t identifier;
	dtraced_hdr_t header;
	ssize_t r;
	uintptr_t msg_ptr;
	unsigned char *msg;

	rval = 0;
	lentoread = len = totallen = 0;

	sockfd = setup_connection(s);
	if (sockfd == -1)
		pthread_exit(NULL);

	while (atomic_load(&s->shutdown) == 0) {
		if ((rval = recv(sockfd, &header, DTRACED_MSGHDRSIZE, 0)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			ERR("%d: %s(): Failed to recv from sub.sock: %m",
			    __LINE__, __func__);
			continue;
		}

		if (DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF) {
			ERR("%d: %s(): Received unknown message type: %lu",
			    __LINE__, __func__, DTRACED_MSG_TYPE(header));
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		len = DTRACED_MSG_LEN(header);
		msg = malloc(len);
		if (msg == NULL) {
			ERR("%d: %s(): Failed to allocate a new message: %m",
			    __LINE__, __func__);
			abort();
		}

		totallen = len;
		identifier = arc4random();
		msg_ptr = (uintptr_t)msg;
		while ((r = recv(sockfd, (void *)msg_ptr, len, 0)) != len) {
			if (r < 0) {
				if (errno == EINTR)
					pthread_exit(s);

				ERR("%d: %s(): Exiting write_dttransport(): %m",
				    __LINE__, __func__);
				atomic_store(&s->shutdown, 1);
				pthread_exit(NULL);
			}

			len -= r;
			msg_ptr += r;
		}


		msg_ptr = (uintptr_t)msg;
		len = totallen;

		while (len != 0) {
			memset(&e, 0, sizeof(e));
			lentoread = len > DTT_MAXDATALEN ? DTT_MAXDATALEN : len;

			e.event_kind = DTT_ELF;
			e.u.elf.identifier = identifier;
			e.u.elf.hasmore = len > DTT_MAXDATALEN ? 1 : 0;
			e.u.elf.len = lentoread;
			e.u.elf.totallen = totallen;
			memcpy(e.u.elf.data, msg, lentoread);

			if (write(s->dtt_fd, &e, sizeof(e)) < 0) {
				if (errno == EINTR)
					pthread_exit(s);
				/*
				 * If we don't have dttransport opened,
				 * we just move on. It might get opened
				 * at some point.
				 */
				continue;
			}

			len -= lentoread;
			msg += lentoread;

			assert(len >= 0 && len < totallen);
			assert((uintptr_t)msg >= msg_ptr);
			assert((uintptr_t)msg <= (msg_ptr + totallen));
		}
		assert(len == 0);

		free((void *)msg_ptr);
	}

	pthread_exit(s);
}
