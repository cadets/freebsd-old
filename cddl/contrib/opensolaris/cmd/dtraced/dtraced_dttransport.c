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
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_chld.h"
#include "dtraced_directory.h"
#include "dtraced_dttransport.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

/*
 * Runs in its own thread. Reads ELF files from dttransport and puts them in
 * the inbound directory.
 */
void *
listen_dttransport(void *_s)
{
	int err;
	int fd;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtt_entry_t e;
	char *path = NULL;
	char *elf = NULL;
	size_t len, offs;
	char donepath[MAXPATHLEN] = { 0 };
	uintptr_t aux1, aux2;
	size_t dirlen;
	size_t donepathlen;
	pidlist_t *kill_entry;

	err = 0;
	fd = 0;
	offs = len = 0;
	
	memset(&e, 0, sizeof(e));

	LOCK(&s->inbounddir->dirmtx);
	dirlen = strlen(s->inbounddir->dirpath);
	UNLOCK(&s->inbounddir->dirmtx);

	while (atomic_load(&s->shutdown) == 0) {
		if (read(s->dtt_fd, &e, sizeof(e)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			dump_errmsg("Failed to read an entry: %m");
			continue;
		}

		switch (e.event_kind) {
		case DTT_ELF:
			if (fd == -1)
				continue;

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
					dump_errmsg(
					    "gen_filename() failed with %s",
					    strerror(errno));
					goto retry;
				}
				fd = open(path, O_CREAT | O_WRONLY, 0600);

				if (fd == -1) {
					dump_errmsg("Failed to open %s: %m",
					    path);
					continue;
				}

				elf = malloc(e.u.elf.totallen);
				if (elf == NULL) {
					dump_errmsg("failed to malloc elf: %m");
					abort();
				}

				memset(elf, 0, e.u.elf.totallen);
				len = e.u.elf.totallen;
			}

			assert(offs < len);
			memcpy(elf + offs, e.u.elf.data, e.u.elf.len);
			offs += e.u.elf.len;

			if (e.u.elf.hasmore == 0) {
				if (write(fd, elf, len) < 0) {
					if (errno == EINTR)
						pthread_exit(s);

					dump_errmsg(
					    "Failed to write data to %s: %m",
					    path);
				}

				donepathlen = strlen(path) - 1;
				assert(donepathlen < MAXPATHLEN);
				memset(donepath, 0, donepathlen);
				memcpy(donepath, path, dirlen);
				memcpy(donepath + dirlen, path + dirlen + 1,
				    donepathlen - dirlen);

				if (rename(path, donepath)) {
					dump_errmsg(
					    "Failed to move %s to %s: %m", path,
					    donepath);
				}

				len = 0;
				offs = 0;
				free(elf);
				close(fd);
				free(path);
				donepathlen = 0;
				fd = 0;
				path = NULL;
			}
			break;
		case DTT_KILL:
			kill_entry = malloc(sizeof(pidlist_t));
			if (kill_entry == NULL) {
				dump_errmsg("failed to malloc kill_entry: %m");
				abort();
			}

			kill_entry->pid = e.u.kill.pid;
			LOCK(&s->kill_listmtx);
			dt_list_append(&s->kill_list, kill_entry);
			UNLOCK(&s->kill_listmtx);

			LOCK(&s->killcvmtx);
			SIGNAL(&s->killcv);
			UNLOCK(&s->killcvmtx);

			break;

		default:
			dump_errmsg("got unknown event (%d) from dttransport",
			    e.event_kind);
			break;
		}
	}

	pthread_exit(s);
}

void *
write_dttransport(void *_s)
{
	ssize_t rval;
	int sockfd;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtt_entry_t e;
	size_t l, lentoread, len, totallen;
	struct sockaddr_un addr;
	dtd_initmsg_t initmsg;
	uint32_t identifier;
	dtraced_hdr_t header;
	ssize_t r;
	uintptr_t msg_ptr;
	unsigned char *msg;

	rval = 0;
	sockfd = 0;
	l = lentoread = len = totallen = 0;
	memset(&initmsg, 0, sizeof(initmsg));

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		dump_errmsg("Failed creating a socket: %m");
		pthread_exit(NULL);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		dump_errmsg("Failed setting addr.sun_path"
		    " to /var/ddtrace/sub.sock");
		sockfd = -1;
		pthread_exit(NULL);
	}

	SEMWAIT(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		dump_errmsg("connect to /var/ddtrace/sub.sock failed: %m");
		sockfd = -1;
		pthread_exit(NULL);
	}

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		pthread_exit(NULL);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		dump_errmsg("Expected dtraced kind, got %d",
		    initmsg.kind);
		close(sockfd);
		pthread_exit(NULL);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		dump_errmsg("Failed to write initmsg to sockfd: %m");
		pthread_exit(NULL);
	}


	while (atomic_load(&s->shutdown) == 0) {
		if ((rval = recv(sockfd, &len, sizeof(size_t), 0)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			dump_errmsg("Failed to recv from sub.sock: %m");
			continue;
		}

		msg = malloc(len);
		if (msg == NULL) {
			dump_errmsg("Failed to allocate a new message: %m");
			abort();
		}

		totallen = len;
		identifier = arc4random();
		msg_ptr = (uintptr_t)msg;
		while ((r = recv(sockfd, (void *)msg_ptr, len, 0)) != len) {
			if (r < 0) {
				atomic_store(&s->shutdown, 1);
				pthread_exit(NULL);
			}

			len -= r;
			msg_ptr += r;
		}

		memcpy(&header, msg, DTRACED_MSGHDRSIZE);
		if (DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF) {
			dump_errmsg("Received unknown message type: %lu",
			    DTRACED_MSG_TYPE(header));
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		assert(DTRACED_MSG_TYPE(header) == DTRACED_MSG_ELF);

		msg_ptr = (uintptr_t)msg;
		msg += DTRACED_MSGHDRSIZE;

		totallen -= DTRACED_MSGHDRSIZE;
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
			assert((uintptr_t)msg <=
			    (msg_ptr + totallen + DTRACED_MSGHDRSIZE));
		}

		assert(len == 0);

		free((void *)msg_ptr);
	}

	pthread_exit(s);
}

