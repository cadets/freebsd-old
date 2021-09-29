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
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_directory.h"
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

	if (ev->filter == EVFILT_READ) {
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
		job->connsockfd = ev->ident;

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
	int err;
	int _nosha;
	int fd;
	int elffd;
	int i;
	char *path;
	char *contents, *msg, *_msg;
	size_t msglen;
	size_t pathlen;
	size_t elflen;
	struct dtd_joblist *curjob;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtd_dir_t *dir;
	ssize_t r;
	pid_t pid;
	struct stat stat;
	unsigned char *buf, *_buf;
	size_t nbytes, totalbytes;
	dtraced_hdr_t header;
	struct dtd_joblist *job;
	uint16_t vmid;
	const char *jobname[] = {
		[0]               = "NONE",
		[NOTIFY_ELFWRITE] = "NOTIFY_ELFWRITE",
		[KILL]            = "KILL",
		[READ_DATA]       = "READ_DATA"
	};

	_nosha = s->nosha;
	dir = NULL;
	memset(&stat, 0, sizeof(stat));

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
			fd = curjob->connsockfd;
			path = curjob->j.notify_elfwrite.path;
			pathlen = curjob->j.notify_elfwrite.pathlen;
			dir = curjob->j.notify_elfwrite.dir;
			_nosha = curjob->j.notify_elfwrite.nosha;

			dump_debugmsg("    %s%s to %d", dir->dirpath, path,
			    fd);
			/*
			 * Sanity assertions.
			 */
			assert(fd != -1);
			assert(path != NULL);
			assert(pathlen <= MAXPATHLEN);

			assert(dir->dirfd != -1);

			elffd = openat(dir->dirfd, path, O_RDONLY);
			if (elffd == -1) {
				dump_errmsg("Failed to open %s: %m", path);
				free(path);
				break;
			}

			if (fstat(elffd, &stat) != 0) {
				dump_errmsg("Failed to fstat %s: %m", path);
				free(path);
				close(elffd);
				break;
			}

			elflen = stat.st_size;
			msglen =
			    _nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
			msglen += DTRACED_MSGHDRSIZE;
			msg = malloc(msglen);
			if (msg == NULL) {
				dump_errmsg("failed to malloc msg: %m");
				abort();
			}

			dump_debugmsg("    Length of ELF file: %zu",
			    elflen);
			dump_debugmsg("    Message length: %zu", msglen);

			if (msg == NULL) {
				dump_errmsg(
				    "Failed to allocate ELF contents: %m");
				free(path);
				close(elffd);
				break;
			}

			DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
			memset(msg, 0, msglen);
			memcpy(msg, &header, DTRACED_MSGHDRSIZE);

			_msg = msg + DTRACED_MSGHDRSIZE;
			contents = _nosha ? _msg : _msg + SHA256_DIGEST_LENGTH;

			if ((r = read(elffd, contents, elflen)) < 0) {
				dump_errmsg("Failed to read ELF contents: %m");
				free(path);
				free(msg);
				close(elffd);
				break;
			}

			if (_nosha == 0 &&
			    SHA256(contents, elflen, _msg) == NULL) {
				dump_errmsg(
				    "Failed to create a SHA256 of the file");
				free(path);
				free(msg);
				close(elffd);
				break;
			}

			if (send(fd, &msglen, sizeof(msglen), 0) < 0) {
				if (errno == EPIPE) {
					/*
					 * Get the entry from a socket list to
					 * delete it. This is a bit "slow", but
					 * should be happening rarely enough
					 * that we don't really care. A small
					 * delay here is acceptable, as most
					 * consumers of this event will open the
					 * path sent to them and process the ELF
					 * file.
					 */
					LOCK(&s->socklistmtx);
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto elfcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					dump_errmsg(
					    "Failed to write to %d (%zu): %m",
					    fd, msglen);

				goto elfcleanup;
			}

			if ((r = send(fd, msg, msglen, 0)) < 0) {
				if (errno == EPIPE) {
					/*
					 * Get the entry from a socket list to
					 * delete it. This is a bit "slow", but
					 * should be happening rarely enough
					 * that we don't really care. A small
					 * delay here is acceptable, as most
					 * consumers of this event will open the
					 * path sent to them and process the ELF
					 * file.
					 */
					LOCK(&s->socklistmtx);
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto elfcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					dump_errmsg("Failed to write to %d "
						    "(%s, %zu): %m",
					    fd, path, pathlen);

				goto elfcleanup;
			}

			if (reenable_fd(s, fd, EVFILT_WRITE))
				dump_errmsg("process_joblist: reenable_fd() "
					    "failed with: %m");

elfcleanup:
			free(path);
			free(msg);
			close(elffd);
			break;

		default:
			dump_errmsg("Unknown job: %d", curjob->job);
			pthread_exit(NULL);
		}

done:
		free(curjob);
	}

	pthread_exit(s);
}

