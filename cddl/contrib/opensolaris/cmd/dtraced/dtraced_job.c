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
#include "dtraced_lock.h"
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
	size_t nbytes, totalbytes, n_entries;
	dtraced_hdr_t header;
	struct kevent change_event[1];
	unsigned char ack = 1;
	struct dtd_joblist *job;
	struct dtd_fdlist *fd_list;
	identlist_t *newident;
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
			fd = curjob->connsockfd;
			nbytes = 0;
			totalbytes = 0;

			if ((r =
			    recv(fd, &totalbytes, sizeof(totalbytes), 0)) < 0) {
				dump_errmsg("recv() failed with: %m");
				break;
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
					free(buf);
					buf = NULL;
					break;
				}

				assert(r != 0);

				_buf += r;
				nbytes -= r;
			}

			ack = 1;
			if (send(fd, &ack, 1, 0) < 0) {
				dump_errmsg("send() failed with: %m");
				if (buf)
					free(buf);
				break;
			}

			/*
			 * We are done receiving the data and nothing failed,
			 * re-enable the event and keep going.
			 */
			EV_SET(change_event, fd, EVFILT_READ,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL)) {
				dump_errmsg("kevent() failed with: %m");
				free(buf);
				break;
			}

			if (r < 0) {
				if (buf)
					free(buf);
				break;
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
				dump_debugmsg("        ELF file");

				if (strcmp(
				    DTRACED_MSG_LOC(header), "base") == 0)
					dir = s->basedir;
				else if (strcmp(
				    DTRACED_MSG_LOC(header), "outbound") == 0)
					dir = s->outbounddir;
				else if (strcmp(
				    DTRACED_MSG_LOC(header), "inbound") == 0)
					dir = s->inbounddir;
				else
					dir = NULL;

				if (dir == NULL) {
					dump_errmsg(
					    "unrecognized location: %s",
					    DTRACED_MSG_LOC(header));

					free(buf);
					pthread_exit(NULL);
				}

				if (s->ctrlmachine == 0) {
					newident = malloc(sizeof(identlist_t));
					if (newident == NULL) {
						dump_errmsg(
						    "Failed to allocate new"
						    " identifier: %m");
						abort();
					}

					if (DTRACED_MSG_IDENT_PRESENT(header)) {
						memcpy(newident->ident,
						    DTRACED_MSG_IDENT(header),
						    DTRACED_PROGIDENTLEN);

						LOCK(&s->identlistmtx);
						dt_list_append(&s->identlist,
						    newident);
						UNLOCK(&s->identlistmtx);
					}
				}

				if (write_data(dir, _buf, nbytes))
					dump_errmsg("write_data() failed");
				break;

			case DTRACED_MSG_KILL:
				dump_debugmsg("        KILL (%d)",
				    DTRACED_MSG_KILLPID(header));
				/*
				 * We enqueue a KILL message in the joblist
				 * (another thread will simply pick this up). We
				 * need to only do it for FORWARDERs.
				 */

				LOCK(&s->socklistmtx);
				for (fd_list = dt_list_next(&s->sockfds);
				     fd_list; fd_list = dt_list_next(fd_list)) {
					if (fd_list->kind !=
					    DTRACED_KIND_FORWARDER)
						continue;

					if ((fd_list->subs & DTD_SUB_KILL) == 0)
						continue;

					job =
					    malloc(sizeof(struct dtd_joblist));
					if (job == NULL) {
						dump_errmsg(
						    "malloc() failed with: %m");
						abort();
					}

					memset(job, 0,
					    sizeof(struct dtd_joblist));

					job->job = KILL;
					job->connsockfd = fd_list->fd;
					job->j.kill.pid =
					    DTRACED_MSG_KILLPID(header);
					job->j.kill.vmid =
					    DTRACED_MSG_KILLVMID(header);

					dump_debugmsg("        kill %d to %d",
					    DTRACED_MSG_KILLPID(header),
					    fd_list->fd);

					LOCK(&s->joblistmtx);
					dt_list_append(&s->joblist, job);
					UNLOCK(&s->joblistmtx);
				}
				UNLOCK(&s->socklistmtx);
				break;

			case DTRACED_MSG_CLEANUP:
				n_entries = DTRACED_MSG_NUMENTRIES(header);
				printf("n_entries = %zu\n", n_entries);
				if (n_entries == 0) {
					// cleanup_all();
					break;
				}

				break;

			default:
				assert(0);
			}

			free(buf);
			break;
		case KILL:
			fd = curjob->connsockfd;
			pid = curjob->j.kill.pid;
			vmid = curjob->j.kill.vmid;

			dump_debugmsg("    kill pid %d to %d", pid, fd);

			assert(fd != -1);
			/*
			 * If we end up with pid <= 1, something went wrong.
			 */
			assert(pid > 1);
			msglen = DTRACED_MSGHDRSIZE;
			msg = malloc(msglen);
			if (msg == NULL) {
				dump_errmsg(
				    "Failed to allocate a kill message: %m");
				abort();
			}

			/*
			 * For now the header only includes the message kind, so
			 * we don't really make it a structure. In the future,
			 * this might change.
			 */
			DTRACED_MSG_TYPE(header) = DTRACED_MSG_KILL;
			DTRACED_MSG_KILLPID(header) = pid;
			DTRACED_MSG_KILLVMID(header) = vmid;
			
			memcpy(msg, &header, DTRACED_MSGHDRSIZE);

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
						goto killcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					dump_errmsg(
					    "Failed to write to %d (%zu): %m",
					    fd, msglen);

				goto killcleanup;
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
						goto killcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					dump_errmsg("Failed to write to %d: %m",
					    fd);

				goto killcleanup;
			}

			EV_SET(change_event, fd, EVFILT_WRITE,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL)) {
				dump_errmsg("process_joblist: kevent() "
					    "failed with: %m");
				free(msg);
				break;
			}

killcleanup:
			free(msg);
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

			EV_SET(change_event, fd, EVFILT_WRITE,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL))
				dump_errmsg("process_joblist: kevent() "
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

		free(curjob);
	}

	pthread_exit(s);
}

