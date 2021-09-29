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
#include <sys/stat.h>

#include <dt_list.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_elfjob.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

void
handle_elfwrite(struct dtd_state *s, struct dtd_joblist *curjob)
{
	int fd, _nosha;
	ssize_t r;
	__cleanup(closefd_generic) int elffd = -1;
	__cleanup(freep) char *path = NULL;
	__cleanup(freep) unsigned char *msg = NULL;
	unsigned char *contents, *_msg;
	size_t pathlen, elflen, msglen;
	dtraced_hdr_t header;
	dtd_dir_t *dir;
	struct dtd_fdlist *fde;
	struct stat stat;

	fd = curjob->connsockfd;
	path = curjob->j.notify_elfwrite.path;
	pathlen = curjob->j.notify_elfwrite.pathlen;
	dir = curjob->j.notify_elfwrite.dir;
	_nosha = curjob->j.notify_elfwrite.nosha;

	dump_debugmsg("    %s%s to %d", dir->dirpath, path, fd);
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
		return;
	}

	if (fstat(elffd, &stat) != 0) {
		dump_errmsg("Failed to fstat %s: %m", path);
		return;
	}

	elflen = stat.st_size;
	msglen = _nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
	msglen += DTRACED_MSGHDRSIZE;
	msg = malloc(msglen);
	if (msg == NULL) {
		dump_errmsg("failed to malloc msg: %m");
		abort();
	}

	dump_debugmsg("    Length of ELF file: %zu", elflen);
	dump_debugmsg("    Message length: %zu", msglen);

	if (msg == NULL) {
		dump_errmsg("Failed to allocate ELF contents: %m");
		return;
	}

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
	memset(msg, 0, msglen);
	memcpy(msg, &header, DTRACED_MSGHDRSIZE);

	_msg = msg + DTRACED_MSGHDRSIZE;
	contents = _nosha ? _msg : _msg + SHA256_DIGEST_LENGTH;

	if ((r = read(elffd, contents, elflen)) < 0) {
		dump_errmsg("Failed to read ELF contents: %m");
		return;
	}

	if (_nosha == 0 && SHA256(contents, elflen, _msg) == NULL) {
		dump_errmsg("Failed to create a SHA256 of the file");
		return;
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
			fde = dt_in_list(&s->sockfds, &fd, sizeof(int));
			if (fde == NULL) {
				UNLOCK(&s->socklistmtx);
				return;
			}

			dt_list_delete(&s->sockfds, fde);
			UNLOCK(&s->socklistmtx);
		} else
			dump_errmsg(
			    "Failed to write to %d (%zu): %m", fd, msglen);

		return;
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
			fde = dt_in_list(&s->sockfds, &fd, sizeof(int));
			if (fde == NULL) {
				UNLOCK(&s->socklistmtx);
				return;
			}

			dt_list_delete(&s->sockfds, fde);
			UNLOCK(&s->socklistmtx);
		} else
			dump_errmsg("Failed to write to %d "
				    "(%s, %zu): %m",
			    fd, path, pathlen);

		return;
	}

	if (reenable_fd(s->kq_hdl, fd, EVFILT_WRITE))
		dump_errmsg("process_joblist: reenable_fd() "
			    "failed with: %m");
}
