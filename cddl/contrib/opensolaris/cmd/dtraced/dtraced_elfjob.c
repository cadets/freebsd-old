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
#include <openssl/sha.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_elfjob.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

void
handle_elfwrite(struct dtraced_state *s, struct dtraced_job *curjob)
{
	int fd, _nosha;
	ssize_t r;
	__cleanup(closefd_generic) int elffd = -1;
	__cleanup(freep) char *path = NULL;
	__cleanup(freep) unsigned char *msg = NULL;
	unsigned char *contents;
	size_t pathlen, elflen, msglen;
	dtraced_hdr_t header;
	dtd_dir_t *dir;
	__cleanup(releasefd) dtraced_fd_t *dfd = curjob->connsockfd;
	struct stat stat;

	fd = dfd->fd;
	path = curjob->j.notify_elfwrite.path;
	pathlen = curjob->j.notify_elfwrite.pathlen;
	dir = curjob->j.notify_elfwrite.dir;
	_nosha = curjob->j.notify_elfwrite.nosha;

	DEBUG("%d: %s(): %s%s to %d", __LINE__, __func__, dir->dirpath, path,
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
		ERR("%d: %s(): Failed to open %s: %m", __LINE__, __func__,
		    path);
		return;
	}

	if (fstat(elffd, &stat) != 0) {
		ERR("%d: %s(): Failed to fstat %s: %m", __LINE__, __func__,
		    path);
		return;
	}

	elflen = stat.st_size;
	msglen = _nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
	msg = malloc(msglen);
	if (msg == NULL) {
		ERR("%d: %s(): Failed to malloc msg: %m", __LINE__, __func__);
		abort();
	}

	DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
	DTRACED_MSG_LEN(header) = msglen;

	memset(msg, 0, msglen);
	contents = _nosha ? msg : msg + SHA256_DIGEST_LENGTH;

	if ((r = read(elffd, contents, elflen)) < 0) {
		ERR("%d: %s(): Failed to read ELF contents: %m", __LINE__,
		    __func__);
		return;
	}

	if (_nosha == 0 && SHA256(contents, elflen, msg) == NULL) {
		ERR("%d: %s(): Failed to create a SHA256 of the file", __LINE__,
		    __func__);
		return;
	}

	if (send(fd, &header, DTRACED_MSGHDRSIZE, 0) < 0) {
		ERR("%d: %s(): Failed to write to %d (%s, %zu): %m", __LINE__,
		    __func__, fd, path, pathlen);
		return;
	}

	if ((r = send(fd, msg, msglen, 0)) < 0) {
		ERR("%d: %s(): Failed to write to %d (%s, %zu): %m", __LINE__,
		    __func__, fd, path, pathlen);
		return;
	}

	DEBUG("%d: %s(): Re-enabling %d", __LINE__, __func__, fd);
	if (reenable_fd(s->kq_hdl, fd, EVFILT_WRITE))
		ERR("%d: %s(): reenable_fd() failed with: %m", __LINE__,
		    __func__);
}
