/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
 * All rights reserved.
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
 *
 * $FreeBSD$
 */

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <sysexits.h>
#include <err.h>
#include <syslog.h>
#include <dtdaemon.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif

#include "dthyve.h"

static int sockfd	= -1;
static int dirfd	= -1;

/*
 * Open the vtdtr device in order to set up the state.
 */
int
dthyve_init(void)
{
	int error;
	size_t l;
	int kind;
	struct sockaddr_un addr;

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1)
		return (-1);

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTDAEMON_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		sockfd = -1;
		return (-1);
	}

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		sockfd = -1;
		return (-1);
	}

	if (recv(sockfd, &kind, sizeof(kind), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %s",
		    strerror(errno));
		return (-1);
	}

	if (kind != DTDAEMON_KIND_DTDAEMON) {
		fprintf(stderr, "Expected dtdaemon kind, got %zu\n", kind);
		close(sockfd);
		return (-1);
	}

	kind = DTDAEMON_KIND_FORWARDER;
	if (send(sockfd, &kind, sizeof(kind), 0) < 0) {
		fprintf(stderr, "Failed to write %zu to sockfd: %s",
		    kind, strerror(errno));
		return (-1);
	}

	dirfd = open("/var/ddtrace/inbound", O_DIRECTORY, 0600);
	if (dirfd == -1)
		fprintf(stderr, "Failed to open /var/ddtrace/inbound: %m");
	
	return (0);
}

/*
 * If we have the file-descriptor, we also have at least the
 * default configuration of the device. Thus, it is sufficient
 * to simply check if the fd is not -1.
 */
int
dthyve_configured(void)
{

	return (sockfd != -1);
}

/*
 * Read events from the device. This may or may not be a blocking
 * read, depending on the configuration of vtdtr.
 */
int
dthyve_read(void **buf, size_t *len)
{
	int rval;
	/*
	 * Buffer used for reading data in bit by bit.
	 */
	if (buf == NULL) {
		fprintf(stderr, "dthyve: buf is NULL\n");
		return (-1);
	}

	if (sockfd == -1) {
		fprintf(stderr, "dthyve: sockfd has not been initialised\n");
		return (-1);
	}

	if ((rval = recv(sockfd, len, sizeof(size_t), 0)) < 0) {
		fprintf(stderr, "Failed to recv from sub.sock: %s\n",
		    strerror(errno));
		return (-1);
	}

	if (rval == 0) {
		fprintf(stderr, "dthyve: received 0 bytes from %d\n", sockfd);
		close(sockfd);
		sockfd = -1;
		return (-1);
	}


	*buf = malloc(*len);
	if (*buf == NULL) {
		fprintf(stderr, "dthyve: failed to malloc buf\n");
		return (-1);
	}
	
	memset(*buf, 0, *len);

	if ((rval = recv(sockfd, *buf, *len, 0)) < 0) {
		fprintf(stderr, "Failed to recv from sub.sock: %s\n",
		    strerror(errno));
		return (-1);
	}

	if (rval == 0) {
		fprintf(stderr, "dthyve: received 0 bytes from %d\n", sockfd);
		close(sockfd);
		sockfd = -1;
		return (-1);
	}

	return (0);
}

void
dthyve_destroy()
{

	close(sockfd);
}

int
dthyve_newelf(char *name)
{

	return (openat(dirfd, name, O_CREAT | O_WRONLY, 0600));
}

int
dthyve_rename(char *n1, char *n2)
{

	return (renameat(dirfd, n1, dirfd, n2));
}

int
dthyve_access(char *path)
{

	return (faccessat(dirfd, path, F_OK, 0));
}

