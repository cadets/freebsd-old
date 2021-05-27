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

#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef WITHOUT_CAPSICUM
#include <sys/capsicum.h>
#endif

#include <assert.h>
#include <dtdaemon.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#ifndef WITHOUT_CAPSICUM
#include <capsicum_helpers.h>
#endif

#include "dthyve.h"

static int rx_sockfd = -1;
static int wx_sockfd = -1;
static int dirfd = -1;

static int
dtdaemon_sockinit(uint64_t subs)
{
	size_t l;
	struct sockaddr_un addr;
	dtd_initmsg_t initmsg;
	int sock;

	memset(&initmsg, 0, sizeof(initmsg));
	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "socket() failed with: %s\n", strerror(errno));
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTDAEMON_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		fprintf(stderr,
		    "attempting to copy %s failed (need %zu bytes)\n",
		    DTDAEMON_SOCKPATH, l);
		return (-1);
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "connect() failed with: %s\n", strerror(errno));
		return (-1);
	}

	if (recv(sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "read() initmsg failed with: %s",
		    strerror(errno));
		close(sock);
		return (-1);
	}

	if (initmsg.kind != DTDAEMON_KIND_DTDAEMON) {
		fprintf(stderr, "Expected dtdaemon kind, got %d\n",
		    initmsg.kind);
		close(sock);
		return (-1);
	}

	initmsg.kind = DTDAEMON_KIND_FORWARDER;
	initmsg.subs = subs;
	if (send(sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "write() initmsg failed with: %s",
		    strerror(errno));
		close(sock);
		return (-1);
	}

	return (sock);
}

/*
 * Open the vtdtr device in order to set up the state.
 */
int
dthyve_init(void)
{
	rx_sockfd = dtdaemon_sockinit(DTD_SUB_ELFWRITE);
	if (rx_sockfd == -1)
		fprintf(stderr, "failed to init rx_socktfd\n");

	wx_sockfd = dtdaemon_sockinit(DTD_SUB_READDATA);
	if (wx_sockfd == -1)
		fprintf(stderr, "failed to init wx_socktfd\n");

	dirfd = open("/var/ddtrace/inbound", O_DIRECTORY, 0600);
	if (dirfd == -1)
		fprintf(stderr, "Failed to open /var/ddtrace/inbound: %s",
		    strerror(errno));

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

	return (rx_sockfd != -1 && wx_sockfd != -1);
}

/*
 * Read events from the device. This may or may not be a blocking
 * read, depending on the configuration of vtdtr.
 */
int
dthyve_read(void **buf, size_t *len)
{
	ssize_t rval;
	void *curpos;
	size_t nbytes;

	if (buf == NULL) {
		fprintf(stderr, "dthyve: buf is NULL\n");
		return (-1);
	}

	if (rx_sockfd == -1) {
		fprintf(stderr, "dthyve: rx_sockfd has not been initialised\n");
		return (-1);
	}

	if ((rval = recv(rx_sockfd, len, sizeof(size_t), 0)) <= 0) {
		fprintf(stderr, "Failed to recv from sub.sock: %s\n",
		    strerror(errno));
		close(rx_sockfd);
		rx_sockfd = -1;
		return (-1);
	}

	assert(rval == sizeof(size_t));

	if (rval == 0) {
		fprintf(stderr, "dthyve: received 0 bytes from %d\n", rx_sockfd);
		close(rx_sockfd);
		rx_sockfd = -1;
		return (-1);
	}

	*buf = malloc(*len);
	if (*buf == NULL) {
		fprintf(stderr, "dthyve: failed to allocate buf\n");
		return (-1);
	}
	
	memset(*buf, 0, *len);

	curpos = *buf;
	nbytes = *len;
	while ((rval = recv(rx_sockfd, curpos, nbytes, 0)) != nbytes) {
		if (rval < 0) {
			fprintf(stderr, "recv() failed with: %s\n",
			    strerror(errno));
			return (-1);
		}

		assert(rval != 0);

		curpos += rval;
		nbytes -= rval;
	}

	assert(nbytes == rval);

	if (rval == 0) {
		fprintf(stderr, "dthyve: received 0 bytes from %d\n", rx_sockfd);
		close(rx_sockfd);
		rx_sockfd = -1;
		return (-1);
	}

	return (0);
}

int
dthyve_write(void *buf, size_t len)
{
	unsigned char data = 0;
	ssize_t rval;

	if (buf == NULL) {
		fprintf(stderr, "dthyve_write(): buf == NULL\n");
		return (-1);
	}

	if (wx_sockfd == -1) {
		fprintf(stderr, "wx_sock is not initialized\n");
		return (-1);
	}

	if (send(wx_sockfd, &len, sizeof(len), 0) < 0) {
		close(wx_sockfd);
		wx_sockfd = -1;
		fprintf(stderr, "send() failed with: %s\n", strerror(errno));
		return (-1);
	}

	if ((rval = send(wx_sockfd, buf, len, 0)) < 0) {
		close(wx_sockfd);
		wx_sockfd = -1;
		fprintf(stderr, "send() failed with: %s\n", strerror(errno));
		return (-1);
	}

	if (recv(wx_sockfd, &data, 1, 0) < 0) {
		close(wx_sockfd);
		wx_sockfd = -1;
		fprintf(stderr, "recv() failed with: %s\n", strerror(errno));
		return (-1);
	}

	if (data != 1) {
		close(wx_sockfd);
		fprintf(stderr, "received %02x, expected %02x\n", data, 1);
		wx_sockfd = -1;
		return (-1);
	}

	return (0);
}

void
dthyve_destroy()
{

	close(rx_sockfd);
	close(wx_sockfd);
	close(dirfd);
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

