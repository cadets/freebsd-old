/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 */

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/uio.h>

#ifdef _KERNEL
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/sbuf.h>
#include <sys/proc.h>
#include <sys/kthread.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <strings.h>
#include <stddef.h>
#include <unistd.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_transport.h"
#include "dl_utils.h"

struct dl_transport {
	int dlt_fd;
};

static inline void
dl_transport_check_integrity(struct dl_transport *self)
{

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
}

int
dl_transport_new(struct dl_transport **self)
{
	struct dl_transport *transport;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
       
	transport = (struct dl_transport *) dlog_alloc(
	    sizeof(struct dl_transport));
	if (transport == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed to allocate transport instance\n");
		return -1;
	}
	bzero(transport, sizeof(struct dl_transport));
	transport->dlt_fd = -1;

	*self = transport;
	dl_transport_check_integrity(*self);
	return 0;
}

void dl_transport_delete(struct dl_transport *self)
{

	dl_transport_check_integrity(self);

	close(self->dlt_fd);
	dlog_free(self);
}

int
dl_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnumber)
{
	struct sockaddr_in dest;
	int rc;

	dl_transport_check_integrity(self);

	bzero(&dest, sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(portnumber);

	self->dlt_fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
	if (self->dlt_fd == -1)
		return -1;

	 /* TODO: MTU * maximum outstanding requests */
	int sendbuf = 100*1024*20;
	rc = setsockopt(self->dlt_fd, SOL_SOCKET, SO_SNDBUF, &sendbuf,
	    sizeof(sendbuf));
	DLOGTR1(PRIO_LOW, "setsockopt = %d\n", rc);

	if (inet_pton(AF_INET, hostname, &(dest.sin_addr)) == 0)
		return -2;

	rc = connect(self->dlt_fd, (struct sockaddr *) &dest, sizeof(dest));
	return rc;
}

int
dl_transport_read_msg(struct dl_transport *self, struct dl_bbuf **target)
{
	const unsigned char *buffer;
	int ret, total = 0;
	int32_t msg_size;
	
	dl_transport_check_integrity(self);
	DL_ASSERT(self != NULL, "Target buffer  cannot be NULL");

	/* Read the size of the request or response to process. */
	ret = recv(self->dlt_fd, &msg_size, sizeof(int32_t), 0);
	msg_size = be32toh(msg_size);
#ifdef DEBUG
	DLOGTR2(PRIO_LOW, "Read %d bytes (%d)...\n", ret, msg_size);
#endif
	if (ret == 0) {

		/* Peer has closed connection */
		return -1;
	} else if (ret > 0) {

#ifdef DEBUG
		DLOGTR1(PRIO_LOW, "\tNumber of bytes: %d\n", msg_size);
#endif

		buffer = dlog_alloc(sizeof(char) * msg_size);
		// TODO: error handling
		dl_bbuf_new(target, NULL, msg_size,
			DL_BBUF_FIXEDLEN | DL_BBUF_BIGENDIAN);

		while (total < msg_size) {
			total += ret = recv(self->dlt_fd, buffer,
				msg_size-total, 0);
			DLOGTR2(PRIO_LOW, "\tRead %d characters; expected %d\n",
			    ret, msg_size);
			dl_bbuf_bcat(*target, buffer, ret);
		}
		dlog_free(buffer);

		/* Flip the target buffer as clients are reading values
		 * from it.
		*/
		dl_bbuf_flip(*target);

		return 0;
	} else {
		return -1;
	}
}

int
dl_transport_send_request(const struct dl_transport *self,
    const struct dl_bbuf *buffer)
{
	struct iovec iov[2];
	int32_t buflen;

	dl_transport_check_integrity(self);
	DL_ASSERT(buffer != NULL, "Buffer to send cannot be NULL");

	buflen = htobe32(dl_bbuf_pos(buffer));

	iov[0].iov_base = &buflen;
	iov[0].iov_len = sizeof(int32_t);

	iov[1].iov_base = dl_bbuf_data(buffer);
	iov[1].iov_len = dl_bbuf_pos(buffer);

#ifdef DEBUG
	DLOGTR1(PRIO_LOW, "Sending request (bytes= %d)\n", iov[1].iov_len);
#endif
	return writev(self->dlt_fd, iov, 2);
}

int
dl_transport_poll(const struct dl_transport *self, int events, int timeout)
{
	struct pollfd ufd;

	dl_transport_check_integrity(self);

	ufd.fd = self->dlt_fd;
	ufd.events = events;

	return poll(&ufd, 1, timeout);
}

int
dl_transport_get_fd(struct dl_transport *self)
{
	return self->dlt_fd;
}
