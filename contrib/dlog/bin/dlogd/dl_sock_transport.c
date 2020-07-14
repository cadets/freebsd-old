/*-
 * Copyright (c) 2018-20 (Graeme Jenkinson)
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

#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <errno.h>
#include <unistd.h>
#include <netdb.h>
#include <strings.h>
#include <string.h>
#include <stddef.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_event_handler.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer_stats.h"
#include "dl_transport.h"
#include "dl_sock_transport.h"
#include "dl_utils.h"

struct dl_sock_transport {
	int dlt_fd;
};

static const int DLT_SOCK_POLL_TIMEOUT = 2000;

static inline void
dl_transport_check_integrity(struct dl_sock_transport *self)
{

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
}

static dl_event_handler_handle dl_sock_get_transport_fd(void *);
static void dl_sock_transport_hdlr(void *, int, int);

static int dl_sock_transport_connect(struct dl_transport *,
    const char * const, const int);
static void dl_sock_transport_delete(struct dl_transport *);
static int dl_sock_transport_get_fd(struct dl_transport *);
static int dl_sock_transport_read_msg(struct dl_transport *, struct dl_bbuf **);
static int dl_sock_transport_send_request(struct dl_transport *,
    struct dl_bbuf const *);

static void
dl_sock_transport_delete(struct dl_transport *self)
{

	dl_transport_check_integrity(self->dlt_sock);

	dl_poll_reactor_unregister(&self->dlt_event_hdlr);
	close(self->dlt_sock->dlt_fd);
	dlog_free(self->dlt_sock);
}

static int
dl_sock_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnum)
{
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int sock, rc, flags;

	dl_transport_check_integrity(self->dlt_sock);

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM; /* Streaming socket */
	hints.ai_flags = AI_PASSIVE;    /* For wildcard IP address */
	hints.ai_protocol = 0;          /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	/* Convert the port nunber of a string to pass
	 * into getaddrinfo().
	 */
	ssize_t n;
	n = snprintf(NULL, 0, "%d", portnum);
	
	char port[n + 1];
	snprintf(port, n + 1, "%d", portnum);

 	rc = getaddrinfo(hostname, port, &hints, &result);
	if (rc != 0) {
		
		DLOGTR1(PRIO_HIGH,
		    "getaddrinfo: %s\n", gai_strerror(rc));
		return -1;
        }

	for (rp = result; rp != NULL; rp = rp->ai_next) {
	
		sock = socket(rp->ai_family, rp->ai_socktype,
                       rp->ai_protocol);
		if (sock == -1) {

			continue;
		}

		rc = connect(sock, rp->ai_addr, rp->ai_addrlen);
		if (rc == 0 ||
		    (rc == -1 && errno == EINPROGRESS)) {

			break;
		}

               	close(sock);
	}

	if (rp == NULL) {

		DLOGTR1(PRIO_NORMAL, "Error connecting to %s\n",
		    hostname);
		return -1;
	}

	freeaddrinfo(result);

	/* Successfully connected to socket */
	self->dlt_sock->dlt_fd = sock;

	/* Register the event handler for the socket */
	self->dlt_event_hdlr.dleh_instance = self;
	self->dlt_event_hdlr.dleh_get_handle = dl_sock_get_transport_fd;
	self->dlt_event_hdlr.dleh_handle_event = dl_sock_transport_hdlr;

	dl_poll_reactor_register(&self->dlt_event_hdlr,
	    POLLERR | POLLOUT | POLLHUP);

	/* Disbale NAGLE - send small messages immediately. */
	flags = 1;
	setsockopt(self->dlt_sock->dlt_fd, IPPROTO_TCP, TCP_NODELAY,
	   (void *) &flags, sizeof(flags));

	return rc;
}

static int
dl_sock_transport_read_msg(struct dl_transport *self,
    struct dl_bbuf **target)
{
	const unsigned char *buffer;
	int32_t msg_size;
	int rc, total = 0;
	
	dl_transport_check_integrity(self->dlt_sock);
	DL_ASSERT(self != NULL, "Target buffer  cannot be NULL");

	/* Read the size of the request or response to process. */
	rc = recv(self->dlt_sock->dlt_fd, &msg_size, sizeof(int32_t), 0);
	if (rc == 0) {

		/* No data to read EOF */
		return 0;
	} else if (rc > 0) {

		msg_size = be32toh(msg_size);

		buffer = dlog_alloc(sizeof(char) * msg_size);
		if (buffer == NULL) {

			DLOGTR0(PRIO_HIGH,
			    "Error allocating buffer to store the message");
			return -1;
		}

		rc = dl_bbuf_new(target, NULL, msg_size,
			DL_BBUF_FIXEDLEN | DL_BBUF_BIGENDIAN);
		if (rc != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error allocating buffer to store the message");
			dlog_free(buffer);
			return -1;
		}

		while (total < msg_size) {

			total += rc  = recv(self->dlt_sock->dlt_fd, buffer,
				msg_size-total, 0);
			dl_bbuf_bcat(*target, buffer, rc);
		}
		dlog_free(buffer);

		/* Flip the target buffer as clients are reading values
		 * from it.
		*/
		dl_bbuf_flip(*target);

		/* Update the Producer statistics. */
		dlps_set_bytes_received(
		    dl_producer_get_stats(self->dlt_producer), msg_size);
		return msg_size;
	} else {

		/* Peer has closed connection */
		DLOGTR1(PRIO_HIGH, "Peer has closed connection (%d)", rc);
		return -1;
	}
}

static int
dl_sock_transport_send_request(struct dl_transport *self,
    const struct dl_bbuf *buffer)
{
	struct pollfd fds;
	int rc;
	unsigned char *b;
	size_t write_so_far = 0;
	ssize_t len_write;
	size_t buffer_size;
	size_t offset;
	size_t bytes_to_write;
	
	dl_transport_check_integrity(self->dlt_sock);
	DL_ASSERT(buffer != NULL, "Buffer to send cannot be NULL");

	b = dl_bbuf_data(buffer);
	buffer_size = dl_bbuf_pos(buffer);

retry_send:
	offset = (write_so_far % buffer_size);
	bytes_to_write = (buffer_size - write_so_far);

	len_write = write(self->dlt_sock->dlt_fd, b + offset, bytes_to_write); 
	if (len_write == -1 && errno != EAGAIN) {

		DLOGTR1(PRIO_LOW, "Transport send error (%d)\n", errno);
		return -1;
	}

	if (len_write > 0 && (size_t) len_write <= buffer_size)
		write_so_far += len_write;

	if (write_so_far == buffer_size) {

		/* Update the Producer statistics. */
		dlps_set_bytes_sent(
		    dl_producer_get_stats(self->dlt_producer), buffer_size);

		return write_so_far;
	}

	/* Poll on the socket until it is ready to retry. */
	fds.fd = self->dlt_sock->dlt_fd;
	fds.events = POLLOUT;
	rc = poll(&fds, 1, DLT_SOCK_POLL_TIMEOUT);
	if (rc == -1) {

		/* Socket is ready to write, retry. */
		DLOGTR1(PRIO_HIGH,
		    "Error whilst polling on socket (%d)\n", errno);
	} else if (rc == 0) {

		/* Timeout whilst waiting on socket. */
		DLOGTR0(PRIO_NORMAL,
		    "Timed out whilst attempting to resend.\n");
	} else {

		/* Socket is ready to write, retry. */
		goto retry_send;
	}

	return -1;
}

static void 
dl_sock_transport_hdlr(void *instance, int fd, int revents)
{
	struct dl_transport * const self = instance;
	struct dl_bbuf *buffer;
	socklen_t len = sizeof(int);
	int rc, err = 0;
	
	dl_transport_check_integrity(self->dlt_sock);

	if (revents & (POLLHUP | POLLERR)) {

		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (err == ECONNREFUSED) {

			DLOGTR0(PRIO_LOW, "Connection refused\n");
		}
		
		dlps_set_tcp_connect(
		    dl_producer_get_stats(self->dlt_producer), false);
		dl_producer_down(self->dlt_producer);
		return;
	}

	if (revents & POLLIN) {

		rc = dl_transport_read_msg(self, &buffer);
		if (rc == 0) {

			/* No data to read. */
		} if (rc > 0) {

			/* Process the received response. */
			if (dl_producer_response(self->dlt_producer,
			    buffer) != 0) {

				DLOGTR0(PRIO_HIGH,
				    "Error processing Response.\n");
			}

			/* Free the buffer in which the raw response was
			 * returned by the transport.
			 */
			dl_bbuf_delete(buffer);
		} else {

			/* Server disconnected. */
			dlps_set_tcp_connect(
			    dl_producer_get_stats(self->dlt_producer), false);
			dl_producer_down(self->dlt_producer);
			return;

		}
	}

	if (revents & POLLOUT) {

		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (rc == 0) {
			if (err == 0) {
				DLOGTR0(PRIO_LOW, "TCP Connected\n");
				dlps_set_tcp_connect(
				    dl_producer_get_stats(self->dlt_producer), true);

				/* Re-register the handler to trigger
				* when data is read to read
				* to when HANGUP or ERR is detected.
				*/
				dl_poll_reactor_unregister(
					&self->dlt_event_hdlr);
				dl_poll_reactor_register(
					&self->dlt_event_hdlr,
					POLLIN|POLLHUP|POLLERR);

				dl_producer_up(self->dlt_producer);
			} 
		} else {
			dlps_set_tcp_connect(
			    dl_producer_get_stats(self->dlt_producer), false);
			dl_producer_down(self->dlt_producer);
		}
	}
}

static dl_event_handler_handle
dl_sock_get_transport_fd(void *instance)
{
	struct dl_transport const * const self = instance;

	dl_transport_check_integrity(self->dlt_sock);
	return dl_transport_get_fd(self);
}

static int
dl_sock_transport_get_fd(struct dl_transport *self)
{

	dl_transport_check_integrity(self->dlt_sock);
	return self->dlt_sock->dlt_fd;
}

int
dl_sock_transport_new(struct dl_transport **self,
    struct dl_producer *producer)
{
	struct dl_sock_transport *sock;
	struct dl_transport *transport;
	int rc;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
	DL_ASSERT(producer != NULL, ("Producer instance cannot be NULL"));
        
       	rc = dl_transport_new(&transport, dl_sock_transport_delete,
	    dl_sock_transport_connect, dl_sock_transport_read_msg,
	    dl_sock_transport_send_request, dl_sock_transport_get_fd,
	    producer);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to instatiate TlsTransport super class\n");
		goto err_sock_ctor;
	}

	transport->dlt_sock = sock = (struct dl_sock_transport *) dlog_alloc(
	    sizeof(struct dl_sock_transport));
	if (transport == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed to allocate transport instance\n");
		return -1;
	}
	bzero(sock, sizeof(struct dl_sock_transport));
	sock->dlt_fd = -1;

	dl_transport_check_integrity(sock);
	*self = transport;
	return 0;

err_sock_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating TlsTransport instance\n");
	*self = NULL;
	return -1;
}

