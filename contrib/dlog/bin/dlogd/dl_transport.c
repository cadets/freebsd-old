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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <strings.h>
#include <stddef.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_config.h"
#include "dl_primitive_types.h"
#include "dl_memory.h"
#include "dl_transport.h"
#include "dl_utils.h"

extern int dl_transport_new(struct dl_transport **, dlt_delete, dlt_connect,
    dlt_read_msg, dlt_send_request, dlt_get_fd, struct dl_producer *);

static inline void
dl_transport_check_integrity(const char *func __attribute((unused)),
    struct dl_transport *self)
{

	DL_ASSERT(self != NULL,
	    ("%s: Transport instance cannot be NULL", func));
	DL_ASSERT(self->dlt_delete_fcn != NULL,
	    ("%s: Transport instance delete() method cannot be NULL", func));
	DL_ASSERT(self->dlt_connect_fcn != NULL,
	    ("%s: Transport instance connect() method cannot be NULL", func));
	DL_ASSERT(self->dlt_read_msg_fcn != NULL,
	    ("%s: Transport instance read_msg() method cannot be NULL", func));
	DL_ASSERT(self->dlt_send_request_fcn != NULL,
	    ("%s: Transport instance send_request() method cannot be NULL", func));
	//DL_ASSERT(self->dlt_close_fcn != NULL,
	//    ("Transport instance close() method cannot be NULL"));
	DL_ASSERT(self->dlt_get_fd_fcn != NULL,
	    ("%s: Transport instance get_fd() method cannot be NULL", func));
}

int
dl_transport_new(struct dl_transport **self,
    dlt_delete delete_fcn, dlt_connect connect_fcn,
    dlt_read_msg read_msg_fcn, dlt_send_request send_request_fcn,
    dlt_get_fd get_fd_fcn, struct dl_producer *producer)
{
	struct dl_transport *transport;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
       
	transport = (struct dl_transport *) dlog_alloc(
	    sizeof(struct dl_transport));
	if (transport == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to allocate transport instance\n");
		return -1;
	}
	bzero(transport, sizeof(struct dl_transport));
	transport->dlt_delete_fcn = delete_fcn;
	transport->dlt_connect_fcn = connect_fcn;
	transport->dlt_read_msg_fcn = read_msg_fcn;
	transport->dlt_send_request_fcn = send_request_fcn;
	transport->dlt_get_fd_fcn = get_fd_fcn;
	transport->dlt_producer = producer;

	*self = transport;
	dl_transport_check_integrity(__func__, *self);
	return 0;
}

//close

int
dl_transport_connect(struct dl_transport *self,
    const char * const hostname, const int portnumber)
{

	dl_transport_check_integrity(__func__, self);
	return self->dlt_connect_fcn(self, hostname, portnumber);
}

void
dl_transport_delete(struct dl_transport *self)
{

	dl_transport_check_integrity(__func__, self);
	return self->dlt_delete_fcn(self);
}

int
dl_transport_get_fd(struct dl_transport *self)
{

	dl_transport_check_integrity(__func__, self);
	return self->dlt_get_fd_fcn(self);
}

int
dl_transport_read_msg(struct dl_transport *self, struct dl_bbuf **target)
{
	
	dl_transport_check_integrity(__func__, self);
	DL_ASSERT(self != NULL, "Target buffer  cannot be NULL");
	return self->dlt_read_msg_fcn(self, target);
}

int
dl_transport_send_request(const struct dl_transport *self,
    const struct dl_bbuf *buffer)
{

	dl_transport_check_integrity(__func__, self);
	DL_ASSERT(buffer != NULL, "Buffer to send cannot be NULL");
	return self->dlt_send_request_fcn(self, buffer);
}

	int
dl_transport_factory_get_inst(struct dl_transport **self,
    struct dl_producer *producer, nvlist_t *props)
{
	bool tls;

	DL_ASSERT(self != NULL, ("Transport instance cannot be NULL"));
	DL_ASSERT(props != NULL, ("Properties instance cannot be NULL"));

	if (nvlist_exists_bool(props, DL_CONF_TLS_ENABLE)) {
		tls = nvlist_get_bool(props, DL_CONF_TLS_ENABLE);
	} else {
		tls = DL_DEFAULT_TLS_ENABLE;
	}

	if (tls) {
		return dl_tls_transport_new(self, producer, props);
	} else {
		return dl_sock_transport_new(self, producer);
	}
}
