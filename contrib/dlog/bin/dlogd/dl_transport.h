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

#ifndef _DL_TRANSPORT_H
#define _DL_TRANSPORT_H

#include <sys/nv.h>

#include "dl_bbuf.h"
#include "dl_event_handler.h"
#include "dl_sock_transport.h"
#include "dl_tls_transport.h"

struct dl_transport;

typedef void (* dlt_delete)(struct dl_transport *);
typedef int (* dlt_connect)(struct dl_transport *,
    const char * const, const int);
typedef int (* dlt_read_msg)(struct dl_transport *, struct dl_bbuf **);
typedef int (* dlt_send_request)(struct dl_transport *,
    struct dl_bbuf const *);
typedef int (* dlt_close)(struct dl_transport *);
typedef int (* dlt_get_fd)(struct dl_transport *);

struct dl_transport {
	dlt_delete dlt_delete_fcn;
	dlt_connect dlt_connect_fcn;
	dlt_read_msg dlt_read_msg_fcn;
	dlt_send_request dlt_send_request_fcn;
	dlt_close dlt_close_fcn;
	dlt_get_fd dlt_get_fd_fcn;
	struct dl_event_handler dlt_event_hdlr;
	struct dl_producer *dlt_producer;
	union {
		struct dl_tls_transport *dlt_tls;
		struct dl_sock_transport *dlt_sock;
	};
};

extern int dl_transport_close(struct dl_transport *);
extern int dl_transport_connect(struct dl_transport *,
    const char * const, const int);
extern void dl_transport_delete(struct dl_transport *);
extern int dl_transport_get_fd(struct dl_transport *);
extern int dl_transport_new(struct dl_transport **,
    dlt_delete, dlt_connect, dlt_read_msg, dlt_send_request, dlt_get_fd,
    struct dl_producer *);
extern int dl_transport_read_msg(struct dl_transport *, struct dl_bbuf **);
extern int dl_transport_send_request(struct dl_transport const *,
    struct dl_bbuf const *);

extern int dl_transport_factory_get_inst(struct dl_transport **,
    struct dl_producer *, nvlist_t *);

#endif
