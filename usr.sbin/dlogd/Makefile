#-
# Copyright (c) 2018 (Graeme Jenkinson)
# All rights reserved.
#
# This software was developed by BAE Systems, the University of Cambridge
# Computer Laboratory, and Memorial University under DARPA/AFRL contract
# FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
# (TC) research program.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
#

DLOGDIR= ${SRCTOP}/contrib/dlog
.PATH : ${DLOGDIR}/src ${DLOGDIR}/bin/dlogd

PROG= dlogd

DLOG_SRCS= dl_bbuf.c \
	dl_correlation_id.c \
	dl_fetch_request.c \
	dl_fetch_response.c \
	dl_index.c \
	dl_list_offset_request.c \
	dl_list_offset_response.c \
	dl_message_set.c \
	dl_offset.c \
	dl_poll_reactor.c \
	dl_primitive_types.c \
	dl_producer.c \
	dl_produce_request.c \
	dl_produce_response.c \
	dl_request.c \
	dl_request_queue.c \
	dl_response.c \
	dl_segment.c \
	dl_topic.c \
	dl_transport.c \
	dl_sock_transport.c \
	dl_tls_transport.c \
	dl_user_segment.c \
	dl_utils.c \
	lookup3.c

SRCS= dlogd.c ${DLOG_SRCS}
MAN=

CONFS= dlogd.cfg
CONFSDIR= ${CONFDIR}/dlogd
CONFSMODE= 600

LIBADD=c
LIBADD+=crypto
LIBADD+=nv
LIBADD+=pthread
LIBADD+=sbuf
LIBADD+=ssl
LIBADD+=ucl
LIBADD+=z

CFLAGS+=-DNDEBUG
CFLAGS+=-g
CFLAGS+=-Wno-incompatible-pointer-types-discards-qualifiers
CFLAGS+=-L/usr/local/lib
CFLAGS+=-I/usr/local/include
CFLAGS+=-I${DLOGDIR}/src
CFLAGS+=-I${DLOGDIR}/bin/dlogd
CFLAGS+=-I${SRCTOP}/contrib/libucl/include
CFLAGS+=-I${SRCTOP}/sys/dev/dlog

.include <bsd.prog.mk>
