/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#ifndef _DL_PRODUCER_STATS_H
#define _DL_PRODUCER_STATS_H

#include <sys/types.h>
#include <sys/sbuf.h>

#include <stdbool.h>

struct dl_producer_stats;

extern int dl_producer_stats_new(struct dl_producer_stats **, char *);
extern void dl_producer_stats_delete(struct dl_producer_stats *);

extern void dlps_set_rtt(struct dl_producer_stats *, int32_t);
extern void dlps_set_received_cid(struct dl_producer_stats *, int32_t);
extern void dlps_set_received_error(struct dl_producer_stats *, bool);
extern void dlps_set_received_timestamp(struct dl_producer_stats *);
extern void dlps_set_sent_cid(struct dl_producer_stats *, int32_t);
extern void dlps_set_sent_error(struct dl_producer_stats *, bool);
extern void dlps_set_sent_timestamp(struct dl_producer_stats *);
extern void dlps_set_state(struct dl_producer_stats *, int32_t state);
extern void dlps_set_topic_name(struct dl_producer_stats *, char *);
extern void dlps_set_resend(struct dl_producer_stats *, bool);
extern void dlps_set_resend_timeout(struct dl_producer_stats *, int);
extern void dlps_set_tcp_connect(struct dl_producer_stats *, bool);
extern void dlps_set_tls_connect(struct dl_producer_stats *, bool);
extern void dlps_set_bytes_sent(struct dl_producer_stats *, int32_t);
extern void dlps_set_bytes_received(struct dl_producer_stats *, int32_t);
extern void dlps_set_queue_capacity(struct dl_producer_stats *, int);
extern void dlps_set_queue_requests(struct dl_producer_stats *, int);
extern void dlps_set_queue_unackd(struct dl_producer_stats *, int);

extern int32_t dlps_get_rtt(struct dl_producer_stats *);
extern int32_t dlps_get_received_cid(struct dl_producer_stats *);
extern bool dlps_get_received_error(struct dl_producer_stats *);
extern time_t dlps_get_received_timestamp(struct dl_producer_stats *);
extern int32_t dlps_get_sent_cid(struct dl_producer_stats *);
extern bool dlps_get_sent_error(struct dl_producer_stats *);
extern time_t dlps_get_sent_timestamp(struct dl_producer_stats *);
extern int32_t dlps_get_state(struct dl_producer_stats *);
extern char * dlps_get_topic_name(struct dl_producer_stats *);
extern bool dlps_get_resend(struct dl_producer_stats *);
extern int dlps_get_resend_timeout(struct dl_producer_stats *);
extern bool dlps_get_tcp_connect(struct dl_producer_stats *);
extern bool dlps_get_tls_connect(struct dl_producer_stats *);
extern int32_t dlps_get_bytes_sent(struct dl_producer_stats *);
extern int32_t dlps_get_bytes_received(struct dl_producer_stats *);
extern int dlps_get_queue_capacity(struct dl_producer_stats *);
extern int dlps_get_queue_requests(struct dl_producer_stats *);
extern int dlps_get_queue_unackd(struct dl_producer_stats *);

#endif
