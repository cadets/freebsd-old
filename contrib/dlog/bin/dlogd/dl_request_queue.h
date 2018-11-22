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

#ifndef _DL_REQUEST_QUEUE_H
#define _DL_REQUEST_QUEUE_H

#include <sys/queue.h>
#include <sys/types.h>

#include <stdbool.h>
#include <semaphore.h>

#include "dl_bbuf.h"

struct dl_request_element {
	STAILQ_ENTRY(dl_request_element) dlrq_entries;
	struct dl_bbuf *dlrq_buffer;
/*
struct dl_request_metadata {
	time_t dlrqm_last_sent;
	int32_t dlrqm_correlation_id;
	int16_t dlrqm_api_key;
	uint16_t dlrqm_retries;
};
*/
	time_t dlrq_last_sent;
	int32_t dlrq_correlation_id;
	int16_t dlrq_api_key;
	uint16_t dlrq_retries;
	uint8_t dlrq_max_retries;
};

STAILQ_HEAD(dl_request_queue, dl_request_element);

struct dl_request_q_stats {
	int dlrqs_capacity;
	int dlrqs_requests;
	int dlrqs_unackd;
};

struct dl_request_q {
	struct dl_request_queue dlrq_queue;
	struct dl_request_element *dlrq_requests;
	struct dl_request_q_stats *dlrq_stats;
	sem_t dlrq_request_items;
	sem_t dlrq_unackd_items;
	sem_t dlrq_spaces;
	pthread_mutex_t dlrq_mtx;
};

extern int dl_request_q_capacity(struct dl_request_q *, int *);
extern int dl_request_q_dequeue(struct dl_request_q *,
    struct dl_request_element **);
extern int dl_request_q_dequeue_unackd(struct dl_request_q *,
    struct dl_request_element **);
extern int dl_request_q_enqueue(struct dl_request_q *,
    struct dl_request_element *);
extern int dl_request_q_enqueue_new(struct dl_request_q *,
    struct dl_bbuf *, int32_t, int16_t);
extern int dl_request_q_peek(struct dl_request_q *,
    struct dl_request_element **);
extern int dl_request_q_peek_unackd(struct dl_request_q *,
    struct dl_request_element **);

extern int dl_request_q_new(struct dl_request_q **,
    struct dl_request_q_stats *, uint32_t);
extern void dl_request_q_delete(struct dl_request_q *);

extern void dl_request_q_lock(struct dl_request_q *);
extern void dl_request_q_unlock(struct dl_request_q *);

extern int dl_request_q_ack(struct dl_request_q *, int32_t,
    struct dl_request_element **);

//extern int dlrq_it_new(struct dl_request_q *);
//extern int dlrq_unackid_it_new(struct dl_request_q *);
//extern int dlrq_it_delete(struct dl_request_q *);
//extern int dlrq_it_next(struct dl_request_q *);
//extern int dlrq_it_has_next(struct dl_request_q *);

#endif
