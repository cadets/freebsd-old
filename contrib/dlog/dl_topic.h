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

#ifndef _DL_BROKER_TOPIC_H
#define _DL_BROKER_TOPIC_H

#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/types.h>

#include "dl_bbuf.h"
#include "dl_protocol.h"
#include "dl_request_queue.h"
#include "dl_segment.h"

struct dl_topic;

LIST_HEAD(dl_topics, dl_topic);

struct dl_topic {
	LIST_ENTRY(dl_topic) dlt_entries;
	u_int64_t dlt_offset; /* Current position in the log. */
	//u_int32_t dlp_offset; /* Relative offset into the log's active segment. */
	struct sbuf *dlt_name;
	struct dl_segments dlp_segments;
	struct dl_segment *dlp_active_segment;
};

struct dl_topic_desc {
	struct dl_segment_desc dltd_active_seg;
	char *dltd_name;
};

extern void dl_topic_delete(struct dl_topic *);
extern int dl_topic_new(struct dl_topic **, char *);
extern int dl_topic_as_desc(struct dl_topic *, struct dl_topic_desc **);
extern int dl_topic_from_desc(struct dl_topic **, struct sbuf *,
    struct dl_segment_desc *);

extern struct sbuf *dl_topic_get_name(struct dl_topic *);
extern struct dl_segment *dl_topic_get_active_segment(struct dl_topic *);

extern void dl_topic_hashmap_delete(void *);
extern void * dl_topic_hashmap_new(int, unsigned long *);
extern int dl_topic_hashmap_get(char const * const, struct dl_topic **);
extern int dl_topic_hashmap_put(void *, struct dl_topic *);

extern int dl_topic_produce_to(struct dl_topic *, struct dl_bbuf *); 

extern unsigned long topic_hashmask;
extern struct dl_topics *topic_hashmap;

#endif
