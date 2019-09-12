/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#ifndef _DL_SEGMENT_H
#define _DL_SEGMENT_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/sbuf.h>

#include "dl_bbuf.h"
#include "dl_new.h"
#include "dl_offset.h"

SLIST_HEAD(dl_segments, dl_segment);

/* Number of digits in base 10 required to represent a 32-bit number. */
#define DL_LOG_DIGITS 20

struct dl_segment_class {
	struct dl_class dlr_class;
	int (* dls_get_message_by_offset)(struct dl_segment *, int,
	struct dl_bbuf **);
	int (* dls_insert_message)(struct dl_segment *, struct dl_bbuf *);
	int (* dls_sync)(struct dl_segment *);
	uint32_t (* dls_get_offset)(struct dl_segment *);
};

struct dl_segment {
	struct dl_segment_class *dls_class;
	SLIST_ENTRY(dl_segment) dls_entries;
	volatile uint64_t dls_base_offset; 	/* Start offset of the segment. */
	off_t dls_last_sync_pos;
};

extern const void *DL_SEGMENT;

extern uint64_t dl_segment_get_base_offset(struct dl_segment *);
extern void dl_segment_set_base_offset(struct dl_segment *, uint64_t);
extern off_t dl_segment_get_last_sync_pos(struct dl_segment *);
extern void dl_segment_set_last_sync_pos(struct dl_segment *, off_t);

extern int dl_segment_get_message_by_offset(void *, int,
    struct dl_bbuf **);
extern int dl_segment_get_offset(void *);
extern int dl_segment_insert_message(void *, struct dl_bbuf *);
extern int dl_segment_sync(void *);
extern int dl_segment_get_log(void *);

#endif
