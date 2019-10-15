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

#ifndef _DL_TOPIC_H
#define _DL_TOPIC_H

#include <sys/types.h>
#include <sys/dnv.h>
#include <sys/sbuf.h>

#include <dev/dlog/dlog.h>

#include "dl_bbuf.h"
#include "dl_segment.h"

struct dl_topic;
struct dl_topic_hashmap;

typedef void (*dl_topic_callback)(struct dl_topic *, void *);

extern void dl_topic_delete(struct dl_topic *);
extern int dl_topic_new(struct dl_topic **, char *,
    nvlist_t *, struct dl_segment *);
extern int dl_topic_as_desc(struct dl_topic *, struct dl_topic_desc **);
extern int dl_topic_from_desc(struct dl_topic **, struct dl_topic_desc *);

extern bool dl_topic_validate_name(char const * const);
extern char *dl_topic_get_name(struct dl_topic *);
extern struct dl_segment *dl_topic_get_active_segment(struct dl_topic *);
extern void dl_topic_set_active_segment(struct dl_topic *, struct dl_segment *);
extern int dl_topic_produce_record_to(struct dl_topic *, char *,
    unsigned char *, size_t); 
extern int dl_topic_get_message_by_offset(struct dl_topic *, struct dl_bbuf **);

extern void dl_topic_hashmap_clear(struct dl_topic_hashmap *);
extern void dl_topic_hashmap_delete(struct dl_topic_hashmap *);
extern void dl_topic_hashmap_foreach(struct dl_topic_hashmap *, dl_topic_callback, void *);
extern int dl_topic_hashmap_get(struct dl_topic_hashmap *, char const * const, struct dl_topic **);
extern int dl_topic_hashmap_put(struct dl_topic_hashmap *, char *, struct dl_topic *);
extern int dl_topic_hashmap_put_if_absent(struct dl_topic_hashmap *, char *, struct dl_topic *);
extern int dl_topic_hashmap_new(struct dl_topic_hashmap **, size_t);
extern int dl_topic_hashmap_remove(struct dl_topic_hashmap *, char *);

#endif
