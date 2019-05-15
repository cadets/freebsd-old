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

#ifndef _DL_RECORD_HEADER_H
#define _DL_RECORD_HEADER_H

#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/types.h>

#include "dl_bbuf.h"

struct dl_record_header {
	STAILQ_ENTRY(dl_record_header) dlrh_entries;
	struct sbuf *dlrh_key;
	unsigned char const *dlrh_value;
	int32_t dlrh_key_len;
	int32_t dlrh_value_len;
};

extern int dl_record_header_new(struct dl_record_header **,
    char *, unsigned char *, int32_t);
extern void dl_record_header_delete(struct dl_record_header *);

extern int dl_record_header_decode(struct dl_record_header **,
    struct dl_bbuf *);
extern int dl_record_header_encode(struct dl_record_header const *,
    struct dl_bbuf **);
extern int dl_record_header_encode_into(struct dl_record_header const *,
    struct dl_bbuf *);

extern struct sbuf * dl_record_header_get_key(struct dl_record_header *);
extern unsigned char const * dl_record_header_get_value(
    struct dl_record_header *);

#endif
