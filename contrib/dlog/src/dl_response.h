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

#ifndef _DL_RESPONSE_H
#define _DL_RESPONSE_H

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>
#endif

#include "dl_bbuf.h"
#include "dl_fetch_response.h"
#include "dl_list_offset_response.h"
#include "dl_produce_response.h"

// TODO: don't think that this is really needed
struct dl_response_header {
	int32_t dlrsh_correlation_id;
};

struct dl_response {
	union {
		struct dl_produce_response *dlrs_produce_response;
		struct dl_fetch_response *dlrs_fetch_response;
		struct dl_list_offset_response *dlrs_offset_response;
	};
	int32_t dlrs_correlation_id;
	int16_t dlrs_api_key;
};

/* Response createion/destruction API. */
extern int dl_response_new(struct dl_response **, int16_t, int32_t);
extern void dl_response_delete(struct dl_response const * const);

/* Serialization/deserialization API. */
extern int dl_response_decode(struct dl_response **,
    struct dl_bbuf const * const);
extern int32_t dl_response_encode(struct dl_response *, struct dl_bbuf **);
extern int dl_response_header_decode(struct dl_response_header **,
    struct dl_bbuf *);

#endif
