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

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_response_header.h"
#include "dl_utils.h"

struct dl_response_header {
	int32_t dlrh_correlation_id;
};

int
dl_response_header_new(struct dl_response_header **self,
    int32_t correlation_id)
{
	struct dl_response_header *header;

	/* Construct the ResponseHeader. */
	header = (struct dl_response_header *) dlog_alloc(
	    sizeof(struct dl_response_header));
#ifdef _KERNEL
	DL_ASSERT(header != NULL, ("Failed allocating ResponseHeader."));
#else
	if (header== NULL ) {
		goto err_response_header;
	}
#endif	
	header->dlrh_correlation_id = correlation_id;

	*self = header;
	return 0;

#ifndef _KERNEL
err_response_header:
	DLOGTR0(PRIO_HIGH, "Failed instatiating RequestHeader.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_response_header_delete(struct dl_response_header *self)
{

	DL_ASSERT(self != NULL,
	    ("ProduceResponseHeader instance cannot be NULL."));
	dlog_free(self);
}

/**
 * Encode the ResponseHeader.
 *
 * ResponseHeader = CorrelationId
 *  
 * CorrelationId
 */
int
dl_response_header_encode(struct dl_response_header const * const self,
    struct dl_bbuf * const target)
{

	DL_ASSERT(self != NULL, ("Response cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Encode the Response CorrelationId into the buffer. */
	return DL_ENCODE_CORRELATION_ID(target, self->dlrh_correlation_id);
}

int
dl_response_header_decode(struct dl_response_header **self,
    struct dl_bbuf *source)
{
	struct dl_response_header *header;
	int rc = 0;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	header = (struct dl_response_header *) dlog_alloc(
	    sizeof(struct dl_response_header));
#ifdef _KERNEL
	DL_ASSERT(header != NULL, ("Failed allocateding Response header."));
#else
	if (self == NULL) {
		DLOGTR0(PRIO_HIGH, "Failed allocateding Response header.\n");
		*self = NULL;
		return -1;
	}
#endif
	/* Decode the CorrelationId */	
	rc = DL_DECODE_CORRELATION_ID(source, &header->dlrh_correlation_id);
	if (rc == 0) {
		/* Successfully decoded the Response header. */
		*self =  header;
		return 0;
	}

	return -1;
}

int32_t
dl_response_header_get_correlation_id(struct dl_response_header *self)
{

	DL_ASSERT(self != NULL, ("Response header cannot be NULL"));
	return self->dlrh_correlation_id;
}
