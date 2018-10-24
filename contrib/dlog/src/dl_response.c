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

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

static int32_t dl_response_header_encode(struct dl_response const * const,
    struct dl_bbuf * const);

#define DL_ENCODE_SIZE(buffer, value) dl_encode_int32(buffer, value)

/**
 * Encode the ResponseHeader.
 *
 * ResponseHeader = CorrelationId
 *  
 * CorrelationId
 */
int32_t 
dl_response_header_encode(struct dl_response const * const response,
    struct dl_bbuf * const target)
{

	DL_ASSERT(response != NULL, ("Response cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Encode the Response CorrelationId into the buffer. */
	return DL_ENCODE_CORRELATION_ID(target, response->dlrs_correlation_id);
}

int
dl_response_new(struct dl_response **self, int16_t api_key,
    int32_t correlation_id)
{
	struct dl_response *response;

	DL_ASSERT(self != NULL, ("Response cannot be NULL."));
	DL_ASSERT(api_key == DL_PRODUCE_API_KEY ||
	    api_key == DL_FETCH_API_KEY || api_key== DL_OFFSET_API_KEY,
	    ("Invalid ApiKey."));

	response = (struct dl_response *) dlog_alloc(
	    sizeof(struct dl_response));
#ifdef _KERNEL
	DL_ASSERT(response != NULL, ("Allocation for Response failed"));
#else
	if (response == NULL) {
		DLOGTR0(PRIO_HIGH, "Allocation for Response failed");
		return -1;
	}
#endif
	response->dlrs_api_key = api_key;
	response->dlrs_correlation_id = correlation_id;

	/* Response successfully constructed. */
	*self = response;
	return 0;
}

/**
 * Response destructor.
 */
void
dl_response_delete(struct dl_response const * const self)
{

	DL_ASSERT(self != NULL, ("Response cannot be NULL."));
	DL_ASSERT(self->dlrs_api_key == DL_PRODUCE_API_KEY ||
	    self->dlrs_api_key == DL_FETCH_API_KEY ||
	    self->dlrs_api_key== DL_OFFSET_API_KEY, ("Invalid ApiKey."));

	switch (self->dlrs_api_key) {
	case DL_PRODUCE_API_KEY:
		dl_produce_response_delete(self->dlrs_produce_response);
		break;
#ifndef _KERNEL
	case DL_FETCH_API_KEY:
		dl_fetch_response_delete(self->dlrs_fetch_response);
		break;
	case DL_OFFSET_API_KEY:
		dl_list_offset_response_delete(self->dlrs_offset_response);
		break;
#endif
	}
	
	dlog_free(self);	
}

/*
int
dl_response_decode(struct dl_response ** const self,
    struct dl_bbuf const * const source)
{
	struct dl_response *response;
	int rc;

	DL_ASSERT(self != NULL, ("Request buffer cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	response = (struct dl_response *) dlog_alloc(
	    sizeof(struct dl_response));
#ifdef _KERNEL
	DL_ASSERT(response != NULL, ("Allocation for Request failed"));
	{
#else
	if (response != NULL) {
#endif
		* Decode the Request Header into the buffer. *
		if (dl_response_header_decode(response, source) == 0) {
		
			* Decode the Request Body into the buffer. *
			switch (response->dlrs_api_key) {
			case DL_PRODUCE_API_KEY:
				rc = dl_produce_response_decode(
				    &response, source);
				break;
			case DL_FETCH_API_KEY:
				rc = dl_fetch_response_decode(
				    &response, source);
				break;
			case DL_OFFSET_API_KEY:
				rc = dl_list_offset_response_decode(
				    &response, source);
				break;
			default:
				DLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
				    response->dlrs_api_key);
				return -1;
			}
			if (rc == 0) {
				*self = response;
				return 0;
			}
		} else {
			DLOGTR0(PRIO_HIGH, "Error decoding response header.\n");
			return -1;
		}
	}

	DLOGTR0(PRIO_HIGH, "Instatiation of Request failed\n");
	dlog_free(response);
	*self = NULL;
	return -1;
}
*/

int32_t
dl_response_encode(struct dl_response *response, struct dl_bbuf **target)
{

	DL_ASSERT(response != NULL, ("Response message cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Allocate and initialise a buffer to encode the response.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	if (dl_bbuf_new(target, NULL, DL_MTU,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) == 0) {

		if (dl_response_header_encode(response, *target) == 0) {

			switch (response->dlrs_api_key) {
			case DL_PRODUCE_API_KEY:
				return dl_produce_response_encode(
				    response->dlrs_produce_response, *target);
				break;
#ifndef _KERNEL
			case DL_FETCH_API_KEY:
				return dl_fetch_response_encode(
				    response->dlrs_fetch_response, *target);
				break;
			case DL_OFFSET_API_KEY:
				return dl_list_offset_response_encode(
				    response->dlrs_offset_response, *target);
				break;
#endif
			default:
				DLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
				    response->dlrs_api_key);
				return -1;
			}
		}
		DLOGTR0(PRIO_HIGH, "Failed encoding response header.\n");
		return -1;
	}
	
	DLOGTR0(PRIO_HIGH, "Failed instantiating buffer to encode response.\n");
	return -1;
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
	rc = DL_DECODE_CORRELATION_ID(source, &header->dlrsh_correlation_id);

	if (rc == 0) {
		/* Successfully decoded the Response header. */
		*self =  header;
		return 0;
	}

	return -1;
}
