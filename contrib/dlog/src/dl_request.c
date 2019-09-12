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

#include <sys/types.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

static int dl_request_ctor(void *, va_list * app); 

static const struct dl_request_class TYPE = {
	{
		sizeof(struct dl_request),
		dl_request_ctor,
		NULL,
		NULL
	},
	dl_request_encode,
	NULL
};

const void *DL_REQUEST = &TYPE;

int
dl_request_header_decode(struct dl_request * const request,
    struct dl_bbuf * const source)
{
	int16_t api_version;
	int rc = 0;

	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
	DL_ASSERT(dl_bbuf_get_flags(source) & DL_BBUF_AUTOEXTEND,
	    ("Buffer for encoding must be auto extending."));

	/* Decode the Request APIKey. */
	rc |= DL_DECODE_API_KEY(source, &request->dlrqm_api_key);

	/* Decode the Request APIVersion and check it is supported. */
	rc |= DL_DECODE_API_VERSION(source, &api_version);
	if (api_version < DLOG_API_V3) {

		DLOGTR1(PRIO_HIGH, "Unsupported API version %d\n", api_version);
		return -1;
	}

	/* Decode the Request CorrelationId. */
	rc |= DL_DECODE_CORRELATION_ID(source, &request->dlrqm_correlation_id);

	/* Decode the Request ClientId. */
	rc |= DL_DECODE_CLIENT_ID(source, &request->dlrqm_client_id);

	/* Check whether the decoding steps completed successfully. This
	 * should be the case as the only way that this should fail is if the
	 * buffer doesn't possess sufficient capacity, as the buffer is
	 * autoextending that should only happen in circumstance when it
	 * is difficult to recover from (system out of memory.)
	 */
	if (rc == 0)
		return 0;

	return -1;
}

/**
 * Encode the RequestHeader.
 *
 * RequestHeader = APIKey APIVersion CorrelationId ClientId
 *  
 * APIKey
 * APIVersion
 * CorrelationId
 * ClientId
 */
int
dl_request_header_encode(struct dl_request const * const request,
    struct dl_bbuf * const target)
{
	int rc = 0;

	DL_ASSERT(request!= NULL, ("Request cannot be NULL."));
	DL_ASSERT(target != NULL,
	    ("Target buffer for encoding cannot be NULL."));
	DL_ASSERT(dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND,
	    ("Buffer for encoding must be auto extending."));

	/* Encode the Request APIKey into the buffer. */
	rc |= DL_ENCODE_API_KEY(target, request->dlrqm_api_key);

	/* Encode the Request APIVersion into the buffer. */
	rc |= DL_ENCODE_API_VERSION(target, DLOG_API_VERSION);

	/* Encode the Request CorrelationId into the buffer. */
	rc |= DL_ENCODE_CORRELATION_ID(target, request->dlrqm_correlation_id);

	/* Encode the Request ClientId into the buffer. */
	rc |= DL_ENCODE_CLIENT_ID(target, request->dlrqm_client_id);
	
	/* Check whether the encoding steps completed successfully. This
	 * should be the case as the only way that this should fail is if the
	 * buffer doesn't possess sufficient capacity, as the buffer is
	 * autoextending that should only happen in circumstance when it
	 * is difficult to recover from (system out of memory.)
	 */
	if (rc == 0)
		return 0;

	return -1;
}

/**
 * Request constructor.
 */
int
dl_request_ctor(void *_self, va_list *ap)
{
	struct dl_request *self = (struct dl_request *) _self;

	DL_ASSERT(self != NULL, ("Request cannot be NULL."));

	self->dlrqm_api_key = va_arg(*ap, int);
	self->dlrqm_correlation_id = va_arg(*ap, int);
	self->dlrqm_client_id = va_arg(*ap, struct sbuf *);

	return 0;
}

#ifdef MOVE_TO_FACTORY
int
dl_request_decode(struct dl_request ** const self,
    struct dl_bbuf * const source)
{
	struct dl_request *request;
	int32_t req_size;
	int rc;

	DL_ASSERT(self != NULL, ("Request buffer cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	request = (struct dl_request *) dlog_alloc(sizeof(struct dl_request));
	DL_ASSERT(request != NULL, ("Allocation for Request failed"));
	if (request == NULL)
		goto err_request;

	/* Encode a placeholder for the total request size. */	
	rc = DL_DECODE_REQUEST_SIZE(source, &req_size);

	/* Decode the Request Header into the buffer. */
	if (dl_request_header_decode(request, source) == 0) {
			
		/* Decode the Request Body into the buffer. */
		switch (request->dlrqm_api_key) {
		case DL_PRODUCE_API_KEY:
			rc = dl_produce_request_decode(
		    	    &request, source);
			break;
		case DL_FETCH_API_KEY:
			rc = dl_fetch_request_decode(
			    &request, source);
			break;
		case DL_OFFSET_API_KEY:
			rc = dl_list_offset_request_decode(
			    &request, source);
			break;
		default:
			DLOGTR1(PRIO_HIGH, "Invalid api key %d\n",
			    request->dlrqm_api_key);
			rc = -1;
		}

		if (rc != 0) {
			dl_delete(request);
			goto err_request;
		}

		*self = request;
		return 0;
	}
	DLOGTR0(PRIO_HIGH, "Error decoding request header.\n");

err_request:
	DLOGTR0(PRIO_HIGH, "Instatiation of Request failed\n");
	*self = NULL;
	return -1;
}
#endif

/**
 * Encode the Request.
 *
 * Request = Size RequestHeader ProduceRequest|FetchRequest|OffsetRequest
 *
 */
int
dl_request_encode(void *self, struct dl_bbuf **target)
{
	const struct dl_request_class **class = self;
	int rc = 0;

	DL_ASSERT(self!= NULL, ("Request cannot be NULL"));
	DL_ASSERT(target != NULL, ("Target buffer cannot be NULL"));

	/* Allocate and initialise a buffer to encode the request.
	 * An AUTOEXTEND buffer should only fail when the reallocation of
	 * the buffer fails; at which point the error handling is somewhat
	 * tricky as the system is out of memory.
	 */
	if (dl_bbuf_new(target, NULL, DL_MTU,
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) == 0) {

		/* Encode a placeholder for the total request size. */	
		rc |= DL_ENCODE_REQUEST_SIZE(*target, -1);
	
		/* Encode the Request Header. */
		if (dl_request_header_encode(self, *target) == 0) {

			if (self != NULL && *class != NULL &&
			    (*class)->dlr_encode_into) {	

				return (* class)->dlr_encode_into(self,
				    *target);
			}
		}

		DLOGTR0(PRIO_HIGH, "Failed encoding request header\n");
		return -1;
	}

	DLOGTR0(PRIO_HIGH, "Failed instantiating buffer to encode request\n");
	return -1;
}
