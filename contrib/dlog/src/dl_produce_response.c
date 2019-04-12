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

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_produce_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

int
dl_produce_response_new(struct dl_response **self,
    const int32_t correlation_id, struct sbuf *topic_name,
    int32_t throttle_time, int64_t offset, int16_t error_code)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_topic *response_topic;
	struct dl_response *response;
	int rc;
	
	DL_ASSERT(topic_name != NULL,
	    ("ProduceResponse topic name cannot be NULL."));

	/* Construct the Response. */
	rc = dl_response_new(&response, DL_PRODUCE_API_KEY, correlation_id);
#ifdef _KERNEL
	DL_ASSERT(rc != 0, ("Failed to allocate Request."));
#else
	if (rc != 0)
		goto err_response_ctor;
#endif
	/* Construct the ProduceResponse. */
	produce_response = response->dlrs_produce_response =
	    (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
#ifdef _KERNEL
	DL_ASSERT(produce_response != NULL, ("Failed allocating Response."));
#else
	if (produce_response == NULL ) {
		goto err_produce_response;
	}
#endif	
	SLIST_INIT(&produce_response->dlpr_topics);
	produce_response->dlpr_throttle_time = throttle_time;
	produce_response->dlpr_ntopics = 1;

	response_topic = (struct dl_produce_response_topic *)
	    dlog_alloc(sizeof(struct dl_produce_response_topic));	    
#ifdef _KERNEL
	DL_ASSERT(response_topic != NULL,
	    ("Failed allocating response topic.\n"));
#else
	if (response_topic == NULL ) {
		goto err_response_topic;
	}
#endif	
	response_topic->dlprt_topic_name = topic_name;
	response_topic->dlprt_npartitions = 1;
	response_topic->dlprt_partitions[0].dlprp_offset = offset;
	response_topic->dlprt_partitions[0].dlprp_partition = 0;
	response_topic->dlprt_partitions[0].dlprp_error_code = error_code;
	
	SLIST_INSERT_HEAD(&produce_response->dlpr_topics, response_topic,
	    dlprt_entries);

	*self = response;
	return 0;

#ifndef _KERNEL
err_response_topic:
	dlog_free(produce_response);

err_produce_response:
	dl_response_delete(response);

err_response_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_produce_response_delete(struct dl_produce_response *self)
{
	struct dl_produce_response *produce_response = self;
	struct dl_produce_response_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &produce_response->dlpr_topics,
	    dlprt_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&produce_response->dlpr_topics);
		SLIST_REMOVE(&produce_response->dlpr_topics, req_topic,
		    dl_produce_response_topic, dlprt_entries);

		dlog_free(req_topic);
	};
	dlog_free(self);
}

int
dl_produce_response_decode(struct dl_response **self,
    struct dl_bbuf *source)
{
	struct dl_produce_response *produce_response;
	struct dl_produce_response_partition *part_responses;
	struct dl_produce_response_topic *topic_response;
	struct dl_response *response;
	struct sbuf *topic_name;
	int32_t part, response_it, nparts;
	int rc = 0;

	DL_ASSERT(self != NULL, ("Response cannot be NULL."));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL."));

	/* Construct the Response. */
	// TODO: what to do about the correlation id, this boils down to
	// whether there is a necessary split between the header and payload
	//rc = dl_response_new(&response, DL_PRODUCE_API_KEY, 0);
#ifdef _KERNEL
	//DL_ASSERT(rc == 0, ("Failed instatiate Response.\n"));
#else
	//if (rc != 0)
	//	goto err_produce_response;
#endif

	response = (struct dl_response *) dlog_alloc(
	    sizeof(struct dl_response));

	/* Allocate and initialise the produce_response instance. */
	response->dlrs_produce_response = produce_response =
	    (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
#ifdef _KERNEL
	DL_ASSERT(produce_response != NULL,
	    ("Failed to allocate ProduceResponse.\n"));
#else
	if (produce_response == NULL) {
		dl_response_delete(response);
		goto err_produce_response;
	}
#endif
	SLIST_INIT(&produce_response->dlpr_topics);

	/* Decode the number of responses in the response array. */
	rc |= dl_bbuf_get_int32(source, &produce_response->dlpr_ntopics);
	DL_ASSERT(produce_response->dlpr_ntopics > 0,
	    ("Non-primitive array types are not NULLABLE"));
	// TODO: need to check this to verify message is well formed

	/* Decode the responses. */
	for (response_it = 0; response_it < produce_response->dlpr_ntopics;
	    response_it++) {

		/* Decode the TopicName. */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);

		/* Decode the partitions. */
		rc |= dl_bbuf_get_int32(source, &nparts);
		// TODO: need to check this to verify message is well formed
	
		/* Allocate, decode and enqueue each response. */
		topic_response = (struct dl_produce_response_topic *)
		    dlog_alloc(sizeof(struct dl_produce_response_topic) +
		    (nparts * sizeof(struct dl_produce_response_partition)));
#ifdef _KERNEL
		DL_ASSERT(topic_response != NULL,
		    ("Failed to allocate ProduceResponse.\n"));
#else
		if (topic_response == NULL) {
			dl_produce_response_delete(produce_response);
			dl_response_delete(response);
			goto err_produce_response;
		}
#endif
		topic_response->dlprt_topic_name = topic_name; 
		topic_response->dlprt_npartitions = nparts; 

		for (part = 0; part < nparts; part++) {

			part_responses =
			    &topic_response->dlprt_partitions[part];

			/* Decode the Partition */
			rc |= DL_DECODE_PARTITION(source,
			    &part_responses->dlprp_partition);

			/* Decode the ErrorCode */
			rc |= DL_DECODE_ERROR_CODE(source,
			    &part_responses->dlprp_error_code);

			/* Decode the Offset */
			rc |= DL_DECODE_OFFSET(source,
			    &part_responses->dlprp_offset);
		}

		SLIST_INSERT_HEAD(&produce_response->dlpr_topics,
		    topic_response, dlprt_entries);
	}

	/* Decode the ThrottleTime. */
	rc |= DL_DECODE_THROTTLE_TIME(source,
	    &produce_response->dlpr_throttle_time);

	if (rc == 0) {
		/* ProduceResponse successfully decoded. */
		*self = response;
		return 0;
	}
#ifndef _KERNEL
err_produce_response:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding ProduceResponse,\n");
	*self = NULL;
	return -1;
}

int32_t
dl_produce_response_encode(struct dl_produce_response *self,
    struct dl_bbuf *target)
{
	struct dl_produce_response_topic *topic_response;
	struct dl_produce_response_partition *part_responses;
	int32_t part;
	int rc = 0;

	DL_ASSERT(self != NULL, ("ProduceResponse cannot be NULL\n."));
	DL_ASSERT(self->dlpr_ntopics > 0,
	    ("Non-primitive [topic_data] array is not NULLABLE"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the number of responses in the response array. */
	rc |= dl_bbuf_put_int32(target, self->dlpr_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	SLIST_FOREACH(topic_response, &self->dlpr_topics, dlprt_entries) {

		DL_ASSERT(topic_response->dlprt_npartitions > 0,
		    ("Non-primitive [response_data] array is not NULLABLE"));

		/* Encode the TopicName. */
		rc |= DL_ENCODE_TOPIC_NAME(target,
		    topic_response->dlprt_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the Topic partitions. */
		rc |= dl_bbuf_put_int32(target,
		    topic_response->dlprt_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < topic_response->dlprt_npartitions;
		    part++) {

			part_responses =
			    &topic_response->dlprt_partitions[part];

			/* Encode the Partition. */
			rc |= DL_ENCODE_PARTITION(target,
			    part_responses->dlprp_error_code);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
			
			/* Encode the ErrorCode. */
			rc |= DL_ENCODE_ERROR_CODE(target,
			    part_responses->dlprp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Encode the Offset. */
			rc |= DL_ENCODE_OFFSET(target,
			    part_responses->dlprp_offset);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
	}
	
	/* Encode the ThrottleTime. */
	rc |= DL_ENCODE_THROTTLE_TIME(target, self->dlpr_throttle_time);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ProduceResponse.\n");
	return -1;
}
