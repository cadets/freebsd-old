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

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_produce_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_utils.h"

#define DL_DECODE_TOPIC_NAME(source, target) dl_decode_string(source, target)
#define DL_DECODE_PARTITION(source, value) dl_bbuf_get_int32(source, value)
#define DL_DECODE_ERROR_CODE(source, value) dl_bbuf_get_int16(source, value)
#define DL_DECODE_OFFSET(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_LOG_APPEND_TIME(source, value) dl_bbuf_get_int64(source, value)
#define DL_DECODE_THROTTLE_TIME(source, value) dl_bbuf_get_int32(source, value)

#define DL_ENCODE_TOPIC_NAME(target, source) dl_encode_string(target, source)
#define DL_ENCODE_PARTITION(target, value) dl_bbuf_put_int32(target, value)
#define DL_ENCODE_ERROR_CODE(target, value) dl_bbuf_put_int16(target, value)
#define DL_ENCODE_OFFSET(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_LOG_APPEND_TIME(target, value) dl_bbuf_put_int64(target, value)
#define DL_ENCODE_THROTTLE_TIME(target, value) dl_bbuf_put_int32(target, value)

static const int32_t MAX_RESPONSE_TOPICS = 10;
static const int32_t MAX_RESPONSE_PARTITIONS = 10;

int
dl_produce_response_new(struct dl_produce_response **self,
    __attribute((unused)) const int32_t correlation_id, struct sbuf *topic_name,
    int32_t throttle_time, int64_t offset, int16_t error_code)
{
	struct dl_produce_response *response;
	struct dl_produce_response_topic *response_topic;
	
	DL_ASSERT(self != NULL,
	    ("ProduceResponse instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL,
	    ("ProduceResponse topic name cannot be NULL."));

	/* Construct the ProduceResponse. */
	response = (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
#ifdef _KERNEL
	DL_ASSERT(response != NULL, ("Failed allocating Response."));
#else
	if (response == NULL ) {
		goto err_response_ctor;
	}
#endif	
	SLIST_INIT(&response->dlpr_topics);
	response->dlpr_throttle_time = throttle_time;
	response->dlpr_ntopics = 1;

	response_topic = (struct dl_produce_response_topic *)
	    dlog_alloc(sizeof(struct dl_produce_response_topic));	    
#ifdef _KERNEL
	DL_ASSERT(response_topic != NULL,
	    ("Failed allocating response topic.\n"));
#else
	if (response_topic == NULL ) {
		goto err_produce_response;
	}
#endif	
	response_topic->dlprt_topic_name = topic_name;
	response_topic->dlprt_npartitions = 1;
	response_topic->dlprt_partitions[0].dlprp_offset = offset;
	response_topic->dlprt_partitions[0].dlprp_partition = 0;
	response_topic->dlprt_partitions[0].dlprp_error_code = error_code;
	response_topic->dlprt_partitions[0].dlprp_append_time = -1;
	
	SLIST_INSERT_HEAD(&response->dlpr_topics, response_topic,
	    dlprt_entries);

	*self = response;
	return 0;

#ifndef _KERNEL
err_produce_response:
	dlog_free(response);

err_response_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_produce_response_delete(struct dl_produce_response *self)
{
	struct dl_produce_response_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &self->dlpr_topics,
	    dlprt_entries, req_topic_tmp) {

		SLIST_REMOVE(&self->dlpr_topics, req_topic,
		    dl_produce_response_topic, dlprt_entries);
		sbuf_delete(req_topic->dlprt_topic_name);
		dlog_free(req_topic);
	};
	dlog_free(self);
}

int
dl_produce_response_decode(struct dl_produce_response **self,
    struct dl_bbuf *source)
{
	struct dl_produce_response *response;
	struct dl_produce_response_partition *part_responses;
	struct dl_produce_response_topic *topic_response;
	struct sbuf *topic_name;
	int32_t part, response_it, nparts;
	int rc = 0;

	DL_ASSERT(self != NULL, ("Response cannot be NULL."));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL."));

	/* Allocate and initialise the ProduceResponse instance. */
	response = (struct dl_produce_response *) dlog_alloc(
	    sizeof(struct dl_produce_response));
#ifdef _KERNEL
	DL_ASSERT(response != NULL,
	    ("Failed to allocate ProduceResponse.\n"));
#else
	if (response == NULL) {
		goto err_produce_response;
	}
#endif
	SLIST_INIT(&response->dlpr_topics);

	/* Decode the number of responses in the response array. */
	rc |= dl_bbuf_get_int32(source, &response->dlpr_ntopics);
	DL_ASSERT(response->dlpr_ntopics > 0,
	    ("Non-primitive array types are not NULLABLE"));
	if (response->dlpr_ntopics > MAX_RESPONSE_TOPICS) {

		dlog_free(response);
		goto err_produce_response;
	}

	/* Decode the responses. */
	for (response_it = 0; response_it < response->dlpr_ntopics;
	    response_it++) {

		/* Decode the TopicName. */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);

		/* Decode the partitions. */
		rc |= dl_bbuf_get_int32(source, &nparts);
		if (nparts > MAX_RESPONSE_PARTITIONS) {
		}

		/* Allocate, decode and enqueue each response. */
		topic_response = (struct dl_produce_response_topic *)
		    dlog_alloc(sizeof(struct dl_produce_response_topic) +
		    (nparts * sizeof(struct dl_produce_response_partition)));
#ifdef _KERNEL
		DL_ASSERT(topic_response != NULL,
		    ("Failed to allocate ProduceResponse.\n"));
#else
		if (topic_response == NULL) {
			dl_produce_response_delete(response);
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

			/* Decode the LogAppendTime*/
			rc |= DL_DECODE_LOG_APPEND_TIME(source,
			    &part_responses->dlprp_append_time);
		}

		SLIST_INSERT_HEAD(&response->dlpr_topics,
		    topic_response, dlprt_entries);
	}

	/* Decode the ThrottleTime. */
	rc |= DL_DECODE_THROTTLE_TIME(source, &response->dlpr_throttle_time);

	if (rc == 0) {
		/* ProduceResponse successfully decoded. */
		*self = response;
		return 0;
	}
err_produce_response:
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
			    part_responses->dlprp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
			
			/* Encode the ErrorCode. */
			rc |= DL_ENCODE_ERROR_CODE(target,
			    part_responses->dlprp_error_code);
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

			/* Encode the LogAppendTime*/
			rc |= DL_ENCODE_LOG_APPEND_TIME(target,
			    part_responses->dlprp_append_time);
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
