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
#include "dl_fetch_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

int
dl_fetch_response_new(struct dl_response **self,
    const int32_t correlation_id, struct sbuf *topic_name, int16_t error_code,
    int64_t high_watermark, struct dl_message_set *msgset)
{
	struct dl_fetch_response *fetch_response;
	struct dl_fetch_response_topic *response_topic;
	struct dl_response *response;
	int rc;
	
	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL,
	    ("ListOffsetResponse topic name cannot be NULL."));

	/* Construct the Response. */
	rc = dl_response_new(&response, DL_FETCH_API_KEY, correlation_id);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Failed to allocate Request."));
#else
	if (rc != 0)
		goto err_response_ctor;
#endif

	/* Construct the ffsetResponse. */
	fetch_response = response->dlrs_fetch_response =
	    (struct dl_fetch_response *) dlog_alloc(
	    sizeof(struct dl_fetch_response));
#ifdef _KERNEL
	DL_ASSERT(fetch_response != NULL, ("Failed to allocate Request."));
#else
	if (fetch_response == NULL) {

		dl_response_delete(response);
		goto err_response_ctor;
	}
#endif
	
	SLIST_INIT(&fetch_response->dlfr_topics);
	fetch_response->dlfr_ntopics = 1;
	fetch_response->dlfr_throttle_time = 0;

	response_topic = (struct dl_fetch_response_topic *) dlog_alloc(
	    sizeof(struct dl_fetch_response_topic) +
	    sizeof(struct dl_fetch_response_partition));
#ifdef _KERNEL
	DL_ASSERT(response_topic != NULL,
	    ("Failed allocating response topic.\n"));
#else
	if (response_topic == NULL ) {

		dl_fetch_response_delete(fetch_response);
		dl_response_delete(response);
		goto err_response_ctor;
	}
#endif	
	
	response_topic->dlfrt_topic_name = topic_name;
	response_topic->dlfrt_npartitions = 1;
	response_topic->dlfrt_partitions[0].dlfrp_message_set = msgset;
	response_topic->dlfrt_partitions[0].dlfrp_high_watermark =
	    high_watermark;
	response_topic->dlfrt_partitions[0].dlfrp_partition = 0;
	response_topic->dlfrt_partitions[0].dlfrp_error_code = error_code;
	
	SLIST_INSERT_HEAD(&fetch_response->dlfr_topics, response_topic,
	    dlfrt_entries);

	*self = response;
	return 0;

#ifndef _KERNEL
err_response_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_fetch_response_delete(struct dl_fetch_response *self)
{
	struct dl_fetch_response_topic *req_topic, *req_topic_tmp;
	struct dl_fetch_response_partition *req_part;
	int part;

	DL_ASSERT(self != NULL, ("FetchResponse instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &self->dlfr_topics,
	    dlfrt_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlfr_topics);
		SLIST_REMOVE(&self->dlfr_topics, req_topic,
		    dl_fetch_response_topic, dlfrt_entries);

		for (part = 0; part < req_topic->dlfrt_npartitions; part++) {

			req_part = &req_topic->dlfrt_partitions[part];

			if (req_part->dlfrp_message_set != NULL)
				dl_message_set_delete(
				    req_part->dlfrp_message_set);
		}
		dlog_free(req_topic);
	};
	dlog_free(self);
}	

int
dl_fetch_response_decode(struct dl_response **self, struct dl_bbuf *source)
{
	struct dl_fetch_response *fetch_response;
	struct dl_fetch_response_topic *topic;
	struct dl_fetch_response_partition *partition;
	struct dl_response *response;
	struct sbuf *topic_name;
	int32_t part, response_it, nparts;
	int rc = 0;

	DL_ASSERT(self != NULL, ("Response cannot be NULL."));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL."));

	/* Construct the Response. */
	// TODO: what to do about the correlation id, this boils down to
	// whether there is a necessary split between the header and payload
	rc = dl_response_new(&response, DL_PRODUCE_API_KEY, 0);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Failed instatiate Response.\n"));
#else
	if (rc != 0)
		goto err_fetch_response;
#endif
	
	/* Construct the FetchResponse. */
	response->dlrs_fetch_response = fetch_response =
	    (struct dl_fetch_response *) dlog_alloc(
		sizeof(struct dl_fetch_response));
#ifdef _KERNEL
	DL_ASSERT(fetch_response != NULL,
	    ("Failed to allocate FetchResponse.\n"));
#else
	if (fetch_response == NULL) {
		dl_response_delete(response);
		goto err_fetch_response;
	}
#endif

	/* Decode the ThrottleTime */	
	rc |= DL_DECODE_THROTTLE_TIME(source,
	    &fetch_response->dlfr_throttle_time);

        /* Decode the responses */	
	SLIST_INIT(&fetch_response->dlfr_topics);

	rc |= dl_bbuf_get_int32(source, &fetch_response->dlfr_ntopics);
	DL_ASSERT(fetch_response->dlfr_ntopics > 0,
	    "Response array is not NULLABLE");

	for (response_it = 0; response_it < fetch_response->dlfr_ntopics;
	    response_it++) {
		
		/* Decode the TopicName */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);
		
		/* Decode the partition responses */	
		rc |= dl_bbuf_get_int32(source, &nparts);
		// TODO: need to check this to verify message is well formed

		topic = (struct dl_fetch_response_topic *) dlog_alloc(
		    sizeof(struct dl_fetch_response_topic) +
		    (nparts * sizeof(struct dl_fetch_response_partition)));
#ifdef _KERNEL
		DL_ASSERT(topic != NULL,
		    ("Failed to allocate FetchResponse.\n"));
#else
		if (topic == NULL) {
			dl_fetch_response_delete(fetch_response);
			dl_response_delete(response);
			goto err_fetch_response;
		}
#endif

		topic->dlfrt_topic_name = topic_name;
		topic->dlfrt_npartitions = nparts;

		for (part = 0; part < nparts; part++) {

			partition = &topic->dlfrt_partitions[part];

			/* Decode the Partition */
			rc |= DL_DECODE_PARTITION(source,
			    &partition->dlfrp_partition);

			/* Decode the ErrorCode */
			rc |= DL_DECODE_ERROR_CODE(source,
			    &partition->dlfrp_error_code);

			/* Decode the HighWatermark */
		    	rc |= DL_DECODE_HIGH_WATERMARK(source,
			    &partition->dlfrp_high_watermark);

			/* Decode the MessageSet */
			rc |= dl_message_set_decode(
			    &partition->dlfrp_message_set, source);
		}

		SLIST_INSERT_HEAD(&fetch_response->dlfr_topics, topic,
		    dlfrt_entries);
	}

	if (rc == 0) {
		/* FetchResponse successfully decoded. */
		*self = response;
		return 0;
	}

#ifndef _KERNEL
err_fetch_response:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding FetchResponse,\n");
	*self = NULL;
	return -1;
}

int
dl_fetch_response_encode(struct dl_fetch_response *self,
    struct dl_bbuf *target)
{
	struct dl_fetch_response_partition *partition;
	struct dl_fetch_response_topic *topic;
	int32_t part;
	int rc = 0;

	DL_ASSERT(self != NULL, ("ProduceResponse cannot be NULL\n."));
	DL_ASSERT(self->dlfr_ntopics > 0, "Response array is not NULLABLE");
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the ThrottleTime */	
	rc |= DL_ENCODE_THROTTLE_TIME(target, self->dlfr_throttle_time);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	rc |= dl_bbuf_put_int32(target, self->dlfr_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	SLIST_FOREACH(topic, &self->dlfr_topics, dlfrt_entries) {

		/* Decode the TopicName */
		rc |= DL_ENCODE_TOPIC_NAME(target, topic->dlfrt_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		/* Decode the partition responses */	
		rc |= dl_bbuf_put_int32(target, topic->dlfrt_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < topic->dlfrt_npartitions; part++) {

			partition = &topic->dlfrt_partitions[part];

			/* Decode the Partition */
			rc |= DL_ENCODE_PARTITION(target,
			    partition->dlfrp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Decode the ErrorCode */
		    	rc |= DL_ENCODE_ERROR_CODE(target,
			    partition->dlfrp_error_code);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Decode the HighWatermark */
		    	rc |= DL_ENCODE_HIGH_WATERMARK(target,
			    partition->dlfrp_high_watermark);

#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Encode the MessageSet */
			rc |= dl_message_set_encode(
			    partition->dlfrp_message_set, target);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding FetchResponse.\n");
	return -1;
}
