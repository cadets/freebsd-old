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
 * 2. Redistributions in binary form must relist_offset the above copyright
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
#include "dl_list_offset_response.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_response.h"
#include "dl_utils.h"

int
dl_list_offset_response_new(struct dl_response **self,
    const int32_t correlation_id, struct sbuf *topic_name, int16_t error_code,
    int64_t time, int64_t offset)
{
	struct dl_list_offset_response *offset_response;
	struct dl_list_offset_response_topic *response_topic;
	struct dl_response *response;
	int rc;
	
	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL,
	    ("ListOffsetResponse topic name cannot be NULL."));

	/* Construct the Response. */
	rc = dl_response_new(&response, DL_OFFSET_API_KEY, correlation_id);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Failed to allocate Request."));
#else
	if (rc != 0)
		goto err_response_ctor;
#endif

	/* Construct the ListOffsetResponse. */
	offset_response = response->dlrs_offset_response =
	    (struct dl_list_offset_response *) dlog_alloc(
	    sizeof(struct dl_list_offset_response));
#ifdef _KERNEL
	DL_ASSERT(offset_response != NULL, ("Failed to allocate Request."));
#else
	if (offset_response == NULL) {

		dl_response_delete(response);
		goto err_response_ctor;
	}
#endif
	
	SLIST_INIT(&offset_response->dlor_topics);
	offset_response->dlor_ntopics = 1;

	response_topic = (struct dl_list_offset_response_topic *) dlog_alloc(
	    sizeof(struct dl_list_offset_response_topic));	    
#ifdef _KERNEL
	DL_ASSERT(response_topic != NULL,
	    ("Failed allocating response topic.\n"));
#else
	if (response_topic == NULL ) {

		dl_list_offset_response_delete(offset_response);
		dl_response_delete(response);
		goto err_response_ctor;
	}
#endif	
	
	response_topic->dlort_topic_name = topic_name;
	response_topic->dlort_npartitions = 1;
	response_topic->dlort_partitions[0].dlorp_partition = 0;
	response_topic->dlort_partitions[0].dlorp_error_code= error_code;
	response_topic->dlort_partitions[0].dlorp_timestamp = time;
	response_topic->dlort_partitions[0].dlorp_offset = offset;
	
	SLIST_INSERT_HEAD(&offset_response->dlor_topics, response_topic,
	    dlort_entries);

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
dl_list_offset_response_delete(struct dl_list_offset_response *self)
{
	struct dl_list_offset_response *list_offset_response = self;
	struct dl_list_offset_response_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &list_offset_response->dlor_topics,
	    dlort_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&list_offset_response->dlor_topics);
		SLIST_REMOVE(&list_offset_response->dlor_topics, req_topic,
		    dl_list_offset_response_topic, dlort_entries);

		dlog_free(req_topic);
	};
	dlog_free(self);
}	

int
dl_list_offset_response_decode(struct dl_response **self,
    struct dl_bbuf *source)
{
	struct dl_list_offset_response *offset_response;
	struct dl_list_offset_response_partition *response_part;
	struct dl_list_offset_response_topic *response_topic;
	struct dl_response *response;
	struct sbuf *topic_name = NULL;
	int32_t topic_it, part, nparts;
	int rc = 0;
     
	DL_ASSERT(source != NULL, "Source buffer cannot be NULL");

	/* Construct the Response. */
	// TODO: what to do about the correlation id, this boils down to
	// whether there is a necessary split between the header and payload
	rc = dl_response_new(&response, DL_PRODUCE_API_KEY, 0);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Failed instatiate Response.\n"));
#else
	if (rc != 0)
		goto err_list_offset_response;
#endif

	/* Construct the ListOffsetResponse. */
	response->dlrs_offset_response = offset_response =
	    (struct dl_list_offset_response *) dlog_alloc(
		sizeof(struct dl_list_offset_response));
#ifdef _KERNEL
	DL_ASSERT(response != NULL,
	    ("Failed to allocate ListOffsetResponse.\n"));
#else
	if (response == NULL) {
		dl_response_delete(response);
		goto err_list_offset_response;
	}
#endif

	SLIST_INIT(&offset_response->dlor_topics);

        /* Decode the [topic_data] array. */
	rc |= dl_bbuf_get_int32(source, &offset_response->dlor_ntopics);
	
	for (topic_it = 0; topic_it < offset_response->dlor_ntopics;
	    topic_it++) {

		/* Decode the TopicName */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);
		
		/* Decode the partitions. */
		rc |= dl_bbuf_get_int32(source, &nparts);

		response_topic = (struct dl_list_offset_response_topic *)
		    dlog_alloc(sizeof(struct dl_list_offset_response_topic) +
		    (nparts-1 * sizeof(
		    struct dl_list_offset_response_partition)));
		
		response_topic->dlort_topic_name = topic_name;
		response_topic->dlort_npartitions = nparts;

		for (part = 0; part < nparts; part++) {

			response_part = &response_topic->dlort_partitions[part];
		
			/* Decode the Partition */
			rc |= DL_DECODE_PARTITION(source,
			    &response_part->dlorp_partition);
			
			/* Decode the ErrorCode */
			rc |= DL_DECODE_ERROR_CODE(source,
			    &response_part->dlorp_error_code);

			/* Decode the Timestamp */
			rc |= DL_DECODE_TIMESTAMP(source,
			    &response_part->dlorp_timestamp);
			
			/* Decode the Offset*/
			rc |= DL_DECODE_OFFSET(source,
			    &response_part->dlorp_offset);
		}

		SLIST_INSERT_HEAD(&offset_response->dlor_topics,
		    response_topic, dlort_entries);
	}

	if (rc == 0) {
		/* ListOffsetResponse successfully decoded. */
		*self = response;
		return 0;
	}
#ifndef _KERNEL
err_list_offset_response:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding ListOffsetResponse,\n");
	*self = NULL;
	return -1;
}

int32_t
dl_list_offset_response_encode(struct dl_list_offset_response *self,
    struct dl_bbuf *target)
{
	struct dl_list_offset_response_partition *response_partition;
	struct dl_list_offset_response_topic *response_topic;
	int32_t part;
	int rc = 0;

	DL_ASSERT(self != NULL, "Response cannot be NULL");
	DL_ASSERT(self->dlor_ntopics > 0,
	    ("Non-primitive [topic_data] array is not NULLABLE"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));
        
	/* Encode the [topic_data] array. */
	rc |= dl_bbuf_put_int32(target, self->dlor_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	SLIST_FOREACH(response_topic, &self->dlor_topics, dlort_entries) {

		/* Encode the TopicName. */
		rc |= DL_ENCODE_TOPIC_NAME(target,
		    response_topic->dlort_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the [data] array. */
		rc |= dl_bbuf_put_int32(target,
		    response_topic->dlort_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < response_topic->dlort_npartitions;
		    part++) {

			response_partition =
			    &response_topic->dlort_partitions[part];

			/* Encode the Partition. */
			rc |= DL_ENCODE_PARTITION(target,
			    response_partition->dlorp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
	
			/* Encode the ErrorCode. */
			rc |= DL_ENCODE_ERROR_CODE(target,
			    response_partition->dlorp_error_code);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
	
			/* Encode the Timestamp. */
			rc |= DL_ENCODE_TIMESTAMP(target,
			    response_partition->dlorp_timestamp);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
	
			/* Encode the Offset. */
			rc |= DL_ENCODE_OFFSET(target,
			    response_partition->dlorp_offset);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ProduceResponse.\n");
	return -1;
}
