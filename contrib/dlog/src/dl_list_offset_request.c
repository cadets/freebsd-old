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
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_request.h"
#include "dl_utils.h"

/**
 * ListOffsetRequest constructor. 
 */
int
dl_list_offset_request_new(struct dl_request **self, int32_t correlation_id,
    struct sbuf *client_id, struct sbuf *topic_name, int64_t time)
{
	struct dl_request *request;
	struct dl_list_offset_request *list_offset_request;
	struct dl_list_offset_request_topic *topic;
	struct dl_list_offset_request_partition *partition;
	int rc;
	
	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL,
	    ("ListOffsetRequest topic name cannot be NULL."));

	/* Construct the ListOffsetRequest. */
	rc = dl_request_new(&request, DL_OFFSET_API_KEY, correlation_id,
	    client_id);
#ifdef _KERNEL
	DL_ASSERT(rc != 0, ("Failed allocating FetchRequest."));
#else
	if (rc != 0)
		goto err_list_offset_request;
#endif
	list_offset_request = request->dlrqm_offset_request =
	    (struct dl_list_offset_request *) dlog_alloc(
	    sizeof(struct dl_list_offset_request));
#ifdef _KERNEL
	DL_ASSERT(list_offset_request != NULL,
	    ("Failed allocating ListOffsetequest."));
#else
	if (list_offset_request == NULL) {

		dl_request_delete(request);
		goto err_list_offset_request;
	}
#endif
	SLIST_INIT(&list_offset_request->dlor_topics);
	list_offset_request->dlor_ntopics = 1;
	list_offset_request->dlor_replica_id = 0;

	/* Construct a single Topic/Partition. */
	topic = (struct dl_list_offset_request_topic *)
	    dlog_alloc(sizeof(struct dl_list_offset_request_topic));	    
#ifdef _KERNEL
	DL_ASSERT(topic != NULL,
	    ("Failed allocating ListOffsetRequest [topic_data]."));
#else
	if (topic == NULL) {

		dl_request_delete(request);
		goto err_list_offset_request;
	}
#endif
	topic->dlort_topic_name = topic_name;
	topic->dlort_npartitions = 1;

	partition = &topic->dlort_partitions[0];
	partition->dlorp_partition = 0;
	partition->dlorp_time = time;

	SLIST_INSERT_HEAD(&list_offset_request->dlor_topics, topic,
	    dlort_entries);

	/* Successfully constructed the ListOffsetRequest instance. */
	*self = request;
	return 0;

#ifndef _KERNEL
err_list_offset_request:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

/**
 * ListOffsetRequest destructor. 
 */
void
dl_list_offset_request_delete(struct dl_list_offset_request *self)
{
	struct dl_list_offset_request_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &self->dlor_topics,
	    dlort_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlor_topics);
		SLIST_REMOVE(&self->dlor_topics, req_topic,
		    dl_list_offset_request_topic, dlort_entries);

		dlog_free(req_topic);
	};
	dlog_free(self);
}

/**
 * Decode the ListOffsetRequest.
 *
 * ListOffsetRequest = ReplicaId [Topics]
 * Topics = TopicName [Partitions]
 * TopicName
 * Partitions = Partition Timestamp
 * Partition
 * Timestamp
 */
int
dl_list_offset_request_decode(struct dl_list_offset_request **self,
    struct dl_bbuf *source)
{
	struct dl_list_offset_request *request;
	struct dl_list_offset_request_topic *request_topic;
	struct dl_list_offset_request_partition *request_part;
	struct sbuf *topic_name;
	int32_t topic_it, nparts, part;
	int rc = 0;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL\n");

	/* Construct the ListOffsetRequest. */
	request = (struct dl_list_offset_request *) dlog_alloc(
	    sizeof(struct dl_list_offset_request));
#ifdef _KERNEL
	DL_ASSERT(request != NULL, ("Failed to allocate ProduceRequest.\n"));
#else
	if (request == NULL)
		goto err_list_offset_request;
#endif
	/* Decode the ListOffsetRequest ReplicaId. */
	rc |= DL_DECODE_REPLICA_ID(source, &request->dlor_replica_id);

	/* Decode the [topic_data] array. */
	rc |= dl_bbuf_get_int32(source, &request->dlor_ntopics);
		
	SLIST_INIT(&request->dlor_topics);

	for (topic_it = 0; topic_it < request->dlor_ntopics; topic_it++) {

		/* Decode the TopicName. */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);

		/* Decode the [data] array. */
		rc |= dl_bbuf_get_int32(source, &nparts);
			
		request_topic = (struct dl_list_offset_request_topic *)
		    dlog_alloc(sizeof(struct dl_list_offset_request_topic) +
	    	    ((nparts - 1) *
		    sizeof(struct dl_list_offset_request_partition)));
#ifdef _KERNEL
		DL_ASSERT(request != NULL,
		    ("Failed to allocate ProduceRequest.\n"));
#else
		if (request_topic == NULL) {

			dl_list_offset_request_delete(request);
			goto err_list_offset_request;
		}
#endif
		request_topic->dlort_topic_name = topic_name;
		request_topic->dlort_npartitions = nparts;
		
		for (part = 0; part < request_topic->dlort_npartitions;
		    part++) {
			
			request_part = &request_topic->dlort_partitions[part];

			/* Decode the Partition. */
			rc |= DL_DECODE_PARTITION(source,
			    &request_part->dlorp_partition);

			/* Decode the Time. */
			rc |= DL_DECODE_TIMESTAMP(source,
			    &request_part->dlorp_time);
		}

		SLIST_INSERT_HEAD(&request->dlor_topics, request_topic,
		    dlort_entries);
	}

	if (rc == 0) {
		/* ListOffsetRequest successfully decoded. */
		*self = request;
		return 0;
	}

#ifndef _KERNEL
err_list_offset_request:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding ListOffsetRequest.\n");
	*self = NULL;
	return -1;
}

/**
 * Encode the ListOffsetRequest.
 *
 * ListOffsetRequest = ReplicaId [Topics]
 * Topics = TopicName [Partitions]
 * TopicName
 * Partitions = Partition Timestamp
 * Partition
 * Timestamp
 */
int
dl_list_offset_request_encode(struct dl_list_offset_request *self,
    struct dl_bbuf *target)
{
	struct dl_list_offset_request_partition *req_partition;
	struct dl_list_offset_request_topic *req_topic;
	int part, rc = 0;

	DL_ASSERT(self != NULL, "ListOffsetRequest cannot be NULL");
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the ListOffsetRequest ReplicaId into the target. */
	rc |= DL_ENCODE_REPLICA_ID(target, self->dlor_replica_id);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the ListOffsetRequest Topics. */
	rc |= dl_bbuf_put_int32(target, self->dlor_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	SLIST_FOREACH(req_topic, &self->dlor_topics, dlort_entries) {

		/* Encode the Request TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target, req_topic->dlort_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the Partitions. */
		rc |= dl_bbuf_put_int32(target, req_topic->dlort_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < req_topic->dlort_npartitions; part++) {

			req_partition = &req_topic->dlort_partitions[part];

			/* Encode the ListOffsetRequest Partition into the
			 * target.
			 */
			rc |= DL_ENCODE_PARTITION(target,
			    req_partition->dlorp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
			
			/* Encode the ListOffsetRequest Timestamp into the
			 * target.
			 */
			rc |= DL_ENCODE_TIMESTAMP(target,
			    req_partition->dlorp_time);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ListOffsetRequest.\n");
	return -1;
}

