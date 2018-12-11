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
#include "dl_fetch_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

#define DL_DEFAULT_PARTITION 0

static const int32_t DL_DEFAULT_REPLICA_ID = -1;

extern int dl_fetch_request_new(struct dl_request **self,
    const int32_t correlation_id, struct sbuf *client_id,
    struct sbuf *topic_name, const int32_t min_bytes,
    const int32_t max_wait_time, const int64_t fetch_offset,
    const int32_t max_bytes)
{
	struct dl_request *request;
	struct dl_fetch_request *fetch_request;
	struct dl_fetch_request_topic *request_topic;
	int rc;

	DL_ASSERT(self != NULL, "FetchRequest instance cannot be NULL");
	DL_ASSERT(topic_name, ("FetchRequest TopicName cannot be empty.\n"));

	/* Construct the super class Request. */
	rc = dl_request_new(&request, DL_FETCH_API_KEY, correlation_id,
	    client_id);
#ifdef _KERNEL
	DL_ASSERT(rc != 0, ("Failed allocating FetchRequest."));
#else
	if (rc != 0)
		goto err_request_ctor;
#endif
	/* Construct the FetchRequest. */
	fetch_request = request->dlrqm_fetch_request =
	    (struct dl_fetch_request *) dlog_alloc(
		sizeof(struct dl_fetch_request));
#ifdef _KERNEL
	DL_ASSERT(fetch_request != NULL, ("Failed allocating FetchRequest."));
#else
	if (fetch_request == NULL) {
		dl_request_delete(request);
		goto err_request_ctor;
	}
#endif
	fetch_request->dlfr_replica_id = DL_DEFAULT_REPLICA_ID;
	fetch_request->dlfr_max_wait_time = max_wait_time;
	fetch_request->dlfr_min_bytes = min_bytes;
	
	fetch_request->dlfr_ntopics = 1;
	SLIST_INIT(&fetch_request->dlfr_topics);

	request_topic = (struct dl_fetch_request_topic *)
	    dlog_alloc(sizeof(struct dl_fetch_request_topic));
#ifdef _KERNEL
	DL_ASSERT(request_topic != NULL,
	    ("Failed allocating FetchRequest [topic_data]."));
#else
	if (request_topic == NULL) {
		dl_request_delete(request);
		dl_fetch_request_delete(fetch_request);
		goto err_request_ctor;

	}
#endif
	request_topic->dlfrt_topic_name = topic_name;
	request_topic->dlfrt_npartitions = 1;
	request_topic->dlfrt_partitions[0].dlfrp_partition =
	    DL_DEFAULT_PARTITION;
	request_topic->dlfrt_partitions[0].dlfrp_fetch_offset = fetch_offset;
	request_topic->dlfrt_partitions[0].dlfrp_max_bytes = max_bytes;
	
	SLIST_INSERT_HEAD(&fetch_request->dlfr_topics,
	    request_topic, dlfrt_entries);

	*self = request;
	return 0;

#ifndef _KERNEL
err_request_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

void
dl_fetch_request_delete(struct dl_fetch_request *self)
{
	struct dl_fetch_request_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("FetchRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &self->dlfr_topics, dlfrt_entries,
	    req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlfr_topics);
		SLIST_REMOVE(&self->dlfr_topics, req_topic,
		    dl_fetch_request_topic, dlfrt_entries);

		dlog_free(req_topic);
	};
	dlog_free(self);
}

int
dl_fetch_request_decode(struct dl_fetch_request **self, struct dl_bbuf *source)
{
	struct dl_fetch_request *request;
	struct dl_fetch_request_topic *request_topic;
	struct dl_fetch_request_partition *request_partition;
	struct sbuf *topic_name;
	int32_t nparts, part, topic;
	int rc = 0;
	
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL."));
	
	/* Construct the FetchRequest. */
	request = (struct dl_fetch_request *) dlog_alloc(
		sizeof(struct dl_fetch_request));
#ifdef _KERNEL
	DL_ASSERT(request != NULL, ("Failed allocating FetchRequest."));
#else
	if (request == NULL)
		goto err_fetch_request;
#endif
	/* Decode the FetchRequest ReplicaId from the buffer. */
	rc |= DL_DECODE_REPLICA_ID(source, &request->dlfr_replica_id);

	/* Decode the FetchRequest MaxWaitTime from the buffer. */
	rc |= DL_DECODE_MAX_WAIT_TIME(source, &request->dlfr_max_wait_time);

	/* Decode the FetchRequest MinBytes from the buffer. */
	rc |= DL_DECODE_MIN_BYTES(source, &request->dlfr_min_bytes);
	
	SLIST_INIT(&request->dlfr_topics);

	/* Decode the [topic_data] from the buffer. */
	rc |= dl_bbuf_get_int32(source, &request->dlfr_ntopics);

	for (topic = 0; topic < request->dlfr_ntopics; topic++) {

		/* Decode the ProduceRequest TopicName. */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);
	
		/* Decode the [data] array. */
		rc |= dl_bbuf_get_int32(source, &nparts);

		/* Decode the [response_data] from the buffer. */	
		request_topic = (struct dl_fetch_request_topic *)
		    dlog_alloc(sizeof(struct dl_fetch_request_topic) +
	 	    (nparts - 1) * sizeof(struct dl_fetch_request_partition));
#ifdef _KERNEL
		DL_ASSERT(request_topic != NULL,
		    ("Failed allocating FetchRequest [data]."));
#else
		if (request_topic == NULL) {
			dl_fetch_request_delete(request);
			goto err_fetch_request;
		}
#endif
		request_topic->dlfrt_npartitions = nparts;
		request_topic->dlfrt_topic_name = topic_name;

		for (part = 0; part < request_topic->dlfrt_npartitions;
		    part++) {

			request_partition =
			    &request_topic->dlfrt_partitions[part];

			/* Decode the FetchRequest Partition from the
			 * buffer.
			 */
			rc |= dl_bbuf_get_int32(source,
			    &request_partition->dlfrp_partition);

			/* Decode the FetchRequest Offset. */
			rc |= dl_bbuf_get_int64(source,
			    &request_partition->dlfrp_fetch_offset);

			/* Decode the FetchRequest MaxBytes. */
			rc |= dl_bbuf_get_int32(source,
			    &request_partition->dlfrp_max_bytes);
		}

		SLIST_INSERT_HEAD(&request->dlfr_topics, request_topic,
		    dlfrt_entries);
	}

	if (rc == 0) {
		/* FetchRequest successfully decoded. */
		*self = request;
		return 0;
	}

#ifndef _KERNEL
err_fetch_request:
#endif
	DLOGTR0(PRIO_HIGH, "Failed allocating FetchRequest.\n");
	*self = NULL;
	return -1;
}

int
dl_fetch_request_encode(struct dl_fetch_request *self, struct dl_bbuf *target)
{
	struct dl_fetch_request_partition *request_partition;
	struct dl_fetch_request_topic *request_topic;
	int rc = 0, part;

	DL_ASSERT(self != NULL, ("FetchRequest cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the FetchRequest ReplicaId into the buffer. */
	rc |= DL_ENCODE_REPLICA_ID(target, self->dlfr_replica_id);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the FetchRequest MaxWaitTime into the buffer. */
	rc |= DL_ENCODE_MAX_WAIT_TIME(target, self->dlfr_max_wait_time);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the FetchRequest MinBytes into the buffer. */
	rc |= DL_ENCODE_MIN_BYTES(target, self->dlfr_min_bytes);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the [topic data] into the buffer. */
	rc |= dl_bbuf_put_int32(target, self->dlfr_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the FetchRequest ReplicaId into the buffer. */
	SLIST_FOREACH(request_topic, &self->dlfr_topics, dlfrt_entries) {

		/* Encode the FetchRequest TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target,
		    request_topic->dlfrt_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		/* Encode the [partitions] into the buffer. */	
		rc |= dl_bbuf_put_int32(target,
		    request_topic->dlfrt_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < request_topic->dlfrt_npartitions;
		    part++) {

			request_partition =
			    &request_topic->dlfrt_partitions[part];

			/* Encode the FetchRequest Partition into the
			 * buffer.
			 */
			rc |= DL_ENCODE_PARTITION(target,
			    request_partition->dlfrp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Encode the FetchRequest FetchOffset into the
			 * buffer.
			 */
			rc |= DL_ENCODE_OFFSET(target,
			    request_partition->dlfrp_fetch_offset);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			/* Encode the FetchRequest MaxBytes into the buffer. */
			rc |= DL_ENCODE_MAX_BYTES(target,
			    request_partition->dlfrp_max_bytes);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ProduceRequest.\n");
	return -1;
}
