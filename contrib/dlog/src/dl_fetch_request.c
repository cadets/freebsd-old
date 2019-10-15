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

#include <sys/types.h>
#include <sys/queue.h>

#include <stdarg.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_fetch_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

SLIST_HEAD(dl_fetch_request_q, dl_fetch_request_topic);

struct dl_fetch_request_partition {
	int64_t dlfrp_fetch_offset;
	int32_t dlfrp_max_bytes;
	int32_t dlfrp_partition;
};

struct dl_fetch_request_topic {
	SLIST_ENTRY(dl_fetch_request_topic) dlfrt_entries;
	struct sbuf *dlfrt_topic_name;
	int32_t dlfrt_npartitions;
	struct dl_fetch_request_partition dlfrt_partitions[1];
};

struct dl_fetch_request {
	struct dl_request dlfr_super;
	struct dl_fetch_request_q dlfr_topics;
	int32_t dlfr_ntopics;
	int32_t dlfr_replica_id;
	int32_t dlfr_max_wait_time;
	int32_t dlfr_min_bytes;
};

#define DL_DEFAULT_PARTITION 0

static const int32_t DL_DEFAULT_REPLICA_ID = -1;

static int dl_fetch_request_ctor(void *, va_list * app); 
static void dl_fetch_request_dtor(void *);
static int dl_fetch_request_encode_into(void *, struct dl_bbuf *);

extern const void *DL_REQUEST;

static const struct dl_request_class TYPE = {
	{
		sizeof(struct dl_fetch_request),
		dl_fetch_request_ctor,
		dl_fetch_request_dtor,
		NULL	
	},
	NULL,
	dl_fetch_request_encode_into
};

static const void *DL_FETCH_REQUEST = &TYPE;

static int
dl_fetch_request_ctor(void *_self, va_list *ap)
{
	struct dl_fetch_request *self = (struct dl_fetch_request *) _self;
	struct dl_fetch_request_topic *request_topic;

	DL_ASSERT(self != NULL, ("FetchRequest instance cannot be NULL"));

	/* Initialize the Request super class */
	((const struct dl_class *) DL_REQUEST)->dl_ctor(self, ap);

	self->dlfr_ntopics = 1;
	SLIST_INIT(&self->dlfr_topics);
	self->dlfr_replica_id = DL_DEFAULT_REPLICA_ID;
	self->dlfr_min_bytes = va_arg(*ap, int32_t); //min_bytes;
	self->dlfr_max_wait_time = va_arg(*ap, int32_t); //max_wait_time;

	request_topic = (struct dl_fetch_request_topic *)
	    dlog_alloc(sizeof(struct dl_fetch_request_topic));
	DL_ASSERT(request_topic != NULL,
	    ("Failed allocating FetchRequest [topic_data]."));
	if (request_topic == NULL)
		goto err_request_ctor;

	request_topic->dlfrt_topic_name = va_arg(*ap, struct sbuf *);
	DL_ASSERT(request_topic->dlfrt_topic_name != NULL,
	    ("FetchRequest topic name cannot be NULL"));
	request_topic->dlfrt_npartitions = 1;
	request_topic->dlfrt_partitions[0].dlfrp_partition =
	    DL_DEFAULT_PARTITION;
	request_topic->dlfrt_partitions[0].dlfrp_fetch_offset = va_arg(*ap, int64_t); //fetch_offset;
	request_topic->dlfrt_partitions[0].dlfrp_max_bytes = va_arg(*ap, int32_t); //max_bytes;
	
	SLIST_INSERT_HEAD(&self->dlfr_topics,
	    request_topic, dlfrt_entries);

	return 0;

err_request_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating FetchRequest.\n");
	return -1;
}

static void 
dl_fetch_request_dtor(void *_self)
{
	struct dl_fetch_request *self = (struct dl_fetch_request *) _self;
	struct dl_fetch_request_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("FetchRequest cannot be NULL"));

	/* Destroy the Request super class */
	if (((const struct dl_class *) DL_REQUEST)->dl_dtor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_dtor(self);
	
	SLIST_FOREACH_SAFE(req_topic, &self->dlfr_topics, dlfrt_entries,
	    req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlfr_topics);
		SLIST_REMOVE(&self->dlfr_topics, req_topic,
		    dl_fetch_request_topic, dlfrt_entries);

		dlog_free(req_topic);
	};
}

static int
dl_fetch_request_encode_into(void *_self,
    struct dl_bbuf * const target)
{
	struct dl_fetch_request *self = (struct dl_fetch_request *) _self;
	struct dl_fetch_request_partition *request_partition;
	struct dl_fetch_request_topic *request_topic;
	int rc = 0, part;

	DL_ASSERT(self != NULL, ("FetchRequest cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the FetchRequest ReplicaId into the buffer. */
	rc |= DL_ENCODE_REPLICA_ID(target, self->dlfr_replica_id);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the FetchRequest MaxWaitTime into the buffer. */
	rc |= DL_ENCODE_MAX_WAIT_TIME(target, self->dlfr_max_wait_time);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the FetchRequest MinBytes into the buffer. */
	rc |= DL_ENCODE_MIN_BYTES(target, self->dlfr_min_bytes);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the [topic data] into the buffer. */
	rc |= dl_bbuf_put_int32(target, self->dlfr_ntopics);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the FetchRequest ReplicaId into the buffer. */
	SLIST_FOREACH(request_topic, &self->dlfr_topics, dlfrt_entries) {

		/* Encode the FetchRequest TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target,
		    request_topic->dlfrt_topic_name);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));

		/* Encode the [partitions] into the buffer. */	
		rc |= dl_bbuf_put_int32(target,
		    request_topic->dlfrt_npartitions);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));

		for (part = 0; part < request_topic->dlfrt_npartitions;
		    part++) {

			request_partition =
			    &request_topic->dlfrt_partitions[part];

			/* Encode the FetchRequest Partition into the
			 * buffer.
			 */
			rc |= DL_ENCODE_PARTITION(target,
			    request_partition->dlfrp_partition);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));

			/* Encode the FetchRequest FetchOffset into the
			 * buffer.
			 */
			rc |= DL_ENCODE_OFFSET(target,
			    request_partition->dlfrp_fetch_offset);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));

			/* Encode the FetchRequest MaxBytes into the buffer. */
			rc |= DL_ENCODE_MAX_BYTES(target,
			    request_partition->dlfrp_max_bytes);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding FetchRequest.\n");
	return -1;
}

int
dl_fetch_request_new(struct dl_fetch_request **self,
    const int32_t correlation_id, struct sbuf *client,
    const int32_t min_bytes, const int32_t max_wait_time,
    struct sbuf *topic_name, const int64_t fetch_offset,
    const int32_t max_bytes)
{

	return dl_new((void **) self, DL_FETCH_REQUEST, DL_FETCH_API_KEY,
	    correlation_id, client, min_bytes, max_wait_time,
	    topic_name, fetch_offset, max_bytes);
}

void
dl_fetch_request_delete(struct dl_fetch_request *self)
{

	DL_ASSERT(self != NULL, ("FetchRequest instance cannot be NULL."));
	dl_delete(self);
}

int
dl_fetch_request_decode(struct dl_fetch_request **self, struct dl_bbuf *source)
{
	struct dl_fetch_request *request;
	struct dl_fetch_request_topic *request_topic;
	struct dl_fetch_request_partition *request_partition;
	struct sbuf *topic_name;
	int32_t nparts, part, topic, req_size;
	int rc = 0;
	
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL."));
	
	/* Construct the FetchRequest. */
	request = (struct dl_fetch_request *) dlog_alloc(
		sizeof(struct dl_fetch_request));
	DL_ASSERT(request != NULL, ("Failed allocating FetchRequest."));
	if (request == NULL)
		goto err_fetch_request;

	/* Decode the request size. */	
	rc = DL_DECODE_REQUEST_SIZE(source, &req_size);

	/* Decode the Request Header into the buffer. */
	if (dl_request_header_decode(
	    (struct dl_request *) request, source) == 0) {

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

			/* Decode the FetchRequest TopicName. */
			rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);
		
			/* Decode the [data] array. */
			rc |= dl_bbuf_get_int32(source, &nparts);

			/* Decode the [response_data] from the buffer. */	
			request_topic = (struct dl_fetch_request_topic *)
			dlog_alloc(sizeof(struct dl_fetch_request_topic) +
			(nparts - 1) * sizeof(struct dl_fetch_request_partition));
			DL_ASSERT(request_topic != NULL,
			    ("Failed allocating FetchRequest [data]."));
			if (request_topic == NULL) {
				dl_fetch_request_delete(request);
				goto err_fetch_request;
			}

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
	}

err_fetch_request:
	DLOGTR0(PRIO_HIGH, "Failed allocating FetchRequest.\n");
	*self = NULL;
	return -1;
}
