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

#include <sys/types.h>
#include <sys/queue.h>

#include <stdarg.h>

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_list_offset_request.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_utils.h"

SLIST_HEAD(dl_list_offset_request_topics, dl_list_offset_request_topic);

struct dl_list_offset_request_partition {
	int32_t dlorp_partition;
	int64_t dlorp_time;
};

struct dl_list_offset_request_topic {
	SLIST_ENTRY(dl_list_offset_request_topic) dlort_entries;
	struct sbuf *dlort_topic_name;
	int32_t dlort_npartitions;
	struct dl_list_offset_request_partition dlort_partitions[1];
};

struct dl_list_offset_request {
	struct dl_request dlfr_super;
	struct dl_list_offset_request_topics dlor_topics;
	int32_t dlor_ntopics;
	int32_t dlor_replica_id;
};

static int dl_list_offset_request_ctor(void *, va_list * app); 
static void dl_list_offset_request_dtor(void *);
static int dl_list_offset_request_encode_into(void *, struct dl_bbuf *);

extern const void *DL_REQUEST;

static const struct dl_request_class TYPE = {
	{
		sizeof(struct dl_list_offset_request),
		dl_list_offset_request_ctor,
		dl_list_offset_request_dtor,
		NULL
	},
	NULL,
	dl_list_offset_request_encode_into
};

static const void *DL_LIST_OFFSET_REQUEST = &TYPE;

static int
dl_list_offset_request_ctor(void *_self, va_list *ap)
{
	struct dl_list_offset_request *self = (struct dl_list_offset_request *) _self;
	struct dl_list_offset_request_partition *request_part;
	struct dl_list_offset_request_topic *request_topic;

	DL_ASSERT(self != NULL, ("FetchRequest instance cannot be NULL"));

	/* Initialize the Request super class */
	((const struct dl_class *) DL_REQUEST)->dl_ctor(self, ap);

	SLIST_INIT(&self->dlor_topics);
	self->dlor_ntopics = 1;
	self->dlor_replica_id = 0;

	/* Construct a single Topic/Partition. */
	request_topic = (struct dl_list_offset_request_topic *)
	    dlog_alloc(sizeof(struct dl_list_offset_request_topic));	    
	DL_ASSERT(request_topic != NULL,
	    ("Failed allocating ListOffsetRequest [topic_data]."));
	if (request_topic == NULL)
		goto err_request_ctor;

	request_topic->dlort_topic_name = va_arg(*ap, struct sbuf *);
	DL_ASSERT(request_topic->dlort_topic_name != NULL,
	    ("ListOffset request topic name cannot be NULL"));
	request_topic->dlort_npartitions = 1;

	request_part = &request_topic->dlort_partitions[0];
	request_part->dlorp_partition = 0;
	request_part->dlorp_time = va_arg(*ap, int64_t); //time;

	SLIST_INSERT_HEAD(&self->dlor_topics, request_topic, dlort_entries);

	return 0;

err_request_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ListOffsetRequest.\n");
	return -1;
}

static void 
dl_list_offset_request_dtor(void *_self)
{
	struct dl_list_offset_request *self = (struct dl_list_offset_request *) _self;
	struct dl_list_offset_request_topic *req_topic, *req_topic_tmp;

	DL_ASSERT(self != NULL, ("FetchRequest cannot be NULL"));

	/* Destroy the Request super class */
	if (((const struct dl_class *) DL_REQUEST)->dl_dtor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_dtor(self);

	SLIST_FOREACH_SAFE(req_topic, &self->dlor_topics,
	    dlort_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlor_topics);
		SLIST_REMOVE(&self->dlor_topics, req_topic,
		    dl_list_offset_request_topic, dlort_entries);

		dlog_free(req_topic);
	};
	//dlog_free(self);
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
static int
//dl_list_offset_request_encode_into(struct dl_request const * const _self,
dl_list_offset_request_encode_into(void *_self,
    struct dl_bbuf *target)
{
	struct dl_list_offset_request *self =
	    (struct dl_list_offset_request *) _self;
	struct dl_list_offset_request_partition *req_partition;
	struct dl_list_offset_request_topic *req_topic;
	int part, rc = 0;

	DL_ASSERT(self != NULL, "ListOffsetRequest cannot be NULL");
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the ListOffsetRequest ReplicaId into the target. */
	rc |= DL_ENCODE_REPLICA_ID(target, self->dlor_replica_id);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the ListOffsetRequest Topics. */
	rc |= dl_bbuf_put_int32(target, self->dlor_ntopics);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	SLIST_FOREACH(req_topic, &self->dlor_topics, dlort_entries) {

		/* Encode the Request TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target, req_topic->dlort_topic_name);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));

		/* Encode the Partitions. */
		rc |= dl_bbuf_put_int32(target, req_topic->dlort_npartitions);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));

		for (part = 0; part < req_topic->dlort_npartitions; part++) {

			req_partition = &req_topic->dlort_partitions[part];

			/* Encode the ListOffsetRequest Partition into the
			 * target.
			 */
			rc |= DL_ENCODE_PARTITION(target,
			    req_partition->dlorp_partition);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
			
			/* Encode the ListOffsetRequest Timestamp into the
			 * target.
			 */
			rc |= DL_ENCODE_TIMESTAMP(target,
			    req_partition->dlorp_time);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ListOffsetRequest.\n");
	return -1;
}

/**
 * ListOffsetRequest constructor. 
 */
int
dl_list_offset_request_new(struct dl_list_offset_request **self,
    int32_t correlation_id, struct sbuf *client_id, struct sbuf *topic_name,
    int64_t time)
{

	return dl_new((void **) self, DL_LIST_OFFSET_REQUEST, DL_OFFSET_API_KEY,
	    correlation_id, client_id, topic_name, time);
}

/**
 * ListOffsetRequest destructor. 
 */
void
dl_list_offset_request_delete(struct dl_list_offset_request *self)
{

	DL_ASSERT(self != NULL, ("ListOffsetRequest instance cannot be NULL."));
	dl_delete(self);
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
    struct dl_bbuf * const source)
{
	struct dl_list_offset_request *request;
	struct dl_list_offset_request_topic *request_topic;
	struct dl_list_offset_request_partition *request_part;
	struct sbuf *topic_name;
	int32_t topic_it, nparts, part, req_size;
	int rc = 0;

	DL_ASSERT(source != NULL, "Source buffer cannot be NULL\n");

	/* Construct the ListOffsetRequest. */
	request = (struct dl_list_offset_request *) dlog_alloc(
	    sizeof(struct dl_list_offset_request));
	DL_ASSERT(request != NULL, ("Failed to allocate ProduceRequest.\n"));
	if (request == NULL)
		goto err_list_offset_request;

	/* Decode the request size. */	
	rc = DL_DECODE_REQUEST_SIZE(source, &req_size);

	/* Decode the Request Header into the buffer. */
	if (dl_request_header_decode(
	    (struct dl_request *) request, source) == 0) {

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
			DL_ASSERT(request != NULL,
			    ("Failed to allocate ProduceRequest.\n"));
			if (request_topic == NULL) {

				dl_list_offset_request_delete(request);
				goto err_list_offset_request;
			}

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
	}

err_list_offset_request:
	DLOGTR0(PRIO_HIGH, "Failed decoding ListOffsetRequest.\n");
	*self = NULL;
	return -1;
}
