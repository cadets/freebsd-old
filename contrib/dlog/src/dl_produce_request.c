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
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_produce_request.h"
#include "dl_request.h"
#include "dl_utils.h"

int
dl_produce_request_new(struct dl_request **self, const int32_t correlation_id,
    struct sbuf *client, int16_t required_acks, int32_t timeout,
    struct sbuf *topic_name, struct dl_message_set *message_set)
{
	struct dl_produce_request *produce_request;
	struct dl_produce_request_partition *req_part;
	struct dl_produce_request_topic *req_topic;
	struct dl_request *request;
	int rc;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL,
	    ("ProduceRequest topic name cannot be NULL."));

	/* Construct the ProduceRequest. */
	rc = dl_request_new(&request, DL_PRODUCE_API_KEY, correlation_id,
	    client);
#ifdef _KERNEL
	DL_ASSERT(rc != 0, ("Failed to allocate Request.\n"));
#else
	if (rc != 0)
		goto err_request_ctor;
#endif
	produce_request = request->dlrqm_produce_request =
	    (struct dl_produce_request *) dlog_alloc(
		sizeof(struct dl_produce_request));
#ifdef _KERNEL
	DL_ASSERT(produce_request != NULL,
	    ("Failed to allocate ProduceRequest."));
#else
	if (produce_request == NULL) {
		dl_request_delete(request);
		goto err_request_ctor;
	}
#endif
	produce_request->dlpr_required_acks = required_acks;
	produce_request->dlpr_timeout = timeout;

	/* Construct a single Topic/Partition. */
	produce_request->dlpr_ntopics = 1;
	SLIST_INIT(&produce_request->dlpr_topics);
	
	req_topic = (struct dl_produce_request_topic *)
	    dlog_alloc(sizeof(struct dl_produce_request_topic));
#ifdef _KERNEL
	DL_ASSERT(req_topic != NULL,
	    ("Failed to allocate ProduceRequest [topic_data]."));
#else
	if (req_topic == NULL) {
		dl_produce_request_delete(produce_request);
		dl_request_delete(request);
		goto err_request_ctor;
	}
#endif
	req_topic->dlprt_topic_name = topic_name;
	
	req_topic->dlprt_npartitions = 1;
	req_part = &req_topic->dlprt_partitions[0];

	/* Default partition. */
	req_part->dlprp_partition = 0;

	/* Construct the MessageSet. */
	req_part->dlprp_message_set = message_set;
	
	SLIST_INSERT_HEAD(&produce_request->dlpr_topics, req_topic,
	    dlprt_entries);

	*self = request;
	return 0;

#ifndef _KERNEL
err_request_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	*self = NULL;
	return -1;
#endif
}

int
dl_produce_request_new_nomsg(struct dl_request **self,
    const int32_t correlation_id, struct sbuf *client, int16_t required_acks,
    int32_t timeout, struct sbuf *topic_name)
{
	return dl_produce_request_new(self, correlation_id, client,
	    required_acks, timeout, topic_name, NULL);
}

void
dl_produce_request_delete(struct dl_produce_request *self)
{
	struct dl_produce_request *produce_request = self;
	struct dl_produce_request_topic *req_topic, *req_topic_tmp;
	struct dl_produce_request_partition *req_part;
	int part;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL."));

	SLIST_FOREACH_SAFE(req_topic, &produce_request->dlpr_topics,
	    dlprt_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&produce_request->dlpr_topics);
		SLIST_REMOVE(&produce_request->dlpr_topics, req_topic,
		    dl_produce_request_topic, dlprt_entries);

		for (part = 0; part< req_topic->dlprt_npartitions; part++) {

			req_part = &req_topic->dlprt_partitions[part];

			if (req_part->dlprp_message_set != NULL)
				dl_message_set_delete(
				    req_part->dlprp_message_set);
		}
		dlog_free(req_topic);
	};
	dlog_free(self);
}

int
dl_produce_request_decode(struct dl_produce_request **self,
    struct dl_bbuf *source)
{
	struct dl_produce_request *request;
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_part;
	struct sbuf *topic_name;
	int32_t topic, npartitions, part;
	int rc = 0;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));
	
	/* Construct the ProduceRequest. */
	request = (struct dl_produce_request *) dlog_alloc(
	    sizeof(struct dl_produce_request));
#ifdef _KERNEL
	DL_ASSERT(request != NULL, ("Failed to allocate ProduceRequest.\n"));
#else
	if (request == NULL)
		goto err_produce_request;
#endif
	/* Decode the ProduceRequest RequiredAcks. */
	rc |= DL_DECODE_REQUIRED_ACKS(source, &request->dlpr_required_acks);

	/* Decode the ProduceRequest Timeout. */
	rc |= DL_DECODE_TIMEOUT(source, &request->dlpr_timeout);

	SLIST_INIT(&request->dlpr_topics);

	/* Decode the [topic_data] array. */
	rc |= dl_bbuf_get_int32(source, &request->dlpr_ntopics);
	
	for (topic = 0; topic < request->dlpr_ntopics; topic++) {

		/* Decode the ProduceRequest TopicName. */
		rc |= DL_DECODE_TOPIC_NAME(source, &topic_name);
	
		/* Decode the [data] array. */
		rc |= dl_bbuf_get_int32(source, &npartitions);
		
		/* Allocate the Topic/Partitions. */
		req_topic = (struct dl_produce_request_topic *)
		    dlog_alloc(sizeof(struct dl_produce_request_topic) + 
			(npartitions - 1) *
			sizeof(struct dl_produce_request_partition));
#ifdef _KERNEL
		DL_ASSERT(req_topic != NULL, ("Failed to allocate Request."));
#else
		if (req_topic == NULL) {
			dl_produce_request_delete(request);
			goto err_produce_request;
		}
#endif
		req_topic->dlprt_npartitions = npartitions;
		req_topic->dlprt_topic_name = topic_name;

		for (part = 0; part < req_topic->dlprt_npartitions; part++) {

			req_part = &req_topic->dlprt_partitions[part];

			/* Decode the ProduceRequest Partition. */
			rc |= DL_DECODE_PARTITION(source,
			    &req_part->dlprp_partition);
		
			/* Decode the MessageSet. */
			rc |= dl_message_set_decode(
			    &req_part->dlprp_message_set, source);
		}

		SLIST_INSERT_HEAD(&request->dlpr_topics, req_topic,
		    dlprt_entries);
	}

	if (rc == 0) {
		/* ProduceRequest successfully decoded. */
		*self = request;
		return 0;
	}

#ifndef _KERNEL
err_produce_request:
#endif
	DLOGTR0(PRIO_HIGH, "Failed decoding ProduceRequest.\n");
	*self = NULL;
	return -1;
}

int
dl_produce_request_encode(
    struct dl_produce_request const * const self, struct dl_bbuf *target)
{
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_part;
	int rc = 0, part;
		
	DL_ASSERT(self != NULL, ("ProduceRequest cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the Request RequiredAcks into the buffer. */
	rc |= DL_ENCODE_REQUIRED_ACKS(target, self->dlpr_required_acks);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the Request Timeout into the buffer. */
	rc |= DL_ENCODE_TIMEOUT(target, self->dlpr_timeout);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	/* Encode the [topic_data] array. */
	rc |= dl_bbuf_put_int32(target, self->dlpr_ntopics);
#ifdef _KERNEL
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));
#endif

	SLIST_FOREACH(req_topic, &self->dlpr_topics, dlprt_entries) {

		/* Encode the Request TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target, req_topic->dlprt_topic_name);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		     ("Insert into autoextending buffer cannot fail."));
#endif
	 
		/* Encode the [data] array. */
		rc |= dl_bbuf_put_int32(target, req_topic->dlprt_npartitions);
#ifdef _KERNEL
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
#endif

		for (part = 0; part < req_topic->dlprt_npartitions; part++) {
			
			req_part = &req_topic->dlprt_partitions[part];

			/* Encode the Partition into the buffer. */
			rc |= DL_ENCODE_PARTITION(target,
			    req_part->dlprp_partition);
#ifdef _KERNEL
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));
#endif

			if (req_part->dlprp_message_set != NULL) {

				/* Encode the MessageSet */
				rc |= dl_message_set_encode(
				    req_part->dlprp_message_set,
				    target);
			}
		}
	}

	if (rc == 0)
		return 0;

	DLOGTR0(PRIO_HIGH, "Failed encoding ProduceRequest.\n");
	return -1;
}
