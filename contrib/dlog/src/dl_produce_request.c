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

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_protocol.h"
#include "dl_produce_request.h"
#include "dl_request.h"
#include "dl_utils.h"
	
#define DL_ENCODE_TRANSACTIONAL_ID(target) dl_encode_string(target, NULL);

#define DL_DECODE_TRANSACTIONAL_ID(source, target) dl_decode_string(source, target);

static int dl_produce_request_ctor(void *, va_list * app); 
static void dl_produce_request_dtor(void *);
static int dl_produce_request_encode_into(void *, struct dl_bbuf *);

SLIST_HEAD(dl_produce_request_topics, dl_produce_request_topic);

struct dl_produce_request_partition {
	struct dl_message_set *dlprp_message_set;
	int32_t dlprp_num;
};

struct dl_produce_request_topic {
	SLIST_ENTRY(dl_produce_request_topic) dlprt_entries;
	struct sbuf *dlprt_name;
	int32_t dlprt_npartitions;
	struct dl_produce_request_partition dlprt_partitions[1];
};

struct dl_produce_request {
	struct dl_request dlpr_super;
	struct dl_produce_request_topics dlpr_topics;
	int32_t dlpr_timeout;
	int32_t dlpr_ntopics;
	dl_required_acks dlpr_required_acks;
};

extern const void *DL_REQUEST;

static const struct dl_request_class TYPE = {
	{
		sizeof(struct dl_produce_request),
		dl_produce_request_ctor,
		dl_produce_request_dtor,
		NULL	
	},
	NULL,
	dl_produce_request_encode_into
};

static const void *DL_PRODUCE_REQUEST = &TYPE;

static int
dl_produce_request_ctor(void *super, va_list *ap)
{
	struct dl_produce_request *self = (struct dl_produce_request *) super;
	struct dl_produce_request_partition *req_part;
	struct dl_produce_request_topic *req_topic;

	DL_ASSERT(self != NULL, ("ProduceRequest cannot be NULL"));

	/* Initialize the Request super class */
	if (((const struct dl_class *) DL_REQUEST)->dl_ctor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_ctor(self, ap);

	self->dlpr_required_acks = va_arg(*ap, int);
	self->dlpr_timeout = va_arg(*ap, int);

	/* Construct a single Topic/Partition. */
	self->dlpr_ntopics = 1;
	SLIST_INIT(&self->dlpr_topics);
	
	req_topic = (struct dl_produce_request_topic *)
	    dlog_alloc(sizeof(struct dl_produce_request_topic));
	DL_ASSERT(req_topic != NULL,
	    ("Failed to allocate ProduceRequest [topic_data]"));
	if (req_topic == NULL)
		goto err_request_ctor;

	req_topic->dlprt_name = sbuf_new_auto();
	sbuf_cat(req_topic->dlprt_name, va_arg(*ap, char *));
	sbuf_finish(req_topic->dlprt_name);
	DL_ASSERT(req_topic->dlprt_name != NULL,
	    ("Topic name to produce to cannot be NULL"));

	req_topic->dlprt_npartitions = 1;
	req_part = &req_topic->dlprt_partitions[0];

	/* Default partition. */
	req_part->dlprp_num = 0;

	/* Construct the MessageSet. */
	req_part->dlprp_message_set = va_arg(*ap, struct dl_message_set *);
	
	SLIST_INSERT_HEAD(&self->dlpr_topics, req_topic,
	    dlprt_entries);

	return 0;

err_request_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instatiating ProduceRequest.\n");
	return -1;
}

static void 
dl_produce_request_dtor(void *_self)
{
	struct dl_produce_request *self = (struct dl_produce_request *) _self;
	struct dl_produce_request_topic *req_topic, *req_topic_tmp;
	struct dl_produce_request_partition *req_part;

	DL_ASSERT(self != NULL, ("ProduceRequest cannot be NULL"));

	/* Destroy the Request super class */
	if (((const struct dl_class *) DL_REQUEST)->dl_dtor != NULL)
		((const struct dl_class *) DL_REQUEST)->dl_dtor(self);

	SLIST_FOREACH_SAFE(req_topic, &self->dlpr_topics,
	    dlprt_entries, req_topic_tmp) {

		req_topic = SLIST_FIRST(&self->dlpr_topics);
		SLIST_REMOVE(&self->dlpr_topics, req_topic,
		    dl_produce_request_topic, dlprt_entries);

		for (int part = 0; part < req_topic->dlprt_npartitions; part++) {

			req_part = &req_topic->dlprt_partitions[part];

			if (req_part->dlprp_message_set != NULL)
				dl_message_set_delete(
				    req_part->dlprp_message_set);
		}

		sbuf_delete(req_topic->dlprt_name);
		dlog_free(req_topic);
	};
}

static int
dl_produce_request_encode_into(void * _self, struct dl_bbuf *target)
{
	struct dl_produce_request *self = (struct dl_produce_request *) _self;
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_part;
	int rc = 0, part;
		
	DL_ASSERT(self != NULL, ("ProduceRequest cannot be NULL"));
	DL_ASSERT((dl_bbuf_get_flags(target) & DL_BBUF_AUTOEXTEND) != 0,
	    ("Target buffer must be auto-extending"));

	/* Encode the Request TransactionalId into the buffer. */
	if (DLOG_API_VERSION >= DLOG_API_V3) {
		rc |= DL_ENCODE_TRANSACTIONAL_ID(target);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));
	}

	/* Encode the Request RequiredAcks into the buffer. */
	rc |= DL_ENCODE_REQUIRED_ACKS(target, self->dlpr_required_acks);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the Request Timeout into the buffer. */
	rc |= DL_ENCODE_TIMEOUT(target, self->dlpr_timeout);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	/* Encode the [topic_data] array. */
	rc |= dl_bbuf_put_int32(target, self->dlpr_ntopics);
	DL_ASSERT(rc == 0, ("Insert into autoextending buffer cannot fail."));

	SLIST_FOREACH(req_topic, &self->dlpr_topics, dlprt_entries) {

		/* Encode the Request TopicName into the buffer. */
		rc |= DL_ENCODE_TOPIC_NAME(target, req_topic->dlprt_name);
		DL_ASSERT(rc == 0,
		     ("Insert into autoextending buffer cannot fail."));
	 
		/* Encode the [data] array. */
		rc |= dl_bbuf_put_int32(target, req_topic->dlprt_npartitions);
		DL_ASSERT(rc == 0,
		    ("Insert into autoextending buffer cannot fail."));

		for (part = 0; part < req_topic->dlprt_npartitions; part++) {
			
			req_part = &req_topic->dlprt_partitions[part];

			/* Encode the Partition into the buffer. */
			rc |= DL_ENCODE_PARTITION(target, req_part->dlprp_num);
			DL_ASSERT(rc == 0,
			    ("Insert into autoextending buffer cannot fail."));

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

int
dl_produce_request_new(struct dl_produce_request **self, const int32_t correlation_id,
    struct sbuf *client, dl_required_acks required_acks, int32_t timeout,
    char *topic_name, struct dl_message_set *message_set)
{

	return dl_new((void **) self, DL_PRODUCE_REQUEST, DL_PRODUCE_API_KEY,
	    correlation_id, client, required_acks, timeout, topic_name,
	    message_set);
}

int
dl_produce_request_new_nomsg(struct dl_produce_request **self,
    const int32_t correlation_id, struct sbuf *client, dl_required_acks required_acks,
    int32_t timeout, char *topic_name)
{

	return dl_new((void **) self, DL_PRODUCE_REQUEST, DL_PRODUCE_API_KEY,
	    correlation_id, client, required_acks, timeout, topic_name, NULL);
}

void
dl_produce_request_delete(struct dl_produce_request *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	dl_delete(self);
}

int
dl_produce_request_decode(struct dl_produce_request **self,
    struct dl_bbuf *source)
{
	struct dl_produce_request *request;
	struct dl_produce_request_topic *req_topic;
	struct dl_produce_request_partition *req_part;
	struct sbuf *topic_name, *tx_id;
	int32_t topic, npartitions, part, req_size;
	int rc = 0;

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	DL_ASSERT(source != NULL, ("Source buffer cannot be NULL"));

	/* Construct the ProduceRequest. */
	request = (struct dl_produce_request *) dlog_alloc(
	    sizeof(struct dl_produce_request));
	DL_ASSERT(request != NULL, ("Failed to allocate ProduceRequest.\n"));
	if (request == NULL)
		goto err_produce_request;

	/* Decode the request size. */	
	rc = DL_DECODE_REQUEST_SIZE(source, &req_size);

	/* Decode the Request Header into the buffer. */
	if (dl_request_header_decode(
	    (struct dl_request *) request, source) == 0) {

		/* Decode the Request TransactionalId. */
		if (DLOG_API_VERSION >= DLOG_API_V3) {

			rc |= DL_DECODE_TRANSACTIONAL_ID(source, &tx_id);
		}

		/* Decode the ProduceRequest RequiredAcks. */
		rc |= DL_DECODE_REQUIRED_ACKS(source, (int16_t *) &request->dlpr_required_acks);

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
			DL_ASSERT(req_topic != NULL, ("Failed to allocate Request."));
			if (req_topic == NULL) {
				//dl_produce_request_delete(request);
				goto err_produce_request;
			}

			req_topic->dlprt_npartitions = npartitions;
			req_topic->dlprt_name = topic_name;

			for (part = 0; part < req_topic->dlprt_npartitions; part++) {

				req_part = &req_topic->dlprt_partitions[part];

				/* Decode the ProduceRequest Partition. */
				rc |= DL_DECODE_PARTITION(source,
				&req_part->dlprp_num);
			
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
	}

err_produce_request:
	DLOGTR0(PRIO_HIGH, "Failed decoding ProduceRequest.\n");
	*self = NULL;
	return -1;
}

int
dl_produce_request_get_singleton_topic(struct dl_produce_request *self,
    struct dl_produce_request_topic **topic)
{

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	DL_ASSERT(SLIST_EMPTY(&self->dlpr_topics) == 0,
	    ("ProduceRequest instance must have a topic"));
	DL_ASSERT(topic != NULL, ("ProduceRequestTopic instance cannot be NULL"));

	if (SLIST_EMPTY(&self->dlpr_topics) == 0) {

		*topic = SLIST_FIRST(&self->dlpr_topics);
		return 0;
	}

	*topic = NULL;
	return -1;
}

int32_t
dl_produce_request_get_timeout(struct dl_produce_request *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	return self->dlpr_timeout;
}

dl_required_acks
dl_produce_request_get_required_acks(struct dl_produce_request *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	return self->dlpr_required_acks;
}

void
dl_produce_request_topic_foreach(struct dl_produce_request *self,
    dl_produce_request_topic_callback cb, void *arg)
{
	struct dl_produce_request_topic *req_topic;
	
	SLIST_FOREACH(req_topic, &self->dlpr_topics, dlprt_entries) {

		/* Invoke the callback */
		(*cb)(req_topic, arg);
	};
}

struct sbuf *
dl_produce_request_topic_get_name(struct dl_produce_request_topic *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequestTopic instance cannot be NULL"));
	return self->dlprt_name;
}

int
dl_produce_request_topic_get_singleton_partition(struct dl_produce_request_topic *self,
    struct dl_produce_request_partition **part)
{

	DL_ASSERT(self != NULL, ("ProduceRequest instance cannot be NULL"));
	DL_ASSERT(part != NULL, ("ProduceRequestPartition instance cannot be NULL"));

	*part = &self->dlprt_partitions[0];
	return 0;
}

int32_t
dl_produce_request_partition_get_num(struct dl_produce_request_partition *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequestPartition instance cannot be NULL"));

	return self->dlprp_num;
}

struct dl_message_set *
dl_produce_request_partition_get_message_set(struct dl_produce_request_partition *self)
{

	DL_ASSERT(self != NULL, ("ProduceRequestPartition instance cannot be NULL"));

	return self->dlprp_message_set;
}

void
dl_produce_request_partition_foreach(struct dl_produce_request_topic *self,
    dl_produce_request_partition_callback cb, void *arg)
{

	DL_ASSERT(self != NULL, ("ProduceRequestTopic instance cannot be NULL"));
	
	for (int i =0; i < self->dlprt_npartitions; i++) {

		/* Invoke the callback */
		(*cb)(&self->dlprt_partitions[i], arg);
	};
}
