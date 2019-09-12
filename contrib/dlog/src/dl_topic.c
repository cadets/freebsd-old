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
#include <sys/sbuf.h>
#include <sys/queue.h>

#ifndef _KERNEL
#include <string.h>
#endif

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_message_set.h"
#include "dl_record_batch.h"
#include "dl_request.h"
#include "dl_topic.h"
#include "dl_utils.h"

extern uint32_t hashlittle(const void *, size_t, uint32_t);

/**
 * Class representing a Kafka topic managed by dlog/dlogd.
 */
struct dl_topic {
	LIST_ENTRY(dl_topic) dlt_entries;
	struct dl_record_batch *dlt_rec_batch;
	struct dl_segment *dlt_seg;
	struct sbuf *dlt_name;
	nvlist_t *dlt_props;
};

struct dl_topic_hashmap {
	LIST_HEAD(dl_topics, dl_topic) *dltm_hashtbl;
	unsigned long dltm_hashmask;
};

static int produce_v1(struct dl_topic *, char *, unsigned char *, size_t);
static int produce_v2(struct dl_topic *, char *, unsigned char *, size_t);

/**
 * Check the integrity of a Topic instance.
 *
 * @param self Topic instance to verify.
 */
static inline void
assert_integrity(struct dl_topic *self)
{

	DL_ASSERT(self != NULL, ("Topic instance cannot be NULL."));
	DL_ASSERT(self->dlt_name != NULL,
	    ("Topic instance name cannot be NULL."));
	DL_ASSERT(self->dlt_rec_batch != NULL,
	    ("Topic instance record batch cannot be NULL."));
	DL_ASSERT(self->dlt_seg != NULL,
	    ("Topic instance active segment cannot be NULL."));
}

/**
 * Check the integrity of a TopicHashmap instance.
 *
 * @param self TopicHashmap instance to verify.
 */
static inline void
hashmap_assert_integrity(struct dl_topic_hashmap *self)
{

	DL_ASSERT(self != NULL, ("Hashmap instance cannot be NULL"));
	DL_ASSERT(self->dltm_hashtbl != NULL,
	    ("Hashmap instance's table cannot be NULL"));
}

/**
 * Produce Kafka v1 Message to the topic log.
 *
 * @param self Topic instance to produce message to
 * @param k Key of message
 * @param v Value of message
 * @param v_len Valuen length (in bytes)
 */
static int
produce_v1(struct dl_topic *self, char *k, unsigned char *v, size_t v_len)
{
	struct dl_bbuf *buffer;
	struct dl_message_set *message_set;

	/* Instantiate a new MessageSet. */
	if (dl_message_set_new(&message_set, (unsigned char *) k, strlen(k),
	    v, v_len) != 0)
		goto err_produce;

	if (dl_bbuf_new(&buffer, NULL, DL_MTU,
		DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN) != 0)
		goto err_free_msgset;

	if (dl_message_set_encode_compressed(message_set, buffer) != 0) {

		DLOGTR0(PRIO_HIGH, "Error encoding MessageSet\n");
		goto err_free_msgset;
	}
	dl_message_set_delete(message_set);
	
	if (dl_segment_insert_message(self->dlt_seg,
	    buffer) != 0) {

		DLOGTR0(PRIO_HIGH, "Error inserting message into segment\n");
		goto err_free_bbuf;
	}
	
	dl_bbuf_delete(buffer);
	return 0;

err_free_bbuf:
	dl_bbuf_delete(buffer);

err_free_msgset:
	dl_message_set_delete(message_set);

err_produce:
	DLOGTR0(PRIO_HIGH, "Error producing request\n");
	return -1;
}

/**
 * Produce Kafka v2 Message to the topic log.
 *
 * @param self Topic instance to produce message to
 * @param k Key of message
 * @param v Value of message
 * @param v_len Valuen length (in bytes)
 */
static int
produce_v2(struct dl_topic *self, char *k, unsigned char *v, size_t v_len)
{
	struct dl_bbuf *buffer;
	struct dl_record *record;

	/* Instantiate a new Record. */
	if (dl_record_new(&record, k, v, v_len))
		goto err_produce;

	/* Add the Record into the current RecordBatch. */	
	if (dl_record_batch_add_record(self->dlt_rec_batch, record))
		goto err_free_record;

	/* Record can now be free as it is encoded into batch */
	dl_record_delete(record);

	/* Write the batch once it was exceeded the configured limit. */
	if (dl_record_batch_get_size(self->dlt_rec_batch) > 100) {

		/* Encode the RecordBatch */
		if (dl_record_batch_encode(self->dlt_rec_batch, &buffer) != 0) {

			DLOGTR0(PRIO_HIGH, "Error encoding RecordBatch\n");

			/* Reset the RecordBatch */
			dl_record_batch_delete(self->dlt_rec_batch);
			dl_record_batch_new(&self->dlt_rec_batch);
			goto err_produce;
		}
	
		if (dl_segment_insert_message(self->dlt_seg, buffer) != 0) {

			DLOGTR0(PRIO_HIGH, "Error inserting message into segment\n");
			/* Reset the RecordBatch */
			dl_record_batch_delete(self->dlt_rec_batch);
			dl_record_batch_new(&self->dlt_rec_batch);

			/* Delete the buffer into which the RecordBatch was encoded */
			dl_bbuf_delete(buffer);
			goto err_produce;
		}
		
		/* Delete the buffer into which the RecordBatch was encoded */
		dl_bbuf_delete(buffer);

		/* Reset the RecordBatch */
		dl_record_batch_delete(self->dlt_rec_batch);
		dl_record_batch_new(&self->dlt_rec_batch);
	} 

	return 0;

err_free_record:
	dl_record_delete(record);

err_produce:
	DLOGTR0(PRIO_HIGH, "Error producing Request\n");

	return -1;
}

void
dl_topic_hashmap_clear(struct dl_topic_hashmap *self)
{
	struct dl_topic *topic, *tmp;

	hashmap_assert_integrity(self);

	for (unsigned long i = 0; i < self->dltm_hashmask + 1 ; i++) {
		LIST_FOREACH_SAFE(topic, &self->dltm_hashtbl[i], dlt_entries, tmp) {
	
			LIST_REMOVE(topic, dlt_entries);
			dl_topic_delete(topic);
		}
	}
}

void
dl_topic_hashmap_delete(struct dl_topic_hashmap *self)
{

	hashmap_assert_integrity(self);

	dlog_free(self->dltm_hashtbl);
	dlog_free(self);
}

void
dl_topic_hashmap_foreach(struct dl_topic_hashmap *self, dl_topic_callback cb,
    void *arg)
{
	struct dl_topic *topic, *tmp;

	hashmap_assert_integrity(self);
	for (unsigned long i = 0; i < self->dltm_hashmask + 1 ; i++) {
		LIST_FOREACH_SAFE(topic, &self->dltm_hashtbl[i], dlt_entries,
		    tmp) {
	
			/* Invoke the callback */
			(*cb)(topic, arg);
		}
	}
}

int
dl_topic_hashmap_get(struct dl_topic_hashmap *self, char const * const key,
    struct dl_topic **value)
{
	struct dl_topic *t;
	uint32_t h;

	hashmap_assert_integrity(self);
	DL_ASSERT(key != NULL, ("Key instance cannot be NULL"));
	DL_ASSERT(value != NULL, ("Value instance cannot be NULL"));

	/* Lookup the topic in the topic hashmap. */
	h = hashlittle(key, strlen(key), 0);

	LIST_FOREACH(t, &self->dltm_hashtbl[h & self->dltm_hashmask], dlt_entries) {
		if (strcmp(key, sbuf_data(t->dlt_name)) == 0) {

			*value = t;
			return 0;
		}
	}

	return -1;
}

int
dl_topic_hashmap_new(struct dl_topic_hashmap **self, size_t elements)
{
	struct dl_topic_hashmap *hashmap;
	unsigned long hashsize;
	struct dl_topics *hashtbl;

	DL_ASSERT(self != NULL, ("TopicHashmap instance cannot be NULL"));
	
	hashmap = (struct dl_topic_hashmap *) dlog_alloc(sizeof(struct dl_topic_hashmap));

	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	hashtbl = dlog_alloc((unsigned long) hashsize * sizeof(*hashtbl));
	DL_ASSERT(hashtbl != NULL, ("Failed allocating hashtable."));
	if (hashtbl != NULL) {
		for (unsigned long i = 0; i < hashsize; i++)
			LIST_INIT(&hashtbl[i]);
	}

	hashmap->dltm_hashtbl = hashtbl;
	hashmap->dltm_hashmask = hashsize - 1;

	hashmap_assert_integrity(hashmap);
	*self = hashmap;
	return 0;
}


int
dl_topic_hashmap_put(struct dl_topic_hashmap *self, char *k, struct dl_topic *v)
{
	uint32_t h;

	hashmap_assert_integrity(self);
	h = hashlittle(k, strlen(k), 0);

	LIST_INSERT_HEAD(&self->dltm_hashtbl[h & self->dltm_hashmask], v, dlt_entries); 
	return 0;
}

int
dl_topic_hashmap_put_if_absent(struct dl_topic_hashmap *self, char * k,
    struct dl_topic *v)
{
	struct dl_topic *topic;
	
	hashmap_assert_integrity(self);
	DL_ASSERT(k != NULL, ("Key cannot be NULL"));
	DL_ASSERT(v != NULL, ("Value cannot be NULL"));

	if (dl_topic_hashmap_get(self, k, &topic) == -1) {

		return dl_topic_hashmap_put(self, k, v);
	}

	return -1;
}

int
dl_topic_hashmap_remove(struct dl_topic_hashmap *self, char *key)
{
	struct dl_topic *topic, *tmp;
	uint32_t h;

	hashmap_assert_integrity(self);
	DL_ASSERT(key != NULL, ("Key cannot be NULL"));

	h = hashlittle(key, strlen(key), 0);
	LIST_FOREACH_SAFE(topic, &self->dltm_hashtbl[h & self->dltm_hashmask],
	    dlt_entries, tmp) {
		if (strcmp(key, sbuf_data(topic->dlt_name)) == 0) {

			LIST_REMOVE(topic, dlt_entries);
			dl_topic_delete(topic);
			return 0;
		}
	}

	return -1;
}

int
dl_topic_new(struct dl_topic **self, char *topic_name,
    nvlist_t *props, struct dl_segment *seg)
{
	struct dl_topic *topic;
		
	DL_ASSERT(self != NULL, ("Topic instance cannot be NULL"));
	DL_ASSERT(topic_name != NULL, ("Topic bname cannot be NULL"));
	DL_ASSERT(seg != NULL, ("Topic active segment cannot be NULL"));

	topic = (struct dl_topic *) dlog_alloc(sizeof(struct dl_topic));
	DL_ASSERT(topic != NULL, ("Failed instantiating Topic instance\n"));
	if (topic == NULL)
		goto err_topic_ctor;

	/* Take a defensive copy of the topic name. */
	topic->dlt_name = sbuf_new_auto();
	sbuf_printf(topic->dlt_name, "%s", topic_name);
	sbuf_finish(topic->dlt_name);

	topic->dlt_seg = seg;
	
	if (dl_record_batch_new(&topic->dlt_rec_batch) != 0) {

		goto err_free_sbuf;	
	}

	topic->dlt_props = props;

	assert_integrity(topic);
	*self = topic;
	return 0;

err_free_sbuf:
	sbuf_delete(topic->dlt_name);

err_topic_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Topic instance\n");
	*self = NULL;

	return -1;
}

/**
 * Convert a Topic instance to a TopicDesc.
 * The TopicDesc class is used to pass Topics configured in userspace
 * to the dlog device driver in kernel.
 *
 * @param self The instance of the Topic class to transform.
 * @param desc The TopicDesc is returned in this parameter.
 * @return 0 is sucessful, -1 otherwise 
 */
int
dl_topic_as_desc(struct dl_topic *self, struct dl_topic_desc **desc)
{
	struct dl_topic_desc *desc_tmp;

	/* Validate the pre-conditions. */	
	assert_integrity(self);
	DL_ASSERT(desc != NULL,
	    ("Topic description instance cannot be NULL."));

	desc_tmp = (struct dl_topic_desc *) dlog_alloc(
	    sizeof(struct dl_topic_desc));
	DL_ASSERT(desc_tmp != NULL,
	    ("Failed allocating TopicDesc instance."));
	if (desc_tmp == NULL)
		goto topic_desc_err;

	strncpy(desc_tmp->dltd_name, sbuf_data(self->dlt_name),
	    DL_MAX_TOPIC_NAME_LEN);
	desc_tmp->dltd_active_seg.dlsd_offset =
	    dl_segment_get_offset(self->dlt_seg);
	desc_tmp->dltd_active_seg.dlsd_base_offset =
	    dl_segment_get_base_offset(self->dlt_seg);

	*desc = desc_tmp;
	return 0;

topic_desc_err:
	DLOGTR0(PRIO_HIGH, "Failed allocating TopicDesc instance.\n");

	*desc = NULL;
	return -1;
}

void
dl_topic_delete(struct dl_topic *self)
{

	assert_integrity(self);

	/* Delete the RecordBatch. */
	dl_record_batch_delete(self->dlt_rec_batch);

	/* Delete the segments within the topic. */
	dl_delete(self->dlt_seg);

	/* Delete the topic name. */
	sbuf_delete(self->dlt_name);

	/* Free the memory used by this topic instance. */
	dlog_free(self);
}

char *
dl_topic_get_name(struct dl_topic *self)
{

	assert_integrity(self);
	return sbuf_data(self->dlt_name);
}

struct dl_segment *
dl_topic_get_active_segment(struct dl_topic *self)
{

	assert_integrity(self);
	return self->dlt_seg;
}

void
dl_topic_set_active_segment(struct dl_topic *self, struct dl_segment *seg)
{

	assert_integrity(self);
	self->dlt_seg = seg;
}

int
dl_topic_produce_record_to(struct dl_topic *self, char *k,
    unsigned char *v, size_t v_len)
{

	assert_integrity(self);

	if (dnvlist_get_number(self->dlt_props, DL_CONF_MSG_VERSION,
	    DL_DEFAULT_MSG_VERSION) == 2) {

		return produce_v2(self, k, v, v_len);
	} else {

		return produce_v1(self, k, v, v_len);
	}
}

bool
dl_topic_validate_name(char const * const name)
{

	DL_ASSERT(name != NULL, ("Topic name cannot be NULL"));
	if (strcmp(name, "") == 0)
		return false;

	return true;
}

int
dl_topic_get_message_by_offset(struct dl_topic *self, struct dl_bbuf **msg_buf)
{

	assert_integrity(self);
	return dl_segment_get_message_by_offset(self->dlt_seg,
	    dl_segment_get_offset(self->dlt_seg), msg_buf);
}
