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
#include <sys/hash.h>
#include <sys/types.h>
#else
#include <stddef.h>
#endif
#include <sys/types.h>
#include <sys/sbuf.h>

#ifndef _KERNEL
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_request.h"
#include "dl_topic.h"
#include "dl_user_segment.h"
#include "dl_kernel_segment.h"
#include "dl_utils.h"

extern uint32_t hashlittle(const void *, size_t, uint32_t);

unsigned long topic_hashmask;
struct dl_topics *topic_hashmap;

static void inline
dl_topic_check_integrity(struct dl_topic *self)
{

	DL_ASSERT(self != NULL, ("Topic instance cannot be NULL."));
}

void
dl_topic_hashmap_delete(void *self)
{

	DL_ASSERT(self != NULL, ("Hashmap instance cannot be NULL"));

	dlog_free(self);
}

void *
dl_topic_hashmap_new(int elements, unsigned long *hashmask)
{
	long hashsize;
	LIST_HEAD(dl_topics, dl_topic) *hashtbl = NULL;
	int i;

	DL_ASSERT(elements > 0, ("Elements in hash table must be > 0"));
	DL_ASSERT(hashmask != NULL, ("hashmask cannot be NULL"));

	for (hashsize = 1; hashsize <= elements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	hashtbl = dlog_alloc((unsigned long) hashsize * sizeof(*hashtbl));
#ifdef KERNEL
	DL_ASSERT(hashtbl != NULL, ("Failed allocating hashtable."));
#else
	if (hashtbl != NULL) {
		for (i = 0; i < hashsize; i++)
			LIST_INIT(&hashtbl[i]);
		*hashmask = hashsize -1;
	}
#endif
	return hashtbl;
}

int
dl_topic_hashmap_get(char const * const key, struct dl_topic **topic)
{
	struct dl_topic *t;
	uint32_t h;

	/* Lookup the topic in the topic hashmap. */
	h = hashlittle(key, strlen(key), 0);

	LIST_FOREACH(t, &topic_hashmap[h & topic_hashmask], dlt_entries) {
		if (strcmp(key, sbuf_data(t->dlt_name)) == 0) {

			*topic = t;
			return 0;
		}
	}

	return -1;
}

int
dl_topic_hashmap_put(void *a __attribute((unused)),
    struct dl_topic *b __attribute((unused)))
{
	return 0;
}

// TODO error handling
#ifndef _KERNEL
int
dl_topic_new(struct dl_topic **self, char *topic_name, char *path_name)
{
	struct dl_topic *topic;
	struct kevent event;
	struct sbuf *path;
	int rc;
		
	topic = (struct dl_topic*) dlog_alloc(
	    sizeof(struct dl_topic));
	if (topic != NULL) {
		topic->dlt_name = sbuf_new_auto();
		sbuf_printf(topic->dlt_name, "%s", topic_name);
		sbuf_finish(topic->dlt_name);

		path = sbuf_new_auto();
		sbuf_printf(path, "%s/%s", path_name, topic_name);
		sbuf_finish(path);
		rc = dl_make_folder(path);
		if (rc == 0) {

		SLIST_INIT(&topic->dlp_segments);
#ifdef _KERNEL
		rc = dl_user_kernel_new_default(&topic->dlp_active_segment,
		    path, topic->dlt_name);
#else
		rc = dl_user_segment_new_default(&topic->dlp_active_segment,
		    path, topic->dlt_name);
#endif
		if (rc == 0) {
			sbuf_delete(path);

			SLIST_INSERT_HEAD(&topic->dlp_segments,
			    topic->dlp_active_segment, dls_entries);

			/* Register kqueue event to monitor writes on the
			 * partition's active segment. fsync() is called on
			 * the segment when writes exceed a per-topic
			 * configured limit.
			 */
			topic->_klog = kqueue();
			if (topic->_klog == -1) {
				// TODO
			}

			/* Initialise a kevent to monitor writes to the log
			 * file.
			 */
			EV_SET(&event,
			    dl_user_segment_get_log(
			    topic->dlp_active_segment),
			    EVFILT_VNODE, EV_ADD | EV_CLEAR, NOTE_WRITE, 0,
			    NULL);

			/* Attach the event to the kqueue. */
			rc = kevent(topic->_klog, &event,
			    1, NULL, 0, NULL); 
			//if (rc == -1)
			//	printf("error\n");
			//if (event.flags & EV_ERROR)
			//	printf("error\n");

			*self = topic;
			dl_topic_check_integrity(*self);
			return 0;
		}
		}
		sbuf_delete(path);
		dlog_free(topic);
	}

	DLOGTR0(PRIO_HIGH, "Failed instantiating Topic instance\n");
	*self = NULL;
	return -1;
}

int
dl_topic_as_desc(struct dl_topic *self, struct dl_topic_desc **desc)
{
	struct dl_topic_desc *temp;
	
	dl_topic_check_integrity(self);
	DL_ASSERT(desc != NULL, ("Topic description instance cannot be NULL."));

	temp = (struct dl_topic_desc *) dlog_alloc(
	    sizeof(struct dl_topic_desc));
	if (temp == NULL)
		goto topic_desc_err;

	temp->dltd_name = sbuf_data(self->dlt_name);
	temp->dltd_active_seg.dlsd_offset =
	    dl_segment_get_offset(self->dlp_active_segment);
	temp->dltd_active_seg.dlsd_base_offset =
	    dl_segment_get_base_offset(self->dlp_active_segment);
	temp->dltd_active_seg.dlsd_seg_size =
	    self->dlp_active_segment->segment_size;
	char * log_name = dl_user_segment_get_log_name(
	    self->dlp_active_segment);
	temp->dltd_active_seg.dlsd_log = open(log_name,
	    O_RDWR | O_APPEND | O_CREAT, 0666);

	*desc = temp;
	return 0;

topic_desc_err:
	*desc = NULL;
	return -1;
}
#endif

#ifdef _KERNEL
int
dl_topic_from_desc(struct dl_topic **self, struct sbuf *topic_name,
    struct dl_segment_desc *seg_desc)
{
	struct dl_topic *topic;
	int rc;

	DL_ASSERT(self != NULL, ("Topic instance cannot be NULL."));
	DL_ASSERT(topic_name != NULL, ("Topic name cannot be NULL."));
	DL_ASSERT(seg_desc != NULL, ("Segment description cannot be NULL."));
		
	topic = (struct dl_topic *) dlog_alloc(sizeof(struct dl_topic));
#ifdef KERNEL
	DL_ASSERT(partition != NULL, ("Failed allocating topic."));
#else
	if (topic == NULL)
		goto err_topic;
#endif
	bzero(topic, sizeof(struct dl_topic));

	/* Take a defensive copy of the topic name. */
	topic->dlt_name = sbuf_new_auto();
	sbuf_cpy(topic->dlt_name, sbuf_data(topic_name));
	sbuf_finish(topic->dlt_name);

	/* Initialise the topic's active segment. */
	SLIST_INIT(&topic->dlp_segments);

	rc = dl_kernel_segment_from_desc(&topic->dlp_active_segment, seg_desc);
	if (rc != 0) {
		/* The segment could not be instatiated from the
		 * topic. Free the topic instance and return an error.
		 */
		dlog_free(topic);
		goto err_topic;
	}

	SLIST_INSERT_HEAD(&topic->dlp_segments,
	    topic->dlp_active_segment, dls_entries);

	dl_topic_check_integrity(topic);
	*self = topic;
	return 0;

err_topic:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Topic instance\n");
	*self = NULL;
	return -1;
}
#endif

void
dl_topic_delete(struct dl_topic *self)
{
	struct dl_segment *seg, *seg_tmp;

	dl_topic_check_integrity(self);

	/* Delete the segments within the topic. */
	SLIST_FOREACH_SAFE(seg, &self->dlp_segments, dls_entries, seg_tmp) {

		seg->dls_delete_fcn(seg);
	};

	/* Delete the topic name. */
	sbuf_delete(self->dlt_name);

	/* Free the memory used by this topic instance. */
	dlog_free(self);
}

struct sbuf *
dl_topic_get_name(struct dl_topic *self)
{

	dl_topic_check_integrity(self);
	return self->dlt_name;
}

struct dl_segment *
dl_topic_get_active_segment(struct dl_topic *self)
{

	dl_topic_check_integrity(self);
	return self->dlp_active_segment;
}

int
dl_topic_produce_to(struct dl_topic *self, struct dl_bbuf *buffer)
{

	dl_topic_check_integrity(self);
	DL_ASSERT(buffer != NULL, ("Buffer to produce cannot be NULL."));

	/* Produce the Message into the topic. */
	return dl_segment_insert_message(
	    self->dlp_active_segment, buffer);
}	
