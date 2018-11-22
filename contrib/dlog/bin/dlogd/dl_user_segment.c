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

#include <sys/types.h>
#include <sys/uio.h>

#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_user_segment.h"
#include "dl_segment.h"
#include "dl_utils.h"

static const long int DL_SEGMENT_DEFAULT_SIZE = 1024*1024;

/* Number of digits in base 10 required to represent a 32-bit number. */
#define DL_LOG_DIGITS 20

struct dl_user_segment {
	SLIST_ENTRY(dl_segment) dls_entries;
	pthread_mutex_t dls_lock; /* Lock for whilst updating segment. */
	struct dl_offset *dls_offset; /* The offset within the Segment */
	struct dl_index *dls_idx; /* The index of the Segment */
	struct sbuf *log_name;
	char *log_name_raw;
	int dls_log; /* Segement's log file descriptor. */
};

static void dl_user_segment_lock(struct dl_segment *);
static void dl_user_segment_unlock(struct dl_segment *);
static int dl_user_segment_get_message_by_offset(struct dl_segment *,
    int, struct dl_bbuf **);
static int dl_user_segment_insert_message(struct dl_segment *,
    struct dl_bbuf *);
static void dl_user_segment_delete(struct dl_segment *);
static uint32_t dl_user_get_offset(struct dl_segment *);

static inline void
dl_user_segment_check_integrity(struct dl_user_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
	DL_ASSERT(self->dls_idx != NULL,
	    ("Segment instance index cannot be NULL."));
	DL_ASSERT(self->dls_offset != NULL,
	    ("Segment instance offset cannot be NULL."));
}

void
dl_user_segment_delete(struct dl_segment *self)
{

	dl_user_segment_check_integrity(self->dls_user);

	dl_index_delete(self->dls_user->dls_idx);
	pthread_mutex_destroy(&self->dls_user->dls_lock);
	close(self->dls_user->dls_log);
	sbuf_delete(self->dls_user->log_name);
	dlog_free(self->dls_user);
}

int
dl_user_segment_new_default(struct dl_segment **self,
    struct sbuf *path_name, struct sbuf *partition_name)
{

	return dl_user_segment_new(self, 0, DL_SEGMENT_DEFAULT_SIZE,
	    path_name, partition_name);
}

int
dl_user_segment_new_default_sized(struct dl_segment **self,
    long int base_offset, struct sbuf *path_name,
    struct sbuf *partition_name)
{

	return dl_user_segment_new(self, base_offset, 1024*1024, path_name,
	    partition_name);
}

int
dl_user_segment_new(struct dl_segment **self, long int base_offset,
    long int length, struct sbuf *path_name, struct sbuf *partition_name)
{
	struct dl_segment *seg;
	struct dl_user_segment *useg;
	int rc;

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));
	DL_ASSERT(path_name != NULL,
	    ("UserSegment path name name cannot be NULL"));
	DL_ASSERT(partition_name != NULL,
	    ("UserSegment partition name cannot be NULL"));

	/* Initalise the super class. */
	rc = dl_segment_new(&seg, base_offset, length,
	    dl_user_segment_insert_message,
	    dl_user_segment_get_message_by_offset,
	    dl_user_get_offset,
	    dl_user_segment_lock, dl_user_segment_unlock,
	    dl_user_segment_delete);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW,
		    "Failed allocating UserSegment super class\n");
		goto err_seg_ctor;
	}
	
	useg = seg->dls_user = (struct dl_user_segment *) dlog_alloc(
		sizeof(struct dl_user_segment));
	if (useg == NULL ) {

		DLOGTR0(PRIO_LOW, "Failed allocating UserSegment instance\n");
		goto err_user_seg_ctor;
	}
	
	bzero(useg, sizeof(struct dl_user_segment));

	/* Initialise the class members. */
	useg->log_name = sbuf_new_auto();
	sbuf_printf(useg->log_name, "%s/%.*ld.log",
	    sbuf_data(path_name), DL_LOG_DIGITS, base_offset);
	sbuf_finish(useg->log_name);
	useg->log_name_raw = sbuf_data(useg->log_name);
	useg->dls_log = open(useg->log_name_raw,
	    O_RDWR | O_APPEND | O_CREAT, 0666);
	if (useg->dls_log == -1) {

		DLOGTR0(PRIO_LOW, "Failed opening UserSegment file\n");
		goto err_user_seg_alloc_ctor;
	}

	dl_alloc_big_file(useg->dls_log, 0, length);

	rc = dl_offset_new(&useg->dls_offset, path_name);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed instatiating UserSegment offset\n");
		goto err_user_seg_alloc_ctor;
	}

	rc = pthread_mutex_init(&useg->dls_lock, NULL);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH, "Error initializing UserSegment mutex\n");
		goto err_user_seg_offset_ctor;
	}

	rc = dl_index_new(&useg->dls_idx, useg->dls_log, base_offset,
	    path_name);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed instatiating UserSegment index\n");
		goto err_user_seg_mutex_ctor;
	}
	
	dl_user_segment_check_integrity(useg);
	*self = seg;
	return 0;

err_user_seg_mutex_ctor:
	pthread_mutex_destroy(&useg->dls_lock);

err_user_seg_offset_ctor:
	dl_offset_delete(useg->dls_offset);

err_user_seg_alloc_ctor:
	dlog_free(useg);

err_user_seg_ctor:
	dl_segment_delete(seg);

err_seg_ctor:
	DLOGTR0(PRIO_HIGH, "Error Instantiating UserSegment\n");

	*self = NULL;
	return -1;
}

/* TODO: The Kafka log format also includes a timestamp */
static int
dl_user_segment_insert_message(struct dl_segment *self, struct dl_bbuf *buffer)
{
	struct iovec log_bufs[2];
	struct dl_bbuf *metadata;
	int rc;

	dl_user_segment_check_integrity(self->dls_user);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	DLOGTR1(PRIO_HIGH, "Inserting (%d bytes) into the log\n",
	    dl_bbuf_pos(buffer));

	dl_segment_lock(self);

	/* Update the log file. */
	dl_bbuf_new(&metadata, NULL, sizeof(uint32_t),
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	dl_bbuf_put_int32(metadata, dl_offset_val(self->dls_user->dls_offset));

	log_bufs[0].iov_base = dl_bbuf_data(metadata);
	log_bufs[0].iov_len = dl_bbuf_pos(metadata);
	
	log_bufs[1].iov_base = dl_bbuf_data(buffer);
	log_bufs[1].iov_len = dl_bbuf_pos(buffer);

	rc = writev(self->dls_user->dls_log, log_bufs,
	    sizeof(log_bufs)/sizeof(struct iovec));	
	if (rc == -1) {

		DLOGTR1(PRIO_LOW,
		    "User segment insert message faile writev (%d)\n", errno);
		goto err_insert_message;
	}
	
	/* Delete the buffer holding the log metadata */
	dl_bbuf_delete(metadata);

	/* Update the offset. */
	dl_offset_inc(self->dls_user->dls_offset);

	dl_segment_unlock(self);
	return 0;

err_insert_message:
	dl_segment_unlock(self);

	DLOGTR0(PRIO_HIGH, "Error inserting message into Segment\n");
	return -1;
}

static int
dl_user_segment_get_message_by_offset(struct dl_segment *self, int offset,
    struct dl_bbuf **msg_buf)
{
	struct dl_bbuf *t;
	unsigned char *msg_tmp;
	int32_t tmp_buf[2], cid, size;
	off_t poffset;
	int rc;

	dl_user_segment_check_integrity(self->dls_user);

	rc = dl_index_lookup(self->dls_user->dls_idx, offset, &poffset);
	if (rc == 0) {
		rc = pread(self->dls_user->dls_log, tmp_buf, sizeof(tmp_buf),
		    poffset);
		if (rc == -1) {

			return -1;
		}

		dl_bbuf_new(&t, (unsigned char *) tmp_buf,
		    sizeof(tmp_buf), DL_BBUF_BIGENDIAN);
		dl_bbuf_get_int32(t, &cid);
		dl_bbuf_get_int32(t, &size);
		dl_bbuf_delete(t);

		msg_tmp = dlog_alloc(size * sizeof(unsigned char) + sizeof(int32_t));
		if (msg_tmp == NULL) {

			return -1;
		}

		rc = pread(self->dls_user->dls_log, msg_tmp, size + sizeof(int32_t),
		    poffset + sizeof(int32_t));
		if (rc == -1) {
			dlog_free(msg_tmp);
			return -1;
		}

		dl_bbuf_new(msg_buf, NULL, size + sizeof(int32_t),
		    DL_BBUF_BIGENDIAN);
		dl_bbuf_bcat(*msg_buf, msg_tmp, size + sizeof(int32_t));
		dlog_free(msg_tmp);
		return 0;
	} else {
		DLOGTR2(PRIO_LOW, "For offset %d no message found (%d).\n",
		    offset, errno);
		return -1;
	}
}

static void
dl_user_segment_lock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_user_segment_check_integrity(self->dls_user);
	pthread_mutex_lock(&self->dls_user->dls_lock);
}

static void
dl_user_segment_unlock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_user_segment_check_integrity(self->dls_user);
	pthread_mutex_unlock(&self->dls_user->dls_lock);
}

static uint32_t 
dl_user_get_offset(struct dl_segment *self)
{

	dl_user_segment_check_integrity(self->dls_user);
	return dl_offset_val(self->dls_user->dls_offset);
}

struct dl_offset * 
dl_user_segment_get_offset_tmp(struct dl_segment *self)
{

	dl_user_segment_check_integrity(self->dls_user);
	return self->dls_user->dls_offset;
}

int
dl_user_segment_get_log(struct dl_segment *self)
{
	dl_user_segment_check_integrity(self->dls_user);
	return self->dls_user->dls_log;
}

struct dl_index *
dl_user_segment_get_index(struct dl_segment *self)
{

	dl_user_segment_check_integrity(self->dls_user);
	return self->dls_user->dls_idx;
}

char *
dl_user_segment_get_log_name(struct dl_segment *self)
{

	dl_user_segment_check_integrity(self->dls_user);
	return self->dls_user->log_name_raw;
}
