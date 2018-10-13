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

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_user_segment.h"
#include "dl_utils.h"

struct dl_index {
	pthread_mutex_t dli_mtx; /* Lock for updating/lookup of index. */
	off_t dli_last;
	int dli_idx_fd;
	int dli_log_fd;
};

struct dl_index_record {
	uint32_t dlir_offset;
	uint32_t dlir_poffset;
};

/* Number of digits in base 10 required to represent a 32-bit number. */
#define DL_INDEX_DIGITS 20

static inline void 
dl_index_check_integrity(struct dl_index const * const self)
{

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
}

int
dl_index_new(struct dl_index **self, int log, int64_t base_offset,
    struct sbuf *part_name)
{
	struct dl_index *idx;
	struct sbuf *idx_name;
	struct dl_index_record record;
	struct dl_bbuf *idx_buf;
	int32_t roffset ;
	off_t idx_end;
	int rc;

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	
	idx = (struct dl_index *) dlog_alloc(sizeof(struct dl_index));
	if (idx == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed instantiating dl_index.\n");
		*self = NULL;
		return -1;
	}

	bzero(idx, sizeof(struct dl_index));

	idx_name = sbuf_new_auto();
	sbuf_printf(idx_name, "%s/%.*ld.index",
	    sbuf_data(part_name), DL_INDEX_DIGITS, base_offset);
	sbuf_finish(idx_name);
	idx->dli_idx_fd = open(sbuf_data(idx_name),
	    O_RDWR | O_APPEND | O_CREAT, 0666);
	if (idx->dli_idx_fd == -1) {

		DLOGTR1(PRIO_HIGH,
		    "Failed instantiating dl_index %d.\n", errno);
		sbuf_delete(idx_name);
		dlog_free(idx);
		*self = NULL;
		return -1;
	}
	sbuf_delete(idx_name);
	idx->dli_log_fd = log;

	rc = pthread_mutex_init(&idx->dli_mtx, NULL);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed instantiating dl_index %d.\n", errno);
		sbuf_delete(idx_name);
		dlog_free(idx);
		*self = NULL;
		return -1;
	}

	/* Read the last value out of the index. */
	idx_end = lseek(idx->dli_idx_fd, 0, SEEK_END);
	if (idx_end == 0) {

		DLOGTR0(PRIO_LOW, "New index file created\n");
		idx->dli_last = 0;
	} else {

		rc = pread(idx->dli_idx_fd, &record, sizeof(record),
		idx_end - sizeof(record));
		if (rc == -1 || rc == 0) {

			DLOGTR1(PRIO_HIGH,
			"Failed to read from index file %d\n", errno);
			return -1;
		} else {
			DLOGTR0(PRIO_LOW,
			    "Reading the last index from file \n");

			/* Data in the index is stored in big-endian format for
			* compatibility with the Kafka log format.
			* The data read from the index is used as an external buffer
			* from a bbuf instance, this allows the values of the relative
			* and * physical offset to be read.
			*/
			rc = dl_bbuf_new(&idx_buf,
			    (unsigned char *) &record, sizeof(record),
			    DL_BBUF_BIGENDIAN);
			if (rc != 0)
				return -1;

			dl_bbuf_get_int32(idx_buf, &roffset);
			idx->dli_last = roffset;
			dl_bbuf_delete(idx_buf);
		}
	}
	DLOGTR1(PRIO_HIGH, "Read offset (%ld)\n", idx->dli_last);

	dl_index_check_integrity(idx);
	*self = idx;
	return 0;
}

void
dl_index_delete(struct dl_index *self)
{

	dl_index_check_integrity(self);

	pthread_mutex_destroy(&self->dli_mtx);
	close(self->dli_idx_fd);
	dlog_free(self);
}

void
dl_index_update(struct dl_index *self, off_t log_end)
{
	struct iovec index_bufs[2];
	uint32_t o, s, t;
	int rc;
	
	dl_index_check_integrity(self);
	
	/* Create the index. */
	pthread_mutex_lock(&self->dli_mtx);
	while (self->dli_last < log_end) {
	
		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(o);

		index_bufs[1].iov_base = &s;
		index_bufs[1].iov_len = sizeof(s);

		rc = preadv(self->dli_log_fd, index_bufs,
			sizeof(index_bufs)/sizeof(struct iovec),
			self->dli_last);	
		if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from log file %d\n", errno);
			break;
		}

		index_bufs[0].iov_base = &o;
		index_bufs[0].iov_len = sizeof(o);

		t = htobe32(self->dli_last);
		index_bufs[1].iov_base = &t;
		index_bufs[1].iov_len = sizeof(t);

		rc = writev(self->dli_idx_fd, index_bufs,
			sizeof(index_bufs)/sizeof(struct iovec));
		if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to write to index file %d\n", errno);
			break;
		}

		/* Advance the index offset into the log by the processed
		 * entry.x
		 */
		self->dli_last += sizeof(o);
		self->dli_last += sizeof(s);
		self->dli_last += be32toh(s);
	}
	pthread_mutex_unlock(&self->dli_mtx);

	/* Sync the updated index file to disk. */
	fsync(self->dli_idx_fd);
}

off_t
dl_index_lookup(struct dl_index *self, uint32_t offset)
{
	struct dl_index_record record;
	struct dl_bbuf *idx_buf;
	int32_t roffset, poffset;
	int rc;

	dl_index_check_integrity(self);

	rc = pread(self->dli_idx_fd, &record, sizeof(record),
	    offset * sizeof(struct dl_index_record));
	if (rc == -1 || rc == 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to read from index file %d\n", errno);
		return -1;
	}

	/* Data in the index is stored in big-endian format for
	 * compatibility with the Kafka log format.
	 * The data read from the index is used as an external buffer
	 * from a bbuf instance, this allows the values of the relative
	 * and * physical offset to be read.
	 */
	rc = dl_bbuf_new(&idx_buf, (unsigned char *) &record,
	    sizeof(record), DL_BBUF_BIGENDIAN);
	if (rc != 0)
		return -1;

	dl_bbuf_get_int32(idx_buf, &roffset);
	DL_ASSERT((int32_t) offset == roffset,
	    ("Request offset (%X) doesn't match index (%u).",
	     offset, roffset));
	dl_bbuf_get_int32(idx_buf, &poffset);
	dl_bbuf_delete(idx_buf);

	return poffset;
}

off_t
dl_index_get_last(struct dl_index *self)
{

	dl_index_check_integrity(self);
	return self->dli_last;
}

