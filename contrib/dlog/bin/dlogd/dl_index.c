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
#include <stdbool.h>
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
	off_t dli_last; /* The last offset in the log indexed. */
	pthread_mutex_t dli_mtx; /* Lock for updating/lookup of index. */
	int dli_idx_fd; /* File descriptor of index. */
	int dli_log_fd; /* FIle descriptor of the log. */
};

struct dl_index_record {
	off_t dlir_poffset; /* Physical offset into log of dlir_offset. */
	uint32_t dlir_offset; /* Log offset */
};

/* The size of the index record. */
#define DL_INDEX_RECORD_SIZE \
    (sizeof(((struct dl_index_record *) 0)->dlir_poffset) + \
    sizeof(((struct dl_index_record *) 0)->dlir_offset))

/* Number of digits in base 10 required to represent a 32-bit number. */
#define DL_INDEX_DIGITS 20

static int dl_index_lookup_by_file_offset(struct dl_index *, off_t,
    struct dl_index_record *);
static int dl_index_update_locked(struct dl_index *, off_t);

static inline void 
dl_index_check_integrity(struct dl_index const * const self)
{

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL."));
	DL_ASSERT(self->dli_last != -1,
	    ("Index log offset cannot be invalid (-1)."));
	DL_ASSERT(self->dli_idx_fd  != -1,
	    ("Index file descriptor cannot be invalid (-1)."));
	DL_ASSERT(self->dli_log_fd != -1,
	    ("Index log file descriptor cannot be invalid (-1)."));
}

static int 
dl_index_lookup_by_file_offset(struct dl_index *self, off_t offset,
    struct dl_index_record *record)
{
	struct dl_bbuf *idx_buf;
	int rc;
	unsigned char tmp_record[DL_INDEX_RECORD_SIZE];

	dl_index_check_integrity(self);

	pthread_mutex_lock(&self->dli_mtx);

	rc = pread(self->dli_idx_fd, &tmp_record, DL_INDEX_RECORD_SIZE, offset);
	if (rc == 0) {

		/* EOF */
		goto err_index_lookup;	
	} else if (rc < 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to read from index file %d\n", errno);
		goto err_index_lookup;	
	}
	DL_ASSERT(rc == DL_INDEX_RECORD_SIZE,
	    ("Failed to read index record size"));

	/* Data in the index is stored in big-endian format for
	 * compatibility with the Kafka log format.
	 * The data read from the dindex is used as an external buffer
	 * from a bbuf instance, this allows the values of the relative
	 * and physical offset to be read.
	 */
	rc = dl_bbuf_new(&idx_buf, tmp_record, DL_INDEX_RECORD_SIZE,
	    DL_BBUF_BIGENDIAN);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to create bbuf from record index %d\n", rc);
		goto err_index_lookup;	
	}

	rc |= dl_bbuf_get_uint32(idx_buf, &record->dlir_offset);
	rc |= dl_bbuf_get_int64(idx_buf, &record->dlir_poffset);
	DL_ASSERT(rc == 0, ("dl_bbuf operations failed on index record."));
	dl_bbuf_delete(idx_buf);
	pthread_mutex_unlock(&self->dli_mtx);

	return 0;

err_index_lookup:
	pthread_mutex_unlock(&self->dli_mtx);
	return -1;
}

static int
dl_index_update_locked(struct dl_index *self, off_t log_end)
{
	struct iovec index_bufs[2];
	off_t tmp_poffset;
	uint32_t offset, size;
	int rc, idx_cnt = 0;
		
	dl_index_check_integrity(self);

	/* Create the index. */
	while (self->dli_last < log_end) {

		/* Read the offset of the log entry and size. */
		index_bufs[0].iov_base = &offset;
		index_bufs[0].iov_len = sizeof(offset);

		index_bufs[1].iov_base = &size;
		index_bufs[1].iov_len = sizeof(size);

		rc = preadv(self->dli_log_fd, index_bufs,
		    sizeof(index_bufs)/sizeof(struct iovec), self->dli_last);	
		if (rc == 0) {

			/* EOF */
			break;
		} else if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from log file %d\n", errno);
			break;
		} else if(
		    (off_t) (sizeof(offset) + sizeof(size) + be32toh(size)) >
		    log_end) {
			/* Check that the entry in the log is not corrupt,
			 * that is if the size of the message exceeds the total
			 * log length.
			 */
			DLOGTR3(PRIO_NORMAL,
			    "Log message at offset %u is corrupt (%lu > %ld)",
			    be32toh(offset),
			  
			    (sizeof(offset) + sizeof(size) + be32toh(size)),
			    log_end);
			break;
		}
		DL_ASSERT(rc == sizeof(offset) + sizeof(size),
		   ("Number of bytes read from log"));

		/* Write the index for the log entry. */
		index_bufs[0].iov_base = &offset;
		index_bufs[0].iov_len = sizeof(offset);

		tmp_poffset = htobe64(self->dli_last);
		index_bufs[1].iov_base = &tmp_poffset;
		index_bufs[1].iov_len = sizeof(tmp_poffset);

		rc = pwritev(self->dli_idx_fd, index_bufs,
			sizeof(index_bufs)/sizeof(struct iovec),
			be32toh(offset) * DL_INDEX_RECORD_SIZE); 
		if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to write to index file %d\n", errno);
			break;
		}

		/* Sync the updated index file to disk. */
		fsync(self->dli_idx_fd);
	
		/* Advance the index offset into the log by the processed
		 * entry.
		 */
		self->dli_last += (off_t) (sizeof(offset) + sizeof(size) +
		    be32toh(size));

		/* Increment the count of new indexs that were created. */
		idx_cnt++;
	}

	return idx_cnt;
}

int
dl_index_new(struct dl_index **self, int log, int64_t base_offset,
    struct sbuf *part_name)
{
	struct dl_index *idx;
	struct sbuf *idx_name;
	struct dl_index_record record;
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
		rc = dl_index_lookup_by_file_offset(idx,
		    (idx_end - DL_INDEX_RECORD_SIZE), &record);
		if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from index file %d\n", errno);
			return -1;
		}
		idx->dli_last = record.dlir_poffset;
	}
	DLOGTR1(PRIO_LOW, "Log offset at which last index is found  (%ld)\n",
	    idx->dli_last);

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

int
dl_index_update(struct dl_index *self, off_t log_end)
{
	int idx_cnt = 0;
	
	dl_index_check_integrity(self);
	
	/* Update the index reuting a count of the new indexes created. */
	pthread_mutex_lock(&self->dli_mtx);
	idx_cnt = dl_index_update_locked(self, log_end);
	pthread_mutex_unlock(&self->dli_mtx);

	return idx_cnt;
}

off_t
dl_index_lookup(struct dl_index *self, uint32_t offset, off_t *offset_loc)
{
	int rc;
	struct dl_index_record record;

	dl_index_check_integrity(self);

	rc = dl_index_lookup_by_file_offset(self,
	    (offset * DL_INDEX_RECORD_SIZE), &record);
	if (rc == -1) {

		return -1;
	}
	if (offset != (uint32_t) record.dlir_offset) {
		/* The index file is corrupt.
		 * Recompute the index and then retry the lookup.
		 */
		DLOGTR2(PRIO_HIGH,
		    "Request offset (%X) doesn't match index (%X).",
		    offset, record.dlir_offset);
		 /* Read the previous value of the index and set the 
		  * value of dli_last to list.
		  */
		/*
		if (offset != 0) {
			rc = dl_index_lookup_by_file_offset(self,
			    (offset - 1) * DL_INDEX_RECORD_SIZE, &record);
			if (rc == -1) {
				ftruncate(self->dli_idx_fd, 0);
				self->dli_last = 0;
			} else {
				ftruncate(self->dli_idx_fd,
			    	    (offset - 1) * DL_INDEX_RECORD_SIZE);
				self->dli_last = record.dlir_poffset;
			}
		} else {
			ftruncate(self->dli_idx_fd, 0);
			self->dli_last = 0;
		}
		*/
		return -1;
	}

	*offset_loc = record.dlir_poffset;
	return 0;
}

off_t
dl_index_get_last(struct dl_index *self)
{
	off_t last;

	dl_index_check_integrity(self);

	pthread_mutex_lock(&self->dli_mtx);
	last = self->dli_last;
	pthread_mutex_unlock(&self->dli_mtx);
	return last;
}

