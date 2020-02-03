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

#include <sys/dnv.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_user_segment.h"
#include "dl_utils.h"

typedef uint32_t dl_index_state;

struct dl_index {
	struct dl_event_handler dli_idx_hdlr;
	struct dl_user_segment *dli_useg;
	struct dl_producer *dli_producer;
	off_t dli_last; /* The last offset in the log indexed */
	pthread_t dli_tid; /* Update thread tid */
	dl_index_state dli_state;
	uint64_t dli_base_offset; /* Base offset of log segment */
	int dli_debug_lvl;
	int dli_fd; /* File descriptor of index */
	int dli_kq; /* File descriptor of kqueue monitoring the index */ 
};

/* The size of the index record. */
#define DL_INDEX_RECORD_SIZE \
    (sizeof(((struct dl_index_record *) 0)->dlir_poffset) + \
    sizeof(((struct dl_index_record *) 0)->dlir_offset))

/* dlogd properties. */
extern nvlist_t *dlogd_props;

const static uint32_t DLI_INITIAL = 0;
const static uint32_t DLI_IDLE = 1;
const static uint32_t DLI_UPDATING = 2;
const static uint32_t DLI_FINAL = 3;

static char const * const DLI_STATE_NAME[] =
    {"INITIAL", "IDLE", "UPDATING", "FINAL" };

/* Number of digits in base 10 required to represent a 32-bit number. */
static const int DL_INDEX_DIGITS = 20;
static const char * const DL_INDEX_FMT = "%s/%.*ld.index";
/* Maximum number of indexes created before issuing callback to Producer. */
static const uint32_t DL_INDEX_PRODUCE_CNT = 100;

static void dl_index_idle(struct dl_index * const self);
static void dl_index_updating(struct dl_index * const self);
static void dl_index_final(struct dl_index * const self);

static dl_event_handler_handle dl_index_get_idx_fd(void *);
static void dl_index_idx_handler(void *, int, int);

static void *dl_update_thread(void *vargp);

static int dl_index_lookup_by_poffset(struct dl_index *, off_t,
    struct dl_index_record *);

static inline void 
assert_integrity(struct dl_index const * const self)
{

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL"));
	DL_ASSERT(self->dli_useg != NULL, ("Index UserSegment cannot be NULL"));
}

static dl_event_handler_handle
dl_index_get_idx_fd(void *instance)
{
	struct dl_index const * const s = instance;

	assert_integrity(s);
	return s->dli_kq;
}

static void
dl_index_idx_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_index const * const s = instance;
	struct kevent event;
	int rc;

	assert_integrity(s);
			
	rc = kevent(s->dli_kq, 0, 0, &event, 1, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	} else {

		if (event.fflags & NOTE_DELETE) {

			DLOGTR0(PRIO_HIGH, "IndexSegment file deleted\n");
		}
	}
}

static void *
dl_update_thread(void *vargp)
{
	struct dl_index *self = (struct dl_index *)vargp;
	struct iovec index_iov[2];
	off_t log_end, tmp_poffset;
	uint64_t offset;
	uint32_t size;
	int iocnt = sizeof(index_iov)/sizeof(struct iovec);
	int idx_cnt = 0, rc;
	int log;
	
	assert_integrity(self);

	log = dl_user_segment_get_log(self->dli_useg);

	/* Create the index. */
	log_end = lseek(log, 0, SEEK_END);

	while (self->dli_last < log_end) {

		/* Read the offset of the log entry and size. */
		index_iov[0].iov_base = &offset;
		index_iov[0].iov_len = sizeof(offset);

		index_iov[1].iov_base = &size;
		index_iov[1].iov_len = sizeof(size);

		rc = preadv(log, index_iov, iocnt, self->dli_last);
		if (rc == 0) {

			/* EOF */
			break;
		} else if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from log file %d\n", errno);
			break;
		} else if((off_t) (sizeof(offset) + sizeof(size) +
		    be32toh(size)) > log_end) {
			/* Check that the entry in the log is not corrupt,
			 * that is if the size of the message exceeds the total
			 * log length.
			 */
			DLOGTR3(PRIO_NORMAL,
			    "Log message at offset %lu is corrupt (%lu > %ld)",
			    be64toh(offset),
			    (sizeof(offset) + sizeof(size) + be32toh(size)),
			    log_end);
			break;
		}
		DL_ASSERT(rc == sizeof(offset) + sizeof(size),
		   ("Number of bytes read from log"));

		/* Write the index for the log entry. */
		index_iov[0].iov_base = &offset;
		index_iov[0].iov_len = sizeof(offset);

		tmp_poffset = htobe64(self->dli_last);
		index_iov[1].iov_base = &tmp_poffset;
		index_iov[1].iov_len = sizeof(tmp_poffset);

		//rc = writev(self->dli_update_seg->dlis_idx_fd, index_iov, iocnt);
		rc = writev(self->dli_fd, index_iov, iocnt);
		if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to write to index file %d\n", errno);
			break;
		}

		/* Advance the index offset into the log by the processed
		 * entry.
		 */
		self->dli_last += (off_t) (sizeof(offset) + sizeof(size)
		    + be32toh(size));

		/* Increment the count of new indexes that were created. */
		idx_cnt++;

		/* Issue callback to Producer on indexing log records. */
		 if (idx_cnt % DL_INDEX_PRODUCE_CNT == 0) {
		 }
		 /*

			if (self->dli_debug_lvl > 0) {
				DLOGTR1(PRIO_LOW,
			    	    "%d new log indexes added\n", idx_cnt);
		 	}

			dl_producer_produce(self->dli_producer, idx_cnt);
			idx_cnt = 0;
		 } */
	}

	if (idx_cnt > 0) {
		if (self->dli_debug_lvl > 0)
			DLOGTR1(PRIO_LOW, "%d new log indexes added\n", idx_cnt);

		/* Issue callback to Producer on indexing log records. */
		dl_producer_produce(self->dli_producer, idx_cnt);
	}

	/* self-trigger the updated() event. */
	dl_index_updated(self);

	pthread_exit(NULL);
}

static void
dl_index_idle(struct dl_index * const self)
{

	assert_integrity(self);

	self->dli_state = DLI_IDLE;

	if (self->dli_debug_lvl > 0) {
		DLOGTR2(PRIO_LOW, "Index state = %s (%d)\n",
	    	    DLI_STATE_NAME[self->dli_state], self->dli_state);
	}
}

static void
dl_index_updating(struct dl_index * const self)
{
	int rc;

	assert_integrity(self);

	self->dli_state = DLI_UPDATING;

	if (self->dli_debug_lvl > 0) {
		DLOGTR2(PRIO_LOW, "Index state = %s (%d)\n",
	    	    DLI_STATE_NAME[self->dli_state], self->dli_state);
	}

	/* Start the thread to update the index. */ 
	rc = pthread_create(&self->dli_tid, NULL,
		dl_update_thread, self);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
			"Failed creating updating thread: %d\n", rc);
			dl_index_error(self);
	}
	pthread_detach(self->dli_tid);
}

static void
dl_index_final(struct dl_index * const self)
{

	assert_integrity(self);

	self->dli_state = DLI_FINAL;

	if (self->dli_debug_lvl > 0) {
		DLOGTR2(PRIO_LOW, "Index state = %s (%d)\n",
	    	    DLI_STATE_NAME[self->dli_state], self->dli_state);
	}
}

static int 
dl_index_lookup_by_poffset(struct dl_index *self, off_t offset,
    struct dl_index_record *record)
{
	struct dl_bbuf *idx_buf;
	int rc, size;
	unsigned char raw_record[DL_INDEX_RECORD_SIZE];

	assert_integrity(self);
	DL_ASSERT(record != NULL, ("IndexRecord cannot be NULL"));

	size = pread(self->dli_fd, &raw_record, DL_INDEX_RECORD_SIZE,
	    offset);
	if (size == 0) {

		/* EOF */
		return 0;	
	} else if (size == -1) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to read from index file %d\n", errno);
		return -1;
	} else {
		DL_ASSERT(size == DL_INDEX_RECORD_SIZE,
		    ("Failed to read index record size"));

		/* Data in the index is stored in big-endian format for
		* compatibility with the Kafka log format.
		* The data read from the dindex is used as an external buffer
		* from a bbuf instance, this allows the values of the relative
		* and physical offset to be read.
		*/
		rc = dl_bbuf_new(&idx_buf, raw_record, DL_INDEX_RECORD_SIZE,
		    DL_BBUF_BIGENDIAN);
		rc |= dl_bbuf_get_uint64(idx_buf, &record->dlir_offset);
		rc |= dl_bbuf_get_int64(idx_buf, &record->dlir_poffset);
		DL_ASSERT(rc == 0, ("dl_bbuf operations failed on index record."));

		dl_bbuf_delete(idx_buf);

		if (rc == 0)
			return size;
		
		return -1;
	}
}

int
dl_index_new(struct dl_index **self, struct dl_user_segment *useg,
    char *path, char *topic_name)
{
	struct dl_index *idx;
	struct dl_index_record record;
	struct kevent idx_ev;
	struct sbuf sb;
	off_t idx_end;
	int64_t base_offset;
	char *name;
	int rc;

	DL_ASSERT(self != NULL, ("Index instance cannot be NULL"));
	DL_ASSERT(useg != NULL, ("Index UserSegment cannot be NULL"));
	DL_ASSERT(path != NULL, ("Index path cannot be NULL"));
	DL_ASSERT(topic_name != NULL, ("Index instance topic name cannot be NULL"));

	idx = (struct dl_index *) dlog_alloc(sizeof(struct dl_index));
	DL_ASSERT(idx != NULL, ("Failed to allocate Index instance."));
	if (idx == NULL) {

		goto err_index_ctor;
	}

	bzero(idx, sizeof(struct dl_index));

	/* Read the configured debug level */
	idx->dli_debug_lvl = dnvlist_get_number(dlogd_props,
	    DL_CONF_DEBUG_LEVEL, DL_DEFAULT_DEBUG_LEVEL);
	idx->dli_state = DLI_INITIAL;
	idx->dli_useg = useg;

	/* Create the name of the IndexSegment file: 000...000.index */
	base_offset = dl_segment_get_base_offset(
	    (struct dl_segment *) useg);

	/* Allocate a buffer for the Index filepath.
	 * The formatted filepath is written into the allocated buffer
	 * using an sbuf().
	 */
	name = dlog_alloc(MAXPATHLEN);
	DL_ASSERT(name != NULL, ("Allocating temp buffer for filepath failed"));
	if (name == NULL) {

		DLOGTR0(PRIO_HIGH, "Failed formatting the Index filepath\n");
		goto err_index_free;
	}

	(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, DL_INDEX_FMT, path, DL_INDEX_DIGITS,
	    base_offset);
	if (sbuf_error(&sb) != 0) {

		DLOGTR0(PRIO_HIGH, "Failed formatting the Index filepath\n");
		sbuf_finish(&sb);
		sbuf_delete(&sb);
		dlog_free(name);
		goto err_index_free;
	}

	sbuf_finish(&sb);
	sbuf_delete(&sb);

	/* Open the IndexSegment file. */
	idx->dli_fd = open(name, O_RDWR | O_CREAT, 0666);
	if (idx->dli_fd == -1) {

		DLOGTR2(PRIO_HIGH,
		    "Failed opening IndexSegment %s: %d.\n",
		    name, errno);
		dlog_free(name);
		goto err_index_free;
	}

	/* Free the buffer holding the Index filepath. */
	dlog_free(name);

	/* Register kq event to monitor deletion of the
	 * IndexSegment file.
	 */
	idx->dli_kq = kqueue();
	if (idx->dli_kq == -1) {

		DLOGTR0(PRIO_HIGH, "Failed initializing Index kqueue\n");
		goto err_index_path;
	}

	/* Initialise a kevent to monitor deletes of the IndexSegment file. */
	EV_SET(&idx_ev, idx->dli_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_DELETE, 0, NULL);
	rc = kevent(idx->dli_kq, &idx_ev, 1, NULL, 0, NULL);
	if (rc == -1) {

		DLOGTR0(PRIO_HIGH, "Failed initializing Index kevent\n");
		goto err_index_kqueue;
	}	

	idx->dli_idx_hdlr.dleh_instance = idx;
	idx->dli_idx_hdlr.dleh_get_handle = dl_index_get_idx_fd;
	idx->dli_idx_hdlr.dleh_handle_event = dl_index_idx_handler;

	dl_poll_reactor_register(&idx->dli_idx_hdlr, POLLIN | POLLERR);
	
	idx->dli_base_offset = base_offset;
	idx->dli_useg = useg;

	/* Read the last value out of the index. */
	idx_end = lseek(idx->dli_fd, 0, SEEK_END);
	if (idx_end == 0) {

		DLOGTR0(PRIO_LOW, "New index file created\n");
		idx->dli_last = 0;
	} else {
		rc = dl_index_lookup_by_poffset(idx,
		    (idx_end - DL_INDEX_RECORD_SIZE), &record);
		if (rc <= 0) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from index file %d\n", errno);
			idx->dli_last = 0;
		} else {
			idx->dli_last = record.dlir_poffset;
		}
	}

	if (idx->dli_debug_lvl > 1) {
		DLOGTR1(PRIO_LOW,
		    "Log offset at which last index is found (%ld)\n",
		    idx->dli_last);
	}
	
	assert_integrity(idx);
	*self = idx;

	/* Synchnronously create the Index in the idle state. */
	dl_index_updating(*self);
	return 0;

err_index_kqueue:
	 /* Close file descriptor of kqueue monitoring the index */ 
	close(idx->dli_kq);

err_index_path:
	/* Clsoe file descriptor of index */
	close(idx->dli_fd);

err_index_free:
	/* Free the Index instnace. */
	dlog_free(idx);

err_index_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Index\n");

	*self = NULL;
	return -1;
}

void
dl_index_delete(struct dl_index *self)
{

	assert_integrity(self);

	/* Transition to the final state. */
	dl_index_final(self);
	
	/* Stop the index thread. */
	pthread_cancel(self->dli_tid);
	pthread_join(self->dli_tid, NULL);
	
	dl_poll_reactor_unregister(&self->dli_idx_hdlr);

	/* Close file descriptor of kqueue monitoring the index */ 
	close(self->dli_kq);

	/* Close file descriptor of index */
	close(self->dli_fd);

	/* Free the Index instnace. */
	dlog_free(self);
}

void
dl_index_error(struct dl_index const * const self)
{

	assert_integrity(self);

	switch(self->dli_state) {
	case DLI_IDLE: /* idle -> final */
		/* FALLTHROUGH */
	case DLI_UPDATING: /* updating -> final */
		/* FALLTHROUGH */
		if (self->dli_debug_lvl > 1)
			DLOGTR1(PRIO_LOW,
			    "Index event = error(): %s->FINAL\n",
			    DLI_STATE_NAME[self->dli_state]);

		dl_index_final(self);
		break;
	case DLI_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLI_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid indexstate = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_updated(struct dl_index const * const self)
{

	assert_integrity(self);

	switch(self->dli_state) {
	case DLI_UPDATING: /* updating->idle */
		dl_index_idle(self);
		break;
	case DLI_IDLE: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLI_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLI_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid index state = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_update(struct dl_index const * const self)
{

	assert_integrity(self);

	switch(self->dli_state) {
	case DLI_IDLE: /* idle -> updating */
		dl_index_updating(self);
		break;
	case DLI_UPDATING:
		/* IGNORE */
		break;
	case DLI_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLI_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid index state = %d",
		    self->dli_state));
		break;
	}
}

int
dl_index_lookup(struct dl_index *self, uint64_t offset,
    struct dl_index_record *record)
{
	uint32_t rel_offset;
	int rc;

	assert_integrity(self);
	DL_ASSERT(record != NULL, ("IndexRecord cannot be NULL"));

	rel_offset = offset - 
	    dl_segment_get_base_offset((struct dl_segment *) self->dli_useg);

	rc = dl_index_lookup_by_poffset(self,
	    (rel_offset * DL_INDEX_RECORD_SIZE), record);
	DL_ASSERT(rc == 0, ("Lookup of offset %zu in index failed", offset));
	if (rc == 0) {

		if (self->dli_debug_lvl > 1)
			DLOGTR1(PRIO_LOW,
			    "Log entry for offset %zu not indexed\n", offset);
		return -1;
	} else if (rc == -1) {

		DLOGTR1(PRIO_LOW,
		    "Failed looking up index for offset %zu\n", offset);
		return -1;
	} else {

		return 0;
	}
}

void
dl_index_set_producer(struct dl_index *self, struct dl_producer *producer)
{

	assert_integrity(self);
	self->dli_producer = producer;
}
