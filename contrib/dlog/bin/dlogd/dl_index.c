/*-
 * Copyright (c) 2018-2020 (Graeme Jenkinson)
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

typedef volatile uint32_t dl_index_state;

struct dl_index {
	struct dl_event_handler dli_idx_hdlr;
	struct dl_user_segment *dli_useg;
	struct dl_producer *dli_producer;
	off_t dli_last; /* The last offset in the log indexed */
	pthread_cond_t dli_update_cnd;
	pthread_mutex_t dli_update_mtx;
	pthread_t dli_tid; /* Update thread tid */
	uint64_t dli_base_offset; /* Base offset of log segment */
	dl_index_state dli_state;
	int dli_debug_lvl;
	int dli_fd; /* File descriptor of index */
	int dli_kq; /* File descriptor of kqueue monitoring the index */ 
	char dli_filename[MAXPATHLEN];
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
const static uint32_t DLI_RECREATE = 3;
const static uint32_t DLI_FINAL = 4;

static char const * const DLI_STATE_NAME[] =
    {"INITIAL", "IDLE", "UPDATING", "RECREATE", "FINAL" };

/* Number of digits in base 10 required to represent a 32-bit number. */
static const int DL_INDEX_DIGITS = 20;
static const char * const INDEX_FMT = "%s/%.*ld.index";
static const int INDEX_FLAGS = O_RDWR | O_CREAT;
static const int INDEX_PERMS = 0600;
/* Maximum number of indexes created before issuing callback to Producer. */
static const uint32_t DL_INDEX_PRODUCE_CNT = 100;

static void dl_index_idle(struct dl_index * const self);
static void dl_index_updating(struct dl_index * const self);
static void dl_index_recreate(struct dl_index * const self);
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

	/* Verify the method's preconditions */	
	assert_integrity(s);
	return s->dli_kq;
}

static void
dl_index_idx_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_index * const idx = instance;
	struct kevent event;
	int rc;

	/* Verify the method's preconditions */	
	assert_integrity(idx);
			
	rc = kevent(idx->dli_kq, 0, 0, &event, 1, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	} else {

		if (event.fflags & NOTE_DELETE) {

			DLOGTR0(PRIO_HIGH, "Index segment file deleted\n");
			dl_index_deleted(idx);
		}
	}
}

static void *
dl_update_thread(void *vargp)
{
	struct dl_index *self = (struct dl_index *)vargp;
	struct iovec index_iov[2];
	off_t tmp_poffset;
	uint64_t offset;
	size_t iocnt = sizeof(index_iov)/sizeof(struct iovec);
	uint32_t cnt = 0, size;
	int rc, log;

	/* Verify the method's preconditions */	
	assert_integrity(self);

	log = dl_user_segment_get_fd(self->dli_useg);
	DL_ASSERT(log != -1, ("Log fd cannot be invalid (-1)"));

	/* Create the index. */
	while (true) {

		/* Wait for signal before resuming enqueuing log records */
		while (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE) != DLI_UPDATING) {
			pthread_mutex_lock(&self->dli_update_mtx);
			pthread_cond_wait(&self->dli_update_cnd, &self->dli_update_mtx);
			pthread_mutex_unlock(&self->dli_update_mtx);

			if (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE) == DLI_FINAL) {

				goto terminate_update_thread;
			}
		}

		/* Read the offset of the log entry and size. */
		// TODO this read should probably be a function in UserSegment
		index_iov[0].iov_base = &offset;
		index_iov[0].iov_len = sizeof(offset);

		index_iov[1].iov_base = &size;
		index_iov[1].iov_len = sizeof(size);

		rc = preadv(log, index_iov, iocnt, self->dli_last);
		if (rc == 0) {

			/* EOF */
			if (cnt > 0) {
				if (self->dli_debug_lvl > 1) {
					DLOGTR1(PRIO_LOW,
					    "%d new log indexes added\n", cnt);
				}

				/* Issue callback to Producer on indexing log records. */
				dl_producer_produce(self->dli_producer);

				/* Reset the count of indexes produced */
				cnt = 0;
			}

			/* self-trigger the updated() event. */
			dl_index_updated(self);
		} else if (rc == -1) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from log file %d\n", errno);
			break;
		} else {
			off_t log_end;

			/* Check that the entry in the log is not corrupt,
			 * that is if the size of the message exceeds the total
			 * log length.
			 */
			log_end = lseek(log, 0, SEEK_END);
			if (log_end == -1) {

				DLOGTR1(PRIO_HIGH, "Error seeking end of file: %d\n", errno);
				break;
			}

			if((off_t) (sizeof(offset) + sizeof(size) +
		    	    be32toh(size)) > log_end) {
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
			if (++cnt % DL_INDEX_PRODUCE_CNT == 0) {

				if (self->dli_debug_lvl > 1) {
					DLOGTR1(PRIO_LOW,
					"%d new log indexes added\n", cnt);
				}

				/* Issue callback to Producer on indexing log records. */
				dl_producer_produce(self->dli_producer);
					
				/* Reset the count of indexes produced */
				cnt = 0;
			}
		}
	}

terminate_update_thread:
	if (self->dli_debug_lvl > 1) {
		DLOGTR1(PRIO_LOW, "%s index update thread stopped.\n",
		    dl_topic_get_name(dl_producer_get_topic(self->dli_producer)));
	}

	pthread_exit(NULL);
}

static void
dl_index_idle(struct dl_index * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	__atomic_store_n(&self->dli_state, DLI_IDLE, __ATOMIC_RELEASE);

	if (self->dli_debug_lvl > 0) {
		DLOGTR1(PRIO_LOW, "Index state = %s\n",
	    	    DLI_STATE_NAME[self->dli_state]);
	}
}

static void
dl_index_updating(struct dl_index * const self)
{
	int rc;

	/* Verify the method's preconditions */	
	assert_integrity(self);

	__atomic_store_n(&self->dli_state, DLI_UPDATING, __ATOMIC_RELEASE);

	if (self->dli_debug_lvl > 0) {
		DLOGTR1(PRIO_LOW, "Index state = %s\n",
	    	    DLI_STATE_NAME[self->dli_state]);
	}

	/* Start the update thread */
	rc = pthread_cond_signal(&self->dli_update_cnd);
	DL_ASSERT(rc == 0, ("Failed signalling update thread"));
}

static void
dl_index_recreate(struct dl_index * const self)
{
	struct kevent old_ev, new_ev;
	int rc;

	/* Verify the method's preconditions */	
	assert_integrity(self);

	__atomic_store_n(&self->dli_state, DLI_RECREATE, __ATOMIC_RELEASE);

	if (self->dli_debug_lvl > 0) {
		DLOGTR1(PRIO_LOW, "Index state = %s\n",
	    	    DLI_STATE_NAME[self->dli_state]);
	}

	/* Stop the update thread. */
//	pthread_cancel(self->dli_tid);
	pthread_join(self->dli_tid, NULL);

	/* Remove the kevent monitoring deletion of the IndexSegment file. */
	EV_SET(&old_ev, self->dli_fd, EVFILT_VNODE, EV_DELETE | EV_CLEAR,
		NOTE_DELETE, 0, NULL);
	rc = kevent(self->dli_kq, &old_ev, 1, NULL, 0, NULL);
	if (rc == -1) {

		DLOGTR0(PRIO_HIGH, "Failed initializing Index kevent\n");
		dl_index_error(self);
	}	

	/* Reinitialize the index. */
	self->dli_last = 0;

	/* Open the IndexSegment file. */
	self->dli_fd = open(self->dli_filename, INDEX_FLAGS, INDEX_PERMS);
	if (self->dli_fd == -1) {

		DLOGTR2(PRIO_HIGH, "Failed opening IndexSegment %s: %d.\n",
		    self->dli_filename, errno);
		dl_index_error(self);
	}

	/* Initialise a kevent to monitor deletes of the IndexSegment file. */
	EV_SET(&new_ev, self->dli_fd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
		NOTE_DELETE, 0, NULL);
	rc = kevent(self->dli_kq, &new_ev, 1, NULL, 0, NULL);
	if (rc == -1) {

		DLOGTR0(PRIO_HIGH, "Failed initializing Index kevent\n");
		dl_index_error(self);
	}

	/* Self trigger the restored evewnt */	
	dl_index_restored(self);
}

static void
dl_index_final(struct dl_index * const self)
{
	int rc;

	/* Verify the method's preconditions */	
	assert_integrity(self);

	__atomic_store_n(&self->dli_state, DLI_FINAL, __ATOMIC_RELEASE);

	if (self->dli_debug_lvl > 0) {
		DLOGTR1(PRIO_LOW, "Index state = %s\n",
	    	    DLI_STATE_NAME[self->dli_state]);
	}

	/* Stop the index update thread */
	rc = pthread_cond_signal(&self->dli_update_cnd);
	DL_ASSERT(rc == 0, ("Failed signalling update thread"));

	/* Join the thread - reclaiming it's resources */
	rc = pthread_join(self->dli_tid, NULL);
	DL_ASSERT(rc == 0, ("Failed joining update thread"));
}

static int 
dl_index_lookup_by_poffset(struct dl_index *self, off_t offset,
    struct dl_index_record *record)
{
	struct dl_bbuf *idx_buf;
	int size;
	unsigned char raw_rec[DL_INDEX_RECORD_SIZE];

	/* Verify the method's preconditions */	
	assert_integrity(self);
	DL_ASSERT(record != NULL, ("IndexRecord cannot be NULL"));
		
	size = pread(self->dli_fd, &raw_rec, DL_INDEX_RECORD_SIZE, offset);
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
		 * The data read from the index is used as an external buffer
		 * from a bbuf instance, this allows the values of the relative
		 * and physical offset to be read.
		 */
		dl_bbuf_new(&idx_buf, raw_rec, DL_INDEX_RECORD_SIZE,
		    DL_BBUF_BIGENDIAN);
		dl_bbuf_get_uint64(idx_buf, &record->dlir_offset);
		dl_bbuf_get_int64(idx_buf, &record->dlir_poffset);

		if (dl_bbuf_error(idx_buf) != 0) {

			DL_ASSERT(false, ("dl_bbuf operations failed on index record."));
			dl_bbuf_delete(idx_buf);
			return -1;
		}
		
		dl_bbuf_delete(idx_buf);
		return size;
	}
}

int
dl_index_new(struct dl_index **self, struct dl_user_segment *useg,
    struct dl_producer *producer, char *path)
{
	struct dl_index *idx;
	struct dl_index_record record;
	struct kevent idx_ev;
	struct sbuf sb;
	off_t idx_end;
	int64_t base_offset;
	int rc;

	/* Verify the method's preconditions */	
	DL_ASSERT(self != NULL, ("Index instance cannot be NULL"));
	DL_ASSERT(useg != NULL, ("Index UserSegment cannot be NULL"));
	DL_ASSERT(path != NULL, ("Index path cannot be NULL"));

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

	/* Construct the Index filepath. */
	(void) sbuf_new(&sb, idx->dli_filename, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, INDEX_FMT, path, DL_INDEX_DIGITS,
	    base_offset);
	sbuf_finish(&sb);
	if (sbuf_error(&sb) != 0) {

		DLOGTR0(PRIO_HIGH, "Failed formatting the Index filepath\n");
		sbuf_delete(&sb);
		goto err_index_free;
	}
	sbuf_delete(&sb);

	/* Open the Index file. */
	idx->dli_fd = open(idx->dli_filename, INDEX_FLAGS, INDEX_PERMS);
	if (idx->dli_fd == -1) {

		DLOGTR2(PRIO_HIGH,
		    "Failed opening IndexSegment %s: %d.\n",
		    idx->dli_filename, errno);
		goto err_index_free;
	}

	/* Register kq event to monitor deletion of the
	 * IndexSegment file.
	 */
	idx->dli_kq = kqueue();
	if (idx->dli_kq == -1) {

		DLOGTR0(PRIO_HIGH, "Failed initializing Index kqueue\n");
		goto err_index_path;
	}

	/* Initialise a kevent to monitor deletion of the IndexSegment file. */
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
	idx->dli_producer = producer;

	/* Read the last value out of the index. */
	idx_end = lseek(idx->dli_fd, -DL_INDEX_RECORD_SIZE, SEEK_END);
	if (idx_end == -1) {

		DLOGTR0(PRIO_LOW, "New index file created\n");
		idx->dli_last = 0;
	} else {

		rc = dl_index_lookup_by_poffset(idx, idx_end, &record);
		if (rc <= 0) {

			DLOGTR1(PRIO_HIGH,
			    "Failed to read from index file %d\n", errno);
			idx->dli_last = 0;
		} else {
			struct iovec index_iov[2];
			size_t iocnt = sizeof(index_iov)/sizeof(struct iovec);
			uint64_t offset;
			uint32_t size;
			int log;

			log = dl_user_segment_get_fd(useg);
			DL_ASSERT(log != -1, ("Log fd cannot be invalid (-1)"));

			/* Read the offset of the log entry and size. */
			index_iov[0].iov_base = &offset;
			index_iov[0].iov_len = sizeof(offset);

			index_iov[1].iov_base = &size;
			index_iov[1].iov_len = sizeof(size);

			rc = preadv(log, index_iov, iocnt, record.dlir_poffset);
			if (rc == 0) {

				/* EOF */
				DLOGTR1(PRIO_HIGH,
				    "Invalid index poffset %lu > log file\n",
				    record.dlir_poffset);
				goto err_index_kqueue;
			}  else if (rc == -1) {

				DLOGTR1(PRIO_HIGH,
				    "Failed to read from index file %d\n", errno);
				goto err_index_kqueue;
			} else {
				off_t log_end;

				/* Check that the entry in the log is not corrupt,
				 * that is if the size of the message exceeds the total
				 * log length.
				 */
				log_end = lseek(log, 0, SEEK_END);
				if (log_end == -1) {

					DLOGTR0(PRIO_HIGH, "\n");
					goto err_poll_reactor;
				}

				if((off_t) (sizeof(offset) + sizeof(size) +
				    be32toh(size)) > log_end) {
					DLOGTR3(PRIO_NORMAL,
					    "Log message at offset %lu is corrupt (%lu > %ld)",
					    be64toh(offset),
					    (sizeof(offset) + sizeof(size) + be32toh(size)),
					    log_end);
					goto err_poll_reactor;
				}

				idx->dli_last = record.dlir_poffset +
				    (off_t) (sizeof(offset) + sizeof(size) +
				    be32toh(size));
			}
		}
	}

	if (idx->dli_debug_lvl > 1) {
		DLOGTR1(PRIO_LOW,
		    "Log offset at which last index is found (%ld)\n",
		    idx->dli_last);
	}

	rc = pthread_mutex_init(&idx->dli_update_mtx, NULL);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed creating update mutex: %d\n", rc);
		goto err_index_kqueue;
	}

	rc = pthread_cond_init(&idx->dli_update_cnd, NULL);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed creating update cond var: %d\n", rc);
		goto err_index_mutex;
	}

	/* Start the thread to update the index. */ 
	rc = pthread_create(&idx->dli_tid, NULL, dl_update_thread, idx);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH, "Failed creating updating thread: %d\n", rc);
		goto err_index_cond;
	}

	/* Verfiy the mehods postconditions */
	assert_integrity(idx);
	*self = idx;

	/* Synchnronously create the Index in the idle state. */
	dl_index_idle(*self);
	return 0;

err_index_cond:
	/* Destory the enqueue thread cond var. */
	rc = pthread_cond_destroy(&idx->dli_update_cnd);

err_index_mutex:
	/* Destory the enqueue thread mutex. */
	rc = pthread_mutex_destroy(&idx->dli_update_mtx);

err_poll_reactor:
	/* Unregister the poll reactor. */
	dl_poll_reactor_unregister(&idx->dli_idx_hdlr);

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

	/* Verify the method's preconditions */	
	assert_integrity(self);

	/* Close file descriptor of kqueue monitoring the index
	 * (this removes all monitored events)
	 */ 
	close(self->dli_kq);

	/* Unregister the poll reactor handler */
	dl_poll_reactor_unregister(&self->dli_idx_hdlr);

	/* Transition to the final state. */
	dl_index_final(self);
	
	/* Destroy the cond var and associated mutex */
	pthread_cond_destroy(&self->dli_update_cnd);
	pthread_mutex_destroy(&self->dli_update_mtx);

	/* Close file descriptor of index */
	close(self->dli_fd);
	
	/* Free the Index instance. */
	dlog_free(self);
}

void
dl_index_deleted(struct dl_index const * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	switch (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE)) {
	case DLI_IDLE: /* idle -> recreate */
		/* FALLTHROUGH */
	case DLI_UPDATING: /* updating -> recreate */
		dl_index_recreate(self);
		break;
	case DLI_RECREATE:
		/* IGNORE */
		break;
	case DLI_INITIAL:
		/* FALLTHROUGH */
	case DLI_FINAL:
		/* FALLTHROUGH */
	default:
		/* CANNOT HAPPEN */
		DL_ASSERT(0, ("Invalid index state = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_error(struct dl_index const * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	switch (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE)) {
	case DLI_IDLE: /* idle -> final */
		/* FALLTHROUGH */
	case DLI_UPDATING: /* updating -> final */
		/* FALLTHROUGH */
	case DLI_RECREATE: /* recreate->final */
		if (self->dli_debug_lvl > 1)
			DLOGTR1(PRIO_LOW,
			    "Index event = error(): %s->FINAL\n",
			    DLI_STATE_NAME[self->dli_state]);

		dl_index_final(self);
		break;
	case DLI_INITIAL:
		/* FALLTHROUGH */
	case DLI_FINAL:
		/* FALLTHROUGH */
	default:
		/* CANNOT HAPPEN */
		DL_ASSERT(0, ("Invalid indexstate = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_restored(struct dl_index const * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	switch (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE)) {
	case DLI_RECREATE: /* recreate->idle */
		dl_index_updating(self);
		break;
	case DLI_FINAL:
		/* IGNORE */
		break;
	case DLI_INITIAL:
		/* FALLTHROUGH */
	case DLI_IDLE:
		/* FALLTHROUGH */
	case DLI_UPDATING:
		/* FALLTHROUGH */
	default:
		/* CANNOT HAPPEN */
		DL_ASSERT(0, ("Invalid index state = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_updated(struct dl_index const * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	switch (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE)) {
	case DLI_UPDATING: /* updating->idle */
		dl_index_idle(self);
		break;
	case DLI_FINAL:
		/* IGNORE */
		break;
	case DLI_IDLE: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLI_RECREATE:
		/* FALLTHROUGH */
	case DLI_INITIAL:
		/* FALLTHROUGH */
	default:
		/* CANNOT HAPPEN */
		DL_ASSERT(0, ("Invalid index state = %d",
		    self->dli_state));
		break;
	}
}

void
dl_index_update(struct dl_index const * const self)
{

	/* Verify the method's preconditions */	
	assert_integrity(self);

	switch (__atomic_load_n(&self->dli_state, __ATOMIC_ACQUIRE)) {
	case DLI_IDLE: /* idle -> updating */
		dl_index_updating(self);
		break;
	case DLI_UPDATING:
		/* FALLTHROUGH */
	case DLI_RECREATE:
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
	struct dl_segment *seg = (struct dl_segment *) self->dli_useg;
	uint32_t rel_offset;
	int rc;

	/* Verify the method's preconditions */	
	assert_integrity(self);
	DL_ASSERT(record != NULL, ("IndexRecord cannot be NULL"));

	/* Find the relative offset into the current log segment */
	rel_offset = offset - dl_segment_get_base_offset(seg);

	rc = dl_index_lookup_by_poffset(self,
	    (rel_offset * DL_INDEX_RECORD_SIZE), record);
	if (rc == 0) {

		if (self->dli_debug_lvl > 1)
			DLOGTR1(PRIO_LOW,
			    "Log entry for offset %lu not indexed\n", offset);
		return -1;
	} else if (rc == -1) {

		DLOGTR1(PRIO_NORMAL,
		    "Failed looking up index for offset %lu\n", offset);
		return -1;
	} else {

		return 0;
	}
}
