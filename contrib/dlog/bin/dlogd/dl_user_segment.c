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

#include <sys/types.h>
#include <sys/dnv.h>
#include <sys/uio.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>

#include <poll.h>
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_primitive_types.h"
#include "dl_user_segment.h"
#include "dl_segment.h"
#include "dl_utils.h"

extern const void *DL_SEGMENT;

struct dl_user_segment {
	struct dl_segment dlus_segment;
	struct dl_event_handler dlus_log_hdlr;
	struct dl_producer *dlus_producer;
	pthread_mutex_t dlus_lock; /* Lock for whilst updating segment. */
	struct dl_offset *dlus_offset; /* The offset within the Segment */
	struct dl_index *dlus_idx; /* The index of the Segment */
	int dlus_log; /* Log file descriptor. */
	int dlus_kq;
	char dlus_path[MAXPATHLEN];
};

/* Global singleton dlogd configuration */
extern nvlist_t *dlogd_props;

static int dl_user_segment_ctor(void *, va_list *);
static void dl_user_segment_dtor(void *);

static dl_event_handler_handle get_log_fd(void *);
static void log_handler(void *, int, int);

static int get_message_by_offset(struct dl_segment *, int,
    struct dl_bbuf **);
static int insert_message(struct dl_segment *, struct dl_bbuf *);
static uint32_t get_offset(struct dl_segment *);
static int sync_log(struct dl_segment *);
static bool is_log_rotated(struct dl_user_segment *);
static bool rotate_log(struct dl_user_segment *);

static char const * const DL_DEFAULT_PARTITION = "0";
static const uint64_t DL_DEFAULT_BASE = 0;
static const int UPDATE_INDEX_EVENT = (0x01 << 1);
static const int DLP_UPDATE_INDEX_MS = 2000;
static char const * const USEG_FMT = "%s/%s";
static const int USEG_FLAGS = O_RDONLY;
static const int USEG_PERMS = 0600;

static const struct dl_segment_class TYPE = {
	{
		sizeof(struct dl_user_segment),
		dl_user_segment_ctor,
		dl_user_segment_dtor,
		NULL	
	},
	get_message_by_offset,
	insert_message,
	sync_log,
	get_offset
};

static const void *DL_USER_SEGMENT = &TYPE;

static inline void
assert_integrity(struct dl_user_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
	DL_ASSERT(self->dlus_offset != NULL,
	    ("Segment instance offset cannot be NULL."));
}

static bool
is_log_rotated(struct dl_user_segment *self)
{
	struct dl_offset *offset = self->dlus_offset;
	struct dl_segment *super= (struct dl_segment *) self;
	struct sbuf sb;
	struct stat st;
	char name[MAXPATHLEN];
	
	/* Validate the method's preconditions. */
	assert_integrity(self);

	 if (super->dls_base_offset == dl_offset_get_val(self->dlus_offset))
		return false;

	/* Construct filepath for log segment based on the offset. */
	(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, "%s/%.*ld.log", self->dlus_path,
	    DL_LOG_DIGITS, (uint64_t) dl_offset_get_val(offset));
	sbuf_finish(&sb);
	if (sbuf_error(&sb) != 0) {

		DLOGTR1(PRIO_HIGH,
		    "UserSegment file path %s overflow MAXPATHLEN\n", name);
		sbuf_delete(&sb);
		return false;
	}
	sbuf_delete(&sb);

	/* If a log file with the new offset exists
	 * rotate the current log segment.
	 */
	if (stat(name, &st) == 0) {

		return true;
	}

	return false;
}

static bool
rotate_log(struct dl_user_segment *self)
{
	struct sbuf sb;
	int rc;
	char name[MAXPATHLEN];
	struct dl_index *idx;
	int log_fd;

	/* Validate the method's preconditions. */
	assert_integrity(self);

	DLOGTR0(PRIO_LOW, "Log file rotated by kernel\n");

	/* Construct filepath for new log segment */
	(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, "%s/%.*ld.log", self->dlus_path,
	    DL_LOG_DIGITS, (uint64_t) dl_offset_get_val(self->dlus_offset));
	sbuf_finish(&sb);
	if (sbuf_error(&sb) != 0) {

		DLOGTR1(PRIO_HIGH,
		    "UserSegment file path %s overflow MAXPATHLEN\n", name);
		sbuf_delete(&sb);
		return -1;
	} 
	sbuf_delete(&sb);
	
	DLOGTR1(PRIO_LOW, "Rotating log segment new base offset = %lu\n",
	    (uint64_t) dl_offset_get_val(self->dlus_offset));
	
	/* Unregister the handler whilst the rotation of the log is in
	 * progress.
	 */
	dl_poll_reactor_unregister(&self->dlus_log_hdlr);

	/* Construct a new userspace log segment. */
	log_fd = open(name, USEG_FLAGS, USEG_PERMS);
	if (self->dlus_log == -1) {

		DLOGTR1(PRIO_HIGH, "Failed opening UserSegment file: %s\n",
		    name);
		return -1;
	}

	/* Update the log segment's file descriptor */
	close(self->dlus_log);
	self->dlus_log = log_fd;

	/* Update the log segments base offset */
	dl_segment_set_base_offset((struct dl_segment * ) self,
	    dl_offset_get_val(self->dlus_offset));

	/* Update the log segment's index. */
	rc = dl_index_new(&idx, self, self->dlus_producer, self->dlus_path);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed instatiating index\n");
		close(log_fd);
		return -1;
	}

	/* Update the log segment's index */
	dl_index_delete(self->dlus_idx);
	self->dlus_idx = idx;

	/* Update the handler */
	dl_poll_reactor_register(&self->dlus_log_hdlr, POLLIN | POLLERR);
	
	/* Validate the method's postconditions. */
	assert_integrity(self);

	return true;
}

static dl_event_handler_handle
get_log_fd(void *instance)
{
	struct dl_user_segment const * const self = instance;

	/* Validate the method's preconditions. */
	assert_integrity(self);
	return self->dlus_kq;
}

static void
log_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_user_segment const * const self = instance;
	struct kevent events[2];
	int nevents = sizeof(events)/sizeof(struct kevent);
	int rc;

	/* Validate the method's preconditions. */
	assert_integrity(self);

	rc = kevent(self->dlus_kq, 0, 0, events, nevents, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n",
		    rc, errno);
	} else {
		for (int i = 0; i < rc; i++) {

			if (events[i].ident == UPDATE_INDEX_EVENT || 
			    events[i].fflags & NOTE_WRITE) {

				/* Fire the Index update() event. */
				dl_index_update(self->dlus_idx);
			}
			   
			if (events[i].fflags & NOTE_DELETE) {

				DLOGTR0(PRIO_HIGH, "Log segment file deleted!\n");
			}
		}
	}
}

static int
dl_user_segment_ctor(void *_super, va_list *ap)
{
	struct dl_segment *super= (struct dl_segment *) _super;
	struct dl_user_segment *self = (struct dl_user_segment *) _super;
	struct kevent log_evs[2];
	struct sbuf log_sb, path_sb;
	struct stat st;
	char *topic_name;
	DIR *dir;
	struct dirent *ent;
	uint64_t offset_val;
	int nevents = sizeof(log_evs)/sizeof(struct kevent);
	int rc;
	char log_name[MAXPATHLEN];
	char log_file_name[MAXPATHLEN] = "";

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));

	/* Initialize the UserSegment super class */
	if (((const struct dl_class *) DL_SEGMENT)->dl_ctor != NULL)
		((const struct dl_class *) DL_SEGMENT)->dl_ctor(self, ap);

	/* Initialise the class members. */
	self->dlus_producer = va_arg(*ap, struct dl_producer *);

	topic_name = va_arg(*ap, char *);

	/* Construct a path name for the directory storing the
	 * topic's data.
	 */
	(void) sbuf_new(&path_sb, self->dlus_path, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&path_sb, USEG_FMT,
	    dnvlist_get_string(dlogd_props, DL_CONF_LOG_PATH,
	    DL_DEFAULT_LOG_PATH), topic_name);
	sbuf_finish(&path_sb);
	if (sbuf_error(&path_sb) != 0) {

		DLOGTR0(PRIO_HIGH, "Configured path overflows MAXPATHLEN\n");
		sbuf_delete(&path_sb);
		goto err_user_seg_ctor;
	}

	sbuf_delete(&path_sb);

	if (stat(self->dlus_path, &st) == -1) {
		
		DLOGTR2(PRIO_HIGH, "Configured path %s error %d\n",
		    self->dlus_path, errno);
		goto err_user_seg_ctor;
	}
	
	if (dnvlist_get_bool(dlogd_props, DL_CONF_FROM_BEGINNING,
	    DL_DEFAULT_FROM_BEGINNING)){
		rc = dl_offset_from_beginning_new(&self->dlus_offset,
		    self->dlus_path);
	} else {
		rc = dl_offset_new(&self->dlus_offset, self->dlus_path);
	}
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH, "Failed instatiating UserSegment offset\n");
		goto err_user_seg_ctor;
	}

	/* Open the specified path and determine the log
	 * segment to process based on the current value
	 * of the offset.
	 */
	if ((dir = opendir(self->dlus_path)) == NULL) {

		DLOGTR2(PRIO_HIGH, "Failed opening path %s: %d\n",
		    self->dlus_path, errno);
		goto err_user_seg_offset;
	}

	offset_val = dl_offset_get_val(self->dlus_offset);

	while((ent = readdir(dir)) != NULL) {

		if (ent->d_type == DT_REG &&
		    strchr(ent->d_name, '.') != NULL &&
		    strcmp(strchr(ent->d_name, '.'), ".log") == 0) {
	
			uint64_t tmp = 0;

			if (sscanf(ent->d_name, "%lu", &tmp) == 1) {
		
				if (offset_val >= tmp && tmp >= super->dls_base_offset) {

					super->dls_base_offset = tmp;
					strncpy(log_file_name, ent->d_name, MAXPATHLEN);
				}
			}
		}
	}

	closedir(dir);

	if (strcmp(log_file_name, "") == 0) {

		DLOGTR1(PRIO_LOW, "No log segment found in path %s\n",
		    self->dlus_path);
		goto err_user_seg_offset;
	}

	/* Open the specified log segment.*/
	(void) sbuf_new(&log_sb, log_name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&log_sb, "%s/%s", self->dlus_path, log_file_name);
	sbuf_finish(&log_sb);
	if (sbuf_error(&log_sb) != 0) {

		DLOGTR0(PRIO_HIGH, "Configured log file overflows MAXPATHLEN\n");
		sbuf_delete(&log_sb);
		goto err_user_seg_offset;
	}

	sbuf_delete(&log_sb);

	self->dlus_log = open(log_name, USEG_FLAGS, USEG_PERMS);
	if (self->dlus_log == -1) {

		DLOGTR1(PRIO_HIGH, "Failed opening UserSegment file: %s\n",
		    log_name);
		goto err_user_seg_offset;
	}

	rc = dl_index_new(&self->dlus_idx, self, self->dlus_producer, self->dlus_path);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed instatiating index\n");
		goto err_user_seg_offset;
	}	

	rc = pthread_mutex_init(&self->dlus_lock, NULL);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH, "Error initializing UserSegment mutex\n");
		goto err_user_seg_offset;
	}

	self->dlus_kq = kqueue();
	if (self->dlus_kq == -1) {

		DLOGTR0(PRIO_HIGH, "Error initializing UserSegment kqueue()\n");
		goto err_user_seg_mutex;
	}

	/* Initialise a kevent to monitor deletes of the IndexSegment file. */
	EV_SET(&log_evs[0], self->dlus_log, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_DELETE | NOTE_WRITE, 0, NULL);
	EV_SET(&log_evs[1], UPDATE_INDEX_EVENT, EVFILT_TIMER,
	    EV_ADD , 0, DLP_UPDATE_INDEX_MS, NULL);

	kevent(self->dlus_kq, log_evs, nevents, NULL, 0, NULL); 

	self->dlus_log_hdlr.dleh_instance = self;
	self->dlus_log_hdlr.dleh_get_handle = get_log_fd;
	self->dlus_log_hdlr.dleh_handle_event = log_handler;

	dl_poll_reactor_register(&self->dlus_log_hdlr, POLLIN | POLLERR);

	assert_integrity(self);
	return 0;

err_user_seg_mutex:
	pthread_mutex_destroy(&self->dlus_lock);

err_user_seg_offset:
	dl_offset_delete(self->dlus_offset);

err_user_seg_ctor:
	DLOGTR0(PRIO_HIGH, "Error Instantiating UserSegment\n");

	return -1;
}

static void
dl_user_segment_dtor(void *_super)
{
	struct dl_user_segment *self = (struct dl_user_segment *) _super;

	assert_integrity(self);

	/* Destroy the KernelSegment super class */
	if (((const struct dl_class *) DL_SEGMENT)->dl_dtor != NULL)
		((const struct dl_class *) DL_SEGMENT)->dl_dtor(_super);

	/* Close file descriptor of kqueue monitoring the index,
	 * (this removes all monitored events)
	 */ 
	close(self->dlus_kq);

	/* Unregister the event handler */
	dl_poll_reactor_unregister(&self->dlus_log_hdlr);

	/* Delete the index */
	dl_index_delete(self->dlus_idx);

	/* Delete the offset */	
	dl_offset_delete(self->dlus_offset);

	/* Close the user segment log file */
	close(self->dlus_log);
	
	/* Delete the mutex */
	pthread_mutex_destroy(&self->dlus_lock);
}

void
dl_user_segment_delete(struct dl_user_segment *self)
{

	assert_integrity(self);
	dl_delete(self);
}

int
dl_user_segment_new_default(struct dl_user_segment **self,
    struct dl_producer * producer, char *topic)
{

	return dl_user_segment_new(self, producer, DL_DEFAULT_BASE,
	    topic, DL_DEFAULT_PARTITION);
}

int
dl_user_segment_new_default_base(struct dl_user_segment **self,
    struct dl_producer *producer, uint64_t base_offset, char *topic)
{

	return dl_user_segment_new(self, producer, base_offset,
	    topic, DL_DEFAULT_PARTITION);
}

int
dl_user_segment_new(struct dl_user_segment **self,
    struct dl_producer *producer, uint64_t base_offset, char *topic,
    char *partition_name)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));
	DL_ASSERT(producer != NULL, ("UserSegment producer cannot be NULL"));
	DL_ASSERT(topic != NULL, ("UserSegment topic name cannot be NULL"));
	DL_ASSERT(partition_name != NULL, ("UserSegment partition name cannot be NULL"));

	return dl_new((void **) self, DL_USER_SEGMENT, base_offset, 
	    producer, topic, partition_name);
}

static int
insert_message(struct dl_segment *segment, struct dl_bbuf *buffer)
{
	struct iovec log_bufs[2];
	struct dl_bbuf *metadata;
	struct dl_user_segment *self =(struct dl_user_segment *) segment;
	int rc;

	/* Verify the method's preconditions */
	assert_integrity(self);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	DLOGTR1(PRIO_HIGH, "Inserting (%zu bytes) into the log\n",
	    dl_bbuf_pos(buffer));

	rc = pthread_mutex_lock(&self->dlus_lock);
	DL_ASSERT(rc == 0, ("Failed locking UserSegment mutex"));

	/* Update the log file. */
	dl_bbuf_new(&metadata, NULL, sizeof(uint32_t),
		DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	dl_bbuf_put_int32(metadata, dl_offset_get_val(self->dlus_offset));
	if (dl_bbuf_error(metadata) != 0) {
	
		goto err_insert_message;
	}

	log_bufs[0].iov_base = dl_bbuf_data(metadata);
	log_bufs[0].iov_len = dl_bbuf_pos(metadata);
	
	log_bufs[1].iov_base = dl_bbuf_data(buffer);
	log_bufs[1].iov_len = dl_bbuf_pos(buffer);

	/* TODO: The Kafka log format should also include a timestamp */

	rc = writev(self->dlus_log, log_bufs,
		sizeof(log_bufs)/sizeof(struct iovec));	
	if (rc == -1) {

		DLOGTR1(PRIO_LOW,
			"UserSegment insert message failed writev (%d)\n", errno);
		goto err_insert_message;
	}
	
	/* Delete the buffer holding the log metadata */
	dl_bbuf_delete(metadata);

	/* Update the offset. */
	dl_offset_inc(self->dlus_offset);

	rc = pthread_mutex_unlock(&self->dlus_lock);
	DL_ASSERT(rc == 0, ("Failed unlocking UserSegment mutex"));

	return 0;

err_insert_message:
	/* Delete the buffer holding the log metadata */
	dl_bbuf_delete(metadata);

	pthread_mutex_unlock(&self->dlus_lock);

	DLOGTR0(PRIO_HIGH, "Error inserting message into Segment\n");
	return -1;
}

static int
get_message_by_offset(struct dl_segment *segment, int offset,
    struct dl_bbuf **msg_buf)
{
	struct dl_bbuf *t;
	struct dl_index_record record;
	struct dl_user_segment *self = (struct dl_user_segment *) segment;
	unsigned char *msg_tmp;
	int64_t base_offset;
	int32_t tmp_buf[3], size;
	int rc;

	assert_integrity(self);

retry:	
	rc = dl_index_lookup(self->dlus_idx, offset, &record);
	if (rc == 0) {
		rc = pread(self->dlus_log, tmp_buf, sizeof(tmp_buf),
		    record.dlir_poffset);
		if (rc == -1) {

			return -1;
		}

		dl_bbuf_new(&t, (unsigned char *) tmp_buf,
		    sizeof(tmp_buf), DL_BBUF_BIGENDIAN);
		dl_bbuf_get_int64(t, &base_offset);
		dl_bbuf_get_int32(t, &size);
		if (dl_bbuf_error(t) != 0) {
	
			dl_bbuf_delete(t);
			return -1;
		}
		dl_bbuf_delete(t);

		msg_tmp = dlog_alloc(size * sizeof(unsigned char) +
		    + sizeof(int64_t) + sizeof(int32_t));
		if (msg_tmp == NULL) {

			return -1;
		}

		rc = pread(self->dlus_log, msg_tmp,
		    size + sizeof(int64_t) + sizeof(int32_t), record.dlir_poffset);
		if (rc == -1) {

			dlog_free(msg_tmp);
			return -1;
		}

		dl_bbuf_new(msg_buf, NULL, size + sizeof(int64_t) + sizeof(int32_t),
		    DL_BBUF_BIGENDIAN);
		dl_bbuf_bcat(*msg_buf, msg_tmp, size + sizeof(int64_t) + sizeof(int32_t));
		if (dl_bbuf_error(*msg_buf) != 0) {
	
			dlog_free(msg_tmp);
			return -1;
		}
		dlog_free(msg_tmp);

		return 0;
	}

	if (is_log_rotated(self)) {

		DLOGTR0(PRIO_LOW, "Log rotated...\n");

		if (rotate_log(self)) {

			goto retry;
		}
	}

	DLOGTR2(PRIO_LOW, "For offset %d no message found (%d)\n", offset, errno);
	return -1;
}

static uint32_t 
get_offset(struct dl_segment * segment)
{
	struct dl_user_segment *self = (struct dl_user_segment *) segment;

	assert_integrity(self);
	return dl_offset_get_val(self->dlus_offset);
}

static int
sync_log(struct dl_segment *segment)
{
	struct dl_user_segment *self =
	    (struct dl_user_segment *) segment;

	assert_integrity(self);
	return fsync(self->dlus_log);
}

extern int
dl_user_segment_get_fd(struct dl_user_segment const * const self)
{

	assert_integrity(self);
	return self->dlus_log;
}

struct dl_index * 
dl_user_segment_get_index(struct dl_user_segment const * const self)
{

	assert_integrity(self);
	return self->dlus_idx;
}

struct dl_offset * 
dl_user_segment_get_offset(struct dl_user_segment const * const self)
{

	assert_integrity(self);
	return self->dlus_offset;
}
