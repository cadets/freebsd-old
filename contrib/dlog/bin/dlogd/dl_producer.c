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
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/dnv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/proc.h>

#include <sys/stat.h>

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <dev/dlog/dlog.h>

#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_config.h"
#include "dl_event_handler.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_new.h"
#include "dl_poll_reactor.h"
#include "dl_produce_request.h"
#include "dl_produce_response.h"
#include "dl_producer.h"
#include "dl_producer_stats.h"
#include "dl_request_queue.h"
#include "dl_response_header.h"
#include "dl_topic.h"
#include "dl_tls_transport.h"
#include "dl_transport.h"
#include "dl_user_segment.h"
#include "dl_utils.h"

typedef uint32_t dl_producer_state;

struct dl_producer {
	struct dl_producer_stats *dlp_stats;
	LIST_ENTRY(dl_prodcuer) dlp_entries;
	struct dl_correlation_id *dlp_cid;
	struct dl_event_handler dlp_ktimer_hdlr;
	struct dl_index *dlp_idx;
	struct dl_request_q *dlp_requests;
	struct dl_topic *dlp_topic;
	struct dl_transport *dlp_transport;
	nvlist_t *dlp_props;
	dl_producer_state dlp_state;
	pthread_t dlp_enqueue_tid;
	pthread_t dlp_produce_tid;
	pthread_t dlp_resender_tid;
	struct sbuf *dlp_broker;
	struct sbuf *dlp_name;
	uint32_t dlp_produce_cnt;
	int dlp_broker_port;
	int dlp_ktimer;
	int dlp_reconn_ms;
	int dlp_resend_timeout;
	int dlp_resend_period;
	int dlp_debug_level;
	bool dlp_resend;
};

const static uint32_t DLP_INITIAL = 0;
const static uint32_t DLP_IDLE = 1;
const static uint32_t DLP_SYNCING = 2;
const static uint32_t DLP_OFFLINE = 3;
const static uint32_t DLP_ONLINE = 4;
const static uint32_t DLP_CONNECTING = 5;
const static uint32_t DLP_FINAL = 6;

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_syncing(struct dl_producer * const self, uint32_t);
static void dl_producer_offline(struct dl_producer * const self);
static void dl_producer_online(struct dl_producer * const self);
static void dl_producer_connecting(struct dl_producer * const self);
static void dl_producer_final(struct dl_producer * const self);

static dl_event_handler_handle dl_producer_get_timer_fd(void *);
static void dl_producer_timer_handler(void *instance, int, int);

static void *dlp_produce_thread(void *vargp);
static void *dlp_resender_thread(void *vargp);

static bool is_log_rotated(struct dl_producer *);

static char const * const DLP_STATE_NAME[] =
    {"INITIAL", "IDLE", "SYNCING", "OFFLINE", "ONLINE", "CONNECTING", "FINAL" };
static const int RECONNECT_TIMEOUT_EVENT = (0x01 << 0);
static const int DLP_MINRECONN_MS = 1000;
static const int DLP_MAXRECONN_MS = 60000;

static inline void
assert_integrity(struct dl_producer const * const self)
{

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(self->dlp_cid != NULL,
	    ("Producer correlation id cannot be NULL."));
	DL_ASSERT(self->dlp_requests != NULL,
	    ("Producer request queue cannot be NULL."));
	DL_ASSERT(self->dlp_topic != NULL,
	    ("Producer topic cannot be NULL."));
	DL_ASSERT(self->dlp_name != NULL,
	    ("Producer instance cannot be NULL."));
}

static bool
is_log_rotated(struct dl_producer *self)
{
	struct dl_offset *offset;
	struct dl_segment *seg;
	struct sbuf sb;
	struct stat st;
	char name[MAXPATHLEN], *topic, *path;

	/* Get the name of the topic produce to. */	
	topic = dl_topic_get_name(self->dlp_topic);
	DL_ASSERT(topic != NULL, ("Topic's name cannot be NULL"));

	/* Get the topic's active segment. */
	seg = dl_topic_get_active_segment(self->dlp_topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));
				
	offset = dl_user_segment_get_offset((struct dl_user_segment *) seg);
	DL_ASSERT(seg != NULL, ("Active segment's offset cannot be NULL"));
		
	/* Construct filepath for log segment based on the offset. */
	path = dnvlist_get_string(self->dlp_props,
	    DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

	(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, "%s/%s/%.*ld.log", path, topic,
	    DL_LOG_DIGITS, (uint64_t) dl_offset_get_val(offset));
	if (sbuf_error(&sb) == 0) {

		DLOGTR1(PRIO_HIGH,
		    "UserSegment file path %s overflow MAXPATHLEN\n", name);
		sbuf_finish(&sb);
		sbuf_delete(&sb);
		return false;
	}

	/* If a log file with the new offfset exists
	 * rotate the current log segment.
	 */
	if (stat(name, &st) == 0) {

		return true;
	}

	return false;
}

static dl_event_handler_handle
dl_producer_get_timer_fd(void *instance)
{
	struct dl_producer const * const self = instance;

	/* Validate the method's preconditions. */
	assert_integrity(self);
	return self->dlp_ktimer;
}

static void
dl_producer_timer_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_producer const * const self = instance;
	struct kevent event;
	int rc;

	/* Validate the method's preconditions. */
	assert_integrity(self);

	rc = kevent(self->dlp_ktimer, 0, 0, &event, 1, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n",
		    rc, errno);
	} else {

		switch (event.ident) {
		case RECONNECT_TIMEOUT_EVENT:

			/* Re-connect timeout expired.
			 * Fired reconnect() event into Producer state machine.
			 */
			dl_producer_reconnect(self);
			break;
		default:
			DLOGTR1(PRIO_HIGH, "Invalid kqueue event: %lu\n",
			    event.ident);
			break;
		}
	}
}

static void *
dlp_resender_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *)vargp;
	struct dl_request_element *request;
	struct timeval tv, tdiff;
	int rc;

	assert_integrity(self);

	if (self->dlp_debug_level > 0)
		DLOGTR0(PRIO_LOW, "Resender thread started\n");

	for (;;) {
		
		/* Iterate accross all the unack'd requests. */	
		dl_request_q_lock(self->dlp_requests);		
		while (dl_request_q_peek_unackd(self->dlp_requests,
		    &request) == 0) {

			gettimeofday(&tv, NULL);
			timersub(&tv, &request->dlrq_tv, &tdiff);
			if ((tdiff.tv_sec * 1000 + tdiff.tv_usec/1000)
			    > self->dlp_resend_timeout) {

				/* Dequeue the request as the it's timeout period
				 * has expired.
				 */ 
				if (dl_request_q_dequeue_unackd(
				    self->dlp_requests, &request) == 0) {

					if (request->dlrq_retries-- <=  0) {

						if (self->dlp_debug_level > 0)
							DLOGTR1(PRIO_LOW,
							"Exceeded resend for request id = %d\n",
							request->dlrq_correlation_id);

						/* The request can now be freed. */
						dl_bbuf_delete(request->dlrq_buffer);
						dlog_free(request);
					} else {
						
						rc = dl_request_q_enqueue(
						self->dlp_requests, request);

						if (self->dlp_debug_level > 0)
							DLOGTR1(PRIO_LOW,
							"Resending request id = %d\n",
							request->dlrq_correlation_id);
					}
				} else {
				}
			} else {
				if (self->dlp_debug_level > 1) {
					DLOGTR2(PRIO_LOW,
					    "Resend request id: %d in %ld (ms)\n",
					    request->dlrq_correlation_id,
					    self->dlp_resend_timeout -
					    (tdiff.tv_sec * 1000 + tdiff.tv_usec/1000));
				}

				/* Any further requests will no require
				 * resending, therefore break out of the
				 * loop.
				 */
				goto resender_sleep;
			}
		}
		dl_request_q_unlock(self->dlp_requests);		
		
resender_sleep:
		sleep(self->dlp_resend_period);
	}

	if (self->dlp_debug_level > 0)
		DLOGTR0(PRIO_LOW, "Resender thread stopped.\n");
	pthread_exit(NULL);
}

static void *
dlp_produce_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *)vargp;
	struct dl_request_element *request;
	ssize_t nbytes;
	int cancel_state;

	assert_integrity(self);

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Producer thread started...\n");

	pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &cancel_state);

	for (;;) {

		/* Dequeue the request; this simply moves the item into
		 * the unacknowledged part of the request queue.
		 */
		while (dl_request_q_dequeue(self->dlp_requests, &request) == 0) {

			/* Record the last attempted send time
			 * of the request.
			 */
			gettimeofday(&request->dlrq_tv, NULL);

			nbytes = dl_transport_send_request(
			    self->dlp_transport, request->dlrq_buffer);

			/* Update the producer statistics */
			dlps_set_sent_cid(self->dlp_stats, request->dlrq_correlation_id);
			dlps_set_sent_timestamp(self->dlp_stats);
			if (nbytes != -1) {
				/* Update the producer statistics */
				dlps_set_sent_error(self->dlp_stats, false);

				if (self->dlp_debug_level > 1)
					DLOGTR2(PRIO_LOW,
					    "ProduceRequest: id = %d "
					    "sent (%ld bytes)\n",
					    request->dlrq_correlation_id,
					    nbytes);
			} else {
				/* Update the producer statistics */
				dlps_set_sent_error(self->dlp_stats, true);

				if (self->dlp_debug_level > 1)
					DLOGTR2(PRIO_LOW,
					    "ProduceRequest: id = %d failed "
					    "(%zu bytes)\n",
					    request->dlrq_correlation_id,
					    dl_bbuf_pos(request->dlrq_buffer));
			}
		}
		DL_ASSERT(1,
		    ("Failed dequeuing request; this cannot fail "
		    "as it is simply moving an item in the list."));
	}

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Produce thread stopped.\n");
	pthread_exit(NULL);
}

static void *
dlp_enqueue_thread(void *vargp)
{
	struct dl_bbuf *buffer, *msg_buffer;
	struct dl_producer *self = (struct dl_producer *)vargp;
	struct dl_topic *topic = self->dlp_topic;
	struct dl_offset *offset;
	struct dl_produce_request *message;
	struct dl_segment *seg;
	char *topic_name;
	int rc;

	assert_integrity(self);

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Enqueue thread started...\n");

	/* Get the name of the topic produce to. */	
	topic_name = dl_topic_get_name(self->dlp_topic);
	DL_ASSERT(topic_name != NULL, ("Topic's name cannot be NULL"));

	/* Get the topic's active segment. */
	seg = dl_topic_get_active_segment(topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));
				
	offset = dl_user_segment_get_offset((struct dl_user_segment *) seg);
	DL_ASSERT(seg != NULL, ("Active segment's offset cannot be NULL"));
			
	while (self->dlp_produce_cnt--) {
		if (dl_topic_get_message_by_offset(self->dlp_topic,
	            &msg_buffer) == 0) {

			/* Instantiate a new ProduceRequest */
			if (dl_produce_request_new_nomsg(&message,
			    dl_correlation_id_val(self->dlp_cid),
			    self->dlp_name, DL_DEFAULT_ACKS, DL_DEFAULT_ACK_TIMEOUT,
			    topic_name) == 0) {

				rc = dl_request_encode(message, &buffer);
				if (rc != 0) {

					DLOGTR0(PRIO_HIGH,
					    "Failed creating ProduceRequest\n");
					dl_delete(message);
					dl_producer_error(self);
				}

				/* Free the ProduceRequest */
				dl_delete(message);

				/* Encode the MessageSet/RecordBatch size. */
				rc = dl_bbuf_put_int32(buffer, dl_bbuf_pos(msg_buffer));
				if (rc != 0) {

					DLOGTR0(PRIO_HIGH,
					    "Failed creating ProduceRequest\n");
					dl_bbuf_delete(msg_buffer);
					dl_producer_error(self);
				}

				/* Concat the buffers together */
				rc = dl_bbuf_concat(buffer, msg_buffer);
				if (rc != 0) {

					DLOGTR0(PRIO_HIGH,
					    "Failed creating ProduceRequest\n");
					dl_bbuf_delete(msg_buffer);
					dl_producer_error(self);
				}

				/* Free the Message buffer read from the log file */
				dl_bbuf_delete(msg_buffer);

				/* Prepend the Producer request with the total length. */
				rc = DL_ENCODE_REQUEST_SIZE_AT(buffer,
				    dl_bbuf_pos(buffer) - sizeof(int32_t), 0);
				if (rc != 0) {

					DLOGTR0(PRIO_HIGH,
					    "Failed creating ProduceRequest\n");
					dl_bbuf_delete(buffer);
					dl_producer_error(self);
				}

				if (self->dlp_debug_level > 2) {
					DLOGTR2(PRIO_LOW,
					    "ProduceRequest: id = %d enqueued (%zu bytes)\n",
					    dl_correlation_id_val(self->dlp_cid),
					    dl_bbuf_pos(buffer));
				}

				rc = dl_request_q_enqueue_new(self->dlp_requests,
				    buffer, dl_correlation_id_val(self->dlp_cid),
				    DL_PRODUCE_API_KEY);
				if (rc != 0) {
					DLOGTR1(PRIO_HIGH,
					    "ProduceRequest: id = %d failed enqueing\n",
					    dl_correlation_id_val(self->dlp_cid));
					    dl_bbuf_delete(buffer);
					    dl_producer_error(self);
					break;
				} else {

					/* Increment the monotonic correlation id. */
					dl_correlation_id_inc(self->dlp_cid);

					/* Increment the offset to process. */
					dl_offset_inc(offset);
				}
			} else {

				DLOGTR0(PRIO_HIGH,
				    "Failed creating ProduceRequest\n");
				    dl_producer_error(self);
				break;
			}
		} else {
			DLOGTR0(PRIO_HIGH, "Failed getting message\n");
		}
	}

	/* Check whether the log file has rotated. */
	if (is_log_rotated(self)) {

		//struct dl_user_segment *old_seg, *new_seg;
		struct dl_user_segment *new_seg;
		struct sbuf sb;
		uint64_t offset_val;
		char *path;
		char name[MAXPATHLEN];

		/* Construct filepath for new log segment */
		offset_val = dl_segment_get_offset(seg);
			
		path = dnvlist_get_string(self->dlp_props,
		DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

		(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
		sbuf_printf(&sb, "%s/%s/%.*ld.log", path, topic_name,
		    DL_LOG_DIGITS, offset_val);
		if (sbuf_error(&sb) == 0) {

			DLOGTR1(PRIO_HIGH,
			    "UserSegment file path %s overflow MAXPATHLEN\n",
			    name);
			sbuf_finish(&sb);
			sbuf_delete(&sb);
		} else {

			sbuf_finish(&sb);
			sbuf_delete(&sb);

			/* Construct a new userspace segment. */
			DLOGTR1(PRIO_LOW,
			    "Rotating log segment new base offset = %lu\n",
			    offset_val);
			rc = dl_user_segment_new_default_base(&new_seg,
			    offset_val, topic_name);
			if (rc != 0) {

				DLOGTR0(PRIO_HIGH, "Failed creating new user space segment\n");
			} else {
				/* Swap the current active segment */
				//old_seg = (struct dl_user_segment *)
				 //   dl_topic_get_active_segment(
				 //   self->dlp_topic);

				dl_topic_set_active_segment(
					self->dlp_topic,
					(struct dl_segment *) new_seg);

				/* Associate the Producer with the Index. */
				//dl_index_set_producer(self->dlp_idx, self);

				/* Associate the Topic Segment with the Index. */
				//dl_user_segment_set_index(new_seg,
				//    self->dlp_idx);
			
				/* Associate the Producer with the Index. */
				dl_index_set_producer(
				    dl_user_segment_get_index(new_seg),
				    self);

				/* Delete the old log segment */
				dl_user_segment_delete(
				    (struct dl_user_segment *) seg);
			}
		}
	}
	
	/* Self-trigger syncd() event. */
	dl_producer_syncd(self);

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Enqueue thread stopped.\n");

	pthread_exit(NULL);
}

static void
dl_producer_connecting(struct dl_producer * const self)
{
	int rc;

	assert_integrity(self);

	self->dlp_state = DLP_CONNECTING;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_CONNECTING);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

	rc = dl_transport_factory_get_inst(&self->dlp_transport, self);
	if (rc == 0) {

		rc = dl_transport_connect(self->dlp_transport,
		    sbuf_data(self->dlp_broker),
		    self->dlp_broker_port);
		if (rc == 0 || (rc == -1 && errno == EINPROGRESS)) {

			/* Connect established or in the process
			 * of establishing.
			 */
			return;
		}

		DLOGTR3(PRIO_HIGH, "Failed connecting to %s:%d (%d)\n",
		    sbuf_data(self->dlp_broker), self->dlp_broker_port,
		    errno);

		dl_producer_down(self);
	} else {

		dl_producer_error(self);
	}
}

static void
dl_producer_idle(struct dl_producer * const self)
{

	assert_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_IDLE;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_IDLE);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);
}

static void
dl_producer_syncing(struct dl_producer * const self, uint32_t cnt)
{
	int rc;

	assert_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_SYNCING;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_SYNCING);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

	/* Connection is up, reset the reconnect timeout */
	self->dlp_reconn_ms = DLP_MINRECONN_MS;

	/* Start the thread to enqueue log entries for syncing
	 * with the distributed broker.
	 */
	self->dlp_produce_cnt = cnt;

	rc = pthread_create(&self->dlp_enqueue_tid, NULL,
	    dlp_enqueue_thread, self);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed creating enqueing thread: %d\n", rc);
		dl_producer_error(self);
	}
}

static void
dl_producer_offline(struct dl_producer * const self)
{
	struct kevent kev;

	assert_integrity(self);

	self->dlp_state = DLP_OFFLINE;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_OFFLINE);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

        /* Stop the produce and resender threads */
	if (self->dlp_resend) {
		pthread_cancel(self->dlp_resender_tid);
		pthread_join(self->dlp_resender_tid, NULL);
	}

	pthread_cancel(self->dlp_produce_tid);
	pthread_join(self->dlp_produce_tid, NULL);

	/* Delete the producer transport */
	DL_ASSERT(self->dlp_transport != NULL,
	   ("Transition to Offline with NULL Transport"));
	dl_transport_delete(self->dlp_transport);
	self->dlp_transport = NULL;

	/* Trigger reconnect event after timeout period. */
	EV_SET(&kev, RECONNECT_TIMEOUT_EVENT, EVFILT_TIMER,
	    EV_ADD | EV_ONESHOT, 0, self->dlp_reconn_ms, NULL);
	kevent(self->dlp_ktimer, &kev, 1, NULL, 0, NULL);

	/* Exponential backoff of the retry timer. */
	if (self->dlp_reconn_ms < DLP_MAXRECONN_MS)
		self->dlp_reconn_ms *= 2;
	else
		self->dlp_reconn_ms += DLP_MAXRECONN_MS;
	return;
}

static void
dl_producer_online(struct dl_producer * const self)
{
	int rc;

	assert_integrity(self);

	self->dlp_state = DLP_ONLINE;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_ONLINE);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

	/* Start the thread to syncing log entries with the
	 * distributed broker.
	 */
	rc = pthread_create(&self->dlp_produce_tid, NULL,
	    dlp_produce_thread, self);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed creating produce thread: %d\n", rc);
		dl_producer_error(self);
	}

	/* Start the thread to resend unacknowledged requests. */
	if (self->dlp_resend) {
		rc = pthread_create(&self->dlp_resender_tid, NULL,
		    dlp_resender_thread, self);
		if (rc != 0) {

			DLOGTR1(PRIO_HIGH,
			    "Failed creating resender thread: %d\n", rc);
			dl_producer_error(self);
		}
	}

	/* Self-trigger the up() event now the the producer
	 * thread has been created.
	 */
	dl_producer_up(self);
}


static void
dl_producer_final(struct dl_producer * const self)
{

	assert_integrity(self);

	self->dlp_state = DLP_FINAL;

	/* Update the producer statistics */
	dlps_set_state(self->dlp_stats, DLP_FINAL);

	if (self->dlp_debug_level > 0) {
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);
	}
}

int
dl_producer_new(struct dl_producer **self, char *topic_name,
    char *hostname, int port, nvlist_t *props)
{
	struct dl_producer *producer;
	struct dl_user_segment *segment;
	//struct kevent klog_ev;
	char *client_id;
	//char *path;
	int requestq_len, rc;

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL"));
	DL_ASSERT(topic_name != NULL, ("Producer topic name cannot be NULL"));
	DL_ASSERT(hostname != NULL, ("Producer hostname cannot be NULL"));
	DL_ASSERT(props != NULL, ("Producer properties cannot be NULL"));

	producer = (struct dl_producer *) dlog_alloc(
	    sizeof(struct dl_producer));
	DL_ASSERT(producer != NULL,
	    ("Failed instantiating Producer instance"));
	if (producer == NULL) {

		goto err_producer_ctor;
	}

	bzero(producer, sizeof(struct dl_producer));

	if (dl_producer_stats_new(&producer->dlp_stats, topic_name)) {

		DLOGTR1(PRIO_HIGH,
		    "Failed to instatiate ProducerStats instance %d.\n", errno);
		goto err_producer_free;
	}

	/* Construct a new userspace segment. */
	rc = dl_user_segment_new_default(&segment, topic_name);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH, "Failed creating new user space segment\n");
		goto err_producer_stats;	
	}

	/* Prelocate an initial segment file for the topic and add
	 * to the hashmap.
	 */
	rc = dl_topic_new(&producer->dlp_topic, topic_name,
	    props, (struct dl_segment *) segment);
	if (rc != 0) {
	
		DLOGTR1(PRIO_HIGH, "Failed instantiating topic %s\n", topic_name);
		/* Free the Producer topic USerSegment instance. */
		dl_user_segment_delete(segment);
		goto err_producer_stats;	
	}

	/* Create a new Index of the log segment. */
	/*
	path = dnvlist_get_string(props,
	    DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

	rc = dl_index_new(&producer->dlp_idx, segment, path, topic_name);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed instatiating index\n");
		goto err_producer_topic;
	}	
	*/

	/* Associate the Producer with the Index. */
	dl_index_set_producer(dl_user_segment_get_index(segment),
	    producer);

	//dl_index_set_producer(producer->dlp_idx, producer);

	/* Associate the Topic Segment with the Index. */
	//dl_user_segment_set_index(segment, producer->dlp_idx);

	/* Take a defensive copy of the client id. */
	producer->dlp_name = sbuf_new_auto();
	client_id = dnvlist_get_string(props, DL_CONF_CLIENTID,
	    DL_DEFAULT_CLIENTID);
	sbuf_cpy(producer->dlp_name, client_id);
	sbuf_finish(producer->dlp_name);
	if (sbuf_error(producer->dlp_name) != 0) {

	}

	/* Take defensive copy of the hostname. */
	producer->dlp_broker = sbuf_new_auto();
	sbuf_cpy(producer->dlp_broker, hostname);
	sbuf_finish(producer->dlp_broker);
	if (sbuf_error(producer->dlp_broker) != 0) {

	}

	producer->dlp_broker_port = port;
	   
	requestq_len = dnvlist_get_number(props, DL_CONF_REQUEST_QUEUE_LEN,
	    DL_DEFAULT_REQUEST_QUEUE_LEN);
	rc = dl_request_q_new(&producer->dlp_requests,
	   producer->dlp_stats, requestq_len);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		goto err_producer_topic;
	}

	rc = dl_correlation_id_new(&producer->dlp_cid);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		dl_request_q_delete(producer->dlp_requests);
		goto err_producer_ctor;
	}
	
	producer->dlp_ktimer = kqueue();
	if (producer->dlp_ktimer == -1) {

		DLOGTR1(PRIO_LOW, "Failed creating kqueue(): %d\n", errno);
	}

	producer->dlp_reconn_ms = DLP_MINRECONN_MS;
	producer->dlp_ktimer_hdlr.dleh_instance = producer;
	producer->dlp_ktimer_hdlr.dleh_get_handle =
	    dl_producer_get_timer_fd;
	producer->dlp_ktimer_hdlr.dleh_handle_event =
	    dl_producer_timer_handler;

	dl_poll_reactor_register(&producer->dlp_ktimer_hdlr,
	    POLLIN | POLLOUT | POLLERR);

	/* Read the configured debug level */
	producer->dlp_debug_level = dnvlist_get_number(props,
	    DL_CONF_DEBUG_LEVEL, DL_DEFAULT_DEBUG_LEVEL);

	producer->dlp_props = props;
	producer->dlp_transport = NULL;

	producer->dlp_resend = dnvlist_get_bool(props, DL_CONF_TORESEND,
	    DL_DEFAULT_TORESEND);
	producer->dlp_resend_timeout = dnvlist_get_number(props,
	    DL_CONF_RESENDTIMEOUT, DL_DEFAULT_RESENDTIMEOUT);
	producer->dlp_resend_period = dnvlist_get_number(props,
	    DL_CONF_RESENDPERIOD, DL_DEFAULT_RESENDPERIOD);
	producer->dlp_state = DLP_INITIAL;

	/* Update the producer statistics */
	dlps_set_topic_name(producer->dlp_stats, topic_name);
	dlps_set_state(producer->dlp_stats, DLP_INITIAL);
	dlps_set_resend(producer->dlp_stats, producer->dlp_resend);
	dlps_set_resend_timeout(producer->dlp_stats, producer->dlp_resend_timeout);
	
	*self = producer;
	assert_integrity(*self);

	/* Synchnronously create the Producer in the connecting state. */
	dl_producer_connecting(*self);
	return 0;

//err_producer_index:
	/* Free the Producer index instance. */
//	dl_index_delete(producer->dlp_idx);

err_producer_topic:
	/* Free the Producer topic instance. */
	dl_topic_delete(producer->dlp_topic);

err_producer_stats:
	/* Close and unmap the stats file. */
	dl_producer_stats_delete(producer->dlp_stats);

err_producer_free:
	/* Free the Producer instance. */
	dlog_free(producer);

err_producer_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Producer instance\n");

	*self = NULL;
	return -1;
}

void
dl_producer_delete(struct dl_producer *self)
{

	assert_integrity(self);

        /* Stop the enque, produce and resender threads */
	if (self->dlp_resend) {
		pthread_cancel(self->dlp_resender_tid);
		pthread_join(self->dlp_resender_tid, NULL);
	}
	pthread_cancel(self->dlp_produce_tid);
	pthread_join(self->dlp_produce_tid, NULL);

	pthread_cancel(self->dlp_enqueue_tid);
	pthread_join(self->dlp_enqueue_tid, NULL);

	/* Unregister any poll reactor handlers */
	dl_poll_reactor_unregister(&self->dlp_ktimer_hdlr);

	/* Transition to the final state. */
	dl_producer_final(self);

	/* Close the kqueue used for timeout events. */
	close(self->dlp_ktimer);

	/* Destroy the correlation id */
	dl_correlation_id_delete(self->dlp_cid);

	/* Delete the request queue */
	dl_request_q_delete(self->dlp_requests);

	/* Delete the broker hostname */
	sbuf_delete(self->dlp_broker);

	/* Delete the producer name */
	sbuf_delete(self->dlp_name);

	/* Delete the producer transport */
	if (self->dlp_transport != NULL)
		 dl_transport_delete(self->dlp_transport);
	
	/* Delete the topic managed by the producer. */
	dl_topic_delete(self->dlp_topic);

	/* Close and unmap the stats file. */
	dl_producer_stats_delete(self->dlp_stats);

	dlog_free(self);
}

struct dl_producer_stats *
dl_producer_get_stats(struct dl_producer *self)
{

	assert_integrity(self);
	return self->dlp_stats;
}

struct dl_topic *
dl_producer_get_topic(struct dl_producer *self)
{

	assert_integrity(self);
	return self->dlp_topic;
}

int
dl_producer_response(struct dl_producer *self, struct dl_bbuf *buffer)
{
	struct dl_request_element *request;
	struct timeval tv_now, tdiff;
	struct dl_response_header *hdr;
	struct dl_produce_response *response;
	
	assert_integrity(self);
	DL_ASSERT(buffer != NULL, ("Response buffer cannot be NULL"));

	/* Deserialise the response header. */
	if (dl_response_header_decode(&hdr, buffer) == 0) {

		int32_t cid = dl_response_header_get_correlation_id(hdr);

		/* Acknowledge the request message based on the
		 * CorrelationId returned in the response.
		 */
		if (dl_request_q_ack(self->dlp_requests, cid, &request) == 0) {

			/* Update the producer statistics */
			dlps_set_received_cid(self->dlp_stats, cid);
			dlps_set_received_timestamp(self->dlp_stats);

			gettimeofday(&tv_now, NULL);
			timersub(&tv_now, &request->dlrq_tv, &tdiff);
			dlps_set_rtt(self->dlp_stats,
			    (tdiff.tv_sec * 1000000 + tdiff.tv_usec));

			if (self->dlp_debug_level > 1)
				DLOGTR2(PRIO_NORMAL,
				    "ProduceResponse: id = %d received "
				    "(RTT %ldms)\n", cid,
				    (tdiff.tv_sec * 1000 +
				    tdiff.tv_usec / 1000));

			switch (request->dlrq_api_key) {
			case DL_PRODUCE_API_KEY:

				/* Construct the ProducerResponse */
				if (dl_produce_response_decode(&response, buffer) != 0) {

					DLOGTR0(PRIO_HIGH, "Error decoding ProduceRequest\n");

					/* Update the producer statistics */
					dlps_set_received_error(self->dlp_stats, true);
				} else {
					struct dl_produce_response_topic *topic;

					/* Check whether the ProduceRequest corresponding
					 * to this response resulted in an error.
					 */
					SLIST_FOREACH(topic, &response->dlpr_topics, dlprt_entries) {

						for (int i = 0;
						    i < topic->dlprt_npartitions; i++) {

							struct dl_produce_response_partition part =
							    topic->dlprt_partitions[i];

							if (part.dlprp_error_code != 0) {

								/* Update the producer statistics */
								dlps_set_received_error(
								    self->dlp_stats, true);

								DLOGTR3(PRIO_HIGH,
								   "Error ProduceRequest offset %ld to partition %d failed %d\n",
								    part.dlprp_offset,
								    part.dlprp_partition,
								    part.dlprp_error_code);
							} else {

								/* Update the producer statistics */
								dlps_set_received_error(
								    self->dlp_stats, false);

								if (self->dlp_debug_level > 1)
									DLOGTR3(PRIO_HIGH,
								   	    "ProduceRequest offset %ld to partition %d successful %d\n",
								    	    part.dlprp_offset,
								    	    part.dlprp_partition,
								    	    part.dlprp_error_code);
							}
						}
					}

					dl_produce_response_delete(response);

				}
				break;
			default:
				DLOGTR1(PRIO_HIGH,
				    "Request ApiKey is invalid (%d)\n",
				    request->dlrq_api_key);

				/* Update the producer statistics */
				dlps_set_received_error(self->dlp_stats, true);
				break;
			}
				
			/* The request can now be freed. */
			dl_bbuf_delete(request->dlrq_buffer);
			dlog_free(request);
		} else {
			DLOGTR1(PRIO_HIGH,
			   "Error acknowledging request id = %d\n", cid);
		}

		/* Free the buffer containing the response header. */
		dl_response_header_delete(hdr);
	} else {
		DLOGTR0(PRIO_HIGH, "Error decoding response header.\n");
	}

	return 0;
}
void
dl_producer_produce(struct dl_producer * const self, uint32_t cnt)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_IDLE: /* idle -> syncing */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = produce(): %s->SYNCING\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_syncing(self, cnt);
		break;
	case DLP_CONNECTING: /* IGNORE */
		/* FALLTHROUGH */
	case DLP_ONLINE:
		/* FALLTHROUGH */
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		if (self->dlp_debug_level > 1)
			DLOGTR0(PRIO_LOW, "Ignoring event = produce()\n");

		self->dlp_produce_cnt += cnt;
		break;
	case DLP_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_up(struct dl_producer const * const self)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_CONNECTING: /* connecting -> online */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = up(): %s->ONLINE\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_online(self);
		break;
	case DLP_ONLINE: /* online -> idle*/
		dl_producer_idle(self);
		break;
	case DLP_IDLE: /* IGNORE */
		/* FALLTHROUGH */
	case DLP_SYNCING:
		if (self->dlp_debug_level > 1)
			DLOGTR0(PRIO_LOW, "Ignoring event = up()\n");
		break;
	case DLP_OFFLINE: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_INITIAL:
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid Producer state"));
		break;
	}
}

void
dl_producer_down(struct dl_producer const * const self)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_CONNECTING: /* connecting -> offline */
		/* FALLTHROUGH */
	case DLP_ONLINE: /* online -> offline */
		/* FALLTHROUGH */
	case DLP_IDLE: /* idle-> offline */
		/* FALLTHROUGH */
	case DLP_SYNCING: /* syncing -> offline */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = down(): %s->OFFLINE\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_offline(self);
		break;
	case DLP_OFFLINE: /* IGNORE */
		if (self->dlp_debug_level > 1)
			DLOGTR0(PRIO_LOW, "Ignoring event = down()\n");
		break;
	case DLP_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_syncd(struct dl_producer const * const self)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_SYNCING: /* syncing->idle */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = syncd(): %s->IDLE\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_idle(self);
		break;
	case DLP_IDLE: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_ONLINE:
		/* FALLTHROUGH */
	case DLP_INITIAL:
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_reconnect(struct dl_producer const * const self)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_OFFLINE: /* offline -> connecting */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = reconnect(): %s->CONNECTING\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_connecting(self);
		break;
	case DLP_CONNECTING: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* FALLTHROUGH */
	case DLP_ONLINE:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_INITIAL:
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_error(struct dl_producer const * const self)
{

	assert_integrity(self);

	switch(self->dlp_state) {
	case DLP_SYNCING: /* syncing -> final */
		/* FALLTHROUGH */
	case DLP_OFFLINE: /* offline -> final */
		/* FALLTHROUGH */
	case DLP_ONLINE: /* online -> final */
		/* FALLTHROUGH */
	case DLP_CONNECTING: /* connecting -> final */
		/* FALLTHROUGH */
	case DLP_IDLE: /* idle -> final */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = error(): %s->FINAL\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_final(self);
		break;
	case DLP_INITIAL: /* CANNOT HAPPEN */
		/* FALLTHROUGH */
	case DLP_FINAL:
		/* FALLTHROUGH */
	default:
		DL_ASSERT(0, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}
