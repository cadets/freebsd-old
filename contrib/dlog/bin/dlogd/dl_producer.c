/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/nv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <machine/atomic.h>

#include <errno.h>
#include <pthread.h>
#include <poll.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_config.h"
#include "dl_event_handler.h"
#include "dl_index.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_request.h"
#include "dl_request_queue.h"
#include "dl_topic.h"
#include "dl_tls_transport.h"
#include "dl_transport.h"
#include "dl_user_segment.h"
#include "dl_utils.h"

typedef enum dl_producer_state {
	DLP_INITIAL,
	DLP_IDLE,
	DLP_SYNCING,
	DLP_OFFLINE,
	DLP_ONLINE,
	DLP_CONNECTING,
	DLP_FINAL} dl_producer_state;

struct dl_producer {
	struct dl_producer_stats *dlp_stats;
	LIST_ENTRY(dl_prodcuer) dlp_entries;
	struct dl_correlation_id *dlp_cid;
	struct dl_event_handler dlp_kq_hdlr;
	struct dl_event_handler dlp_ktimer_hdlr;
	struct dl_request_q *dlp_requests;
	struct dl_topic *dlp_topic;
	struct dl_transport *dlp_transport;
	nvlist_t *dlp_props;
	dl_producer_state dlp_state;
	pthread_t dlp_enqueue_tid;
	pthread_t dlp_produce_tid;
	pthread_t dlp_resender_tid;
	struct sbuf *dlp_broker_hostname;
	struct sbuf *dlp_name;
	int dlp_broker_port;
	int dlp_ktimer;
	int dlp_reconn_ms;
	int dlp_resend_timeout;
	int dlp_resend_period;
	int dlp_stats_fd;
	int dlp_debug_level;
	bool dlp_resend;
};

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_syncing(struct dl_producer * const self);
static void dl_producer_offline(struct dl_producer * const self);
static void dl_producer_online(struct dl_producer * const self);
static void dl_producer_connecting(struct dl_producer * const self);
static void dl_producer_final(struct dl_producer * const self);

static dl_event_handler_handle dl_producer_get_kq_fd(void *);
static void dl_producer_kq_handler(void *, int, int);
static dl_event_handler_handle dl_producer_get_timer_fd(void *);
static void dl_producer_timer_handler(void *instance, int, int);

static void *dlp_produce_thread(void *vargp);
static void *dlp_resender_thread(void *vargp);

static char const * const DLP_STATE_NAME[] =
    {"INITIAL", "IDLE", "SYNCING", "OFFLINE", "ONLINE", "CONNECTING", "FINAL" };
static const off_t DL_FSYNC_DEFAULT_CHARS = 1024*1024;
static const off_t DL_INDEX_DEFAULT_CHARS = 1024*1024;
static const int RECONNECT_TIMEOUT_EVENT = 1337;
static const int UPDATE_INDEX_EVENT = 1336;
static const int DLP_MINRECONN_MS = 1000;
static const int DLP_MAXRECONN_MS = 60000;
static const int DLP_UPDATE_INDEX_MS = 2000;

static inline void
dl_producer_check_integrity(struct dl_producer const * const self)
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

static inline void
dlp_stats_rtt(struct dl_producer *self, int32_t rtt)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_rtt = rtt;
}

static inline void
dlp_stats_received_cid(struct dl_producer *self, int32_t cid)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_received.dlpsm_cid = cid;
}

static inline void
dlp_stats_received_error(struct dl_producer *self, bool err)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_received.dlpsm_error = err;
}

static inline void
dlp_stats_received_timestamp(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_received.dlpsm_timestamp = time(NULL);
}

static inline void
dlp_stats_sent_cid(struct dl_producer *self, int32_t cid)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_sent.dlpsm_cid = cid;
}

static inline void
dlp_stats_sent_error(struct dl_producer *self, bool err)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_sent.dlpsm_error = err;
}

static inline void
dlp_stats_sent_timestamp(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_sent.dlpsm_timestamp = time(NULL);
}

static inline void
dlp_stats_state_name(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	strncpy(self->dlp_stats->dlps_state_name,
	    DLP_STATE_NAME[self->dlp_state],
	    sizeof(self->dlp_stats->dlps_state_name)); 
}

static inline void
dlp_stats_topic_name(struct dl_producer *self, char *topic_name)
{

	dl_producer_check_integrity(self);
	strncpy(self->dlp_stats->dlps_topic_name, topic_name,
	    sizeof(self->dlp_stats->dlps_topic_name)); 
}

static inline void
dlp_stats_resend(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_resend = self->dlp_resend;
}

static inline void
dlp_stats_resend_timeout(struct dl_producer *self)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_resend_timeout = self->dlp_resend_timeout;
}

static dl_event_handler_handle
dl_producer_get_kq_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	return p->dlp_topic->_klog;
}

static void
dl_producer_kq_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_index *idx;
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;
	struct kevent event;
	off_t log_position;
	int rc;

	dl_producer_check_integrity(p);

	seg = dl_topic_get_active_segment(p->dlp_topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));

	rc = kevent(p->dlp_topic->_klog, 0, 0, &event, 1, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	} else {

		dl_segment_lock(seg);
		log_position = lseek(dl_user_segment_get_log(seg), 0,
		    SEEK_END);
		if (log_position - seg->last_sync_pos >
		    DL_FSYNC_DEFAULT_CHARS) {

			fsync(dl_user_segment_get_log(seg));
			dl_segment_set_last_sync_pos(seg, log_position);
			dl_segment_unlock(seg);

			idx = dl_user_segment_get_index(seg);
			if (dl_index_update(idx,
			    dl_index_get_last(idx) + DL_FSYNC_DEFAULT_CHARS) > 0) {
				/* Fire the produce() event into the
				 * Producer state machine .
				 */
				dl_producer_produce(p);
			}
		} else {
			dl_segment_unlock(seg);
		}
	}
}

static dl_event_handler_handle
dl_producer_get_timer_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	return p->dlp_ktimer;
}

static void
dl_producer_timer_handler(void *instance, int fd __attribute((unused)),
    int revents __attribute((unused)))
{
	struct dl_index *idx;
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;
	struct kevent events[2];
	off_t log_position;
	int rc;

	dl_producer_check_integrity(p);

	rc = kevent(p->dlp_ktimer, 0, 0, events, 2, 0);
	if (rc == -1) {

		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n",
		    rc, errno);
	} else {

		for (int i = 0; i < rc; i++) {
			switch (events[i].ident) {
			case RECONNECT_TIMEOUT_EVENT:

				/* Re-connect timeout expired, fired
				 * reconnect() event into Producer state
				 * machine.
				 */
				dl_producer_reconnect(p);
				break;
			case UPDATE_INDEX_EVENT:

				/* Periodic update of log index. */
				seg = dl_topic_get_active_segment(p->dlp_topic);
				DL_ASSERT(seg != NULL,
				    ("Topic's active segment cannot be NULL"));

				dl_segment_lock(seg);
				log_position = lseek(
				    dl_user_segment_get_log(seg), 0, SEEK_END);
				dl_segment_unlock(seg);

				idx = dl_user_segment_get_index(seg);
				if (dl_index_update(idx,
			    	    dl_index_get_last(idx) + DL_FSYNC_DEFAULT_CHARS) > 0) {
					/* Fire the produce() event into the
					 * Producer state machine .
					 */
					dl_producer_produce(p);
				}
				break;
			}
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

	dl_producer_check_integrity(self);

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
	int rc;

	dl_producer_check_integrity(self);

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Producer thread started...\n");

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
			dlp_stats_sent_cid(self, request->dlrq_correlation_id);
			dlp_stats_sent_timestamp(self);
			if (nbytes != -1) {
				/* Update the producer statistics */
				dlp_stats_sent_error(self, false);

				if (self->dlp_debug_level > 1)
					DLOGTR2(PRIO_LOW,
					    "ProduceRequest: id = %d "
					    "sent (bytes = %ld)\n",
					    request->dlrq_correlation_id,
					    nbytes);
			} else {
				/* Update the producer statistics */
				dlp_stats_sent_error(self, true);

				if (self->dlp_debug_level > 1)
					DLOGTR2(PRIO_LOW,
					    "ProduceRequest: id = %d failed "
					    "(bytes = %d)\n",
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
	struct dl_request *message;
	struct dl_segment *seg;
	struct sbuf *topic_name;
	int rc;

	dl_producer_check_integrity(self);

	if (self->dlp_debug_level > 1)
		DLOGTR0(PRIO_LOW, "Enqueue thread started...\n");

	/* Get the name of the topic produce to. */	
	topic_name = dl_topic_get_name(self->dlp_topic);
	DL_ASSERT(topic_name != NULL, ("Topic's name cannot be NULL"));

	/* Get the topic's active segment. */
	seg = dl_topic_get_active_segment(topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));

	while (dl_segment_get_message_by_offset(seg,
	    dl_segment_get_offset(seg), &msg_buffer) == 0) {

		/* Instantiate a new ProduceRequest */
		if (dl_produce_request_new_nomsg(&message,
		    dl_correlation_id_val(self->dlp_cid),
		    self->dlp_name, 1, 2000,
		    topic_name) == 0) {

			rc = dl_request_encode(message, &buffer);
			if (rc != 0) {

				DLOGTR0(PRIO_HIGH,
				    "Failed creating ProduceRequest\n");
				dl_producer_error(self);
			}

			/* Free the ProduceRequest */
			dl_request_delete(message);

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

			if (self->dlp_debug_level > 2)
				DLOGTR2(PRIO_LOW,
				    "ProduceRequest: id = %d enqueued (%d bytes)\n",
				    dl_correlation_id_val(self->dlp_cid),
				    dl_bbuf_pos(buffer));

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
				dl_offset_inc(dl_user_segment_get_offset_tmp(seg));
			}
		} else {

			DLOGTR0(PRIO_HIGH,
			    "Failed creating ProduceRequest\n");
			dl_producer_error(self);
			break;
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

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_CONNECTING;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

	rc = dl_transport_factory_get_inst(&self->dlp_transport, self);
	if (rc == 0) {

		rc = dl_transport_connect(self->dlp_transport,
		    sbuf_data(self->dlp_broker_hostname),
		    self->dlp_broker_port);
		if (rc == 0 || (rc == -1 && errno == EINPROGRESS)) {

			/* Connect established or in the process
			 * of establishing.
			 */
			return;
		}

		DLOGTR3(PRIO_HIGH, "Failed connecting to %s:%d (%d)\n",
		    sbuf_data(self->dlp_broker_hostname), self->dlp_broker_port,
		    errno);

		dl_producer_down(self);
	} else {

		dl_producer_error(self);
	}
}

static void
dl_producer_idle(struct dl_producer * const self)
{

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_IDLE;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);
}

static void
dl_producer_syncing(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_SYNCING;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

	/* Connection is up, reset the reconnect timeout */
	self->dlp_reconn_ms = DLP_MINRECONN_MS;

	/* Start the thread to enqueue log entries for syncing
	 * with the distributed broker.
	 */
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

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_OFFLINE;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

	if (self->dlp_debug_level > 0)
		DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);

        /* Stop the produce and resender threads */
	if (self->dlp_resend)
		pthread_cancel(self->dlp_resender_tid);
	pthread_cancel(self->dlp_produce_tid);

	pthread_join(self->dlp_produce_tid, NULL);
	if (self->dlp_resend)
		pthread_join(self->dlp_resender_tid, NULL);

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

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_ONLINE;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

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

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_FINAL;

	/* Update the producer statistics */
	dlp_stats_state_name(self);

	if (self->dlp_debug_level > 0) {
		DLOGTR2(PRIO_HIGH, "Producer state = %s (%d)\n",
	    	    DLP_STATE_NAME[self->dlp_state], self->dlp_state);
	}
}

int
dl_producer_new(struct dl_producer **self, struct dl_topic *topic,
    char *path, char *hostname, int port, nvlist_t *props)
{
	struct dl_producer *producer;
	struct kevent kev;
	struct sbuf *stats_path;
	char *client_id;
	int requestq_len, rc;

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(topic != NULL, ("Producer instance cannot be NULL."));

	producer = (struct dl_producer *) dlog_alloc(
	    sizeof(struct dl_producer));
	if (producer== NULL) {

		goto err_producer;
	}

	bzero(producer, sizeof(struct dl_producer));

	/* Open a memory mapped file for the Producer stats. */
	stats_path = sbuf_new_auto();
	sbuf_printf(stats_path, "%s/%s/stats", path,
	    sbuf_data(dl_topic_get_name(topic))); 
	sbuf_finish(stats_path);
	producer->dlp_stats_fd = open(sbuf_data(stats_path),
	    O_RDWR | O_APPEND | O_CREAT, 0666);
	if (producer->dlp_stats_fd == -1) {

		DLOGTR1(PRIO_HIGH,
		    "Failed opening Producer stats file %d.\n", errno);
		sbuf_delete(stats_path);
		goto err_producer_ctor;
	}
	sbuf_delete(stats_path);
	ftruncate(producer->dlp_stats_fd, sizeof(struct dl_producer_stats));

	producer->dlp_state = DLP_INITIAL;

	producer->dlp_stats = (struct dl_producer_stats *) mmap(
	    NULL, sizeof(struct dl_producer_stats), PROT_READ | PROT_WRITE,
	    MAP_SHARED, producer->dlp_stats_fd, 0);
	if (producer->dlp_stats == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Failed mmap of Producer stats file %d.\n", errno);
		goto err_producer_ctor;
	}

	producer->dlp_props = props;
	producer->dlp_topic = topic;
	producer->dlp_transport = NULL;

	producer->dlp_name = sbuf_new_auto();
	if (nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		client_id = nvlist_get_string(props, DL_CONF_CLIENTID);
	} else {
		client_id = DL_DEFAULT_CLIENTID;
	}
	sbuf_cpy(producer->dlp_name, client_id);
	sbuf_finish(producer->dlp_name);

	if (nvlist_exists_string(props, DL_CONF_RESENDTIMEOUT)) {
		producer->dlp_resend_timeout = nvlist_get_number(props,
		    DL_CONF_RESENDTIMEOUT);
	} else {
		producer->dlp_resend_timeout = DL_DEFAULT_RESENDTIMEOUT;
	}

	if (nvlist_exists_string(props, DL_CONF_RESENDPERIOD)) {
		producer->dlp_resend_period = nvlist_get_number(props,
		    DL_CONF_RESENDPERIOD);
	} else {
		producer->dlp_resend_period = DL_DEFAULT_RESENDPERIOD;
	}

	if (nvlist_exists_number(props, DL_CONF_REQUEST_QUEUE_LEN)) {
		requestq_len = nvlist_get_number(props,
		    DL_CONF_REQUEST_QUEUE_LEN);
	} else {
		requestq_len = DL_DEFAULT_REQUEST_QUEUE_LEN;
	}
	producer->dlp_broker_hostname = sbuf_new_auto();
	sbuf_cpy(producer->dlp_broker_hostname, hostname);
	sbuf_finish(producer->dlp_broker_hostname);
	producer->dlp_broker_port = port;
	   
	(&producer->dlp_stats->dlps_request_q_stats)->dlrq_capacity = 10;

	rc = dl_request_q_new(&producer->dlp_requests,
	   &producer->dlp_stats->dlps_request_q_stats, requestq_len);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		goto err_producer;
	}

	rc = dl_correlation_id_new(&producer->dlp_cid);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		dl_request_q_delete(producer->dlp_requests);
		goto err_producer;
	}

	producer->dlp_kq_hdlr.dleh_instance = producer;
	producer->dlp_kq_hdlr.dleh_get_handle = dl_producer_get_kq_fd;
	producer->dlp_kq_hdlr.dleh_handle_event = dl_producer_kq_handler;

	dl_poll_reactor_register(&producer->dlp_kq_hdlr, POLLIN | POLLERR);

	producer->dlp_ktimer = kqueue();

	producer->dlp_reconn_ms = DLP_MINRECONN_MS;
	producer->dlp_ktimer_hdlr.dleh_instance = producer;
	producer->dlp_ktimer_hdlr.dleh_get_handle =
	    dl_producer_get_timer_fd;
	producer->dlp_ktimer_hdlr.dleh_handle_event =
	    dl_producer_timer_handler;

	/* Trigger reconnect event after timeout period. */
	EV_SET(&kev, UPDATE_INDEX_EVENT, EVFILT_TIMER,
	    EV_ADD , 0, DLP_UPDATE_INDEX_MS, NULL);
	kevent(producer->dlp_ktimer, &kev, 1, NULL, 0, NULL);

	dl_poll_reactor_register(&producer->dlp_ktimer_hdlr,
	    POLLIN | POLLOUT | POLLERR);

	if (nvlist_exists_bool(props, DL_CONF_TORESEND)) {
		producer->dlp_resend = nvlist_get_bool(props,
		    DL_CONF_TORESEND);
	} else {
		producer->dlp_resend = DL_DEFAULT_TORESEND;
	}

	/* Read the configured debug level */
	if (nvlist_exists_string(props, DL_CONF_CLIENTID)) {
		producer->dlp_debug_level = nvlist_get_number(props,
		    DL_CONF_DEBUG_LEVEL);
	} else {
		producer->dlp_debug_level = DL_DEFAULT_DEBUG_LEVEL;
	}

	*self = producer;
	dl_producer_check_integrity(*self);

	/* Update the producer statistics */
	dlp_stats_topic_name(*self, sbuf_data(dl_topic_get_name(topic)));
	dlp_stats_state_name(*self);
	dlp_stats_resend(*self);
	dlp_stats_resend_timeout(*self);

	/* Synchnronously create the Producer in the connecting state. */
	dl_producer_connecting(*self);
	return 0;

err_producer_ctor:
	dlog_free(producer);

err_producer:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Producer instance\n");

	*self = NULL;
	return -1;
}

void
dl_producer_delete(struct dl_producer *self)
{

	dl_producer_check_integrity(self);

	/* Transition to the final state. */
	dl_producer_final(self);

        /* Stop the enque, produce and resender threads */
	if (self->dlp_resend)
		pthread_cancel(self->dlp_resender_tid);
	pthread_cancel(self->dlp_produce_tid);
	pthread_cancel(self->dlp_enqueue_tid);

	if (self->dlp_resend)
		pthread_join(self->dlp_resender_tid, NULL);
	pthread_join(self->dlp_produce_tid, NULL);
	pthread_join(self->dlp_enqueue_tid, NULL);

	/* Unregister any poll reeactor handlers */
	dl_poll_reactor_unregister(&self->dlp_kq_hdlr);
	dl_poll_reactor_unregister(&self->dlp_ktimer_hdlr);

	/* Close and unmap the stats file. */
	close(self->dlp_stats_fd);
	msync(self->dlp_stats, sizeof(struct dl_producer_stats), MS_SYNC);
	munmap(self->dlp_stats, sizeof(struct dl_producer_stats));

	close(self->dlp_ktimer);

	/* Delete the topic managed by the producer. */
	dl_topic_delete(self->dlp_topic);

	/* Destroy the correlation id */
	dl_correlation_id_delete(self->dlp_cid);

	/* Delete the request queuexs */
	dl_request_q_delete(self->dlp_requests);

	/* Delete the broker hostname */
	sbuf_delete(self->dlp_broker_hostname);

	/* Delete the producer name */
	sbuf_delete(self->dlp_name);

	/* Delete the producer transport */
	if (self->dlp_transport != NULL)
		 dl_transport_delete(self->dlp_transport);

	dlog_free(self);
}

struct dl_topic *
dl_producer_get_topic(struct dl_producer *self)
{

	dl_producer_check_integrity(self);

	return self->dlp_topic;
}

int
dl_producer_response(struct dl_producer *self, struct dl_bbuf *buffer)
{
	struct dl_request_element *request;
	struct timeval tv_now, tdiff;
	struct dl_response *response;
	struct dl_response_header *hdr;
	
	dl_producer_check_integrity(self);
	DL_ASSERT(hdr != NULL, ("Response header cannot be NULL"));

	/* Deserialise the response header. */
	if (dl_response_header_decode(&hdr, buffer) == 0) {

		/* Acknowledge the request message based on the
		 * CorrelationId returned in the response.
		 */
		if (dl_request_q_ack(self->dlp_requests,
		    hdr->dlrsh_correlation_id, &request) == 0) {

			/* Update the producer statistics */
			dlp_stats_received_cid(self, hdr->dlrsh_correlation_id);
			dlp_stats_received_timestamp(self);

			gettimeofday(&tv_now, NULL);
			timersub(&tv_now, &request->dlrq_tv, &tdiff);
			dlp_stats_rtt(self,
			    (tdiff.tv_sec * 1000000 + tdiff.tv_usec));

			if (self->dlp_debug_level > 1)
				DLOGTR2(PRIO_NORMAL,
				"ProduceResponse: id = %d received "
				"(RTT = %ldms)\n",
				request->dlrq_correlation_id,
				(tdiff.tv_sec * 1000 +
				tdiff.tv_usec / 1000));

			switch (request->dlrq_api_key) {
			case DL_PRODUCE_API_KEY:
				/* TODO: Construct ProducerResponse */
				// dl_produce_response_decode(&response, &buffer);
			
				//dl_response_delete(response);

				/* Update the producer statistics */
				dlp_stats_received_error(self, false);
				break;
			default:
				DLOGTR1(PRIO_HIGH,
				    "Request ApiKey is invalid (%d)\n",
				    request->dlrq_api_key);

				/* Update the producer statistics */
				dlp_stats_received_error(self, true);
				break;
			}
				
			/* The request can now be freed. */
			dl_bbuf_delete(request->dlrq_buffer);
			dlog_free(request);
		} else {
			DLOGTR1(PRIO_HIGH,
			   "Error acknowledging request id = %d\n",
			    hdr->dlrsh_correlation_id);
		}

		/* Free the buffer containing the response header. */
		dl_response_header_delete(hdr);
	} else {
		DLOGTR0(PRIO_HIGH, "Error decoding response header.\n");
	}

	return 0;
}
void
dl_producer_produce(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_IDLE: /* idle -> syncing */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = produce(): %s->SYNCING\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_syncing(self);
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

	dl_producer_check_integrity(self);

	switch(self->dlp_state) {
	case DLP_CONNECTING: /* connecting -> online */
		if (self->dlp_debug_level > 1)
			DLOGTR1(PRIO_LOW,
			    "Producer event = up(): %s->ONLINE\n",
			    DLP_STATE_NAME[self->dlp_state]);

		dl_producer_online(self);
		break;
	case DLP_ONLINE: /* online -> syncing */
		dl_producer_syncing(self);
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

	dl_producer_check_integrity(self);

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

	dl_producer_check_integrity(self);

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

	dl_producer_check_integrity(self);

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

	dl_producer_check_integrity(self);

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

void dl_producer_stats_tcp_connect(struct dl_producer *self, bool status)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_tcp_connected = status;
}

void
dl_producer_stats_tls_connect(struct dl_producer *self, bool status)
{

	dl_producer_check_integrity(self);
	self->dlp_stats->dlps_tls_connected = status;
}

void
dl_producer_stats_bytes_sent(struct dl_producer *self, int32_t nbytes)
{

	dl_producer_check_integrity(self);
	atomic_add_64(&self->dlp_stats->dlps_bytes_sent, nbytes);
}

void
dl_producer_stats_bytes_received(struct dl_producer *self, int32_t nbytes)
{

	dl_producer_check_integrity(self);
	atomic_add_64(&self->dlp_stats->dlps_bytes_received, nbytes);
}
