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

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/nv.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>
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
	DLP_CONNECTING,
	DLP_FINAL} dl_producer_state;

struct dl_producer {
	struct dl_producer_stats *dlp_stats;
	LIST_ENTRY(dl_prodcuer) dlp_entries;
	struct dl_correlation_id *dlp_cid;
	struct dl_event_handler dlp_kq_hdlr;
	struct dl_event_handler dlp_ktimer_hdlr;
	struct dl_request_q *dlp_requests;
	struct dl_request_q *dlp_unackd_requests;
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
	bool dlp_to_resend;
	int dlp_stats_fd;
};

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_syncing(struct dl_producer * const self);
static void dl_producer_offline(struct dl_producer * const self);
static void dl_producer_connecting(struct dl_producer * const self);
static void dl_producer_final(struct dl_producer * const self);

static dl_event_handler_handle dl_producer_get_kq_fd(void *);
static void dl_producer_kq_handler(void *, int, int);
static dl_event_handler_handle dl_producer_get_timer_fd(void *);
static void dl_producer_timer_handler(void *instance, int, int);

static void *dlp_produce_thread(void *vargp);
static void *dlp_resender_thread(void *vargp);

static char const * const DLP_INITIAL_NAME = "INITIAL";
static char const * const DLP_IDLE_NAME = "IDLE";
static char const * const DLP_SYNCING_NAME = "SYNCING";
static char const * const DLP_OFFLINE_NAME = "OFFLINE";
static char const * const DLP_CONNECTING_NAME = "CONNECTING";
static char const * const DLP_FINAL_NAME = "FINAL";
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
	DL_ASSERT(self->dlp_unackd_requests != NULL,
	    ("Producer unackd request queue cannot be NULL."));
	DL_ASSERT(self->dlp_topic != NULL,
	    ("Producer topic cannot be NULL."));
	DL_ASSERT(self->dlp_name != NULL,
	    ("Producer instance cannot be NULL."));
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
				 * Producer statemachine .
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
					 * Producer statemachine .
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
	struct dl_request_element *request, *request_temp;
	time_t now;

	dl_producer_check_integrity(self);

	DLOGTR0(PRIO_LOW, "Resender thread started\n");

	for (;;) {

		dl_request_q_lock(self->dlp_requests);
		STAILQ_FOREACH_SAFE(request,
		    &self->dlp_unackd_requests->dlrq_requests,
		    dlrq_entries, request_temp) {

			now = time(NULL);
			DLOGTR4(PRIO_LOW, "Was sent %lu now() is %lu. "
			    "Resend when the difference is %d. "
			    "Current: %lu\n",
			    request->dlrq_last_sent, now,
			    self->dlp_resend_timeout,
			    now - request->dlrq_last_sent);

			if ((now - request->dlrq_last_sent) >
			    self->dlp_resend_timeout) {

				/* Resend the request. */
				request->dlrq_last_sent = time(NULL);

				STAILQ_REMOVE(
				    &self->dlp_unackd_requests->dlrq_requests,
				    request, dl_request_element, dlrq_entries);

				DLOGTR0(PRIO_LOW, "Resending request.\n");

				dl_request_q_enqueue(
				    self->dlp_requests, request);

			} else {
				/* Any further requests will no require
				 * resending, therefore break out of the
				 * loop.
				 */
				break;
			}
		}
		dl_request_q_unlock(self->dlp_requests);

		sleep(self->dlp_resend_period);
	}

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

	DLOGTR0(PRIO_LOW, "Producer thread started...\n");

	for (;;) {

		if (dl_request_q_dequeue(self->dlp_requests,
		    &request) == 0) {

			/* Update the producer statistics */
			self->dlp_stats->dlps_queued_requests--;

retry_send:
			nbytes = dl_transport_send_request(
			    self->dlp_transport, request->dlrq_buffer);
			if (nbytes != -1) {
				DLOGTR3(PRIO_LOW,
				    "Successfully sent request id = %d "
				    "(nbytes = %zu, bytes = %d)\n",
				    request->dlrq_correlation_id,
				    nbytes,
				    dl_bbuf_pos(request->dlrq_buffer));
			} else {
				DLOGTR1(PRIO_NORMAL,
				    "Transport send error (%d)\n", errno);

				if (errno == EAGAIN)
					goto retry_send;
			}

			/* The request must be acknowledged, store
			 * the request until an acknowledgment is
			 * received from the broker.
			 */

			/* Record the last attempted send time
			 * of the request.
			 */
			request->dlrq_last_sent = time(NULL);

			rc = dl_request_q_enqueue(
				self->dlp_unackd_requests, request);
			if (rc != 0) {

				DLOGTR0(PRIO_NORMAL,
				    "Failed  enqueuing unacks request\n");
			} else {
				/* Update the producer statistics */
				self->dlp_stats->dlps_unackd_requests++;
			}
		} else {
			dl_producer_error(self);
		}
	}

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
	int rc;

	dl_producer_check_integrity(self);

	DLOGTR0(PRIO_LOW, "Enqueue thread started...\n");
	seg = dl_topic_get_active_segment(topic);

	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));

	while (dl_segment_get_message_by_offset(seg,
	    dl_segment_get_offset(seg), &msg_buffer) == 0) {

		/* Instantiate a new ProduceRequest */
		if (dl_produce_request_new_nomsg(&message,
		    dl_correlation_id_val(self->dlp_cid),
		    self->dlp_name, 1, 2000,
		    dl_topic_get_name(self->dlp_topic)) == 0) {

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

			DLOGTR1(PRIO_LOW,
			    "Enqueing ProduceRequest (%d bytes)\n",
			    dl_bbuf_pos(buffer));

			rc = dl_request_q_enqueue_new(self->dlp_requests,
			    buffer, dl_correlation_id_val(self->dlp_cid),
			    DL_PRODUCE_API_KEY);
			if (rc != 0) {

				DLOGTR0(PRIO_HIGH,
				    "Failed enqueing ProduceRequest\n");
				dl_bbuf_delete(buffer);
				dl_producer_error(self);
				break;
			} else {

				/* Update the producer statistics */
				self->dlp_stats->dlps_queued_requests++;

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

	DLOGTR0(PRIO_LOW, "Enqueue thread stopped.\n");
	pthread_exit(NULL);
}

static void
dl_producer_connecting(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_CONNECTING;
	DLOGTR1(PRIO_LOW, "Producer state = CONNECTING (%d)\n",
	    self->dlp_state);

	rc = dl_transport_factory_get_inst(&self->dlp_transport,
	    self, self->dlp_props);
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
	}

	DLOGTR3(PRIO_HIGH, "Failed connecting to %s:%d (%d)\n",
	    sbuf_data(self->dlp_broker_hostname), self->dlp_broker_port,
	    errno);

	dl_producer_down(self);
}

static void
dl_producer_idle(struct dl_producer * const self)
{

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_IDLE;
	strncpy(self->dlp_stats->dlps_state_name,
	    DLP_IDLE_NAME, 255); 
	DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    DLP_IDLE_NAME, self->dlp_state);
}

static void
dl_producer_syncing(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_SYNCING;
	strncpy(self->dlp_stats->dlps_state_name,
	    DLP_SYNCING_NAME, 255); 
	DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    DLP_SYNCING_NAME, self->dlp_state);

	/* Connection is up reset the reconnect timeout */
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

	/* Start the thread to enqueue log entries for syncing
	 * with the distributed broker.
	 */
	rc = pthread_create(&self->dlp_produce_tid, NULL,
	    dlp_produce_thread, self);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Failed creating produce thread: %d\n", rc);
		dl_producer_error(self);
	}

	/* Start the thread to resend unacknowledged requests. */
	if (self->dlp_to_resend) {
		rc = pthread_create(&self->dlp_resender_tid, NULL,
		    dlp_resender_thread, self);
		if (rc != 0) {

			DLOGTR1(PRIO_HIGH,
			    "Failed creating resender thread: %d\n", rc);
			dl_producer_error(self);
		}
	}
}

static void
dl_producer_offline(struct dl_producer * const self)
{
	struct kevent kev;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_OFFLINE;
	strncpy(self->dlp_stats->dlps_state_name,
	    DLP_OFFLINE_NAME, 255); 
	DLOGTR2(PRIO_LOW, "Producer state = %s (%d)\n",
	    self->dlp_stats->dlps_state_name, self->dlp_state);

        /* Stop the produce and resender threads */
	pthread_cancel(self->dlp_resender_tid);
	pthread_cancel(self->dlp_produce_tid);

	pthread_join(self->dlp_produce_tid, NULL);
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
dl_producer_final(struct dl_producer * const self)
{

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_FINAL;
	strncpy(self->dlp_stats->dlps_state_name,
	    DLP_FINAL_NAME, 255); 
	DLOGTR2(PRIO_HIGH, "Producer state = %s (%d)\n",
	    DLP_FINAL_NAME, self->dlp_state);
}

int
dl_producer_new(struct dl_producer **self, struct dl_topic *topic,
    char *path, char *hostname, int port, nvlist_t *props)
{
	struct dl_producer *producer;
	struct kevent kev;
	struct sbuf *stats_path;
	char *client_id;
	int rc;

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

	producer->dlp_stats = (struct dl_producer_stats *) mmap(
	    NULL, sizeof(struct dl_producer_stats), PROT_READ | PROT_WRITE,
	    MAP_SHARED, producer->dlp_stats_fd, 0);
	if (producer->dlp_stats == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Failed mmap of Producer stats file %d.\n", errno);
		goto err_producer_ctor;
	}

	strncpy(producer->dlp_stats->dlps_topic_name,
	    sbuf_data(dl_topic_get_name(topic)), 255); 
	strncpy(producer->dlp_stats->dlps_state_name,
	    DLP_INITIAL_NAME, 255); 
	producer->dlp_stats->dlps_queued_requests = 0;
	producer->dlp_stats->dlps_unackd_requests = 0;

	producer->dlp_state = DLP_INITIAL;
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

	producer->dlp_broker_hostname = sbuf_new_auto();
	sbuf_cpy(producer->dlp_broker_hostname, hostname);
	sbuf_finish(producer->dlp_broker_hostname);
	producer->dlp_broker_port = port;

	rc = dl_request_q_new(&producer->dlp_unackd_requests, 20);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		goto err_producer;
	}

	rc = dl_request_q_new(&producer->dlp_requests, 20);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		dl_request_q_delete(producer->dlp_unackd_requests);
		goto err_producer;
	}

	rc = dl_correlation_id_new(&producer->dlp_cid);
	if (rc != 0) {

		dlog_free(producer);
		sbuf_delete(producer->dlp_name);
		dl_request_q_delete(producer->dlp_unackd_requests);
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
		producer->dlp_to_resend = nvlist_get_bool(props,
		    DL_CONF_TORESEND);
	} else {
		producer->dlp_to_resend = DL_DEFAULT_TORESEND;
	}

	*self = producer;
	dl_producer_check_integrity(*self);

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

        /* Stop the enque, produce and resender threads */
	pthread_cancel(self->dlp_resender_tid);
	pthread_cancel(self->dlp_produce_tid);
	pthread_cancel(self->dlp_enqueue_tid);

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

	/* Delete the request queues */
	dl_request_q_delete(self->dlp_requests);
	dl_request_q_delete(self->dlp_unackd_requests);

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
dl_producer_response(struct dl_producer *self,
    struct dl_response_header *hdr)
{
	struct dl_request_element *req;

	/* Acknowledge the request message based on the CorrelationId
	 * returned in the response.
	 */
	if (dl_request_q_dequeue(self->dlp_unackd_requests, &req) == 0) {
		/* Update the producer statistics */
		self->dlp_stats->dlps_unackd_requests--;

		if (req->dlrq_correlation_id ==
			hdr->dlrsh_correlation_id) {

			DLOGTR1(PRIO_NORMAL, "Found unack'd request id: %d\n",
			    hdr->dlrsh_correlation_id);

			switch (req->dlrq_api_key) {
			case DL_PRODUCE_API_KEY:
				/* TODO: Construct ProducerResponse */
				break;
			default:
				DLOGTR1(PRIO_HIGH,
				    "Request ApiKey is invalid (%d)\n",
				    req->dlrq_api_key);
				break;
			}
		} else {
			/* The log's response doesn't
			 * correspond to the client's most
			 * recent request.
			 */
			DLOGTR2(PRIO_HIGH,
				"Unack'd request d %d "
				"and response id: %d "
				"do not match\n",
				req->dlrq_correlation_id,
				hdr->dlrsh_correlation_id);
		}

		/* The request can now be freed. */
		dl_bbuf_delete(req->dlrq_buffer);
		dlog_free(req);
	}
	return 0;
}
void
dl_producer_produce(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	DLOGTR0(PRIO_LOW, "Producer event = produce()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		dl_producer_syncing(self);
		break;
	case DLP_OFFLINE:
	case DLP_SYNCING:
		/* IGNORE */
		break;
	case DLP_INITIAL:
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
	DLOGTR0(PRIO_LOW, "Producer event = up()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* connecting -> syncing */
		dl_producer_syncing(self);
		break;
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* IGNORE */
		break;
	case DLP_INITIAL:
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
	DLOGTR0(PRIO_LOW, "Producer event = down()\n");

	switch(self->dlp_state) {
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* FALLTHROUGH */
	case DLP_SYNCING:
		/* connecting|idle|syncing -> offline */
		dl_producer_offline(self);
		break;
	case DLP_OFFLINE:
		/* IGNORE */
		break;
	case DLP_INITIAL:
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
	DLOGTR0(PRIO_LOW, "Producer event = sync()\n");

	switch(self->dlp_state) {
	case DLP_SYNCING:
		/* syncing->idle */
		dl_producer_idle(self);
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_OFFLINE:
		/* IGNORE */
		break;
	case DLP_IDLE:
		/* CANNOT HAPPEN */
		break;
	case DLP_INITIAL:
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
	DLOGTR0(PRIO_LOW, "Producer event = reconnect()\n");

	switch(self->dlp_state) {
	case DLP_SYNCING:
		/* syncing -> idle */
		dl_producer_idle(self);
		break;
	case DLP_OFFLINE:
		/* offline -> connecting */
		dl_producer_connecting(self);
		break;
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		/* CANNOT HAPPEN */
		break;
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
	DLOGTR0(PRIO_LOW, "Producer event = down()\n");

	switch(self->dlp_state) {
	case DLP_SYNCING:
		/* FALLTHROUGH */
	case DLP_OFFLINE:
		/* FALLTHROUGH */
	case DLP_CONNECTING:
		/* FALLTHROUGH */
	case DLP_IDLE:
		dl_producer_final(self);
		break;
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
