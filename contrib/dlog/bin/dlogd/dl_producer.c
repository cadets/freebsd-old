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
#include <sys/socket.h>
#include <sys/sbuf.h>
#include <sys/uio.h>

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
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_request.h"
#include "dl_request_queue.h"
#include "dl_topic.h"
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
	LIST_ENTRY(dl_prodcuer) dlp_entries;
	struct dl_correlation_id *dlp_cid;
	struct dl_event_handler dlp_trans_hdlr;
	struct dl_event_handler dlp_kq_hdlr;
	struct dl_event_handler dlp_ktimer_hdlr;
	struct dl_request_q *dlp_requests;
	struct dl_request_q *dlp_unackd_requests;
	struct dl_topic *dlp_topic;
	struct dl_transport *dlp_transport;
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
};

static void dl_producer_idle(struct dl_producer * const self);
static void dl_producer_syncing(struct dl_producer * const self);
static void dl_producer_offline(struct dl_producer * const self);
static void dl_producer_connecting(struct dl_producer * const self);
static void dl_producer_final(struct dl_producer * const self);

static dl_event_handler_handle dlp_get_transport_fd(void *);
static void dlp_transport_hdlr(void *, int, int);
static dl_event_handler_handle dl_producer_get_kq_fd(void *);
static void dl_producer_kq_handler(void *, int, int);
static dl_event_handler_handle dl_producer_get_timer_fd(void *);
static void dl_producer_timer_handler(void *instance, int, int);

static void *dlp_produce_thread(void *vargp);
static void *dlp_resender_thread(void *vargp);

static const off_t DL_FSYNC_DEFAULT_CHARS = 1024*1024;
static const off_t DL_INDEX_DEFAULT_CHARS = 1024*1024;
static const int NOTIFY_IDENT = 1337;
static const int DLP_MINRECONN_MS = 1000;
static const int DLP_MAXRECONN_MS = 60000;

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
dlp_get_transport_fd(void *instance)
{
	struct dl_producer const * const p = instance;

	dl_producer_check_integrity(p);
	return dl_transport_get_fd(p->dlp_transport);
}

static void 
dlp_transport_hdlr(void *instance, int fd, int revents)
{
	struct dl_producer * const self = instance;
	struct dl_request_element *req;
	struct dl_response *response;
	struct dl_response_header *hdr;
	struct dl_bbuf *buffer;
	socklen_t len = sizeof(int);
	int rc, err;
	
	dl_producer_check_integrity(self);

	if (revents & (POLLHUP | POLLERR)) {

		len = sizeof(int);
		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (err == ECONNREFUSED) {
			DLOGTR0(PRIO_LOW, "Connection refused\n");
		}
		
		dl_producer_down(self);
		return;
	}

	if (revents & POLLIN) {

		if (dl_transport_read_msg(self->dlp_transport,
		    &buffer) == 0) {

#ifndef NDEBUG
			DLOGTR0(PRIO_LOW, "Response\n");

			unsigned char *bufval = dl_bbuf_data(buffer);
			for (int i = 0; i < dl_bbuf_len(buffer); i++) {
				DLOGTR1(PRIO_LOW, "<0x%02hhX>", bufval[i]);
			};
			DLOGTR0(PRIO_LOW, "\n");
#endif
			/* Deserialise the response header. */
			if (dl_response_header_decode(&hdr, buffer) == 0) {

#ifndef NDEBUG
				DLOGTR1(PRIO_LOW,
				    "Got response id = : %d\n",
				    hdr->dlrsh_correlation_id);
#endif

				/* Acknowledge the request message based
				 * on the CorrelationId returned in the
				 * response.
				 */
				if (dl_request_q_dequeue(
				    self->dlp_unackd_requests, &req) == 0) {

					if (req->dlrq_correlation_id ==
					    hdr->dlrsh_correlation_id) {

						DLOGTR1(PRIO_HIGH,
						"Found unack'd request id: %d\n",
						hdr->dlrsh_correlation_id);

						switch (req->dlrq_api_key) {
						case DL_PRODUCE_API_KEY:
							dl_produce_response_decode(
							&response, buffer);
							break;
						case DL_FETCH_API_KEY:
							dl_fetch_response_decode(
							&response, buffer);
							break;
						case DL_OFFSET_API_KEY:
							dl_list_offset_response_decode(
							&response, buffer);
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
#ifndef NDEBUG
						DLOGTR2(PRIO_HIGH,
						    "Unack'd request d %d "
						    "and response id: %d "
						    "do not match\n",
						    req->dlrq_correlation_id,	
						    hdr->dlrsh_correlation_id);	
#endif
					}

					/* The request can now be freed. */
					dlog_free(req);
				} else {
					// TODO
				}

				/* Free the response header */
				//dl_response_header_delete(header);
				dlog_free(hdr);
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Error decoding response header.\n");
			}

			/* Free the buffer in which the raw response was
			 * returned by the transport.
			 */
			dl_bbuf_delete(buffer);
		} else {

			/* Server disconnected. */
			dl_producer_down(self);
			return;

		}
	}

	if (revents & POLLOUT) {

		rc = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len); 
		if (rc == 0) {
			if (err == 0) {
#ifndef NDEBUG
				DLOGTR0(PRIO_LOW, "Connected\n");
#endif

				self->dlp_reconn_ms = DLP_MINRECONN_MS;	
				dl_poll_reactor_unregister(
				    &self->dlp_trans_hdlr);
				dl_poll_reactor_register(
				    &self->dlp_trans_hdlr,
				    POLLIN|POLLHUP|POLLERR);

				dl_producer_up(self);
			} 
		} else {
			dl_producer_down(self);
		}
	}
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
	struct dl_producer const * const p = instance;
	struct dl_segment *seg;
	struct kevent event;
	off_t log_position;
	int rc;
	
	dl_producer_check_integrity(p);

	seg = dl_topic_get_active_segment(p->dlp_topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));

	rc = kevent(p->dlp_topic->_klog, 0, 0, &event, 1, 0);
	if (rc == -1)
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	else {
		dl_segment_lock(seg);
		log_position = lseek(dl_user_segment_get_log(seg), 0,
		    SEEK_END);
		if (log_position - seg->last_sync_pos >
		    DL_FSYNC_DEFAULT_CHARS) {

			fsync(dl_user_segment_get_log(seg));
			dl_segment_set_last_sync_pos(seg, log_position);
			dl_segment_unlock(seg);

			dl_index_update(
			    dl_user_segment_get_index(seg), log_position);
			dl_producer_produce(p);
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
	struct dl_producer const * const p = instance;
	struct kevent event;
	int rc;
	
	dl_producer_check_integrity(p);
	
	rc = kevent(p->dlp_ktimer, 0, 0, &event, 1, 0);
	if (rc == -1) {
		DLOGTR2(PRIO_HIGH, "Error reading kqueue event %d %d\n.",
		    rc, errno);
	} else {

#ifndef NDEBUG
		DLOGTR0(PRIO_LOW, "Re-connect timeout\n");
#endif
		dl_producer_reconnect(p);
	}
}

static void *
dlp_resender_thread(void *vargp)
{
	struct dl_producer *self = (struct dl_producer *)vargp;
	struct dl_request_element *request, *request_temp;
	time_t now;

	dl_producer_check_integrity(self);

#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Resender thread started\n");
#endif

	for (;;) {

		dl_request_q_lock(self->dlp_requests);
		STAILQ_FOREACH_SAFE(request,
		    &self->dlp_unackd_requests->dlrq_requests,
		    dlrq_entries, request_temp) {

			now = time(NULL);
#ifndef NDEBUG
			DLOGTR4(PRIO_LOW, "Was sent %lu now is %lu. "
			    "Resend when the difference is %d. "
			    "Current: %lu\n",
			    request->dlrq_last_sent, now,
			    self->dlp_resend_timeout, 
			    now - request->dlrq_last_sent);
#endif
			if ((now - request->dlrq_last_sent) >
			    self->dlp_resend_timeout) {
				request->dlrq_last_sent = time(NULL);

#ifndef NDEBUG
				DLOGTR4(PRIO_LOW,
				    "Was sent %lu now is %lu. "
				    "Resend when the difference is %d. "
				    "Current: %lu\n",
				     request->dlrq_last_sent, now,
				    self->dlp_resend_timeout, 
				    now - request->dlrq_last_sent);
#endif

				STAILQ_REMOVE(
				    &self->dlp_unackd_requests->dlrq_requests,
				    request, dl_request_element, dlrq_entries);

				/* Resend the request. */
				dl_request_q_enqueue(
				    self->dlp_requests, request);
				
#ifndef NDEBUG
				DLOGTR0(PRIO_LOW, "Resending request.\n");
#endif
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

#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Resender thread stopped.\n");
#endif
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
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer thread started...\n");
#endif

	for (;;) {

#ifndef NDEBUG
		DLOGTR0(PRIO_LOW, "Dequeuing requests...\n");
#endif

		if (dl_request_q_dequeue(self->dlp_requests,
		    &request) == 0) {

			nbytes = dl_transport_send_request(
			    self->dlp_transport, request->dlrq_buffer);
			if (nbytes != -1) {

#ifndef NDEBUG
				DLOGTR3(PRIO_LOW,
				    "Successfully sent request (id = %d) "
				    "Successfully sent request "
				    "(nbytes = %zu, bytes = %d)\n",
				    request->dlrq_correlation_id,
				    nbytes,
				    dl_bbuf_pos(request->dlrq_buffer));
#endif

				/* The request must be acknowledged, store
				 * the request until an acknowledgment is
				 * received from the broker.
				 */

				/* Successfuly send the request,
				 * record the last send time.
				 */
				request->dlrq_last_sent = time(NULL);
#ifndef NDEBUG

				DLOGTR1(PRIO_LOW, "Processed request %d\n",
				    request->dlrq_correlation_id);
#endif

				rc = dl_request_q_enqueue(
				    self->dlp_unackd_requests, request);
				if (rc != 0) {
					//error() ?
				}
			} else {
				// TODO: proper errro handling is necessary
				DLOGTR1(PRIO_NORMAL,
				    "Transport send error (%d)\n", errno);

				// TODO: Don't think I need to do this
				// as the poll reactor is handling errors?
				dl_producer_down(self);
			}
		} else {
			dl_producer_error(self);
		}
	}

#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Produce thread stopped.\n");
#endif
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

#ifndef NDEBUG	
	DLOGTR0(PRIO_LOW, "Enqueue thread started...\n");
#endif
	seg = dl_topic_get_active_segment(topic);
	DL_ASSERT(seg != NULL, ("Topic's active segment cannot be NULL"));
    	
	while (dl_segment_get_message_by_offset(seg, dl_segment_get_offset(seg),
	    &msg_buffer) == 0) {
	
#ifndef NDEBUG	
		DLOGTR1(PRIO_LOW, "MessageSet (%d bytes)\n",
		    dl_bbuf_pos(msg_buffer));

		unsigned char *bufval;
	       
		bufval = dl_bbuf_data(msg_buffer);
		for (int i = 0; i < dl_bbuf_pos(msg_buffer); i++) {
			DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");
#endif
	
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

			// Concat the buffers together?
			rc = dl_bbuf_concat(buffer, msg_buffer);
			if (rc != 0) {
				DLOGTR0(PRIO_HIGH,
				    "Failed creating ProduceRequest\n");
				dl_producer_error(self);
			}
#ifndef NDEBUG
			DLOGTR1(PRIO_LOW, "Enqueuing request %d\n",
			    dl_correlation_id_val(self->dlp_cid));

			DLOGTR1(PRIO_LOW, "ProduceRequest (%d bytes)\n",
			    dl_bbuf_pos(buffer));

			bufval = dl_bbuf_data(buffer);
			for (int i = 0; i < dl_bbuf_pos(buffer); i++) {
				DLOGTR1(PRIO_LOW, "<%02hhX>", bufval[i]);
			};
			DLOGTR0(PRIO_LOW, "\n");
#endif

			rc = dl_request_q_enqueue_new(self->dlp_requests,
			    buffer, dl_correlation_id_val(self->dlp_cid),
			    DL_PRODUCE_API_KEY);
			if (rc != 0) {
				DLOGTR0(PRIO_HIGH,
				    "Failed enqueing ProduceRequest\n");
				dl_producer_error(self);
			}

			/* Increment the monotonic correlation id. */
			dl_correlation_id_inc(self->dlp_cid);
		
			/* Increment the offset to process. */
			dl_offset_inc(dl_user_segment_get_offset_tmp(seg));
		} else {

			DLOGTR0(PRIO_HIGH,
			    "Failed creating ProduceRequest\n");
			dl_producer_error(self);
			break;
		}
	}
	
	/* Self-trigger syncd() event. */
	dl_producer_syncd(self);
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Enqueue thread stopped.\n");
#endif
	pthread_exit(NULL);
}

static void
dl_producer_connecting(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);

	self->dlp_state = DLP_CONNECTING;
#ifndef NDEBUG
	DLOGTR1(PRIO_LOW, "Producer state = CONNECTING (%d)\n",
	    self->dlp_state);
#endif

	rc = dl_transport_new(&self->dlp_transport);
	if (rc == 0) {

		dl_transport_connect(self->dlp_transport,
		    sbuf_data(self->dlp_broker_hostname),
		    self->dlp_broker_port);

		self->dlp_trans_hdlr.dleh_instance = self;
		self->dlp_trans_hdlr.dleh_get_handle =
		    dlp_get_transport_fd;
		self->dlp_trans_hdlr.dleh_handle_event =
		    dlp_transport_hdlr;

		dl_poll_reactor_register(&self->dlp_trans_hdlr,
		    POLLERR | POLLOUT | POLLHUP);
	} else {
		DLOGTR2(PRIO_HIGH, "Failed connecting to %s:%d\n",
		    sbuf_data(self->dlp_broker_hostname),
		    self->dlp_broker_port);

		dl_producer_down(self);
	}
}

static void
dl_producer_idle(struct dl_producer * const self)
{

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_IDLE;
#ifndef NDEBUG
	DLOGTR1(PRIO_LOW, "Producer state = IDLE (%d)\n", self->dlp_state);
#endif
}

static void
dl_producer_syncing(struct dl_producer * const self)
{
	int rc;

	dl_producer_check_integrity(self);
	DL_ASSERT(self->dlp_transport != NULL,
	    ("Producer transport cannot be NULL."));

	self->dlp_state = DLP_SYNCING;
#ifndef NDEBUG
	DLOGTR1(PRIO_LOW, "Producer state = SYNCING (%d)\n",
	    self->dlp_state);
#endif

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

	/* Start the thread to dequeue log entries for syncing
	 * with the distributed broker.
	 */	
	rc = pthread_create(&self->dlp_produce_tid, NULL,
	    dlp_produce_thread, self);
	if (rc != 0) {
		dl_producer_error(self);
	}

	/* Start the thread to resend unacknowledged requests. */
	if (self->dlp_to_resend) {
		rc = pthread_create(&self->dlp_resender_tid, NULL,
		    dlp_resender_thread, self);
		if (rc != 0) {
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
#ifndef NDEBUG
	DLOGTR1(PRIO_LOW, "Producer state = OFFLINE (%d)\n",
	    self->dlp_state);
#endif

        /* Stop the produce and resender threads */	
	pthread_cancel(self->dlp_resender_tid);
	pthread_cancel(self->dlp_produce_tid);

	pthread_join(self->dlp_produce_tid, NULL);
	pthread_join(self->dlp_resender_tid, NULL);
	
	/* The transport connection with the broker is offline, thus
	 * unregister the transport file descriptor.
	 */
	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);
	dl_transport_delete(self->dlp_transport);
	self->dlp_transport = NULL;

	/* Trigger reconnect event after timeout period. */	
	EV_SET(&kev, NOTIFY_IDENT, EVFILT_TIMER,
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
#ifndef NDEBUG
	DLOGTR1(PRIO_HIGH, "Producer state = FINAL (%d)\n",
	    self->dlp_state);
#endif
}

int
dl_producer_new(struct dl_producer **self, struct dl_topic *topic,
    char *hostname, int port, nvlist_t *props)
{
	struct dl_producer *producer;
	int rc;
	char *client_id;

	DL_ASSERT(self != NULL, ("Producer instance cannot be NULL."));
	DL_ASSERT(topic != NULL, ("Producer instance cannot be NULL."));
		
	producer = (struct dl_producer *) dlog_alloc(
	    sizeof(struct dl_producer));
	if (producer== NULL)
		goto err_producer;

	bzero(producer, sizeof(struct dl_producer));

	producer->dlp_state = DLP_INITIAL;
	producer->dlp_topic = topic;
	producer->dlp_transport = NULL;

	producer->dlp_name = sbuf_new_auto();
	if (!nvlist_exists_string(props, DL_CONF_CLIENTID)) {
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
	dl_poll_reactor_unregister(&self->dlp_trans_hdlr);
	dl_poll_reactor_unregister(&self->dlp_kq_hdlr);
	dl_poll_reactor_unregister(&self->dlp_ktimer_hdlr);
	
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

void
dl_producer_produce(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = produce()\n");
#endif

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
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = up()\n");
#endif

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

#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = down()\n");
#endif

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
		DL_ASSERT(1, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_syncd(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = sync()\n");
#endif

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
		DL_ASSERT(1, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_reconnect(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);
	
#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = reconnect()\n");
#endif

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
		DL_ASSERT(1, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}

void
dl_producer_error(struct dl_producer const * const self)
{

	dl_producer_check_integrity(self);

#ifndef NDEBUG
	DLOGTR0(PRIO_LOW, "Producer event = down()\n");
#endif
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
		DL_ASSERT(1, ("Invalid topic state = %d",
		    self->dlp_state));
		break;
	}
}
