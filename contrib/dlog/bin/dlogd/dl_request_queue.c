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
#include <sys/time.h>

#include <pthread.h>
#include <strings.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_request_queue.h"
#include "dl_utils.h"

static inline void
dlrq_check_integrity(struct dl_request_q *self)
{

	DL_ASSERT(self != NULL, ("Request queue inst cannot be NULL."));
}

int 
dl_request_q_dequeue(struct dl_request_q *self,
    struct dl_request_element **elem)
{
	int rc = 0;

	dlrq_check_integrity(self);
	DL_ASSERT(elem != NULL,
	    ("Request element instance cannot be NULL."));

	rc = sem_wait(&self->dlrq_request_items);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue item semaphore"));

	/* Update the request queue statistics. */	
	sem_getvalue(&self->dlrq_request_items,
	    &self->dlrq_stats->dlrqs_requests);

	rc = pthread_mutex_lock(&self->dlrq_mtx);		
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	DL_ASSERT(STAILQ_EMPTY(&self->dlrq_queue) == 0, (""));
	
	DL_ASSERT(self->dlrq_requests != NULL,
	    ("dlrq_requests cannot be NULL after acquiring "
	     "semaphore dlrq_request_items"));

	*elem = self->dlrq_requests;
	self->dlrq_requests = STAILQ_NEXT(self->dlrq_requests, dlrq_entries);

	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	rc = sem_post(&self->dlrq_unackd_items);
	DL_ASSERT(rc == 0, ("Failed releasing RequestQueue space semaphore"));
	
	/* Update the request queue statistics. */	
	sem_getvalue(&self->dlrq_unackd_items,
	    &self->dlrq_stats->dlrqs_unackd);

	return 0;
}

int 
dl_request_q_dequeue_unackd(struct dl_request_q *self,
    struct dl_request_element **elem)
{
	int rc = 0, ret = -1;

	dlrq_check_integrity(self);
	DL_ASSERT(elem != NULL,
	    ("Request element instance cannot be NULL."));

	rc = sem_wait(&self->dlrq_unackd_items);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue item semaphore"));
	DL_ASSERT(STAILQ_EMPTY(&self->dlrq_queue) == 0,
	    ("Queue cannot be empty with unackd items semaphore"));

	/* Update the request queue statistics. */	
	sem_getvalue(&self->dlrq_unackd_items,
	    &self->dlrq_stats->dlrqs_unackd);

	rc = pthread_mutex_lock(&self->dlrq_mtx);		
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	
	if (STAILQ_FIRST(&self->dlrq_queue) != self->dlrq_requests ) {

		*elem = STAILQ_FIRST(&self->dlrq_queue);
		STAILQ_REMOVE_HEAD(&self->dlrq_queue, dlrq_entries);


		ret = 0;
	}

	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	rc = sem_post(&self->dlrq_spaces);
	DL_ASSERT(rc == 0, ("Failed releasing RequestQueue space semaphore"));

	return ret;
}

int 
dl_request_q_enqueue(struct dl_request_q *self,
    struct dl_request_element *request)
{
	int rc = 0, spaces;

	dlrq_check_integrity(self);
	DL_ASSERT(request != NULL, ("Request instance cannot be NULL"));

	rc = sem_wait(&self->dlrq_spaces);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue space semaphore"));
	sem_getvalue(&self->dlrq_spaces, &spaces);

	rc = pthread_mutex_lock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));

	STAILQ_INSERT_TAIL(&self->dlrq_queue, request, dlrq_entries);
	if (self->dlrq_requests == NULL)
		self->dlrq_requests = request;

	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed releasing RequyyestQueue mutex"));

	rc = sem_post(&self->dlrq_request_items);
	DL_ASSERT(rc == 0, ("Failed releasing RequestQueue item semaphore"));

	/* Update the request queue statistics. */	
	sem_getvalue(&self->dlrq_request_items,
	    &self->dlrq_stats->dlrqs_requests);

	return 0;
}

int 
dl_request_q_enqueue_new(struct dl_request_q *self, struct dl_bbuf *buffer,
    int32_t correlation_id, int16_t api_key)
{
	struct dl_request_element *request;
	
	dlrq_check_integrity(self);
	DL_ASSERT(buffer != NULL, ("RequestQueue element buffer cannot be NULL"));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of requests
	 * and responses.
	 */
	request = (struct dl_request_element *) dlog_alloc(
	    sizeof(struct dl_request_element));
	if (request != NULL) {

		/* Construct the request */
		bzero(request, sizeof(struct dl_request_element));

		request->dlrq_buffer = buffer;
		request->dlrq_correlation_id = correlation_id;
		request->dlrq_api_key = api_key;

		if (dl_request_q_enqueue(self, request) != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Failed enqueuing request message..\n");
			dlog_free(request);
			return -1;
		}
		return 0;
	} 

	DLOGTR0(PRIO_HIGH, "Failed allocating request.\n");
	return -1;
}

int
dl_request_q_capacity(struct dl_request_q *self, int *sval)
{

	dlrq_check_integrity(self);
	return sem_getvalue(&self->dlrq_spaces, sval);
}

int
dl_request_q_peek(struct dl_request_q *self, struct dl_request_element **elem)
{
	int rc, ret, sval;

	dlrq_check_integrity(self);
	
	rc = pthread_mutex_lock(&self->dlrq_mtx);		
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	if (sem_getvalue(&self->dlrq_request_items, &sval) != 0)  {
		ret = -1;
	} else {
		if (sval == 0) {
			ret = -1;
		} else {
			DL_ASSERT(STAILQ_EMPTY(&self->dlrq_queue) == 0,
			("Queue cannot be empty with request items present"));
			
			*elem = self->dlrq_requests;

			ret = 0;
		}
	}
	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	return ret;
}

int
dl_request_q_peek_unackd(struct dl_request_q *self, struct dl_request_element **elem)
{
	int rc, ret, sval;

	dlrq_check_integrity(self);
	
	rc = pthread_mutex_lock(&self->dlrq_mtx);		
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	if (sem_getvalue(&self->dlrq_unackd_items, &sval) != 0) { 
		ret = -1;
	} else {
		if (sval == 0) {
			ret = -1;
		} else {
			DL_ASSERT(STAILQ_EMPTY(&self->dlrq_queue) == 0,
			("Queue cannot be empty with unackd items present"));
			
			*elem = STAILQ_FIRST(&self->dlrq_queue);

			//rc = pthread_mutex_unlock(&self->dlrq_mtx);
			DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
			ret = 0;
		}
	}

	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));


	return ret;
}

int
dl_request_q_new(struct dl_request_q **self,
    struct dl_request_q_stats *stats, uint32_t qlimit)
{
	struct dl_request_q *queue;
	int rc;
	
	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL"));

	queue = (struct dl_request_q *) dlog_alloc(
	    sizeof(struct dl_request_q));
	if (queue == NULL)
		goto err_queue_ctor;

	bzero(queue, sizeof(struct dl_request_q));

	STAILQ_INIT(&queue->dlrq_queue);
	queue->dlrq_requests = STAILQ_FIRST(&queue->dlrq_queue);

	/* Initialise the queue statistics. */
	queue->dlrq_stats = stats;
	queue->dlrq_stats->dlrqs_capacity = qlimit;
	queue->dlrq_stats->dlrqs_requests = 0;
	queue->dlrq_stats->dlrqs_unackd = 0;

	rc = sem_init(&queue->dlrq_request_items, 0, 0);
	if (rc != 0) {

		dlog_free(queue);
		goto err_queue_ctor;
	}

	rc = sem_init(&queue->dlrq_unackd_items, 0, 0);
	if (rc != 0) {

		sem_destroy(&queue->dlrq_request_items);
		dlog_free(queue);
		goto err_queue_ctor;
	}

	rc = sem_init(&queue->dlrq_spaces, 0, qlimit);
	if (rc != 0) {

		sem_destroy(&queue->dlrq_unackd_items);
		sem_destroy(&queue->dlrq_request_items);
		dlog_free(queue);
		goto err_queue_ctor;
	}

	int spaces;
	sem_getvalue(&queue->dlrq_spaces, &spaces);

	rc = pthread_mutex_init(&queue->dlrq_mtx, NULL);
	if (rc != 0) {

		sem_destroy(&queue->dlrq_spaces);
		sem_destroy(&queue->dlrq_unackd_items);
		sem_destroy(&queue->dlrq_request_items);
		dlog_free(queue);
		goto err_queue_ctor;
	}

	dlrq_check_integrity(queue);
	*self = queue;
	return 0;

err_queue_ctor:
	DLOGTR0(PRIO_HIGH, "Failed allocating request queue.\n");

	*self = NULL;
	return -1;

}

void
dl_request_q_delete(struct dl_request_q *self)
{

	dlrq_check_integrity(self);

	pthread_mutex_destroy(&self->dlrq_mtx);
	sem_destroy(&self->dlrq_spaces);
	sem_destroy(&self->dlrq_unackd_items);
	sem_destroy(&self->dlrq_request_items);
	dlog_free(self);
}

void
dl_request_q_lock(struct dl_request_q *self) __attribute((no_thread_safety_analysis))
{

	dlrq_check_integrity(self);
	pthread_mutex_lock(&self->dlrq_mtx);
}

void
dl_request_q_unlock(struct dl_request_q *self) __attribute((no_thread_safety_analysis))
{

	dlrq_check_integrity(self);
	pthread_mutex_unlock(&self->dlrq_mtx);
}

int
dl_request_q_ack(struct dl_request_q *self, int32_t id,
    struct dl_request_element **elem)
{
	struct dl_request_element *request;
	int rc, ret = -1;

	rc = sem_wait(&self->dlrq_unackd_items);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue item semaphore"));
	DL_ASSERT(STAILQ_EMPTY(&self->dlrq_queue) == 0,
	    ("Queue cannot be empty with unackd items semaphore"));

	/* Update the request queue statistics. */	
	sem_getvalue(&self->dlrq_unackd_items,
	    &self->dlrq_stats->dlrqs_unackd);

	rc = pthread_mutex_lock(&self->dlrq_mtx);		
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));

	/* Iterate accross all the unack'd requests. */	
	request = STAILQ_FIRST(&self->dlrq_queue);
	DL_ASSERT(request != NULL, ("Queue cannot be empty"));
	do {
		if (request->dlrq_correlation_id == id) {

			STAILQ_REMOVE(&self->dlrq_queue,
			    request, dl_request_element, dlrq_entries);
	
			*elem = request;
			ret = 0;
			break;
		} 
		request = STAILQ_NEXT(request, dlrq_entries);

	} while(request != self->dlrq_requests);
	
	rc = pthread_mutex_unlock(&self->dlrq_mtx);
	DL_ASSERT(rc == 0, ("Failed acquiring RequestQueue mutex"));
	if ( ret == 0) {
		rc = sem_post(&self->dlrq_spaces);
		DL_ASSERT(rc == 0, ("Failed releasing RequestQueue space semaphore"));
	} else {
		rc = sem_post(&self->dlrq_unackd_items);
		DL_ASSERT(rc == 0, ("Failed releasing RequestQueue space semaphore"));
	}

	return ret;
}
