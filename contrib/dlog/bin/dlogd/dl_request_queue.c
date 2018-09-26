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
dl_request_q_enqueue(struct dl_request_q *self,
    struct dl_request_element *request)
{

	dlrq_check_integrity(self);
	DL_ASSERT(request != NULL, ("Request instance cannot be NULL"));

	sem_wait(&self->dlrq_spaces);
	pthread_mutex_lock(&self->dlrq_mtx);
	STAILQ_INSERT_TAIL(&self->dlrq_requests, request, dlrq_entries);
	pthread_mutex_unlock(&self->dlrq_mtx);
	sem_post(&self->dlrq_items);

	return 0;
}

int 
dl_request_q_dequeue(struct dl_request_q *self,
    struct dl_request_element **elem)
{
	struct dl_request_element *request;

	dlrq_check_integrity(self);
	DL_ASSERT(elem != NULL,
	    ("Request element instance cannot be NULL."));

	sem_wait(&self->dlrq_items);
	pthread_mutex_lock(&self->dlrq_mtx);		
	if (STAILQ_EMPTY(&self->dlrq_requests) == 0) {

		request = STAILQ_FIRST(&self->dlrq_requests);
		STAILQ_REMOVE_HEAD(&self->dlrq_requests, dlrq_entries);

		*elem = request;
	}
	pthread_mutex_unlock(&self->dlrq_mtx);
	sem_post(&self->dlrq_spaces);

	return 0;
}

int 
dl_request_q_enqueue_new(struct dl_request_q *self, struct dl_bbuf *buffer,
    int32_t correlation_id, int16_t api_key)
{
	struct dl_request_element *request;
	
	dlrq_check_integrity(self);
	DL_ASSERT(buffer != NULL, ("Buffer cannot be NULL"));

	/* Allocate a new request; this stores the encoded request
	 * along with associate metadata allowing correlation of reuqets
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
dl_request_q_new(struct dl_request_q **self, uint32_t qlimit)
{
	struct dl_request_q *queue;
	int rc;
	
	DL_ASSERT(self != NULL, ("Request queue instance cannot be NULL."));

	queue = (struct dl_request_q *) dlog_alloc(sizeof(struct dl_request_q));
	if (queue == NULL)
		goto err_queue_ctor;

	bzero(queue, sizeof(struct dl_request_q));

	STAILQ_INIT(&queue->dlrq_requests);

	rc = sem_init(&queue->dlrq_items, 0, 0);
	if (rc != 0) {

		dlog_free(queue);
		goto err_queue_ctor;
	}

	rc = sem_init(&queue->dlrq_spaces, 0, qlimit);
	if (rc != 0) {

		sem_destroy(&queue->dlrq_items);
		dlog_free(queue);
		goto err_queue_ctor;
	}
	rc = pthread_mutex_init(&queue->dlrq_mtx, NULL);
	if (rc != 0) {

		sem_destroy(&queue->dlrq_spaces);
		sem_destroy(&queue->dlrq_items);
		dlog_free(queue);
		goto err_queue_ctor;
	}

	*self = queue;
	dlrq_check_integrity(*self);
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
	DL_ASSERT(STAILQ_EMPTY(&self->dlrq_requests) != 0,
	    ("Request queue is not emprty"));

	pthread_mutex_destroy(&self->dlrq_mtx);
	sem_destroy(&self->dlrq_spaces);
	sem_destroy(&self->dlrq_items);
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
