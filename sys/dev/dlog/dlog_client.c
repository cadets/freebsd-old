/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * Copyright (c) 2017-2019 (Graeme Jenkinson)
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
 */

#ifdef _APPLE
#include <kern/clock.h>
#else
#include <sys/time.h>
#endif
#include <sys/param.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/nv.h>

#include <sys/dnv.h>
#ifdef _KERNEL
#include <sys/kthread.h>
#include <sys/sbuf.h>
#include <sys/kernel.h>
#include <sys/socketvar.h>
#include <sys/poll.h>
#include <sys/proc.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#else
#include <sys/sbuf.h>
#include <errno.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#endif

#include "dl_assert.h"
#include "dl_bbuf.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_topic.h"
#include "dl_record.h"
#include "dl_record_batch.h"
#include "dl_request.h"
#include "dl_utils.h"
#include "dl_topic.h"
#include "dlog_client.h"

static unsigned int dlog_nopen = 0;
static unsigned int dlog_nerr = 0;
static unsigned int dlog_nproduce = 0;

extern struct sysctl_oid *dlog_oidp;

SYSCTL_DECL(_debug);

SYSCTL_NODE(_debug, OID_AUTO, dlog, CTLFLAG_RW, 0, "DLog client");

SYSCTL_UINT(_debug_dlog, OID_AUTO, open_handles, CTLFLAG_RD, &dlog_nopen, 0,
    "Number of open DLog handles");

SYSCTL_UINT(_debug_dlog, OID_AUTO, produce_requests, CTLFLAG_RD,
    &dlog_nproduce, 0, "Number of successful ProduceRequests");

SYSCTL_UINT(_debug_dlog, OID_AUTO, produce_errors, CTLFLAG_RD,
    &dlog_nerr, 0, "Number of failed ProduceRequests");

struct dlog_handle {
	struct dl_topic *dlh_topic;
};

extern struct dl_topic_hashmap *topic_hashmap;

static inline void
dlog_client_check_integrity(struct dlog_handle *self)
{

	DL_ASSERT(self != NULL, ("DLog client handle cannot be NULL."));
}

int
dlog_client_open(struct dlog_handle **self,
     nvlist_t const * const props)
{
	struct dlog_handle *handle;
	const char *hostname;
	unsigned short portnumber;
	struct dl_topic *topic;
	const char *topic_name;
	
	DL_ASSERT(config != NULL, ("Client configuration cannot be NULL"));
	DLOGTR0(PRIO_NORMAL, "Opening the Dlog client...\n");

	if (!nvlist_exists_string(props, DL_CONF_TOPIC)) {

		topic_name = DL_DEFAULT_TOPIC;
	} else {
		topic_name = nvlist_get_string(props, DL_CONF_TOPIC);
	}

	/* Lookup the topic in the topic hashmap. */
	if (dl_topic_hashmap_get(topic_hashmap, topic_name, &topic) != 0) {

		/* The specified topic was not found in the topic hashmap. */
		DLOGTR1(PRIO_NORMAL, "Topic %s has not been created\n",
		    topic_name);
		*self = NULL;
		return -1;
	}

	handle = (struct dlog_handle *) dlog_alloc(sizeof(struct dlog_handle));
#ifdef _KERNEL
	DL_ASSERT(handle != NULL, ("Failed allocating DLog client handle."));
#else
	if (handle == NULL) {
		DLOGTR0(PRIO_HIGH, "Failed allocating DLog client handle\n");
		return -1;
	}
#endif	
	bzero(handle, sizeof(struct dlog_handle));

	/* Associate the topic with this client handle. */
	handle->dlh_topic = topic;

	if (!nvlist_exists_string(props, DL_CONF_BROKER)) {
		hostname = DL_DEFAULT_BROKER;
	} else {
		hostname = nvlist_get_string(props, DL_CONF_BROKER);
	}

	if (!nvlist_exists_string(props, DL_CONF_BROKER_PORT)) {
		portnumber = DL_DEFAULT_BROKER_PORT;
	} else {
		portnumber = (unsigned short) nvlist_get_number(props,
		    DL_CONF_BROKER_PORT);
	}
	
	DLOGTR1(PRIO_LOW, "Kafka Message format of producer: %zu\n",
	    dnvlist_get_number(props, DL_CONF_MSG_VERSION,
	    DL_DEFAULT_MSG_VERSION));

	/* Increment the SYSCTL count of open handles */
	dlog_nopen++;

	*self = handle;
	return 0;
}

void
dlog_client_close(struct dlog_handle *self)
{

	dlog_client_check_integrity(self);

	/* Free all the memory associated with the client handle. */
	dlog_free(self);	

	/* Decrement the SYSCTL count of open handles */
	dlog_nopen--;
}

int
dlog_produce(struct dlog_handle *self, char *k, unsigned char *v, size_t v_len)
{
	int rc;

	dlog_client_check_integrity(self);

	rc = dl_topic_produce_record_to(self->dlh_topic, k, v, v_len);
	if (rc == 0)
		dlog_nproduce++;
	else
		dlog_nerr++;

	return rc;
}

int
dlog_produce_no_key(struct dlog_handle *handle, unsigned char *v, size_t v_len)
{

	return dlog_produce(handle, NULL, v, v_len);
}
