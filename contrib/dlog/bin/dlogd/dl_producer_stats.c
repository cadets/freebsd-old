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

#include <sys/dnv.h>
#include <sys/types.h>
#include <machine/atomic.h>
#include <sys/mman.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <dev/dlog/dlog.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_producer_stats.h"
#include "dl_protocol.h"
#include "dl_utils.h"

struct dl_producer_stats_msg {
	time_t dlpsm_timestamp;
	int32_t dlpsm_cid;
	bool dlpsm_error;
};

struct dl_producer_stats_vals {
	volatile uint64_t dlps_bytes_sent;
	volatile uint64_t dlps_bytes_received;
	struct dl_producer_stats_msg dlps_sent;
	struct dl_producer_stats_msg dlps_received;
	int32_t dlps_rtt;
	int32_t dlps_state;
	int dlps_resend_timeout;
	int dlps_queue_capacity;
	int dlps_queue_requests;
	int dlps_queue_unackd;
	bool dlps_tcp_connected;
	bool dlps_tls_connected;
	bool dlps_resend;
	char dlps_topic_name[DL_MAX_TOPIC_NAME_LEN];	
};

struct dl_producer_stats {
	struct dl_producer_stats_vals *dlps_vals;
	int dlps_fd;
};

extern nvlist_t *dlogd_props;

static inline void
check_integrity(struct dl_producer_stats const * const self)
{

	DL_ASSERT(self != NULL, ("ProducerStats instance cannot be NULL."));
}

int
dl_producer_stats_new(struct dl_producer_stats **self,
    char *topic_name)
{
	struct dl_producer_stats *stats;
	struct sbuf *stats_path;
	const char *path;

	DL_ASSERT(self != NULL, ("ProducerStats instance cannot be NULL."));

	stats = (struct dl_producer_stats *) dlog_alloc(
	    sizeof(struct dl_producer_stats));

	/* Open a memory mapped file for the Producer stats. */
	path = dnvlist_get_string(dlogd_props,
	    DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

	stats_path = sbuf_new_auto();
	sbuf_printf(stats_path, "%s/%s/stats", path, topic_name);
	sbuf_finish(stats_path);
	stats->dlps_fd = open(sbuf_data(stats_path),
	    O_RDWR | O_APPEND | O_CREAT, 0666);
	if (stats->dlps_fd == -1) {

		DLOGTR1(PRIO_HIGH,
		    "Failed opening ProducerStats file %d.\n", errno);
		sbuf_delete(stats_path);
		goto err_producer_stats;
	}
	sbuf_delete(stats_path);
	ftruncate(stats->dlps_fd, sizeof(struct dl_producer_stats));

	stats->dlps_vals = (struct dl_producer_stats_vals *) mmap(
	    NULL, sizeof(struct dl_producer_stats_vals),
	    PROT_READ | PROT_WRITE, MAP_SHARED, stats->dlps_fd, 0);
	if (stats->dlps_vals == NULL)  {

		DLOGTR1(PRIO_HIGH,
		    "Failed mapping ProducerStats file %d.\n", errno);
		goto err_producer_stats;
	}

	*self = stats;
	check_integrity(*self);
	return 0;

err_producer_stats:
	DLOGTR0(PRIO_HIGH, "Failed instantiating ProducerStats instance\n");

	*self = NULL;
	return -1;
}

void
dl_producer_stats_delete(struct dl_producer_stats *self)
{

	check_integrity(self);

	/* Close and unmap the stats file. */
	msync(self->dlps_vals, sizeof(struct dl_producer_stats), MS_SYNC);
	munmap(self->dlps_vals, sizeof(struct dl_producer_stats));
	dlog_free(self);
}

void
dlps_set_rtt(struct dl_producer_stats *self, int32_t rtt)
{

	check_integrity(self);
	self->dlps_vals->dlps_rtt = rtt;
}

void
dlps_set_received_cid(struct dl_producer_stats *self, int32_t cid)
{

	check_integrity(self);
	self->dlps_vals->dlps_received.dlpsm_cid = cid;
}

void
dlps_set_received_error(struct dl_producer_stats *self, bool err)
{

	check_integrity(self);
	self->dlps_vals->dlps_received.dlpsm_error = err;
}

void
dlps_set_received_timestamp(struct dl_producer_stats *self)
{

	check_integrity(self);
	self->dlps_vals->dlps_received.dlpsm_timestamp = time(NULL);
}

void
dlps_set_sent_cid(struct dl_producer_stats *self, int32_t cid)
{

	check_integrity(self);
	self->dlps_vals->dlps_sent.dlpsm_cid = cid;
}

void
dlps_set_sent_error(struct dl_producer_stats *self, bool err)
{

	check_integrity(self);
	self->dlps_vals->dlps_sent.dlpsm_error = err;
}

void
dlps_set_sent_timestamp(struct dl_producer_stats *self)
{

	check_integrity(self);
	self->dlps_vals->dlps_sent.dlpsm_timestamp = time(NULL);
}

void
dlps_set_state(struct dl_producer_stats *self, int32_t state)
{

	check_integrity(self);
	self->dlps_vals->dlps_state = state;
}

/* iTODO: In constructor */
void
dlps_set_topic_name(struct dl_producer_stats *self, char *topic_name)
{

	check_integrity(self);
	strncpy(self->dlps_vals->dlps_topic_name, topic_name,
	    sizeof(self->dlps_vals->dlps_topic_name)); 
}

void
dlps_set_resend(struct dl_producer_stats *self, bool resend)
{

	check_integrity(self);
	self->dlps_vals->dlps_resend = resend;
}

void
dlps_set_resend_timeout(struct dl_producer_stats *self, int timeout)
{

	check_integrity(self);
	self->dlps_vals->dlps_resend_timeout = timeout;
}

void
dlps_set_tcp_connect(struct dl_producer_stats *self, bool status)
{

	check_integrity(self);
	self->dlps_vals->dlps_tcp_connected = status;
}

void
dlps_set_tls_connect(struct dl_producer_stats *self, bool status)
{

	check_integrity(self);
	self->dlps_vals->dlps_tls_connected = status;
}

void
dlps_set_bytes_sent(struct dl_producer_stats *self, int32_t nbytes)
{

	check_integrity(self);
	atomic_add_64(&self->dlps_vals->dlps_bytes_sent, nbytes);
}

void
dlps_set_bytes_received(struct dl_producer_stats *self, int32_t nbytes)
{

	check_integrity(self);
	atomic_add_64(&self->dlps_vals->dlps_bytes_received, nbytes);
}
void
dlps_set_queue_capacity(struct dl_producer_stats *self, int capacity)
{

	check_integrity(self);
	self->dlps_vals->dlps_queue_capacity = capacity;
}

void
dlps_set_queue_requests(struct dl_producer_stats *self, int requests)
{

	check_integrity(self);
	self->dlps_vals->dlps_queue_requests = requests;
}

void
dlps_set_queue_unackd(struct dl_producer_stats *self, int unackd)
{

	check_integrity(self);
	self->dlps_vals->dlps_queue_unackd = unackd;
}

int32_t
dlps_get_rtt(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_rtt;
}

int32_t
dlps_get_received_cid(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_received.dlpsm_cid;
}

bool
dlps_get_received_error(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_received.dlpsm_error;
}

time_t
dlps_get_received_timestamp(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_received.dlpsm_timestamp;
}

int32_t
dlps_get_sent_cid(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_sent.dlpsm_cid;
}

bool
dlps_get_sent_error(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_sent.dlpsm_error;
}

time_t
dlps_get_sent_timestamp(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_sent.dlpsm_timestamp;
}

int32_t
dlps_get_state(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_state;
}

char *
dlps_get_topic_name(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_topic_name;
}

bool
dlps_get_resend(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_resend;
}

int
dlps_get_resend_timeout(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_resend_timeout;
}

bool
dlps_get_tcp_connect(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_tcp_connected;
}

bool
dlps_get_tls_connect(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_tls_connected;
}

int32_t
dlps_get_bytes_sent(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_bytes_sent;
}

int32_t
dlps_get_bytes_received(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_bytes_received;
}

int
dlps_get_queue_capacity(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_queue_capacity;
}

int
dlps_get_queue_requests(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_queue_requests;
}

int
dlps_get_queue_unackd(struct dl_producer_stats *self)
{

	check_integrity(self);
	return self->dlps_vals->dlps_queue_unackd;
}
