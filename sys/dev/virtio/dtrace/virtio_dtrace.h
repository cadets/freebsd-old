/*-
 * Copyright (c) 2017 Domagoj Stolfa
 * All rights reserved.
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
 * $FreeBSD$
 */

#ifndef _VIRTIO_DTRACE_H_
#define _VIRTIO_DTRACE_H_

#include <sys/queue.h>
#include <sys/dtrace_bsd.h>

/*
 * The events related to probe installation and uninstallation are presently
 * only meant to be used to instruct the guest.
 *
 * On the other hand, provider registration, probe creation/deletion and
 * provider de-registration is meant only for the host.
 *
 * READY and EOF are used for synchronization for purposes, while CLEANUP will
 * be used to clean up the TX virtqueue on the guest.
 */
#define	VIRTIO_DTRACE_DEVICE_READY    0x00 /* The device is ready */
#define	VIRTIO_DTRACE_REGISTER        0x01 /* Provider Registration */
#define	VIRTIO_DTRACE_UNREGISTER      0x02 /* Provider Unregistration */
#define	VIRTIO_DTRACE_DESTROY         0x03 /* Instance Destruction */
#define	VIRTIO_DTRACE_PROBE_CREATE    0x04 /* Probe Creation */
#define	VIRTIO_DTRACE_PROBE_INSTALL   0x05 /* Probe Installation */
#define	VIRTIO_DTRACE_PROBE_UNDEFINED 0x06 /* Undefined */
#define	VIRTIO_DTRACE_EOF             0x07 /* EOF Signal */
#define	VIRTIO_DTRACE_GO              0x08 /* Start tracing */
#define	VIRTIO_DTRACE_STOP            0x09 /* Start tracing */

struct vtdtr_softc;
struct uuid;

struct vtdtr_pbev_create_event {
	char        mod[DTRACE_MODNAMELEN];
	char        func[DTRACE_FUNCNAMELEN];
	char        name[DTRACE_NAMELEN];
	struct uuid uuid;
}__attribute__((packed));

struct vtdtr_pbev_toggle_event {
	char *dif; /* TODO */
}__attribute__((packed));

struct vtdtr_ctrl_pbevent {
	uint32_t probe;

	union {
		struct vtdtr_pbev_create_event create;
		struct vtdtr_pbev_toggle_event toggle;
	} upbev;
}__attribute__((packed));

struct vtdtr_ctrl_provevent {
	char        name[DTRACE_PROVNAMELEN];
	struct uuid uuid;
}__attribute__((packed));

struct virtio_dtrace_control {
	uint32_t event;

	union {
		struct vtdtr_ctrl_pbevent   probe_ev;
		struct vtdtr_ctrl_provevent prov_ev;
	} uctrl;
}__attribute__((packed));

struct virtio_dtrace_queue {
	struct mtx           vtdq_mtx;
	struct vtdtr_softc  *vtdq_sc;
	struct virtqueue    *vtdq_vq;
	void               (*vtdq_vqintr)(void *);
	int                  vtdq_id;
	struct taskqueue    *vtdq_tq;
	struct task          vtdq_intrtask;
	char                 vtdq_name[16];
	int                  vtdq_ready;
};

struct vtdtr_ctrl_entry {
	struct virtio_dtrace_control   ctrl;
	STAILQ_ENTRY(vtdtr_ctrl_entry) entries;
};

struct vtdtr_ctrlq {
	STAILQ_HEAD(, vtdtr_ctrl_entry) head;
	struct mtx                           mtx;
	size_t                               n_entries;
};


#define	VTDTR_QUEUE_LOCK(__q)   mtx_lock(&((__q)->vtdq_mtx))
#define	VTDTR_QUEUE_UNLOCK(__q) mtx_unlock(&((__q)->vtdq_mtx))
#define	VTDTR_QUEUE_LOCK_ASSERT(__q)		\
	mtx_assert(&((__q)->vtdq_mtx), MA_OWNED)
#define	VTDTR_QUEUE_LOCK_ASSERT_NOTOWNED(__q)	\
	mtx_assert(&((__q)->vtdq_mtx), MA_NOTOWNED)

#endif
