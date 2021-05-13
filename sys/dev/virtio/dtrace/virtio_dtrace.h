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
#include <dev/dttransport/dttransport.h>

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
#define	VIRTIO_DTRACE_DEVICE_READY	0x00 /* The device is ready */
#define	VIRTIO_DTRACE_REGISTER		0x01 /* UNUSED */
#define	VIRTIO_DTRACE_UNREGISTER	0x02 /* UNUSED */
#define	VIRTIO_DTRACE_DESTROY		0x03 /* UNUSED */
#define	VIRTIO_DTRACE_PROBE_CREATE	0x04 /* UNUSED */
#define	VIRTIO_DTRACE_PROBE_INSTALL	0x05 /* Probe Installation */
#define	VIRTIO_DTRACE_PROBE_UNDEFINED	0x06 /* Undefined */
#define	VIRTIO_DTRACE_EOF		0x07 /* EOF Signal */
#define	VIRTIO_DTRACE_GO		0x08 /* Start tracing */
#define	VIRTIO_DTRACE_ELF		0x09 /* ELF file transmission */
#define	VIRTIO_DTRACE_STOP		0x0A /* Start tracing */
#define	VIRTIO_DTRACE_KILL		0x0B /* Kill a DTrace process */

int virtio_dtrace_enqueue(dtt_entry_t *);

#endif
