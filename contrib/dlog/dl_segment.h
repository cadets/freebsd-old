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

#ifndef _DL_SEGMENT_H
#define _DL_SEGMENT_H

#include <sys/types.h>
#include <sys/queue.h>
#include <sys/sbuf.h>
#include <sys/proc.h>

#ifdef _KERNEL
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/kthread.h>
#else
#include <pthread.h>
#endif

#include "dl_bbuf.h"
#ifndef _KERNEL
#include "dl_index.h"
#endif

SLIST_HEAD(dl_segments, dl_segment);

struct dl_segment {
	SLIST_ENTRY(dl_segment) dls_entries;
#ifdef _KERNEL
	struct sx dls_lock; /* Lock for whilst updating segment. */
#else
	pthread_mutex_t dls_lock; /* Lock for whilst updating segment. */
#endif
	u_int64_t base_offset; /* Start offset of the segment. */
	u_int32_t segment_size; /* Number of offsets in the segment */
	u_int64_t offset; /* Current position in the log. TODO remove */
#ifdef _KERNEL
	struct ucred *ucred;
	struct vnode *_log;
#else
	int _log; /* Segement's log file descriptor. */
	int _klog; /* Segement's log file descriptor. */
	struct dl_index *dls_idx;
#endif
	off_t last_sync_pos;
};

struct dl_segment_desc {
	u_int64_t dlsd_base_offset; /* Start offset of the log. */
	u_int32_t dlsd_seg_size;
	int dlsd_log; /* Segement's log file descriptor. */
};

extern void dl_segment_delete(struct dl_segment *);
#ifndef _KERNEL
extern int dl_segment_new(struct dl_segment **, long int, long int,
    struct sbuf *);
extern int dl_segment_new_default(struct dl_segment **, struct sbuf *);
extern int dl_segment_new_default_sized(struct dl_segment **, long int,
    struct sbuf *);
#endif
extern int dl_segment_from_desc(struct dl_segment **,
    struct dl_segment_desc *);

extern void dl_segment_close(struct dl_segment *);
extern int dl_segment_insert_message(struct dl_segment *, struct dl_bbuf *);
extern int dl_segment_get_message_by_offset(struct dl_segment *, int,
    struct dl_bbuf **);
extern void dl_segment_lock(struct dl_segment *);
extern void dl_segment_unlock(struct dl_segment *);

extern u_int64_t dl_segment_get_base_offset(struct dl_segment *);
extern off_t dl_segment_get_last_sync_pos(struct dl_segment *);
#ifndef _KERNEL
extern int dl_segment_get_log(struct dl_segment *);
#endif
extern void dl_segment_set_last_sync_pos(struct dl_segment *, off_t);

#endif
