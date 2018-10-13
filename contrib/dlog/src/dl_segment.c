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
#include <machine/atomic.h>

/*
#include <sys/uio.h>

#ifdef _KERNEL
#include <sys/capsicum.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#endif
*/

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_segment.h"
#include "dl_utils.h"

static inline void dl_segment_check_integrity(struct dl_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
	DL_ASSERT(self->dls_insert_fcn != NULL,
	    ("Segment insert function cannot be NULL"));
	DL_ASSERT(self->dls_get_fcn != NULL,
	    ("Segment get message function cannot be NULL"));
	DL_ASSERT(self->dls_get_offset_fcn != NULL,
	    ("Segment get offset function cannot be NULL"));
	DL_ASSERT(self->dls_lock_fcn != NULL,
	    ("Segment lock function cannot be NULL"));
	DL_ASSERT(self->dls_unlock_fcn != NULL,
	    ("Segment unlock function cannot be NULL"));
	DL_ASSERT(self->dls_delete_fcn != NULL,
	    ("Segment delete function cannot be NULL"));
}

void
dl_segment_delete(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	dlog_free(self);
}

int
dl_segment_new(struct dl_segment **self, uint32_t base_offset,
    uint32_t size, dls_insert_message insert_fcn,
    dls_get_message_by_offset get_fcn,
    dls_get_offset get_offset_fcn, dls_lock lock_fcn,
    dls_unlock unlock_fcn, dls_delete delete_fcn)
{
	struct dl_segment *seg;

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));
	DL_ASSERT(insert_fcn != NULL,
	    ("Segment insert function cannot be NULL"));
	DL_ASSERT(get_fcn != NULL,
	    ("Segment get message function cannot be NULL"));
	DL_ASSERT(get_offset_fcn != NULL,
	    ("Segment get offset function cannot be NULL"));
	DL_ASSERT(lock_fcn != NULL,
	    ("Segment lock function cannot be NULL"));
	DL_ASSERT(unlock_fcn != NULL,
	    ("Segment unlock function cannot be NULL"));
	DL_ASSERT(delete_fcn != NULL,
	    ("Segment delete function cannot be NULL"));

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
#ifdef _KERNEL
	DL_ASSERT(seg != NULL, ("Failed allocating Segment"));
#else
	if (seg == NULL) {

		goto err_seg_ctor;
	}
#endif

	seg->base_offset = base_offset;
	seg->segment_size = size;
	seg->last_sync_pos = 0;
	
	seg->dls_insert_fcn = insert_fcn;
	seg->dls_get_fcn = get_fcn;
	seg->dls_get_offset_fcn = get_offset_fcn;
	seg->dls_lock_fcn = lock_fcn;
	seg->dls_unlock_fcn = unlock_fcn;
	seg->dls_delete_fcn = delete_fcn;
    
	dl_segment_check_integrity(seg);
	*self = seg;

	return 0;

#ifndef _KERNEL
err_seg_ctor:

	DLOGTR0(PRIO_HIGH, "Failed allocating Segment instance\n");
	*self = NULL;
	return -1;
#endif
}

int
dl_segment_get_message_by_offset(struct dl_segment *self, int offset,
    struct dl_bbuf **buffer)
{

	dl_segment_check_integrity(self);
	return self->dls_get_fcn(self, offset,  buffer);
}

void
dl_segment_lock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_segment_check_integrity(self);
	self->dls_lock_fcn(self);
}

void
dl_segment_unlock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_segment_check_integrity(self);
	self->dls_unlock_fcn(self);
}

u_int64_t
dl_segment_get_base_offset(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return atomic_load_64(&self->base_offset);
}

off_t
dl_segment_get_last_sync_pos(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return self->last_sync_pos;
}

void
dl_segment_set_last_sync_pos(struct dl_segment *self, off_t pos)
{

	dl_segment_check_integrity(self);
	self->last_sync_pos = pos;
}

int
dl_segment_insert_message(struct dl_segment *self,
    struct dl_bbuf *buffer)
{

	dl_segment_check_integrity(self);
	DL_ASSERT(buffer != NULL, ("Bufer to insert cannot be NULL"));
	return self->dls_insert_fcn(self, buffer);
}

int
dl_segment_get_offset(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return self->dls_get_offset_fcn(self);
}
