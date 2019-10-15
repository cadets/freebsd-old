/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_segment.h"
#include "dl_utils.h"

static int dl_segment_ctor(void *, va_list * app); 

static const struct dl_segment_class TYPE = {
	{
		sizeof(struct dl_segment),
		dl_segment_ctor,
		NULL,
		NULL
	},
	NULL,
	NULL,
	NULL,
	NULL,
};

const void *DL_SEGMENT= &TYPE;

static inline void
assert_integrity(struct dl_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
	/*
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
	    */
}

/**
 * Segment constructor.
 */
int
dl_segment_ctor(void *_self, va_list *ap)
{
	struct dl_segment *self = (struct dl_segment *) _self;

	DL_ASSERT(self != NULL, ("Segment cannot be NULL."));

	self->dls_base_offset = va_arg(*ap, uint32_t);
	self->dls_last_sync_pos = 0;
	
	return 0;
}

int
dl_segment_get_message_by_offset(void *self, int offset,
    struct dl_bbuf **buffer)
{
	const struct dl_segment_class **class = self;

	assert_integrity(self);
	return (* class)->dls_get_message_by_offset(self, offset, buffer);
}

uint64_t
dl_segment_get_base_offset(struct dl_segment *self)
{

	assert_integrity(self);
	return atomic_load_64(&self->dls_base_offset);
}

void
dl_segment_set_base_offset(struct dl_segment *self, uint64_t base)
{

	assert_integrity(self);
	atomic_store_64(&self->dls_base_offset, base);
}

off_t
dl_segment_get_last_sync_pos(struct dl_segment *self)
{

	assert_integrity(self);
	return self->dls_last_sync_pos;
}

void
dl_segment_set_last_sync_pos(struct dl_segment *self, off_t pos)
{

	assert_integrity(self);
	atomic_store_64(&self->dls_last_sync_pos, pos);
}

int
dl_segment_insert_message(void *self, struct dl_bbuf *buffer)
{
	const struct dl_segment_class **class = self;

	assert_integrity(self);
	DL_ASSERT(buffer != NULL, ("Bufer to insert cannot be NULL"));
	return (* class)->dls_insert_message(self, buffer);
}

int
dl_segment_get_offset(void *self)
{
	const struct dl_segment_class **class = self;

	assert_integrity(self);
	return (* class)->dls_get_offset(self);
}

int
dl_segment_sync(void *self)
{
	const struct dl_segment_class **class = self;

	assert_integrity(self);
	return (* class)->dls_sync(self);
}
