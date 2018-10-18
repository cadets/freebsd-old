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

#ifdef __APPLE__
#include <stdatomic.h>
#else
#include <sys/cdefs.h>
#include <sys/types.h>
#include <machine/atomic.h>
#endif

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stddef.h>
#include <stdint.h>
#endif

#include "dl_assert.h"
#include "dl_correlation_id.h"
#include "dl_memory.h"
#include "dl_utils.h"

struct dl_correlation_id
{
#ifdef __APPLE__
	atomic_int_least32_t val;
#else
	volatile uint32_t val;
#endif
};

int
dl_correlation_id_new(struct dl_correlation_id **self)
{
	struct dl_correlation_id *cid;
	
	DL_ASSERT(self != NULL, ("Correlation ID cannot be NULL"));
       
	cid = (struct dl_correlation_id *)
	    dlog_alloc(sizeof(struct dl_correlation_id));
#ifdef _KERNEL
	DL_ASSERT(cid != NULL, ("Failed to allocate Correlation Id."));
	{
#else
	if (cid != NULL) {
#endif
#ifdef __APPLE__
		atomic_init(&cid->val, 0);
#else
		cid->val = 0;
#endif
		*self = cid;
		return 0;
	}
	DLOGTR0(PRIO_HIGH, "Failed to allocate Correlation Id\n.");
	return -1;
}

int32_t
dl_correlation_id_inc(struct dl_correlation_id * self)
{
	DL_ASSERT(self != NULL, ("Correlation ID cannot be NULL"));

#ifdef __APPLE__
	return atomic_fetch_add(&self->val, 1);
#else
	atomic_add_32(&self->val, 1);
	return 0;
#endif
}

int32_t
dl_correlation_id_val(struct dl_correlation_id *self)
{
	DL_ASSERT(self != NULL, ("Correlation ID cannot be NULL"));

#ifdef __APPLE__
	return atomic_load(&self->val);
#else
	return atomic_load_32(&self->val);
#endif
}

void
dl_correlation_id_delete(struct dl_correlation_id *self)
{
	DL_ASSERT(self != NULL, ("Correlation ID cannot be NULL"));

	dlog_free(self);
}
