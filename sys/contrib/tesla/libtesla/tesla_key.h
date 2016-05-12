/*-
 * Copyright (c) 2013 Jonathan Anderson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
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
 * $Id$
 */

#include "tesla_internal.h"

#ifndef _KERNEL
#include <inttypes.h>
#include <stdio.h>
#endif


#define	IS_SET(mask, index) (mask & (1 << index))

/**
 * Check to see if a key matches a pattern.
 *
 * @returns  1 if @a k matches @a pattern, 0 otherwise
 */
static inline int
tesla_key_matches(const struct tesla_key *pattern, const struct tesla_key *k)
{
	assert(pattern != NULL);
	assert(k != NULL);

	// The pattern's mask must be a subset of the target's (ANY matches
	// 42 but not the other way around).
	if (!SUBSET(pattern->tk_mask, k->tk_mask))
		return (0);

	for (uint32_t i = 0; i < TESLA_KEY_SIZE; i++) {
		// Only check keys specified by the bitmasks.
		uint32_t mask = (1 << i);
		if ((pattern->tk_mask & mask) != mask)
			continue;

		// A non-match of any sub-key implies a non-match of the key.
		if (pattern->tk_keys[i] != k->tk_keys[i])
			return (0);
	}

	return (1);
}

/** Copy new entries from @a source into @a dest. */
static inline int32_t
tesla_key_union(tesla_key *dest, const tesla_key *source)
{
	for (uint32_t i = 0; i < TESLA_KEY_SIZE; i++) {
		if (IS_SET(source->tk_mask, i)) {
			if (IS_SET(dest->tk_mask, i)) {
			    if (dest->tk_keys[i] != source->tk_keys[i])
				return (TESLA_ERROR_EINVAL);
			} else {
				dest->tk_keys[i] = source->tk_keys[i];
			}
		}
	}

	dest->tk_mask |= source->tk_mask;
	return (TESLA_SUCCESS);
}

