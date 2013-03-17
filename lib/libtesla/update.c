/*-
 * Copyright (c) 2012 Jonathan Anderson
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
#include <stdbool.h>
#include <inttypes.h>
#endif

#define	CHECK(fn, ...) do { \
	int err = fn(__VA_ARGS__); \
	if (err != TESLA_SUCCESS) { \
		DEBUG_PRINT("error in " #fn ": %s\n", tesla_strerror(err)); \
		return (err); \
	} \
} while(0)

int32_t
tesla_update_state(uint32_t tesla_context, uint32_t class_id,
	const struct tesla_key *key, const char *name, const char *description,
	const struct tesla_transitions *trans)
{
	if (verbose_debug()) {
		DEBUG_PRINT("\n====\n%s()\n", __func__);
		DEBUG_PRINT("  context:      %s\n",
		            (tesla_context == TESLA_SCOPE_GLOBAL
			     ? "global"
			     : "per-thread"));
		DEBUG_PRINT("  class:        %d ('%s')\n", class_id, name);

		char *matrix = transition_matrix(trans);
		DEBUG_PRINT("  transitions:  %s", matrix);
		tesla_free(matrix);

		DEBUG_PRINT("\n");
		DEBUG_PRINT("  key:          ");
		print_key(key);
		DEBUG_PRINT("\n----\n");
	}

	struct tesla_store *store;
	CHECK(tesla_store_get, tesla_context, TESLA_MAX_CLASSES,
	    TESLA_MAX_INSTANCES, &store);
	VERBOSE_PRINT("store: 0x%tx", (intptr_t) store);
	VERBOSE_PRINT("\n----\n");

	struct tesla_class *class;
	CHECK(tesla_class_get, store, class_id, &class, name, description);

	if (verbose_debug()) {
		print_class(class);
		DEBUG_PRINT("----\n");
	}

	tesla_table *table = class->ts_table;
	tesla_instance *start = table->tt_instances;

	assert(table->tt_length <= 32);

	// Did we match any instances?
	bool matched_something = false;

	// Make space for cloning existing instances.
	tesla_instance clones[table->tt_free];
	size_t cloned = 0;

	// Update existing instances, forking/specialising if necessary.
	for (uint32_t i = 0; i < table->tt_length; i++) {
		tesla_instance *inst = table->tt_instances + i;
		if (!tesla_instance_active(inst))
			continue;

		// Is this instance required to take a transition?
		bool transition_required = false;

		// Has this instance actually taken a transition?
		bool transition_taken = false;

		for (uint32_t j = 0; j < trans->length; j++) {
			tesla_transition *t = trans->transitions + j;
			const tesla_key *k = &inst->ti_key;

			// Check whether or not the instance matches the
			// provided key, masked by what the transition says to
			// expect from its 'previous' state.
			tesla_key masked = *key;
			masked.tk_mask &= t->mask;

			if (!tesla_key_matches(&masked, k))
				continue;

			if (k->tk_mask != t->mask)
				continue;

			if (inst->ti_state != t->from) {
				// If the instance matches everything but the
				// state, so there had better be a transition
				// somewhere in 'trans' that can be taken!
				if (k->tk_mask == masked.tk_mask)
					transition_required = true;

				continue;
			}

			// The match has succeeded: we are either going to
			// update or clone an existing state.
			transition_taken = true;
			matched_something = true;

			// If the keys just match (and we haven't been explictly
			// instructed to fork), just update the state.
			if (!(t->flags & TESLA_TRANS_FORK)
			    && key->tk_mask == k->tk_mask) {
				VERBOSE_PRINT("update %td: %tx->%tx\n",
				              inst - start, t->from, t->to);

				inst->ti_state = t->to;
				break;
			}

			// If the keys weren't an exact match, we need to fork
			// a new (more specific) automaton instance.
			struct tesla_instance *clone = clones + cloned++;
			*clone = *inst;
			clone->ti_state = t->to;

			VERBOSE_PRINT("clone  %td:%tx -> %tx\n",
			              inst - start, inst->ti_state,
			              t->to);

			CHECK(tesla_key_union, &clone->ti_key, key);
			break;
		}

		if (transition_required && !transition_taken)
			tesla_assert_fail(class, inst, trans);
	}

	// Move any clones into the instance.
	for (size_t i = 0; i < cloned; i++) {
		struct tesla_instance *clone = clones + i;
		struct tesla_instance *copied_in_place;

		CHECK(tesla_clone, class, clone, &copied_in_place);
	}


	// Is the transition "special" (e.g. init/cleanup)?
	for (uint32_t i = 0; i < trans->length; i++) {
		const tesla_transition *t = trans->transitions + i;
		if (t->from == 0) {
			struct tesla_instance *inst;
			CHECK(tesla_instance_new, class, key, t->to, &inst);
			assert(tesla_instance_active(inst));

			matched_something = true;
			VERBOSE_PRINT("new    %td: %tx\n",
			              inst - start, inst->ti_state);
		}

		if (t->flags & TESLA_TRANS_CLEANUP) {
			tesla_class_reset(class);
		}
	}

	if (verbose_debug()) {
		DEBUG_PRINT("----\n");
		print_class(class);
		DEBUG_PRINT("\n====\n\n");
	}

	if (!matched_something)
		tesla_match_fail(class, key, trans);

	tesla_class_put(class);

	return (TESLA_SUCCESS);
}

