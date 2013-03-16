/** @file  tesla_debug.c    Debugging helpers for TESLA state. */
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
#include <stdlib.h>

char*
transition_matrix(const struct tesla_transitions *trans)
{
	static const char EACH[] = "(%d:0x%tx -> %d%s) ";

	size_t needed = trans->length * (sizeof(EACH) + 4) + 4;
	char *buffer = tesla_malloc(needed);
	char *c = buffer;

	c += sprintf(c, "[ ");

	for (size_t i = 0; i < trans->length; i++) {
		const tesla_transition *t = trans->transitions + i;
		c += sprintf(c, EACH, t->from, t->mask, t->to,
			     t->fork ? " <fork>" : "");
	}

	c += sprintf(c, "]");

	return buffer;
}

#ifndef NDEBUG

#define print DEBUG_PRINT

/* TODO: kernel version... probably just say no? */
int32_t
verbose_debug()
{
	static int32_t mode = -1;

	if (mode == -1)
		mode = (getenv("VERBOSE_DEBUG") != NULL);

	return mode;
}

void
assert_instanceof(struct tesla_instance *instance, struct tesla_class *tclass)
{
	assert(instance != NULL);
	assert(tclass != NULL);

	struct tesla_table *ttp = tclass->ts_table;
	assert(ttp != NULL);

	int32_t instance_belongs_to_class = 0;
	for (uint32_t i = 0; i < ttp->tt_length; i++) {
		if (instance == &ttp->tt_instances[i]) {
			instance_belongs_to_class = 1;
			break;
		}
	}

	tesla_assert(instance_belongs_to_class,
		("tesla_instance %x not of class '%s'",
		 instance, tclass->ts_name)
	       );
}

void
print_class(const struct tesla_class *c)
{
	print("struct tesla_class @ 0x%tx {\n", (intptr_t) c);
	print("  name:         '%s',\n", c->ts_name);
	print("  description:  '[...]',\n");   // TL;DR
	print("  scope:        ");
	switch (c->ts_scope) {
		case TESLA_SCOPE_PERTHREAD:  print("thread-local\n"); break;
		case TESLA_SCOPE_GLOBAL:     print("global\n");       break;
		default:                     print("UNKNOWN (0x%x)\n", c->ts_scope);
	}
	print("  limit:        %d\n", c->ts_limit);
	print("  fail action:  ");
	switch (c->ts_action) {
		case TESLA_ACTION_FAILSTOP:  print("fail-stop\n"); break;
		case TESLA_ACTION_DTRACE:    print("DTrace probe\n"); break;
		case TESLA_ACTION_PRINTF:    print("printf()\n"); break;
		default:                     print("UNKNOWN (0x%x)\n", c->ts_action);
	}

	struct tesla_table *t = c->ts_table;
	print("  %d/%d instances\n", t->tt_length - t->tt_free, t->tt_length);
	for (uint32_t i = 0; i < t->tt_length; i++) {
		struct tesla_instance *inst = &t->tt_instances[i];
		if (!tesla_instance_active(inst))
			continue;

		print("    %2u: state %d, ", i, inst->ti_state);
		print_key(&inst->ti_key);
		print("\n");
	}
	print("}\n");
}

void
print_key(const struct tesla_key *key)
{
	print("0x%tx [ ", key->tk_mask);

	for (int32_t i = 0; i < TESLA_KEY_SIZE; i++) {
		if (key->tk_mask & (1 << i)) {
			print("%tx ", key->tk_keys[i]);
		} else {
			print("X ");
		}
	}

	print("]");
}

#endif /* !NDEBUG */

