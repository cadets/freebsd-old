/** @file  debug.c    Debugging helpers for TESLA state. */
/*-
 * Copyright (c) 2012-2013 Jonathan Anderson
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
#include <stdlib.h>
#endif

void
print_transitions(const struct tesla_transitions *transp)
{
	char buffer[1024];
	char *end = buffer + sizeof(buffer);

	sprint_transitions(buffer, end, transp);
	print("%s", buffer);
}

char*
sprint_transitions(char *buffer, const char *end,
    const struct tesla_transitions *tp)
{
	char *c = buffer;

	SAFE_SPRINTF(c, end, "[ ");

	for (size_t i = 0; i < tp->length; i++) {
		const tesla_transition *t = tp->transitions + i;

		/* Note: On at least one Mac, combining the following
		 *       into a single snprintf() causes the wrong thing
		 *       to be printed (instead of t->mask, we get an address!).
		 */
		SAFE_SPRINTF(c, end, "(%d:", t->from);
		SAFE_SPRINTF(c, end, "0x%tx", t->mask);
		SAFE_SPRINTF(c, end, " -> %d", t->to);

		if (t->flags & TESLA_TRANS_FORK)
			SAFE_SPRINTF(c, end, " <fork>");

		if (t->flags & TESLA_TRANS_INIT)
			SAFE_SPRINTF(c, end, " <init>");

		if (t->flags & TESLA_TRANS_CLEANUP)
			SAFE_SPRINTF(c, end, " <clean>");

		SAFE_SPRINTF(c, end, ") ");
	}

	SAFE_SPRINTF(c, end, "]");

	return c;
}

char*
key_string(char *buffer, const char *end, const struct tesla_key *key)
{
	char *c = buffer;

	SAFE_SPRINTF(c, end, "0x%tx [ ", key->tk_mask);

	for (int32_t i = 0; i < TESLA_KEY_SIZE; i++) {
		if (key->tk_mask & (1 << i))
			SAFE_SPRINTF(c, end, "%tx ", key->tk_keys[i]);
		else
			SAFE_SPRINTF(c, end, "X ");
	}

	SAFE_SPRINTF(c, end, "]");

	return c;
}

#ifndef NDEBUG

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
	static const size_t LEN = 15 * TESLA_KEY_SIZE + 10;
	char buffer[LEN];
	char *end = buffer + LEN;

	char *e = key_string(buffer, end, key);
	assert(e < end);

	print("%s", buffer);
}

#endif /* !NDEBUG */

