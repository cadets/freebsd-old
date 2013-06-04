/** @file  tesla_debug.c    Debugging helpers for TESLA state. */
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
#include "tesla_strnlen.h"

#ifndef _KERNEL
#include <fnmatch.h>
#include <stdlib.h>
#include <unistd.h>
#endif

void
print_transition(const char *debug, const struct tesla_transition *t)
{
	if (!tesla_debugging(debug))
		return;

	char buffer[1024];
	char *end = buffer + sizeof(buffer);

	sprint_transition(buffer, end, t);
	print("%s", buffer);
}

char*
sprint_transition(char *buf, const char *end, const struct tesla_transition *t)
{
	char *c = buf;

	/* Note: On at least one Mac, combining the following
	 *       into a single snprintf() causes the wrong thing
	 *       to be printed (instead of t->mask, we get an address!).
	 */
	SAFE_SPRINTF(c, end, "(%d:", t->from);
	SAFE_SPRINTF(c, end, "0x%tx", t->from_mask);
	SAFE_SPRINTF(c, end, " -> %d:", t->to);
	SAFE_SPRINTF(c, end, "0x%tx", t->to_mask);

	if (t->flags & TESLA_TRANS_INIT)
		SAFE_SPRINTF(c, end, " <init>");

	if (t->flags & TESLA_TRANS_CLEANUP)
		SAFE_SPRINTF(c, end, " <clean>");

	SAFE_SPRINTF(c, end, ") ");

	return c;
}

void
print_transitions(const char *debug, const struct tesla_transitions *transp)
{
	if (!tesla_debugging(debug))
		return;

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

	for (size_t i = 0; i < tp->length; i++)
		c = sprint_transition(c, end, tp->transitions + i);

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

int32_t
tesla_debugging(const char *name)
{
#ifdef _KERNEL
	return 0;
#else
#ifdef HAVE_ISSETUGID
	/*
	 * Debugging paths could be more vulnerable to format string problems
	 * than other code; don't allow when running setuid or setgid.
	 */
	if (issetugid())
		return 0;
#endif

	const char *env = getenv("TESLA_DEBUG");

	/* If TESLA_DEBUG is not set, we're definitely not debugging. */
	if (env == NULL)
		return 0;

	/* Allow e.g. 'libtesla' to match 'libtesla.foo'. */
	size_t envlen = strnlen(env, 100);
	if ((strncmp(env, name, envlen) == 0) && (name[envlen] == '.'))
		return 1;

	/* Otherwise, use fnmatch's normal star-matching. */
	return (fnmatch(env, name, 0) == 0);
#endif
}

void
assert_instanceof(struct tesla_instance *instance, struct tesla_class *tclass)
{
	assert(instance != NULL);
	assert(tclass != NULL);

	int32_t instance_belongs_to_class = 0;
	for (uint32_t i = 0; i < tclass->tc_limit; i++) {
		if (instance == &tclass->tc_instances[i]) {
			instance_belongs_to_class = 1;
			break;
		}
	}

	tesla_assert(instance_belongs_to_class,
		("tesla_instance %x not of class '%s'",
		 instance, tclass->tc_name)
	       );
}

void
print_class(const struct tesla_class *c)
{
	static const char *DEBUG_NAME = "libtesla.class.state";
	if (!tesla_debugging(DEBUG_NAME))
		return;

	print("----\n");
	print("struct tesla_class @ 0x%tx {\n", (intptr_t) c);
	print("  name:         '%s',\n", c->tc_name);
	print("  description:  '[...]',\n");   // TL;DR
	print("  scope:        ");
	switch (c->tc_scope) {
		case TESLA_SCOPE_PERTHREAD:  print("thread-local\n"); break;
		case TESLA_SCOPE_GLOBAL:     print("global\n");       break;
		default:                     print("UNKNOWN (0x%x)\n", c->tc_scope);
	}
	print("  limit:        %d\n", c->tc_limit);
	print("  %d/%d instances\n", c->tc_limit - c->tc_free, c->tc_limit);
	for (uint32_t i = 0; i < c->tc_limit; i++) {
		const struct tesla_instance *inst = c->tc_instances + i;
		if (!tesla_instance_active(inst))
			continue;

		print("    %2u: state %d, ", i, inst->ti_state);
		print_key(DEBUG_NAME, &inst->ti_key);
		print("\n");
	}
	print("}\n");
	print("----\n");
}

void
print_key(const char *debug_name, const struct tesla_key *key)
{
	if (!tesla_debugging(debug_name))
		return;

	static const size_t LEN = 15 * TESLA_KEY_SIZE + 10;
	char buffer[LEN];
	char *end = buffer + LEN;

	char *e = key_string(buffer, end, key);
	assert(e < end);

	print("%s", buffer);
}

#endif /* !NDEBUG */

