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

#define	ERROR_BUFFER_LENGTH	1024

static void	print_failure_header(const struct tesla_class *);

void
tesla_notify_new_instance(struct tesla_class *tcp,
    struct tesla_instance *tip)
{

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		/* XXXRW: more fine-grained DTrace probes? */
		tesla_state_transition_dtrace(tcp, tip, NULL, -1);
		return;

	default:
		/* for the PRINTF action, should this be a non-verbose print? */
		VERBOSE_PRINT("new    %td: %tx\n",
		              tip - tcp->ts_table->tt_instances,
		              tip->ti_state);

		/*
		 * XXXJA: convince self that we can never "pass" an assertion
		 *        with an event that creates a new instance
		 */

		break;
	}
}

void
tesla_notify_clone(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp, uint32_t index)
{

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		/* XXXRW: more fine-grained DTrace probes? */
		tesla_state_transition_dtrace(tcp, tip, transp, index);
		return;

	default: {
		/* for the PRINTF action, should this be a non-verbose print? */
		assert(index >= 0);
		assert(index < transp->length);
		const struct tesla_transition *t = transp->transitions + index;

		VERBOSE_PRINT("clone  %td:%tx -> %tx\n",
		              tip - tcp->ts_table->tt_instances,
		              tip->ti_state, t->to);

		if (t->flags & TESLA_TRANS_CLEANUP)
			tesla_notify_pass(tcp, tip);

		break;
	}
	}
}

void
tesla_notify_transition(struct tesla_class *tcp,
    struct tesla_instance *tip, const struct tesla_transitions *transp,
    uint32_t index)
{

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		tesla_state_transition_dtrace(tcp, tip, transp, index);
		return;

	default: {
		/* for the PRINTF action, should this be a non-verbose print? */
		assert(index >= 0);
		assert(index < transp->length);
		const struct tesla_transition *t = transp->transitions + index;

		VERBOSE_PRINT("update %td: %tx->%tx\n",
		              tip - tcp->ts_table->tt_instances,
		              t->from, t->to);

		if (t->flags & TESLA_TRANS_CLEANUP)
			tesla_notify_pass(tcp, tip);

		break;
	}
	}
}

void
tesla_notify_assert_fail(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp)
{
	assert(tcp != NULL);
	assert(tip != NULL);

	if (tcp->ts_action == TESLA_ACTION_DTRACE) {
		tesla_assert_fail_dtrace(tcp, tip, transp);
		return;
	}

	print_failure_header(tcp);

	char buffer[ERROR_BUFFER_LENGTH];
	char *next = buffer;
	const char *end = buffer + sizeof(buffer);

	SAFE_SPRINTF(next, end,
		"Instance %td is in state %d\n"
		"but required to take a transition in ",
		(tip - tcp->ts_table->tt_instances), tip->ti_state);
	assert(next > buffer);

	next = sprint_transitions(next, end, transp);

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		assert(0 && "handled above");
		return;

	case TESLA_ACTION_FAILSTOP:
		tesla_panic("%s", buffer);
		break;

	case TESLA_ACTION_PRINTF:
		error("%s", buffer);
		break;
	}
}

void
tesla_notify_match_fail(struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{
	assert(tcp != NULL);
	assert(tkp != NULL);

	if (tcp->ts_action == TESLA_ACTION_DTRACE) {
		tesla_assert_fail_dtrace(tcp, NULL, NULL);
		return;
	}

	print_failure_header(tcp);

	char buffer[ERROR_BUFFER_LENGTH];
	char *next = buffer;
	const char *end = buffer + sizeof(buffer);

	SAFE_SPRINTF(next, end, "No instance matched key '");
	next = key_string(next, end, tkp);
	SAFE_SPRINTF(next, end, "' for transition(s) ");
	next = sprint_transitions(next, end, transp);

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		assert(0 && "handled above");
		break;

	case TESLA_ACTION_FAILSTOP:
		tesla_panic("%s", buffer);
		break;

	case TESLA_ACTION_PRINTF:
		error("%s", buffer);
		break;
	}
}

void
tesla_notify_pass(struct tesla_class *tcp, struct tesla_instance *tip)
{

	switch (tcp->ts_action) {
	case TESLA_ACTION_DTRACE:
		tesla_assert_pass_dtrace(tcp, tip);
		return;

	default:
		VERBOSE_PRINT("pass '%s': %td\n", tcp->ts_name,
		    tip - tcp->ts_table->tt_instances);
		break;
	}
}


static void
print_failure_header(const struct tesla_class *tcp)
{

	error("\n\nTESLA failure:\n");
#if defined(_KERNEL) && defined(KDB)
	kdb_backtrace();
#endif

	error("In automaton '%s':\n%s\n", tcp->ts_name, tcp->ts_description);
}

