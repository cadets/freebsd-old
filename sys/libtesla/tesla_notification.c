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

int
tesla_set_event_handlers(struct tesla_event_handlers *tehp)
{

	if (!tehp || !tehp->teh_init || !tehp->teh_transition
	    || !tehp->teh_clone || !tehp->teh_fail_no_instance
	    || !tehp->teh_bad_transition
	    || !tehp->teh_accept)
		return (TESLA_ERROR_EINVAL);

	ev_handlers = tehp;
	return (TESLA_SUCCESS);
}

/*
 * printf()-based event handlers:
 */
static void	print_new_instance(struct tesla_class *,
	    struct tesla_instance *);

static void	print_transition_taken(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transition*);

static void	print_clone(struct tesla_class *,
	    struct tesla_instance *orig, struct tesla_instance *copy,
	    const struct tesla_transition*);

static void	print_no_instance(struct tesla_class *,
	    const struct tesla_key *, const struct tesla_transitions *);

static void	print_bad_transition(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transitions *);

static void	print_accept(struct tesla_class *, struct tesla_instance *);

struct tesla_event_handlers printf_handlers = {
	.teh_init		= print_new_instance,
	.teh_transition		= print_transition_taken,
	.teh_clone		= print_clone,
	.teh_fail_no_instance	= print_no_instance,
	.teh_bad_transition	= print_bad_transition,
	.teh_accept		= print_accept
};


/*
 * Wrappers that panic on failure:
 */
static void	panic_no_instance(struct tesla_class *,
	    const struct tesla_key *, const struct tesla_transitions *);

static void	panic_bad_transition(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transitions *);

struct tesla_event_handlers failstop_handlers = {
	.teh_init		= print_new_instance,
	.teh_transition		= print_transition_taken,
	.teh_clone		= print_clone,
	.teh_fail_no_instance	= panic_no_instance,
	.teh_bad_transition	= panic_bad_transition,
	.teh_accept		= print_accept
};


/** Default to print-with-failstop in userspace, DTrace in the kernel. */
struct tesla_event_handlers	*ev_handlers =
#ifdef _KERNEL
	&dtrace_handlers
#else
	&failstop_handlers
#endif
	;

static void	print_failure_header(const struct tesla_class *);


void
print_new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.new, "new    %td: %tx\n",
		tip - tcp->tc_instances, tip->ti_state);
}

void
print_transition_taken(struct tesla_class *tcp,
    struct tesla_instance *tip, const struct tesla_transition *transp)
{

	DEBUG(libtesla.state.transition, "update %td: %tx->%tx\n",
		tip - tcp->tc_instances, transp->from, transp->to);
}

void
print_clone(struct tesla_class *tcp,
    struct tesla_instance *old_instance, struct tesla_instance *new_instance,
    const struct tesla_transition *transp)
{

	DEBUG(libtesla.instance.clone, "clone  %td:%tx -> %td:%tx\n",
		old_instance - tcp->tc_instances, transp->from,
		new_instance - tcp->tc_instances, transp->to);
}

static void
no_instance_message(char *buffer, const char *end,
    struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{

	assert(tcp != NULL);
	assert(tkp != NULL);

	print_failure_header(tcp);

	char *next = buffer;

	SAFE_SPRINTF(next, end, "No instance matched key '");
	next = key_string(next, end, tkp);
	SAFE_SPRINTF(next, end, "' for transition(s) ");
	next = sprint_transitions(next, end, transp);
	assert(next > buffer);
}

void
print_no_instance(struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);

	no_instance_message(buffer, end, tcp, tkp, transp);
	error("%s", buffer);
}

void
panic_no_instance(struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);

	no_instance_message(buffer, end, tcp, tkp, transp);
	tesla_panic("%s", buffer);
}

static void
bad_transition_message(char *buffer, const char *end,
    struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp)
{

	assert(tcp != NULL);
	assert(tip != NULL);

	print_failure_header(tcp);

	char *next = buffer;

	SAFE_SPRINTF(next, end,
		"Instance %td is in state %d\n"
		"but required to take a transition in ",
		(tip - tcp->tc_instances), tip->ti_state);
	assert(next > buffer);

	next = sprint_transitions(next, end, transp);
	assert(next > buffer);
}

void
print_bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp)
{

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);

	bad_transition_message(buffer, end, tcp, tip, transp);
	error("%s", buffer);
}

void
panic_bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp)
{

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);

	bad_transition_message(buffer, end, tcp, tip, transp);
	tesla_panic("%s", buffer);
}

void
print_accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.success,
		"pass '%s': %td\n", tcp->tc_name,
		tip - tcp->tc_instances);
}


static void
print_failure_header(const struct tesla_class *tcp)
{

	error("\n\nTESLA failure:\n");
#if defined(_KERNEL) && defined(KDB)
	kdb_backtrace();
#endif

	error("In automaton '%s':\n%s\n", tcp->tc_name, tcp->tc_description);
}
