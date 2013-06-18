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

/**
 * The currently-active event handlers.
 */
static struct tesla_event_metahandler *event_handlers;


/** Perform sanity checks on an event handling vector. */
static int
check_event_handler(const struct tesla_event_handlers *tehp)
{

	if (!tehp || !tehp->teh_init || !tehp->teh_transition
	    || !tehp->teh_clone || !tehp->teh_fail_no_instance
	    || !tehp->teh_bad_transition
	    || !tehp->teh_accept || !tehp->teh_ignored)
		return (TESLA_ERROR_EINVAL);

	return (TESLA_SUCCESS);
}


int
tesla_set_event_handler(struct tesla_event_handlers *tehp)
{
	int error = check_event_handler(tehp);
	if (error != TESLA_SUCCESS)
		return (error);

	const static struct tesla_event_handlers* singleton[1];
	static struct tesla_event_metahandler singleton_handler = {
		.tem_length = 1,
		.tem_mask = 1,
		.tem_handlers = singleton,
	};

	singleton[0] = tehp;
	event_handlers = &singleton_handler;

	return (TESLA_SUCCESS);
}

int
tesla_set_event_handlers(struct tesla_event_metahandler *temp)
{
	int error = TESLA_SUCCESS;

	if (!temp)
		return (TESLA_ERROR_EINVAL);

	/*
	 * It's ok to disable event handlers dynamically using the bitmask,
	 * but all event handlers passed in must be valid.
	 */
	for (uint32_t i = 0; i < temp->tem_length; i++) {
		error = check_event_handler(temp->tem_handlers[i]);
		if (error != TESLA_SUCCESS)
			return (error);
	}

	event_handlers = temp;
	return (TESLA_SUCCESS);
}


/*
 * generic event handlers:
 */
#define	FOREACH_ERROR_HANDLER() \
	for (uint32_t i = 0; i < event_handlers->tem_length; i++) \
		if (event_handlers->tem_mask & (1 << i)) \
			event_handlers->tem_handlers[i]

static void
ev_noop()
{
}

void
ev_new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	FOREACH_ERROR_HANDLER()->teh_init(tcp, tip);
}

void
ev_transition(struct tesla_class *tcp, struct tesla_instance *tip,
	const struct tesla_transition *ttp)
{

	FOREACH_ERROR_HANDLER()->teh_transition(tcp, tip, ttp);
}

void
ev_clone(struct tesla_class *tcp, struct tesla_instance *orig,
	struct tesla_instance *copy, const struct tesla_transition *ttp)
{

	FOREACH_ERROR_HANDLER()->teh_clone(tcp, orig, copy, ttp);
}

void
ev_no_instance(struct tesla_class *tcp, const struct tesla_key *tkp,
	const struct tesla_transitions *ttp)
{

	FOREACH_ERROR_HANDLER()->teh_fail_no_instance(tcp, tkp, ttp);
}

void
ev_bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
	const struct tesla_transitions *ttp)
{

	FOREACH_ERROR_HANDLER()->teh_bad_transition(tcp, tip, ttp);
}

void
ev_accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	FOREACH_ERROR_HANDLER()->teh_accept(tcp, tip);
}

void
ev_ignored(const struct tesla_class *tcp, const struct tesla_key *tkp,
	const struct tesla_transitions *ttp)
{

	FOREACH_ERROR_HANDLER()->teh_ignored(tcp, tkp, ttp);
}


/*
 * printf()-based event handlers:
 */
static void
print_failure_header(const struct tesla_class *tcp)
{

	error("\n\nTESLA failure:\n");
#if defined(_KERNEL) && defined(KDB)
	kdb_backtrace();
#endif

	error("In automaton '%s':\n%s\n", tcp->tc_name, tcp->tc_description);
}

static void
print_new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.new, "new    %td: %tx\n",
		tip - tcp->tc_instances, tip->ti_state);
}

static void
print_transition_taken(struct tesla_class *tcp,
    struct tesla_instance *tip, const struct tesla_transition *transp)
{

	DEBUG(libtesla.state.transition, "update %td: %tx->%tx\n",
		tip - tcp->tc_instances, transp->from, transp->to);
}

static void
print_clone(struct tesla_class *tcp,
    struct tesla_instance *old_instance, struct tesla_instance *new_instance,
    const struct tesla_transition *transp)
{

	DEBUG(libtesla.instance.clone, "clone  %td:%tx -> %td:%tx\n",
		old_instance - tcp->tc_instances, transp->from,
		new_instance - tcp->tc_instances, transp->to);
}

static void
print_no_instance(struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{

	assert(tcp != NULL);
	assert(tkp != NULL);

	print_failure_header(tcp);

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);
	char *next = buffer;

	SAFE_SPRINTF(next, end, "No instance matched key '");
	next = key_string(next, end, tkp);
	SAFE_SPRINTF(next, end, "' for transition(s) ");
	next = sprint_transitions(next, end, transp);
	assert(next > buffer);

	error("%s", buffer);
}

static void
print_bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *transp)
{

	assert(tcp != NULL);
	assert(tip != NULL);

	print_failure_header(tcp);

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);
	char *next = buffer;

	SAFE_SPRINTF(next, end,
		"Instance %td is in state %d\n"
		"but required to take a transition in ",
		(tip - tcp->tc_instances), tip->ti_state);
	assert(next > buffer);

	next = sprint_transitions(next, end, transp);
	assert(next > buffer);

	error("%s", buffer);
}

static void
print_accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.success,
		"pass '%s': %td\n", tcp->tc_name,
		tip - tcp->tc_instances);
}

static void
print_ignored(const struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *transp)
{
	char buffer[ERROR_BUFFER_LENGTH];
	char *next = buffer;
	const char *end = buffer + sizeof(buffer);

	next = key_string(next, end, tkp);
	SAFE_SPRINTF(next, end, " : ");
	sprint_transitions(next, end, transp);

	DEBUG(libtesla.event, "ignore '%s':%s", tcp->tc_name, buffer);
}

static const struct tesla_event_handlers printf_handlers = {
	.teh_init		= print_new_instance,
	.teh_transition		= print_transition_taken,
	.teh_clone		= print_clone,
	.teh_fail_no_instance	= print_no_instance,
	.teh_bad_transition	= print_bad_transition,
	.teh_accept		= print_accept,
	.teh_ignored		= print_ignored,
};


/*
 * Wrappers that panic on failure:
 */
static void
panic_no_instance(struct tesla_class *tcp,
	__unused const struct tesla_key *tkp,
	__unused const struct tesla_transitions *ttp)
{

	tesla_panic("TESLA: failure in '%s': no such instance", tcp->tc_name);
}

static void
panic_bad_transition(struct tesla_class *tcp,
	__unused struct tesla_instance *tip,
	__unused const struct tesla_transitions *ttp)
{

	tesla_panic("TESLA: failure in '%s': bad transition", tcp->tc_name);
}

static const struct tesla_event_handlers failstop_handlers = {
	.teh_init		= ev_noop,
	.teh_transition		= ev_noop,
	.teh_clone		= ev_noop,
	.teh_fail_no_instance	= panic_no_instance,
	.teh_bad_transition	= panic_bad_transition,
	.teh_accept		= ev_noop,
	.teh_ignored		= ev_noop,
};


/**
 * Default event handlers: always print, then use DTrace in the kernel
 * if it's available; if it isn't, panic on failure.
 */
const static struct tesla_event_handlers* const default_handlers[] = {
	&printf_handlers,
#if defined(_KERNEL) && defined(KDTRACE_HOOKS)
	&dtrace_handlers,
#else
	&failstop_handlers,
#endif
};

static struct tesla_event_metahandler default_event_handlers = {
	.tem_length = sizeof(default_handlers) / sizeof(*default_handlers),
	.tem_mask = 0xFFFF,
	.tem_handlers = default_handlers,
};

static struct tesla_event_metahandler *event_handlers = &default_event_handlers;
