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

#ifndef NDEBUG
int have_transitions = 1;
#else
int have_transitions = 0;
#endif

/**
 * The currently-active event handlers.
 */
static struct tesla_event_metahandler *event_handlers;


/** Perform sanity checks on an event handling vector. */
static int
check_event_handler(const struct tesla_event_handlers *tehp)
{

	if (!tehp || !tehp->teh_sunrise || !tehp->teh_sunset
	    || !tehp->teh_init || !tehp->teh_transition
	    || !tehp->teh_clone || !tehp->teh_fail_no_instance
	    || !tehp->teh_bad_transition || !tehp->teh_err
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
	have_transitions = (tehp->teh_transition != 0);

	singleton[0] = tehp;
	event_handlers = &singleton_handler;

	return (TESLA_SUCCESS);
}

int
tesla_set_event_handlers(struct tesla_event_metahandler *temp)
{
	int error = TESLA_SUCCESS;
	int will_have_transitions = 0;

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
		if (temp->tem_handlers[i]->teh_transition)
			will_have_transitions = 1;
	}

	have_transitions = will_have_transitions;
	event_handlers = temp;
	return (TESLA_SUCCESS);
}


/*
 * generic event handlers:
 */
#define	FOREACH_ERROR_HANDLER(x, ...) \
	for (uint32_t i = 0; i < event_handlers->tem_length; i++) \
		if (event_handlers->tem_mask & (1 << i)) \
			if (event_handlers->tem_handlers[i]->x) \
				event_handlers->tem_handlers[i]->x(__VA_ARGS__)

void
ev_sunrise(enum tesla_context c, const struct tesla_lifetime *tl)
{

	FOREACH_ERROR_HANDLER(teh_sunrise, c, tl);
}


void
ev_sunset(enum tesla_context c, const struct tesla_lifetime *tl)
{

	FOREACH_ERROR_HANDLER(teh_sunset, c, tl);
}


void
ev_new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	FOREACH_ERROR_HANDLER(teh_init, tcp, tip);
}

void
ev_transition(struct tesla_class *tcp, struct tesla_instance *tip,
	const struct tesla_transition *ttp)
{

	FOREACH_ERROR_HANDLER(teh_transition, tcp, tip, ttp);
}

void
ev_clone(struct tesla_class *tcp, struct tesla_instance *orig,
	struct tesla_instance *copy, const struct tesla_transition *ttp)
{

	FOREACH_ERROR_HANDLER(teh_clone, tcp, orig, copy, ttp);
}

void
ev_no_instance(struct tesla_class *tcp, int32_t symbol,
	const struct tesla_key *tkp)
{

	FOREACH_ERROR_HANDLER(teh_fail_no_instance, tcp, symbol, tkp);
}

void
ev_bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
	int32_t symbol)
{

	FOREACH_ERROR_HANDLER(teh_bad_transition, tcp, tip, symbol);
}

void
ev_err(const struct tesla_automaton *a, int symbol, int errnum,
	const char *message)
{

	FOREACH_ERROR_HANDLER(teh_err, a, symbol, errnum, message);
}

void
ev_accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	FOREACH_ERROR_HANDLER(teh_accept, tcp, tip);
}

void
ev_ignored(const struct tesla_class *tcp, int32_t symbol,
	const struct tesla_key *tkp)
{

	FOREACH_ERROR_HANDLER(teh_ignored, tcp, symbol, tkp);
}


#ifndef NDEBUG
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

	error("In automaton '%s':\n%s\n",
	      tcp->tc_automaton->ta_name,
	      tcp->tc_automaton->ta_description);
}

static void
print_sunrise(enum tesla_context c, const struct tesla_lifetime *tl)
{

    DEBUG(libtesla.sunrise, "sunrise  %s %s\n",
	    (c == TESLA_CONTEXT_GLOBAL) ? "global" : "per-thread", tl->tl_repr);
}

static void
print_sunset(enum tesla_context c, const struct tesla_lifetime *tl)
{

    DEBUG(libtesla.sunset, "sunset   %s %s\n",
	    (c == TESLA_CONTEXT_GLOBAL) ? "global" : "per-thread", tl->tl_repr);
}

static void
print_new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.new, "new    %td: %d:0x%x ('%s')\n",
		tip - tcp->tc_instances, tip->ti_state, tip->ti_key.tk_mask,
		tcp->tc_automaton->ta_name);
}

static void
print_transition_taken(struct tesla_class *tcp,
    struct tesla_instance *tip, const struct tesla_transition *transp)
{

	DEBUG(libtesla.state.transition, "update %td: %d:0x%x->%d:0x%x\n",
		tip - tcp->tc_instances,
		transp->from, transp->from_mask,
		transp->to, transp->to_mask);
}

static void
print_clone(struct tesla_class *tcp,
    struct tesla_instance *old_instance, struct tesla_instance *new_instance,
    const struct tesla_transition *transp)
{

	DEBUG(libtesla.instance.clone, "clone  %td:%d:0x%x -> %td:%d:0x%x\n",
		old_instance - tcp->tc_instances,
		transp->from, transp->from_mask,
		new_instance - tcp->tc_instances,
		transp->to, transp->to_mask);
}

static void
print_no_instance(struct tesla_class *tcp, int32_t symbol,
    const struct tesla_key *tkp)
{

	assert(tcp != NULL);
	assert(tkp != NULL);

	const tesla_transitions *transp =
		tcp->tc_automaton->ta_transitions + symbol;

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
    int32_t symbol)
{

	assert(tcp != NULL);
	assert(tip != NULL);

	const tesla_automaton *autom = tcp->tc_automaton;
	const tesla_transitions *transp = autom->ta_transitions + symbol;

	print_failure_header(tcp);

	char buffer[ERROR_BUFFER_LENGTH];
	const char *end = buffer + sizeof(buffer);
	char *next = buffer;

	SAFE_SPRINTF(next, end,
		"Instance %td is in state %d\n"
		"but received event '%s'\n"
		"(causes transition in: ",
		(tip - tcp->tc_instances), tip->ti_state,
		autom->ta_symbol_names[symbol]);
	assert(next > buffer);

	next = sprint_transitions(next, end, transp);
	assert(next > buffer);

	SAFE_SPRINTF(next, end, ")\n");
	assert(next > buffer);

	error("%s", buffer);
}

static void
print_error(const struct tesla_automaton *a, int symbol, int errnum,
	const char *message)
{

	DEBUG(libtesla.event, "%s in '%s' %s: %s\n",
		message, a->ta_name, a->ta_symbol_names[symbol],
		tesla_strerror(errnum));
}

static void
print_accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	DEBUG(libtesla.instance.success,
		"pass '%s': %td\n", tcp->tc_automaton->ta_name,
		tip - tcp->tc_instances);
}

static void
print_ignored(const struct tesla_class *tcp, int32_t symbol,
    __unused const struct tesla_key *tkp)
{
	const struct tesla_automaton *a = tcp->tc_automaton;

	DEBUG(libtesla.event, "ignore '%s': %s\n", a->ta_name,
		a->ta_symbol_names[symbol]);
}

static const struct tesla_event_handlers printf_handlers = {
	.teh_sunrise		= print_sunrise,
	.teh_sunset		= print_sunset,
	.teh_init		= print_new_instance,
	.teh_transition		= print_transition_taken,
	.teh_clone		= print_clone,
	.teh_fail_no_instance	= print_no_instance,
	.teh_bad_transition	= print_bad_transition,
	.teh_err		= print_error,
	.teh_accept		= print_accept,
	.teh_ignored		= print_ignored,
};

static const struct tesla_event_handlers printf_on_failure = {
	.teh_sunrise		= 0,
	.teh_sunset		= 0,
	.teh_init		= 0,
	.teh_transition		= 0,
	.teh_clone		= 0,
	.teh_fail_no_instance	= print_no_instance,
	.teh_bad_transition	= print_bad_transition,
	.teh_err		= print_error,
	.teh_accept		= 0,
	.teh_ignored		= 0,
};
#endif

/*
 * Wrappers that panic on failure:
 */
static void
panic_no_instance(struct tesla_class *tcp, int32_t symbol,
	__unused const struct tesla_key *tkp)
{
	const char *event_name = tcp->tc_automaton->ta_symbol_names[symbol];

	tesla_panic("TESLA: failure in '%s' %s: no such instance",
	            tcp->tc_automaton->ta_name, event_name);
}

static void
panic_bad_transition(struct tesla_class *tcp,
	__unused struct tesla_instance *tip, int32_t symbol)
{
	const char *event_name = tcp->tc_automaton->ta_symbol_names[symbol];

	tesla_panic("TESLA: failure in '%s' %s: bad transition",
	            tcp->tc_automaton->ta_name, event_name);
}

static void
panic_error(const struct tesla_automaton *a, int symbol, int errnum,
	const char *message)
{

	tesla_panic("TESLA: %s in '%s' %s: %s", message,
		a->ta_name, a->ta_symbol_names[symbol],
		tesla_strerror(errnum));
}

static const struct tesla_event_handlers failstop_handlers = {
	.teh_init		= 0,
	.teh_transition		= 0,
	.teh_clone		= 0,
	.teh_fail_no_instance	= panic_no_instance,
	.teh_bad_transition	= panic_bad_transition,
	.teh_err		= panic_error,
	.teh_accept		= 0,
	.teh_ignored		= 0,
};


/**
 * Default event handlers: printf first (but disable in kernel), then
 * either use DTrace or fail-stop if DTrace is not available.
 */
const static struct tesla_event_handlers* const default_handlers[] = {
#ifndef NDEBUG
	&printf_handlers,
	&printf_on_failure,
#endif
#if defined(_KERNEL) && defined(KDTRACE_HOOKS)
	&dtrace_handlers,
#endif
	&failstop_handlers,
};

static struct tesla_event_metahandler default_event_handlers = {
	.tem_length = sizeof(default_handlers) / sizeof(*default_handlers),
#if defined(_KERNEL) && defined(KDTRACE_HOOKS)
	.tem_mask = TESLA_KERN_DTRACE_EV,
#else
	.tem_mask = 0xFF,
#endif
	.tem_handlers = default_handlers,
};

#ifdef _KERNEL
#include <sys/sysctl.h>

SYSCTL_NODE(, OID_AUTO, tesla, CTLFLAG_RW, 0, "TESLA");
SYSCTL_NODE(_tesla, OID_AUTO, events, CTLFLAG_RW, 0, "control of TESLA events");
SYSCTL_UINT(_tesla_events, OID_AUTO, handlers, CTLFLAG_RW,
	   &default_event_handlers.tem_mask, 0,
	   "Mask of currently-enabled TESLA event handlers");
#endif

static struct tesla_event_metahandler *event_handlers = &default_event_handlers;
