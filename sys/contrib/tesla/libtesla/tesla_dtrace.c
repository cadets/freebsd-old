/*-
 * Copyright (c) 2013 Robert N. M. Watson
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

#ifdef _KERNEL
#include "opt_kdtrace.h"
#include <sys/sdt.h>

SDT_PROVIDER_DEFINE(tesla);

SDT_PROBE_DEFINE2(tesla, automata, instance, create, create,
    "struct tesla_class *", "struct tesla_instance *");
SDT_PROBE_DEFINE3(tesla, automata, event, transition, state-transition,
    "struct tesla_class *", "struct tesla_instance *",
    "struct tesla_transition *");
SDT_PROBE_DEFINE4(tesla, automata, instance, clone, clone,
    "struct tesla_class *", "struct tesla_instance *",
    "struct tesla_instance *", "struct tesla_transition *");
SDT_PROBE_DEFINE3(tesla, automata, fail, no_instance, no-instance-match,
    "struct tesla_class *", "struct tesla_key *",
    "struct tesla_transitions *");
SDT_PROBE_DEFINE3(tesla, automata, fail, bad_transition, bad-transition,
    "struct tesla_class *", "struct tesla_instance *",
    "struct tesla_transitions *");
SDT_PROBE_DEFINE3(tesla, automata, fail, other_err, other-error,
    "struct tesla_class *", "int", "const char *");
SDT_PROBE_DEFINE2(tesla, automata, success, accept, accept,
    "struct tesla_class *", "struct tesla_instance *");
SDT_PROBE_DEFINE3(tesla, automata, event, ignored, ignored-event,
    "struct tesla_class *", "struct tesla_key *",
    "struct tesla_transitions *");

static void
new_instance(struct tesla_class *tcp, struct tesla_instance *tip)
{

	SDT_PROBE(tesla, automata, instance, create, tcp, tip, 0, 0, 0);
}

static void
transition(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transition *ttp)
{

	SDT_PROBE(tesla, automata, event, transition, tcp, tip, ttp, 0, 0);
}

static void
clone(struct tesla_class *tcp, struct tesla_instance *origp,
    struct tesla_instance *copyp, const struct tesla_transition *ttp)
{

	SDT_PROBE(tesla, automata, instance, clone, tcp, origp, copyp, ttp, 0);
}

static void
no_instance(struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *ttp)
{

	SDT_PROBE(tesla, automata, fail, no_instance, tcp, tkp, ttp, 0, 0);
}

static void
bad_transition(struct tesla_class *tcp, struct tesla_instance *tip,
    const struct tesla_transitions *ttp)
{

	SDT_PROBE(tesla, automata, fail, bad_transition, tcp, tip, ttp, 0, 0);
}

static void
err(struct tesla_class *tcp, int errno, const char *message)
{

	SDT_PROBE(tesla, automata, fail, other_err, tcp, errno, message, 0, 0);
}

static void
accept(struct tesla_class *tcp, struct tesla_instance *tip)
{

	SDT_PROBE(tesla, automata, success, accept, tcp, tip, 0, 0, 0);
}

static void
ignored(const struct tesla_class *tcp, const struct tesla_key *tkp,
    const struct tesla_transitions *ttp)
{

	SDT_PROBE(tesla, automata, event, ignored, tcp, tkp, ttp, 0, 0);
}

const struct tesla_event_handlers dtrace_handlers = {
	.teh_init			= new_instance,
	.teh_transition			= transition,
	.teh_clone			= clone,
	.teh_fail_no_instance		= no_instance,
	.teh_bad_transition		= bad_transition,
	.teh_err			= err,
	.teh_accept			= accept,
	.teh_ignored			= ignored,
};

#endif /* _KERNEL */
