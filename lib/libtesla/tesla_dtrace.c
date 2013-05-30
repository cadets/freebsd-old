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
SDT_PROBE_DEFINE2(tesla, kernel, , state_transition, state-transition,
    "struct tesla_class *", "struct tesla_instance *");
SDT_PROBE_DEFINE2(tesla, kernel, assert, fail, fail, "struct tesla_class *",
    "struct tesla_instance *");
SDT_PROBE_DEFINE2(tesla, kernel, assert, pass, pass, "struct tesla_class *",
    "struct tesla_instance *");

void
tesla_state_transition_dtrace(struct tesla_class *tcp,
    struct tesla_instance *tip,
    __unused const struct tesla_transition *transp)
{

	SDT_PROBE(tesla, kernel, , state_transition, tcp, tip, 0, 0, 0);
}

void
tesla_assert_fail_dtrace(struct tesla_class *tcp, struct tesla_instance *tip,
    __unused const struct tesla_transitions *transp)
{

	if (tip)
	    SDT_PROBE(tesla, kernel, assert, fail, tcp, tip, 0, 0, 0);

	/* XXXRW:
	 * 'tip' could be NULL if we failed to match any automaton instances
	 * to go with a supplied key; perhaps a separate probe?
	 */
}

void
tesla_assert_pass_dtrace(struct tesla_class *tcp, struct tesla_instance *tip)
{

	SDT_PROBE(tesla, kernel, assert, pass, tcp, tip, 0, 0, 0);
}

#else /* !_KERNEL */

void
tesla_state_transition_dtrace(__unused struct tesla_class *tcp,
    __unused struct tesla_instance *tip,
    __unused const struct tesla_transition *transp)
{

	assert(0 && "DTrace not implemented in userspace");
}

void
tesla_assert_fail_dtrace(__unused struct tesla_class *tcp,
    __unused struct tesla_instance *tip,
    __unused const struct tesla_transitions *transp)
{

	assert(0 && "DTrace not implemented in userspace");
}

void
tesla_assert_pass_dtrace(__unused struct tesla_class *tcp,
    __unused struct tesla_instance *tip)
{

	assert(0 && "DTrace not implemented in userspace");
}

#endif /* _KERNEL */

