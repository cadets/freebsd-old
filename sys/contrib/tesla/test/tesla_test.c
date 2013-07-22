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

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <sys/tesla-kernel.h>

/*
 * Set of simple test sysctls that should trigger (or not) TESLA failures.
 */

SYSCTL_NODE(_debug, OID_AUTO, tesla, CTLFLAG_RW, 0, "TESLA test sysctl nodes");

static int debug_tesla_func_counter;

/*
 * To avoid a no-op function.
 */
static void __noinline
debug_tesla_func(void)
{

	debug_tesla_func_counter++;
}

static int
debug_tesla_eventually_pass(SYSCTL_HANDLER_ARGS)
{
	int error;

	TESLA_SYSCALL(eventually(called(debug_tesla_func())));
	error = sysctl_handle_int(oidp, &debug_tesla_func_counter, 0, req);
	if (error)
		return (error);

	debug_tesla_func();
	return (0);
}

SYSCTL_PROC(_debug_tesla, OID_AUTO, eventually_pass, CTLTYPE_INT | CTLFLAG_RD,
    0, 0, debug_tesla_eventually_pass, "I",
    "TESLA eventually assertion that passes");

static int
debug_tesla_eventually_fail(SYSCTL_HANDLER_ARGS)
{
	int error;

	TESLA_SYSCALL(eventually(called(debug_tesla_func())));
	error = sysctl_handle_int(oidp, &debug_tesla_func_counter, 0, req);
	if (error)
		return (error);

	return (0);
}

SYSCTL_PROC(_debug_tesla, OID_AUTO, eventually_fail, CTLTYPE_INT | CTLFLAG_RD,
    0, 0, debug_tesla_eventually_fail, "I",
    "TESLA eventually assertion that fails");

static int
debug_tesla_previously_pass(SYSCTL_HANDLER_ARGS)
{
	int error;

	debug_tesla_func();
	error = sysctl_handle_int(oidp, &debug_tesla_func_counter, 0, req);
	if (error)
		return (error);

	TESLA_SYSCALL(previously(called(debug_tesla_func())));
	return (0);
}

SYSCTL_PROC(_debug_tesla, OID_AUTO, previously_pass, CTLTYPE_INT | CTLFLAG_RD,
    0, 0, debug_tesla_previously_pass, "I",
    "TESLA previously assertion that passes");

static int
debug_tesla_previously_fail(SYSCTL_HANDLER_ARGS)
{
	int error;

	error = sysctl_handle_int(oidp, &debug_tesla_func_counter, 0, req);
	if (error)
		return (error);

	TESLA_SYSCALL(previously(called(debug_tesla_func())));
	return (0);
}

SYSCTL_PROC(_debug_tesla, OID_AUTO, previously_fail, CTLTYPE_INT | CTLFLAG_RD,
    0, 0, debug_tesla_previously_fail, "I",
    "TESLA previous assertion that fails");
