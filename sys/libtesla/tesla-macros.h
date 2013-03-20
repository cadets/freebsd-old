/** @file tesla-macros.h    Macros to prettify TESLA names. */
/*
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
 */

#ifndef	TESLA_MACROS_H
#define	TESLA_MACROS_H

#ifdef _KERNEL
#include <libtesla/tesla.h>
#else
#include <limits.h>
#include <tesla.h>
#endif

/*
 * Macros to make TESLA assertions a little easier to read.
 */

/** An assertion made within the execution of a particular function. */
#define	TESLA_WITHIN(function, expression)				\
	TESLA_PERTHREAD(						\
		callee(called(function)),				\
		callee(returned(function)),				\
		expression						\
	)

/** An inline assertion. */
#define	TESLA_ASSERT(locality, start, end, predicate)			\
	__tesla_inline_assertion(					\
		__FILE__, __LINE__, __COUNTER__,			\
		locality, start, end, predicate				\
	)

/** An assertion in the global TESLA context. */
#define	TESLA_GLOBAL(...)	TESLA_ASSERT(__tesla_global, __VA_ARGS__)

/** An assertion in a thread's TESLA context. */
#define	TESLA_PERTHREAD(...)	TESLA_ASSERT(__tesla_perthread, __VA_ARGS__)

/** A strictly-ordered sequence of events. */
#define	TSEQUENCE(...)	__tesla_sequence(__tesla_ignore, __VA_ARGS__)

#define	called(...)	__tesla_call(__VA_ARGS__)
#define	returned(...)	__tesla_return(__VA_ARGS__)

#define	callee(...)	__tesla_callee(__tesla_ignore, __VA_ARGS__)
#define	caller(...)	__tesla_caller(__tesla_ignore, __VA_ARGS__)

#define	TESLA_NOW __tesla_now


#define	TESLA_STRUCT_AUTOMATON(fn_name)	__tesla_struct_automaton(fn_name)

#define automaton(name, ...)    __tesla_automaton(name, __VA_ARGS__)

#define	done return (__tesla_automaton_done())

#define	optional(...)	__tesla_optional(__tesla_ignore, __VA_ARGS__)
#define	ANY_REP	INT_MAX
#define	REPEAT(m, n, ...)	__tesla_repeat(m, n, __VA_ARGS__)
#define	UPTO(n, ...)		__tesla_repeat(0, n, __VA_ARGS__)
#define	ATLEAST(n, ...)		__tesla_repeat(n, ANY_REP, __VA_ARGS__)
#define	ANY(int_type)		__tesla_any(int_type)

/** A more programmer-friendly way to write assertions about the past. */
#define previously(x)    TSEQUENCE(x, TESLA_NOW)

/** A more programmer-friendly way to write assertions about the future. */
#define eventually(x)    TSEQUENCE(TESLA_NOW, x)

#ifdef _KERNEL

#define	TESLA_SYSCALL(x)	TESLA_PERTHREAD(			\
				    callee(returned(syscall_thread_enter)), \
				    callee(called(syscall_thread_exit)), \
				    x)

#endif

#endif	/* !TESLA_MACROS_H */


