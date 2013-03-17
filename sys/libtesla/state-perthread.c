/*-
 * Copyright (c) 2011 Robert N. M. Watson
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

/*
 * Routines for managing TESLA per-thread state, used in per-thread automata.
 * Kernel and userspace implementations differ quite a lot, due to very
 * different guarantees for kernel per-thread storage and pthread
 * thread-specific state.  For example, the kernel implementation guarantees
 * that space will be available if the initial tesla_class allocation
 * succeedes, and instruments thread create and destroy to ensure this is the
 * case.  However, it has to do a lot more book-keeping, and allocates space
 * that might never be used.  In userspace, per-thread state is allocated the
 * first time TESLA sees the thread, but malloc may fail, meaning that TESLA
 * has to handle the possibility of not finding the state it needs.
 */

#ifdef _KERNEL

/*
 * Registration state for per-thread storage.
 */
static eventhandler_tag	tesla_perthread_ctor_tag;
static eventhandler_tag	tesla_perthread_dtor_tag;

static void
tesla_perthread_ctor(__unused void *arg, struct thread *td)
{
	struct tesla_store *store;
	uint32_t error;

	store = tesla_malloc(sizeof(*store));
	error = tesla_store_init(store, TESLA_SCOPE_PERTHREAD,
	    TESLA_MAX_CLASSES, TESLA_MAX_INSTANCES);
	tesla_assert(error == TESLA_SUCCESS, ("tesla_store_init failed"));
	td->td_tesla = store;
}

static void
tesla_perthread_dtor(struct thread *td)
{
	struct tesla_store *store;

	store = td->td_tesla;
	td->td_tesla = NULL;
	tesla_store_free(store);
	tesla_free(store);
}

static void
tesla_perthread_sysinit(__unused void *arg)
{

	tesla_perthread_ctor_tag = EVENTHANDLER_REGISTER(thread_ctor,
	    tesla_perthread_ctor, NULL, EVENTHANDLER_PRI_ANY);
	tesla_perthread_dtor_tag = EVENTHANDLER_REGISTER(thread_dtor,
	    tesla_perthread_dtor, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(tesla_perthread, SI_SUB_TESLA, SI_ORDER_FIRST,
    tesla_perthread_sysinit, NULL);

#endif /* !_KERNEL */

int
tesla_class_perthread_postinit(__unused struct tesla_class *c)
{
	return 0;
}

void
tesla_class_perthread_acquire(__unused struct tesla_class *c)
{
}

void
tesla_class_perthread_release(__unused struct tesla_class *c)
{
}

void
tesla_class_perthread_destroy(__unused struct tesla_class *c)
{
}
