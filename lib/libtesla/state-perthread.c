/*-
 * Copyright (c) 2011 Robert N. M. Watson
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
 * Global state used to manage per-thread storage slots for TESLA per-thread
 * assertions.  tspd_tesla_classp is non-NULL when a slot has been allocated.
 */
static struct tesla_class_perthread_desc {
	struct tesla_class	*tspd_tesla_classp;
	size_t			 tspd_len;
} tesla_class_perthread_desc[TESLA_PERTHREAD_MAX];
static struct sx tesla_class_perthread_sx;

/*
 * Registration state for per-thread storage.
 */
static eventhandler_tag	tesla_class_perthread_ctor_tag;
static eventhandler_tag	tesla_class_perthread_dtor_tag;

static void
tesla_class_perthread_ctor(__unused void *arg, struct thread *td)
{
	struct tesla_class_perthread_desc *tspdp;
	struct tesla_class *tsp;
	struct tesla_table *ttp;
	u_int index;

	sx_slock(&tesla_class_perthread_sx);
	for (index = 0; index < TESLA_PERTHREAD_MAX; index++) {
		tspdp = &tesla_class_perthread_desc[index];
		tsp = tspdp->tspd_tesla_classp;
		if (tsp == NULL) {
			td->td_tesla[index] = NULL;
			continue;
		}
		ttp = malloc(tspdp->tspd_len, M_TESLA, M_WAITOK | M_ZERO);
		ttp->tt_length = tsp->ts_limit;
		ttp->tt_free = tsp->ts_limit;
		td->td_tesla[index] = ttp;
	}
	sx_sunlock(&tesla_class_perthread_sx);
}

static void
tesla_class_perthread_dtor_locked(struct thread *td)
{
	u_int index;

	sx_assert(&tesla_class_perthread_sx, SX_LOCKED);
	for (index = 0; index < TESLA_PERTHREAD_MAX; index++) {
		if (td->td_tesla[index] == NULL)
			continue;
		free(M_TESLA, td->td_tesla[index]);
		td->td_tesla[index] = NULL;
	}
}

static void
tesla_class_perthread_dtor(__unused void *arg, struct thread *td)
{

	sx_slock(&tesla_class_perthread_sx);
	tesla_class_perthread_dtor_locked(td);
	sx_sunlock(&tesla_class_perthread_sx);
}

static void
tesla_class_perthread_sysinit(__unused void *arg)
{

	sx_init(&tesla_class_perthread_sx, "tesla_class_perthread_sx");
	tesla_class_perthread_ctor_tag = EVENTHANDLER_REGISTER(thread_ctor,
	    tesla_class_perthread_ctor, NULL, EVENTHANDLER_PRI_ANY);
	tesla_class_perthread_dtor_tag = EVENTHANDLER_REGISTER(thread_dtor,
	    tesla_class_perthread_dtor, NULL, EVENTHANDLER_PRI_ANY);
}
SYSINIT(tesla_class_perthread, SI_SUB_TESLA, SI_ORDER_FIRST,
    tesla_class_perthread_sysinit, NULL);

static void
tesla_class_perthread_sysuninit(__unused void *arg)
{
	struct proc *p;
	struct thread *td;

	/*
	 * XXXRW: Possibility of a race for in-flight handlers and
	 * instrumentation?
	 */
	EVENTHANDLER_DEREGISTER(tesla_class_perthread_ctor,
	    tesla_class_perthread_ctor_tag);
	EVENTHANDLER_DEREGISTER(tesla_class_perthread_dtor,
	    tesla_class_perthread_dtor_tag);

	sx_xlock(&allproc_lock);
	sx_xlock(&tesla_class_perthread_sx);
	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);
		FOREACH_THREAD_IN_PROC(p, td) {
			tesla_class_perthread_dtor_locked(td);
		}
		PROC_UNLOCK(p);
	}
	sx_xunlock(&tesla_class_perthread_sx);
	sx_xunlock(&allproc_lock);
	sx_destroy(&tesla_class_perthread_sx);
}
SYSUNINIT(tesla_class_perthread, SI_SUB_TESLA, SI_ORDER_FIRST,
    tesla_class_perthread_sysuninit, NULL);

int
tesla_class_perthread_new(struct tesla_class *tsp)
{
	struct tesla_class_perthread_desc *tspdp;
	struct tesla_table *ttp;
	struct proc *p;
	struct thread *td;
	int looped;
	u_int index;

	/*
	 * First, allocate a TESLA per-thread storage slot, if available.
	 */
	tspdp = NULL;
	sx_xlock(&tesla_class_perthread_sx);
	for (index = 0; index < TESLA_PERTHREAD_MAX; index++) {
		if (tesla_class_perthread_desc[index].tspd_tesla_classp
		    == NULL) {
			tspdp = &tesla_class_perthread_desc[index];
			break;
		}
	}
	if (tspdp == NULL) {
		sx_xunlock(&tesla_class_perthread_sx);
		return (TESLA_ERROR_ENOMEM);
	}
	tsp->ts_perthread_index = index;
	tspdp->tspd_tesla_classp = tsp;
	tspdp->tspd_len = sizeof(*ttp) + sizeof(struct tesla_instance) *
	    tsp->ts_limit;

	/*
	 * Walk all existing threads and add required allocations.  If we
	 * can't allocate under the process lock, we have to loop out, use
	 * M_WAITOK, and then repeat.  This looks starvation-prone, but
	 * actually isn't: holding tesla_class_perthread_sx blocks further
	 * thread allocations from taking place, so the main concern is
	 * in-progress allocations, which will be bounded in number.
	 */
	ttp = NULL;
	looped = 0;
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
loop:
		if (looped) {
			KASSERT(ttp == NULL,
			    ("tesla_class_perthread_new: ttp not NULL"));
			ttp = malloc(tspdp->tspd_len, M_TESLA,
			    M_WAITOK | M_ZERO);
			looped = 0;
		}
		PROC_LOCK(p);
		FOREACH_THREAD_IN_PROC(p, td) {
			/*
			 * If we looped, then some threads may already have
			 * memory; skip them.
			 */
			if (td->td_tesla[index] != NULL)
				continue;
			if (ttp == NULL)
				ttp = malloc(tspdp->tspd_len, M_TESLA,
				    M_NOWAIT | M_ZERO);
			if (ttp == NULL) {
				PROC_UNLOCK(p);
				looped = 1;
				goto loop;
			}
			ttp->tt_length = tsp->ts_limit;
			ttp->tt_free = tsp->ts_limit;
			td->td_tesla[index] = ttp;
			ttp = NULL;
		}
		PROC_UNLOCK(p);
	}
	sx_sunlock(&allproc_lock);
	/* Due to races, we may have allocated an extra, so free it now. */
	if (ttp != NULL)
		free(ttp, M_TESLA);
	sx_xunlock(&tesla_class_perthread_sx);
	return (TESLA_SUCCESS);
}

void
tesla_class_perthread_destroy(struct tesla_class *tsp)
{
	struct tesla_class_perthread_desc *tspdp;
	struct proc *p;
	struct thread *td;
	u_int index;

	sx_xlock(&tesla_class_perthread_sx);
	index = tsp->ts_perthread_index;
	tspdp = &tesla_class_perthread_desc[index];

	/*
	 * First, walk all threads and release resources.  This is easier on
	 * free than alloc due to the non-blocking nature of free.
	 *
	 * XXXRW: Do we need a test for td->td_tesla[index] == NULL and a
	 * continue?  I think probably not.
	 */
	sx_slock(&allproc_lock);
	FOREACH_PROC_IN_SYSTEM(p) {
		PROC_LOCK(p);
		FOREACH_THREAD_IN_PROC(p, td) {
			free(M_TESLA, td->td_tesla[index]);
			td->td_tesla[index] = NULL;
		}
		PROC_UNLOCK(p);
	}
	sx_unlock(&allproc_lock);

	/*
	 * Finally, release the reservation.
	 */
	tspdp->tspd_tesla_classp = NULL;
	tspdp->tspd_len = 0;
	sx_xunlock(&tesla_class_perthread_sx);
}

void
tesla_class_perthread_flush(struct tesla_class *tsp)
{
	struct tesla_table *ttp;

	ttp = curthread->td_tesla[tsp->ts_perthread_index];
	bzero(&ttp->tt_instances,
	    sizeof(struct tesla_instance) * ttp->tt_length);
	ttp->tt_free = ttp->tt_length;
}

int
tesla_class_perthread_gettable(struct tesla_class *tsp,
    struct tesla_table **ttpp)
{
	struct tesla_table *ttp;

	ttp = curthread->td_tesla[tsp->ts_perthread_index];
	KASSERT(ttp != NULL,
	    ("tesla_class_perthread_gettable: NULL tesla thread state"));
	*ttpp = ttp;
	return (TESLA_SUCCESS);
}

#else  /* !_KERNEL */

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

#endif /* _KERNEL */
