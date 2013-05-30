/*-
 * Copyright (c) 2011, 2013 Robert N. M. Watson
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

#ifndef TESLA_INTERNAL_H
#define	TESLA_INTERNAL_H

#include "config.h"

#ifdef _KERNEL
#include "opt_kdb.h"
#include <sys/param.h>
#include <sys/eventhandler.h>
#include <sys/kdb.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sx.h>
#include <sys/systm.h>

#include <machine/_inttypes.h>

#include <libtesla/libtesla.h>
#else
#include <assert.h>
#include <err.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include <libtesla.h>
#endif

//! Is @ref x a subset of @ref y?
#define	SUBSET(x,y) ((x & y) == x)

/**
 * Call this if things go catastrophically, unrecoverably wrong.
 */
void	tesla_die(const char *event) __attribute__((noreturn));

/**
 * Clean up a @ref tesla_class.
 */
void	tesla_class_destroy(struct tesla_class*);

/**
 * Create a new @ref tesla_instance.
 *
 * The caller is responsible for locking the class if needed.
 */
int32_t	tesla_instance_new(struct tesla_class *tclass,
	    const struct tesla_key *name, uint32_t state,
	    struct tesla_instance **out);

/**
 * Clone an existing @ref tesla_instance within a @ref tesla_class.
 */
int32_t	tesla_clone(struct tesla_class*, const struct tesla_instance *orig,
	    struct tesla_instance **copy);

/**
 * Find all automata instances in a class that match a particular key.
 *
 * The caller is responsible for locking the class if necessary.
 *
 * @param[in]     tclass   the class of automata to match
 * @param[in]     key      must remain valid as long as the iterator is in use
 * @param[out]    array    a caller-allocated array to store matches in
 * @param[in,out] size     in: size of array. out: number of instances.
 *
 * @returns    a standard TESLA error code (e.g., TESLA_ERROR_ENOMEM)
 */
int32_t	tesla_match(struct tesla_class *tclass, const struct tesla_key *key,
	    struct tesla_instance **array, uint32_t *size);

/** Actions that can be taken by @ref tesla_update_state. */
enum tesla_action_t {
	/** The instance's state should be updated. */
	UPDATE,

	/** The instance should be copied to a new instance. */
	FORK,

	/** The instance is irrelevant to the given transitions. */
	IGNORE,

	/** The instance matches, but there are no valid transitions for it. */
	FAIL
};

/**
 * What is the correct action to perform on a given @ref tesla_instance to
 * satisfy a set of @ref tesla_transitions?
 *
 * @param[out]   trigger    the @ref tesla_transition that triggered the action
 */
enum tesla_action_t	tesla_action(const struct tesla_instance*,
	    const struct tesla_key*, const struct tesla_transitions*,
	    const struct tesla_transition** trigger);

/** Copy new entries from @ref source into @ref dest. */
int32_t	tesla_key_union(struct tesla_key *dest, const struct tesla_key *source);


#ifndef __unused
#if __has_attribute(unused)
#define __unused __attribute__((unused))
#else
#define __unused
#endif
#endif

// Kernel vs userspace implementation details.
#ifdef _KERNEL

/** In the kernel, panic really means panic(). */
#define tesla_panic(...) panic(__VA_ARGS__)

/** Our @ref tesla_assert has the same signature as @ref KASSERT. */
#define tesla_assert(...) KASSERT(__VA_ARGS__)

/** Emulate simple POSIX assertions. */
#define assert(cond) KASSERT((cond), ("Assertion failed: '%s'", #cond))

#define tesla_malloc(len) malloc(len, M_TESLA, M_WAITOK | M_ZERO)
#define tesla_free(x) free(x, M_TESLA)

#define tesla_lock(l) mtx_lock(l)
#define tesla_unlock(l) mtx_unlock(l)

#else	/* !_KERNEL */

/** @ref errx() is the userspace equivalent of panic(). */
#define tesla_panic(...) errx(1, __VA_ARGS__)

/** POSIX @ref assert() doesn't let us provide an error message. */
#define tesla_assert(condition, ...) assert(condition)

#define tesla_malloc(len) calloc(1, len)
#define tesla_free(x) free(x)

#define tesla_lock(l) \
	do { __debug int err = pthread_mutex_lock(l); assert(err == 0); } while(0)

#define tesla_unlock(l) \
	do { __debug int err = pthread_mutex_unlock(l); assert(err == 0); } while(0)

#endif


/*
 * Assertion state definition is internal to libtesla so we can change it as
 * we need to.
 */
struct tesla_class {
	const char	*tc_name;	/* Name of the assertion. */
	const char	*tc_description;/* Description of the assertion. */
	uint32_t	 tc_scope;	/* Per-thread or global. */
	uint32_t	 tc_limit;	/* Simultaneous automata limit. */
	uint32_t	 tc_action;	/* What to do on failure. */

	struct tesla_instance	*tc_instances;	/* Instances of this class. */
	uint32_t		tc_free;	/* Unused instances. */

#ifdef _KERNEL
	struct mtx		tc_lock;	/* Synchronise tc_table. */
#else
	pthread_mutex_t		 tc_lock;	/* Synchronise tc_table. */
#endif
};

typedef struct tesla_class		tesla_class;
typedef struct tesla_instance		tesla_instance;
typedef struct tesla_key		tesla_key;
typedef struct tesla_store		tesla_store;
typedef struct tesla_transition		tesla_transition;
typedef struct tesla_transitions	tesla_transitions;


/**
 * @internal Definition of @ref tesla_store.
 *
 * Modifications to this structure should only be made while a lock is held
 * or in a thread-local context.
 */
struct tesla_store {
	uint32_t		length;
	struct tesla_class	*classes;
};

/**
 * Initialise @ref tesla_store internals.
 * Locking is the responsibility of the caller.
 */
int	tesla_store_init(tesla_store*, uint32_t context, uint32_t classes,
		uint32_t instances);

/**
 * Initialize @ref tesla_class internals.
 * Locking is the responsibility of the caller.
 */
int	tesla_class_init(struct tesla_class*, uint32_t context,
		uint32_t instances);

#if 0
//! We have failed to find an instance that matches a @ref tesla_key.
void	tesla_match_fail(struct tesla_class*, const struct tesla_key*,
		const struct tesla_transitions*);
#endif

/*
 * XXXRW: temporarily, maximum number of classes and instances are hard-coded
 * constants.  In the future, this should somehow be more dynamic.
 */
#define	TESLA_MAX_CLASSES		12
#define	TESLA_MAX_INSTANCES		8

/*
 * When the assertion fails, what to do?
 */
#define	TESLA_ACTION_FAILSTOP	1	/* Stop on failure. */
#define	TESLA_ACTION_DTRACE	2	/* Fire DTrace probe on failure. */
#define	TESLA_ACTION_PRINTF	3	/* Console/stdio printf. */

#if defined(_KERNEL) && defined(MALLOC_DECLARE)
/*
 * Memory type for TESLA allocations in the kernel.
 */
MALLOC_DECLARE(M_TESLA);
#endif

/*
 * Context-specific automata management:
 */
int32_t	tesla_class_global_postinit(struct tesla_class*);
void	tesla_class_global_acquire(struct tesla_class*);
void	tesla_class_global_release(struct tesla_class*);
void	tesla_class_global_destroy(struct tesla_class*);

int32_t	tesla_class_perthread_postinit(struct tesla_class*c);
void	tesla_class_perthread_acquire(struct tesla_class*);
void	tesla_class_perthread_release(struct tesla_class*);
void	tesla_class_perthread_destroy(struct tesla_class*);

/*
 * Event notification:
 */
/** A new @ref tesla_instance has been created. */
void	tesla_notify_new_instance(struct tesla_class *,
    struct tesla_instance *);

/** A @ref tesla_instance has taken an expected transition. */
void	tesla_notify_transition(struct tesla_class *, struct tesla_instance *,
    const struct tesla_transition*);

/** An exisiting @ref tesla_instance has been cloned because of an event. */
void	tesla_notify_clone(struct tesla_class *,
    struct tesla_instance *old_instance, struct tesla_instance *new_instance,
    const struct tesla_transition*);

/** A @ref tesla_instance was unable to take any of a set of transitions. */
void	tesla_notify_assert_fail(struct tesla_class *, struct tesla_instance *,
    const struct tesla_transitions *);

/** No @ref tesla_class instance was found to match a @ref tesla_key. */
void	tesla_notify_match_fail(struct tesla_class *, const struct tesla_key *,
    const struct tesla_transitions *);

/** A @ref tesla_instance has "passed" (worked through the automaton). */
void	tesla_notify_pass(struct tesla_class *, struct tesla_instance *);

/*
 * DTrace notifications of various events.
 */
void	tesla_state_transition_dtrace(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transition *);
void	tesla_assert_fail_dtrace(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transitions *);
void	tesla_assert_pass_dtrace(struct tesla_class *,
	    struct tesla_instance *);

/*
 * Debug helpers.
 */

#define	SAFE_SPRINTF(current, end, ...) do {				\
	int written = snprintf(current, end - current, __VA_ARGS__);	\
	if ((written > 0) && (current + written < end))			\
		current += written;					\
} while (0)

#define print(...)	printf(__VA_ARGS__)

#ifdef _KERNEL
#define error(...)	printf(__VA_ARGS__)
#else
#define error(...)	fprintf(stderr, __VA_ARGS__)
#endif

#ifndef NDEBUG

#define __debug

#ifdef _KERNEL
#include <sys/systm.h>
#else
#include <stdio.h>
#endif

/** Are we in (verbose) debug mode? */
int32_t	tesla_debugging(const char*);

#define DEBUG(dclass, ...) \
	if (tesla_debugging(#dclass)) printf(__VA_ARGS__)

#else // NDEBUG

// When not in debug mode, some values might not get checked.
#define __debug __unused

#define DEBUG(...)
int32_t	tesla_debugging(const char*) { return 0; }

#endif

/**
 * Assert that a @ref tesla_instance is an instance of a @ref tesla_class.
 *
 * This could be expensive (a linear walk over all @ref tesla_instance in
 * @ref #tclass), so it should only be called from debug code.
 *
 * @param   i          the instance to test
 * @param   tclass     the expected class of @ref #i
 */
void	assert_instanceof(struct tesla_instance *i, struct tesla_class *tclass);

/** Print a key into a buffer. */
char*	key_string(char *buffer, const char *end, const struct tesla_key *);

/** Print a @ref tesla_key to stderr. */
void	print_key(const char *debug_name, const struct tesla_key *key);

/** Print a @ref tesla_class to stderr. */
void	print_class(const struct tesla_class*);

/** Print a human-readable version of a @ref tesla_transition. */
void	print_transition(const char *debug, const struct tesla_transition *);

/** Print a human-readable version of a @ref tesla_transition into a buffer. */
char*	sprint_transition(char *buffer, const char *end,
    const struct tesla_transition *);

/** Print a human-readable version of @ref tesla_transitions. */
void	print_transitions(const char *debug, const struct tesla_transitions *);

/** Print a human-readable version of @ref tesla_transitions into a buffer. */
char*	sprint_transitions(char *buffer, const char *end,
    const struct tesla_transitions *);

#endif /* TESLA_INTERNAL_H */
