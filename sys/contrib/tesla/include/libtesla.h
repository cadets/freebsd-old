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

#ifndef	_LIBTESLA_H
#define	_LIBTESLA_H

#include <sys/cdefs.h>

__BEGIN_DECLS

/**
 * Support library for TESLA instrumentation.
 * @addtogroup libtesla
 * @{
 */

#ifdef _KERNEL
#include <sys/types.h>
#else
#include <stdint.h>		/* int32_t, uint32_t */
#endif

/**
 * Error values that can be returned by libtesla functions.
 *
 * libtesla functions mostly return error values, and therefore return
 * pointers, etc, via call-by-reference arguments.
 */
enum tesla_err_t {
	TESLA_SUCCESS,		/* Success. */
	TESLA_ERROR_ENOENT,	/* Entry not found. */
	TESLA_ERROR_ENOMEM,	/* Insufficient memory. */
	TESLA_ERROR_EINVAL,	/* Invalid parameters. */
	TESLA_ERROR_UNKNOWN,	/* An unknown (e.g. platform) error. */
};

/**
 * Provide string versions of TESLA errors.
 */
const char	*tesla_strerror(int32_t error);



/**
 * An internal description of a TESLA automaton, which may be instantiated
 * a number of times with different names and current states.
 */
struct tesla_class;
struct tesla_lifetime_event;
struct tesla_transitions;

/**
 * A static description of a TESLA automaton.
 */
struct tesla_automaton {
	/** A unique name, hopefully human-readable. */
	const char			*ta_name;

	/**
	 * The number of symbols in the input alphabet (events that can
	 * be observed).
	 *
	 * Input alphabet symbols are integers in the range [0,alphabet_size].
	 */
	const int32_t			 ta_alphabet_size;

        /**
         * The symbol number used to signal cleanup.
         */
        const int32_t                    ta_cleanup_symbol;

	/**
	 * Transitions that will be taken in response to events.
	 *
	 * The transitions that can be taken in response to event 42 will
	 * be found in transitions[42].
	 */
	const struct tesla_transitions	*ta_transitions;

	/** Original source description of the automaton. */
	const char			*ta_description;

	/** Human-readable descriptions of input symbols (for debugging). */
	const char*			*ta_symbol_names;

	/** The automaton's lifetime. */
	const struct tesla_lifetime	*ta_lifetime;
};


/**
 * A short, unique, deterministic representation of a lifetime entry/exit event,
 * a pair of which defines an automaton's lifetime.
 */
struct tesla_lifetime_event {
	/**
	 * An opaque representation of the automaton's initialisation event.
	 *
	 * This description should be short and deterministic,
	 * i.e., multiple automata that share the same init event should
	 * have exactly the same ta_init description string.
	 *
	 * This can be written by hand if needed (e.g. for testing),
	 * but in practice we generate it from protocol buffers.
	 */
	const char			*tle_repr;

	/** The length of @ref #tle_repr. */
	const int32_t			 tle_length;

	/**
	 * A precomputed hash of @ref #tle_repr.
	 *
	 * libtesla doesn't care what hash algorithm is used; in test code or
	 * statically-compiled clients, incrementing integers works well.
	 *
	 * All clients should be consistent, however; the TESLA instrumenter
	 * uses SuperFastHash.
	 */
	const int32_t			 tle_hash;
};


/**
 * The description of a TESLA lifetime.
 */
struct tesla_lifetime {
	struct tesla_lifetime_event	tl_begin;
	struct tesla_lifetime_event	tl_end;

	/** A human-readable string for debugging. */
	const char			*tl_repr;
};


/**
 * Register a @ref tesla_automaton, receiving a @ref tesla_class back.
 *
 * The @ref tesla_automaton must exist for the lifetime of the TESLA context
 * (until thread destruction in the per-thread case, indefinitely in the
 * global case).
 */
int	tesla_register(const struct tesla_automaton*, struct tesla_class**);


/**
 * A storage container for one or more @ref tesla_class objects.
 *
 * There may be one @ref tesla_store for each thread (for storing thread-local
 * automata) plus a single global @ref tesla_store.
 */
struct tesla_store;

/**
 * A context where TESLA data is stored.
 *
 * TESLA data can be stored in a number of places that imply different
 * synchronisation requirements. For instance, thread-local storage does not
 * require synchronisation on access, whereas global storage does.
 * On the other hand, thread-local storage cannot be used to track events
 * across multiple threads.
 */
enum tesla_context {
	TESLA_CONTEXT_GLOBAL,
	TESLA_CONTEXT_THREAD,
};

/**
 * Retrieve the @ref tesla_store for a context (e.g., a thread).
 *
 * If the @ref tesla_store does not exist yet, it will be created.
 *
 * @param[in]  context     @ref TESLA_CONTEXT_THREAD or
 *                         @ref TESLA_CONTEXT_GLOBAL
 * @param[in]  classes     number of @ref tesla_class'es to expect
 * @param[in]  instances   @ref tesla_instance count per @ref tesla_class
 * @param[out] store       return parameter for @ref tesla_store pointer
 */
int32_t	tesla_store_get(enum tesla_context context,
	                uint32_t classes, uint32_t instances,
	                struct tesla_store* *store);


/**
 * Retrieve (or create) a @ref tesla_class from a @ref tesla_store.
 *
 * Once the caller is done with the @ref tesla_class, @ref tesla_class_put
 * must be called.
 *
 * @param[in]   store    where the @ref tesla_class is expected to be stored
 * @param[in]   description   information about the automaton
 * @param[out]  tclass   the retrieved (or generated) @ref tesla_class;
 *                       only set if function returns TESLA_SUCCESS
 *
 * @returns a TESLA error code (TESLA_SUCCESS, TESLA_ERROR_EINVAL, etc.)
 */
int32_t	tesla_class_get(struct tesla_store *store,
	                const struct tesla_automaton *description,
	                struct tesla_class **tclass);

/** Release resources (e.g., locks) associated with a @ref tesla_class. */
void	tesla_class_put(struct tesla_class*);


/** A single allowable transition in a TESLA automaton. */
struct tesla_transition {
	/** The state we are moving from. */
	uint32_t	from;

	/** The mask of the state we're moving from. */
	uint32_t	from_mask;

	/** The state we are moving to. */
	uint32_t	to;

	/** A mask of the keys that the 'to' state should have set. */
	uint32_t	to_mask;

	/** Things we may need to do on this transition. */
	int		flags;
};

#define	TESLA_TRANS_INIT	0x02	/* May need to initialise the class. */
#define	TESLA_TRANS_CLEANUP	0x04	/* Clean up the class now. */

/**
 * A set of permissible state transitions for an automata instance.
 *
 * An automaton must take exactly one of these transitions.
 */
struct tesla_transitions {
	/** The number of possible transitions in @ref #transitions. */
	uint32_t		 length;

	/** Possible transitions: exactly one must be taken. */
	struct tesla_transition	*transitions;
};

#define	TESLA_KEY_SIZE		4

/**
 * A TESLA instance can be identified by a @ref tesla_class and a
 * @ref tesla_key. This key represents the values of event parameters (e.g. a
 * credential passed to a security check), some of which may not be specified.
 *
 * Clients can use @ref tesla_key to look up sets of automata instances, using
 * the bitmask to specify don't-care parameters.
 *
 * Keys can hold arbitrary integers/pointers.
 */
struct tesla_key {
	/** The keys / event parameters that name this automata instance. */
	uintptr_t	tk_keys[TESLA_KEY_SIZE];

	/** A bitmask of the keys that are actually set. */
	uint32_t	tk_mask;
};


/**
 * Update all automata instances that match a given key to a new state.
 *
 * @param  context      where the automaton is stored
 * @param  automaton    static description of the automaton
 * @param  symbol       identifier of the input symbol (event) to be consumed
 * @param  pattern      the name extracted from the event
 */
void	tesla_update_state(enum tesla_context context,
	const struct tesla_automaton *automaton,
	uint32_t symbol, const struct tesla_key *pattern);

/**
 * We have encountered an entry bound for some automata.
 *
 * @param  context      Where the automaton is stored.
 * @param  l            Static description of the lifetime (begin, end events).
 */
void	tesla_sunrise(enum tesla_context context,
	const struct tesla_lifetime *l);

/** We have encountered an exit bound for some automata. */
void	tesla_sunset(enum tesla_context context,
	const struct tesla_lifetime*);


/** A single instance of an automaton: a name (@ref ti_key) and a state. */
struct tesla_instance {
	struct tesla_key	ti_key;
	uint32_t		ti_state;
};


/*
 * Event notification:
 */
/** An initialisation event has occurred; entering an automaton lifetime. */
typedef void	(*tesla_ev_sunrise)(enum tesla_context,
	    const struct tesla_lifetime *);

/** A cleanup event has occurred; exiting an automaton lifetime. */
typedef void	(*tesla_ev_sunset)(enum tesla_context,
	    const struct tesla_lifetime *);

/** A new @ref tesla_instance has been created. */
typedef void	(*tesla_ev_new_instance)(struct tesla_class *,
	    struct tesla_instance *);

/** A @ref tesla_instance has taken a transition. */
typedef void	(*tesla_ev_transition)(struct tesla_class *,
	    struct tesla_instance *, const struct tesla_transition*);

/** An exisiting @ref tesla_instance has been cloned because of an event. */
typedef void	(*tesla_ev_clone)(struct tesla_class *,
	    struct tesla_instance *orig, struct tesla_instance *copy,
	    const struct tesla_transition*);

/** No @ref tesla_class instance was found to match a @ref tesla_key. */
typedef void	(*tesla_ev_no_instance)(struct tesla_class *,
	    int32_t symbol, const struct tesla_key *);

/** A @ref tesla_instance is not in the right state to take a transition. */
typedef void	(*tesla_ev_bad_transition)(struct tesla_class *,
	    struct tesla_instance *, int32_t symbol);

/** Generic error handler. */
typedef void	(*tesla_ev_error)(const struct tesla_automaton *,
	    int32_t symbol, int32_t errnum, const char *message);

/** A @ref tesla_instance has accepted a sequence of events. */
typedef void	(*tesla_ev_accept)(struct tesla_class *,
	    struct tesla_instance *);

/** An event is being ignored. */
typedef void	(*tesla_ev_ignored)(const struct tesla_class *,
	    int32_t symbol, const struct tesla_key *);

/** A vector of event handlers. */
struct tesla_event_handlers {
	tesla_ev_sunrise	teh_sunrise;
	tesla_ev_sunset		teh_sunset;
	tesla_ev_new_instance	teh_init;
	tesla_ev_transition	teh_transition;
	tesla_ev_clone		teh_clone;
	tesla_ev_no_instance	teh_fail_no_instance;
	tesla_ev_bad_transition	teh_bad_transition;
	tesla_ev_error		teh_err;
	tesla_ev_accept		teh_accept;
	tesla_ev_ignored	teh_ignored;
};

/**
 * A 'meta-handler' that wraps a number of event handling vectors.
 *
 * This event handler dispatches events to any number of backends, governed
 * by @a tem_mask: if bit 0 is set, tem_handler[0] is called, etc.
 */
struct tesla_event_metahandler {
	/** The number of event handlers wrapped by this handler. */
	const uint32_t	tem_length;

	/** Which backend handlers to use; may be modified dynamically. */
	uint32_t	tem_mask;

	/** The backend event handlers. */
	const struct tesla_event_handlers* const *tem_handlers;
};

/** Register an event handler vector. */
int	tesla_set_event_handler(struct tesla_event_handlers *);

/** Register a set of event handling vectors. */
int	tesla_set_event_handlers(struct tesla_event_metahandler *);

/** The type for printf handler functions */
typedef uint32_t(*printf_type)(const char *, ...);

/** The function that will be called to log messages. */
extern printf_type __tesla_printf;

#ifdef _KERNEL
#define	TESLA_KERN_PRINTF_EV	0x1
#define	TESLA_KERN_PRINTERR_EV	0x2
#define	TESLA_KERN_DTRACE_EV	0x4
#define	TESLA_KERN_PANIC_EV	0x8
#endif

/** @} */

__END_DECLS

#endif /* _TESLA_STATE */
