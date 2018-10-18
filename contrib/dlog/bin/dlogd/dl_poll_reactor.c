/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 * 
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
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

#include <sys/queue.h>

#include <poll.h>
#include <strings.h>
#include <stddef.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_utils.h"

struct dl_handler_registry {
	STAILQ_ENTRY(dl_handler_registry) dlh_entries;
	struct dl_event_handler const *dlh_handler;
	struct pollfd dlh_fd;
};

static void dl_add_to_registry(struct dl_event_handler const * const handler,
   int);
static size_t dl_build_poll_array(struct pollfd *);
static void dl_dispatch_signalled_handles(const struct pollfd *, const size_t);
static struct dl_event_handler const * dl_find_handler(const int fd);
static void dl_remove_from_registry(
    struct dl_event_handler const * const handler);

// TODO: Limit number of handles correctly
static const size_t MAX_NO_OF_HANDLES = 100;

static STAILQ_HEAD(dl_handlers, dl_handler_registry) handlers =
    STAILQ_HEAD_INITIALIZER(handlers);

/* Add a copy of all registered handlers to the given array. */
static size_t
dl_build_poll_array(struct pollfd *fds)
{
	struct dl_handler_registry *registry;
	size_t nhandles = 0;
	
	DL_ASSERT(fds != NULL, ("File descriptor array cannot be NULL."));

	STAILQ_FOREACH(registry, &handlers, dlh_entries) {

		fds->fd = registry->dlh_fd.fd;
		fds->events = registry->dlh_fd.events;

		fds++;
		nhandles++;
	}
	return nhandles;
}

/**
 * Identify the event handler corresponding to the given descriptor in the
 * registered handlers.
 */
static struct dl_event_handler const *
dl_find_handler(const int fd)
{
	struct dl_handler_registry *registry;
	
	DL_ASSERT(fd > 0, ("File descriptor is invalid."));

	STAILQ_FOREACH(registry, &handlers, dlh_entries) {

		if (registry->dlh_fd.fd == fd)
			return registry->dlh_handler;
	}
	return NULL;
}

/** Add a copy of the given handler to the first free position in
 * registeredHandlers.
 */
static void
dl_add_to_registry(struct dl_event_handler const * const handler, int events)
{
	struct dl_handler_registry *registry;

	DL_ASSERT(handler != NULL, ("dl_event_handler cannot be NULL."));

	registry = (struct dl_handler_registry *) dlog_alloc(
	    sizeof(struct dl_handler_registry));
	if (registry != NULL ) {
		registry->dlh_handler = handler;
		registry->dlh_fd.fd = handler->dleh_get_handle(
		    handler->dleh_instance);
		registry->dlh_fd.events = events;

		STAILQ_INSERT_TAIL(&handlers, registry, dlh_entries);
	}
}

/* Identify the event handler in the registeredHandlers and remove it. */
static void
dl_remove_from_registry(struct dl_event_handler const * const handler)
{
	struct dl_handler_registry *registry;

	DL_ASSERT(handler != NULL, ("dl_event_handler cannot be NULL."));
	
	STAILQ_FOREACH(registry, &handlers, dlh_entries) {

		if (registry->dlh_handler == handler) {

			STAILQ_REMOVE(&handlers, registry,
			    dl_handler_registry, dlh_entries);
			dlog_free(registry);
			break;
		}
	}
}

static void
dl_dispatch_signalled_handles(const struct pollfd *fds, const size_t nhandles)
{
	struct dl_event_handler const *signalled_handler;
	size_t handle;

	DL_ASSERT(fds != NULL, ("File descriptor array cannot be NULL."));
	DL_ASSERT(nhandles > 0, ("File descriptors return by poll."));

	/**
	 * Loop through all handles. Upon detection of a handle signalled by
	 * poll, its corresponding event handler is fetched and invoked.
	 */
	for (handle = 0; handle < nhandles; ++handle) {
		/**
		 * Detect all signalled handles and invoke their corresponding
		 * event handlers.
		 */
		if (fds[handle].events & fds[handle].revents) {

			signalled_handler = dl_find_handler(fds[handle].fd);
			if (signalled_handler != NULL){
				signalled_handler->dleh_handle_event(
				    signalled_handler->dleh_instance,
				    fds[handle].fd, fds[handle].revents);
			}
		}
	}
}

/* Implementation of the Reactor interface used for registrys. */

void
dl_poll_reactor_handle_events(void)
{
	struct pollfd fds[MAX_NO_OF_HANDLES];
	size_t nhandles;

	bzero(fds, sizeof(fds));
	nhandles = dl_build_poll_array(fds);

	/* Invoke the synchronous event demultiplexer. */
	if (poll(fds, nhandles, -1) > 0) {
		/** 
		 * Identify all signalled handles and invoke the event handler
		 * associated with each one.
		 */
		dl_dispatch_signalled_handles(fds, nhandles);
	} else {
		DLOGTR0(PRIO_LOW, "Poll failure\n");
	}
}

void
dl_poll_reactor_register(struct dl_event_handler const * const handler,
    int events)
{

	DL_ASSERT(handler != NULL, "dl_event_handler cannot be NULL\n");

        dl_add_to_registry(handler, events);
}

void
dl_poll_reactor_unregister(struct dl_event_handler const * const handler)
{

	DL_ASSERT(handler != NULL, "dl_event_handler cannot be NULL\n");
	
	dl_remove_from_registry(handler);
}
