/*-
 * Copyright (c) 2017 (Ilia Shumailov)
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


#include <sys/types.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/event.h>
#include <sys/queue.h>

#ifdef _KERNEL
#include <sys/sbuf.h>
#else
#include <sbuf.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <search.h>
#endif

#include "dlog_broker.h"

#include "dl_assert.h"
#include "dl_broker_client.h"
#include "dl_broker_segment.h"
#include "dl_broker_topic.h"
#include "dl_config.h"
#include "dl_event_handler.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_protocol.h"
#include "dl_request.h"
#include "dl_response.h"
#include "dl_transport.h"
#include "dl_utils.h"

#define MAX_NO_OF_CLIENTS 10

struct dlog_broker_handle {
	struct dl_broker_client *clients[MAX_NO_OF_CLIENTS];
	struct dl_broker_config *conf;
	struct dl_event_handler event_handler;
	dl_event_handler_handle socket;
};

static int dl_init_listening_socket(int);

struct dlog_broker_statistics dlog_broker_stats;

unsigned long topic_hashmask;
LIST_HEAD(dl_broker_topics, dl_broker_topic) *topic_hashmap;

#ifdef _KERNEL
static int
dl_init_listening_socket(int portnumber)
{
	// TODO: socreate
	// sobind
	// solisten
	return -1;

}
#else /* !KERNEL */
static int
dl_init_listening_socket(int portnumber)
{
	struct sockaddr_in self;
	int sockfd;

	/*---Create streaming socket---*/
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
		return -1;

	/*---Initialize address/port structure---*/
	bzero(&self, sizeof(self));
	self.sin_family = AF_INET;
	self.sin_port = htons(portnumber);
	self.sin_addr.s_addr = INADDR_ANY;

	/*---Assign a port number to the socket---*/
	if (bind(sockfd, (struct sockaddr *) &self, sizeof(self)) != 0)
		return -2;

	/*---Make it a "listening socket"---*/
	if (listen(sockfd, 20) != 0)
		return -3;

	return sockfd;
}
#endif /* KERNEL */

/**
 * Returns the index where a client matching the given pointer is found.
 * Returns -1 if no match was found. 
 */ 
static int
dl_match_controlled_client_by_pointer(const struct dlog_broker_handle *server,
    const struct dl_broker_client *clientToMatch)
{
	int clientSlot = -1;
	int slotFound = 0;
	int i = 0;
		       
	for (i = 0; (i < MAX_NO_OF_CLIENTS) && (0 == slotFound); ++i) {
			          
		if (clientToMatch == server->clients[i]) {
			clientSlot = i;
			slotFound = 1;
		}
	}
		       
	return clientSlot;
}

static int
dl_find_free_client_slot(const struct dlog_broker_handle *server)
{

	return dl_match_controlled_client_by_pointer(server, NULL);
}

static int
dl_find_matching_client_slot(const struct dlog_broker_handle *server,
    const struct dl_broker_client *client)
{  

	return dl_match_controlled_client_by_pointer(server, client);
}

static dl_event_handler_handle
dl_get_server_socket(void* instance)
{
	const struct dlog_broker_handle *handle = instance;
	return handle->socket;
}

static void
dl_on_client_closed(void *server, void *closed_client)
{
	struct dlog_broker_handle *server_instance = server;
	struct dl_broker_client *client_instance = closed_client;
	int client_slot;
	
	client_slot = dl_find_matching_client_slot(server_instance,
	    client_instance);
	if (client_slot >= 0) {
		dl_broker_client_delete(client_instance);
				
		server_instance->clients[client_slot] = NULL;
	} else {
		DLOGTR0(PRIO_LOW, "Phantom client detected");
	}
}

static void
dl_handle_read_event(void *instance)
{
	struct dlog_broker_handle *server = instance;
	struct dl_broker_event_notifier event_notifier = {0};
    	int free_slot;
       
	DLOGTR0(PRIO_LOW, "Client request\n");

	free_slot = dl_find_free_client_slot(server);
       	if (0 <= free_slot) {
		/* Define a callback for events requiring the actions of the
		 * server (for example a closed connection). */
		event_notifier.server = server;
		event_notifier.on_client_closed = dl_on_client_closed;
		// TODO not sure that this is needed
		event_notifier.dlben_conf = server->conf;
				       
		server->clients[free_slot] = dl_broker_client_new(
		    server->socket, &event_notifier);
				               
		DLOGTR0(PRIO_LOW,
		    "Server: Incoming connect request accepted\n");
	} else {
		DLOGTR0(PRIO_HIGH, "Server: Not space for more clients\n");
	}
}

void
dlog_broker_init(char const * const topic_name,
    struct dl_broker_config const * const conf)
{
	struct kevent event;
	struct dl_partition *topic_partition;
	struct dl_segment *active_segment;
	struct dl_broker_topic *topic;
	struct sbuf *tname;

	DL_ASSERT(topic_name != NULL, "Partition name cannot be NULL");
	DL_ASSERT(conf != NULL, "Broker configuration cannot be NULL");

	/* Create the hashmap to store the names of the topics managed by the
	 * broker and their segments.
	 */
	topic_hashmap = dl_topic_hashinit(10, &topic_hashmask);

	/* Preallocate an initial segement file for the topic and add to the hashmap. */
	tname = sbuf_new_auto();
	sbuf_cpy(tname, topic_name);
	topic = dl_topic_new(tname);
	uint32_t h = hashlittle(sbuf_data(tname), sbuf_len(tname), 0);
	LIST_INSERT_HEAD(&topic_hashmap[h & topic_hashmask], topic, dlt_entries); 
}

/* TODO allow specifying which network interface to bind to */
struct dlog_broker_handle *
dlog_broker_create_server(const int portnumber,
    struct dl_broker_config const * const conf)
{
	struct dlog_broker_handle *handle;
	dl_event_handler_handle socket;

	handle = (struct dlog_broker_handle *) dlog_alloc(
	    sizeof(struct dlog_broker_handle));
	if (handle != NULL ) {

		/* Construct the DLog broker handle and register the
		 * event handler with the poll reactor.
		 */
		socket = dl_init_listening_socket(portnumber);
		if (socket > 0) {
			// TODO: error handling
			handle->socket = socket;
			handle->conf = conf;
			handle->event_handler.dleh_instance = handle;
			handle->event_handler.dleh_get_handle = dl_get_server_socket;
			handle->event_handler.dleh_handle_event = dl_handle_read_event;

			dl_poll_reactor_register(&handle->event_handler);
		} else {
			DLOGTR0(PRIO_HIGH, "Error initialising server socket.\n");
			dlog_free(handle);
		}
	}
	return handle;
}

void
dlog_broker_fini()
{
	struct dl_partition *topic_partition;
	// unregister the handlers?

	/* Register the topics active partition with the poll reactor. */
	//topic_partition = SLIST_FIRST(&topic->dlt_partitions);
	//dl_poll_reactor_unregister(&topic_partition->event_handler);
}
