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
 *
 */

#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/nv.h>
#include <sys/queue.h>
#include <sys/event.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <ucl.h>
#include <unistd.h>
#include <malloc_np.h>

#include "dlog.h"
#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_poll_reactor.h"
#include "dl_producer.h"
#include "dl_response.h"
#include "dl_topic.h"
#include "dl_transport.h"
#include "dl_utils.h"

extern uint32_t hashlittle(const void *, size_t, uint32_t);

static char const * const DLOGD_PIDFILE = "/var/run/dlogd.pid";
static char const * const DLOGD_DEFAULT_CONFIG = "/etc/dlogd/dlogd.cfg";
static char const * const DLOG_DEV = "/dev/dlog";
static char const * const DLOGD_CLIENTID = "clientid";
static char const * const DLOGD_NELEMENTS = "nelements";
static const int DLOGD_NELEMENTS_DEFAULT = 10;
static char const * const DLOGD_TOPICS = "topics";
static char const * const DLOGD_LOG_PATH= "log_path";
static char const * const DLOGD_LOG_PATH_DEFAULT= ".";
static char const * const DLOGD_PRIVATEKEY_FILE = "privatekey_file";
static char const * const DLOGD_CLIENT_FILE = "client_file";
static char const * const DLOGD_CACERT_FILE = "cacert_file";
static char const * const DLOGD_USER_PASSWORD = "user_password";
static char const * const DLOGD_TLS = "tls";

struct dl_producer_elem {
	LIST_ENTRY(dl_producer_elem) dlp_entries;
	struct dl_producer *dlp_inst;
};

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static int stop  = 0;
static char const* dlogd_name;
static LIST_HEAD(dl_producers, dl_producer_elem) *producers;
static unsigned long hashmask;
static int dlog;
static nvlist_t *props;
static int nelements = DLOGD_NELEMENTS_DEFAULT;

static inline void 
dlogd_usage(FILE * fp)
{

	(void) fprintf(fp, "Usage: %s [-d] [-c config_file]\n", dlogd_name);
}

static void
dlogd_stop(int sig __attribute__((unused)))
{

	stop = 1;
}

static void
dlogd_close_dlog(void)
{
	int rc;

	/* Close the distibuted log. */	
	DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	rc = close(dlog);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error closing distributed log %d\n",
		    errno);
}


static void
dlogd_close_pidfile(void)
{

	/* Unlink the dlogd pid file. */	
	DLOGTR0(PRIO_LOW, "Unlinking dlogd pid file\n");
	if (unlink(DLOGD_PIDFILE) == -1 && errno != ENOENT)
		DLOGTR0(PRIO_HIGH, "Error unlinking dlogd pid file\n");
}

static int
register_daemon(void)
{
	FILE * pidfile;
	int fd;
	pid_t pid;

	signal(SIGINT, dlogd_stop);

	if ((pidfile = fopen(DLOGD_PIDFILE, "a")) == NULL) {
		return (-1);
	}
	atexit(dlogd_close_dlog);

	/* Attempt to lock the pid file; if a lock is present, exit. */
	fd = fileno(pidfile);
	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		return (-1);
	}

	pid = getpid();
	ftruncate(fd, 0);
	if (fprintf(pidfile, "%u\n", pid) < 0) {
		/* Should not start the daemon. */
	}

	fflush(pidfile);
	atexit(dlogd_close_pidfile);
	return 0;
}

static int 
setup_daemon(void)
{
	long hashsize;

	/* Create a new nvlist to store producer configuration. */
	props = nvlist_create(0);

	nvlist_add_bool(props, DL_CONF_TORESEND, false);

	/* Open the DLog device */
	dlog = open(DLOG_DEV, O_RDWR);
	if (dlog == -1)  {

		DLOGTR2(PRIO_LOW, "Error opening %s (%d)\n", DLOG_DEV,
		    errno);
		return -1;
	}

	/* Create the hashmap to store producers for the topics managed by the
	 * dlog daemon.
	 */
	for (hashsize = 1; hashsize <= nelements; hashsize <<= 1)
		continue;
	hashsize >>= 1;

	producers = dlog_alloc(
	    (unsigned long) hashsize * sizeof(*producers));
	if (producers == NULL) {

		DLOGTR2(PRIO_LOW, "Error opening %s (%d)\n", DLOG_DEV,
		    errno);
		return -1;
	}

	for (int i = 0; i < hashsize; i++)
		LIST_INIT(&producers[i]);
	hashmask = hashsize -1;

	return 0;
}

static void
dlogd_terminate(void)
{
	
	if (unlink(DLOGD_PIDFILE) == -1 && errno != ENOENT) {

		DLOGTR0(PRIO_HIGH, "Failed unli\n");
	}
}

static int
dlogd_manage_topic(char * topic_name, char *log_path, char *hostname,
    int64_t port)
{
	struct dl_producer *producer;
	struct dl_producer_elem *elem;
	struct dl_topic_desc *topic_desc;
	struct dl_topic *topic;
	uint32_t h;
	int rc;

	/* Preallocate an initial segement file for the topic and add
	 * to the hashmap.
	 */
	rc = dl_topic_new(&topic, topic_name, log_path);
	if (rc == 0) {

		rc = dl_topic_as_desc(topic, &topic_desc);	
		if (rc == 0) {
			rc = ioctl(dlog, DLOGIOC_ADDTOPICPART,
				&topic_desc);	
			if (rc == 0) {
				rc = dl_producer_new(&producer, topic,
					hostname, port, props); 
				if (rc == 0) {
					elem = (struct dl_producer_elem *) dlog_alloc(sizeof(struct dl_producer_elem));
					elem->dlp_inst = producer;

					h = hashlittle(topic_name,
						strlen(topic_name), 0);
					LIST_INSERT_HEAD(
					    &producers[h & hashmask],
					    elem, dlp_entries); 
				} else {
					ioctl(dlog, DLOGIOC_DELTOPICPART,
					    &topic_desc);	
				}
			
				dlog_free(topic_desc);
			} else {
				DLOGTR1(PRIO_HIGH,
					"Failed to configure topic %s\n",
					topic_name);
				dlog_free(topic_desc);
				dl_topic_delete(topic);
				return -1;
			}
		} else {
			DLOGTR1(PRIO_HIGH,
				"Failed to create topic %s\n", topic_name);
			dl_topic_delete(topic);
			return -1;
		}
	} else {
		DLOGTR1(PRIO_HIGH, "Failed to create topic %s\n",
		    topic_name);
		return -1;
	}

	return 0;
}

int
main(int argc, char *argv[])
{
	struct dl_producer_elem *p, *p_tmp;	
	struct ucl_parser* parser;
	ucl_object_t *top, *cur, *obj, *t, *topics_obj = NULL;
	ucl_object_iter_t it, tit = NULL;
	struct dl_topic *topic_tmp;
	char const *conf_file = DLOGD_DEFAULT_CONFIG;
	char *topic_name;
	char *hostname;
	char *log_path = DLOGD_LOG_PATH_DEFAULT;
	int64_t port;
	int c, rc;
	size_t old_maxsockbuf, old_maxsockbuf_size;
	size_t new_maxsockbuf  = 20 * DL_MTU * 2;
	size_t new_maxsockbuf_size = sizeof(size_t);
	bool debug = false;

	dlogd_name = basename(argv[0]); 	

	/* Parse the dlogd command line arguments */
	opterr = 0;
	while ((c = getopt(argc, argv, "dc:")) != -1) {
		switch(c) {
		case 'c':
			conf_file = optarg;
			break;
		case 'd':
			/* Debug option */
			debug = true;
			break;
		case '?':
		default:
			dlogd_usage(stderr);
			exit(EXIT_FAILURE);
		}
	}

	if (debug == false && daemon(0, 0) == -1) {

		DLOGTR0(PRIO_HIGH, "Failed registering dlogd as daemon\n");
		exit(EXIT_FAILURE);
	}
	
	DLOGTR1(PRIO_LOW, "%s daemon starting...\n", dlogd_name);

	if (register_daemon() != 0) {

		DLOGTR0(PRIO_HIGH, "Failed registering dlogd as daemon\n");
		exit(EXIT_FAILURE);
	}

	if (setup_daemon() != 0) {

	}

	/* Configure the maxsockbuf based on the DLog MTU. */
	sysctlbyname("kern.ipc.maxsockbuf",
	    &old_maxsockbuf, &old_maxsockbuf_size,
	    &new_maxsockbuf, new_maxsockbuf_size);

	/* Instatiate libucl parser to parse the dlogd config file. */
	parser = ucl_parser_new(0);
	if (parser == NULL) {

		DLOGTR0(PRIO_HIGH, "Error creating libucl parser\n");
		goto err;
	}
	
	if (!ucl_parser_add_file(parser, conf_file)) {

		DLOGTR0(PRIO_HIGH, "Failed to parse config file\n");
		/* Free the libucl parser. */	
		ucl_parser_free(parser);
		goto err;
	}

	/* Obtain a reference to the top object */
	top = ucl_parser_get_object(parser);
	if (top == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "Failed to obtain reference to libucl objecit\n");
		goto err_free_libucl;
	}

	/* Iterate over the object */
	it = ucl_object_iterate_new(top);
	while ((obj = ucl_object_iterate_safe(it, true)) != NULL) {

		/* Parse each the configuration item. */
		if (strcmp(ucl_object_key(obj), DLOGD_CLIENTID) == 0) {

			nvlist_add_string(props, DL_CONF_CLIENTID,
			    ucl_object_tostring_forced(obj));
		}

		if (strcmp(ucl_object_key(obj), DLOGD_PRIVATEKEY_FILE) == 0) {

			nvlist_add_string(props, DL_CONF_PRIVATEKEY_FILE,
			    ucl_object_tostring_forced(obj));
		}
		
		if (strcmp(ucl_object_key(obj), DLOGD_CLIENT_FILE) == 0) {

			nvlist_add_string(props, DL_CONF_CLIENT_FILE,
			    ucl_object_tostring_forced(obj));
		}
		
		if (strcmp(ucl_object_key(obj), DLOGD_CACERT_FILE) == 0) {

			nvlist_add_string(props, DL_CONF_CACERT_FILE,
			    ucl_object_tostring_forced(obj));
		}
	
		if (strcmp(ucl_object_key(obj), DLOGD_USER_PASSWORD) == 0) {

			nvlist_add_string(props, DL_CONF_USER_PASSWORD,
			    ucl_object_tostring_forced(obj));
		}
		
		if (strcmp(ucl_object_key(obj), DLOGD_TLS) == 0) {

			nvlist_add_bool(props, DL_CONF_TLS_ENABLE,
			    ucl_object_toboolean(obj));
		}
				
		if (strcmp(ucl_object_key(obj), DLOGD_NELEMENTS) == 0) {
	
			nelements = ucl_object_toint(obj);
			if (nelements <= 0 )
				nelements = DLOGD_NELEMENTS_DEFAULT;
		}

		if (strcmp(ucl_object_key(obj), DLOGD_LOG_PATH) == 0) {

			    log_path = ucl_object_tostring_forced(obj);
		}

		if (strcmp(ucl_object_key(obj), DLOGD_TOPICS) == 0) {

			topics_obj = obj;
		}
	}
		
	/* Check whether topics to manage have been configured */
	if (topics_obj == NULL) {

		DLOGTR0(PRIO_HIGH,
		    "No topics configured for dlog to manage\n");
		goto err_free_libucl;
	}

	/* Parse the configured topics. */
	it = ucl_object_iterate_reset(it, topics_obj);
	while ((cur = ucl_object_iterate_safe(it, true)) != NULL) {
		
		topic_name = ucl_object_key(cur);

		/* Iterate over the values of a key */
		while ((t = ucl_iterate_object (cur, &tit, true))) {

			if (strcmp(ucl_object_key(t), "hostname") == 0) {
			
				hostname = ucl_object_tostring_forced(t);
			}

			if (strcmp(ucl_object_key(t), "port") == 0) {

				port = ucl_object_toint(t);
			}
		}

		rc = dlogd_manage_topic(topic_name, log_path, hostname,
		    port);
		if (rc != 0) {
		}
	}
	ucl_object_iterate_free(it);

	ucl_object_unref(top);

	/* Free the libucl parser. */	
	ucl_parser_free(parser);
	
	/* Handle any events registered for the configured topics/producers. */
	while (stop == 0) {

		dl_poll_reactor_handle_events();
	}

	/* Destroy the nvlist used to store producer configuration. */
	nvlist_destroy(props);

	/* Delete all of the producers */
	DLOGTR0(PRIO_LOW, "Deleting the producers.\n");
	for (unsigned int p_it = 0; p_it < hashmask + 1 ; p_it++) {
		LIST_FOREACH_SAFE(p, &producers[p_it], dlp_entries, p_tmp) {

			LIST_REMOVE(p, dlp_entries);

			topic_tmp = dl_producer_get_topic(p->dlp_inst);
			DL_ASSERT(topic_tmp != NULL,
			    ("Producer topic cannot be NULL"));
			
			DLOGTR1(PRIO_LOW,
			    "Deleting the topic %s producer.\n",
			    sbuf_data(dl_topic_get_name(topic_tmp)));
					
			/* Delete the topic producer */
			dl_producer_delete(p->dlp_inst);
	
			/* Delete the producer element */
			dlog_free(p);
		}
	}

	dlogd_terminate();

	/* Delete the producer hashmap */
	DLOGTR0(PRIO_LOW, "Deleting the producer hashmap.\n");
	dlog_free(producers);

	/* Restore the maxsockbuf. */
	new_maxsockbuf = old_maxsockbuf;
	new_maxsockbuf_size = sizeof(size_t);

	sysctlbyname("kern.ipc.maxsockbuf",
	    &old_maxsockbuf, &old_maxsockbuf_size,
	    &new_maxsockbuf, new_maxsockbuf_size);

	DLOGTR1(PRIO_LOW, "%s daemon stopped.\n", dlogd_name);

	return 0;

err_free_libucl:
	/* Free the libucl parser. */	
	ucl_parser_free(parser);
	
err:
	exit(EXIT_FAILURE);
}
