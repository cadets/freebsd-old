/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
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

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <malloc_np.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/nv.h>

#include <dev/dlog/dlog.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_utils.h"
#include "dl_memory.h"

/* Global singleton dlogd configuration */
extern nvlist_t *dlogd_props;
nvlist_t *dlogd_props;

unsigned short PRIO_LOG = PRIO_LOW;

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

static char const * const DLOG_DEV = "/dev/dlog";

static char const* dlog_topics_name;
static int debug_lvl = 0;

static int dlog_topics_add(int, char *);
static int dlog_topics_delete(int, char *);
static int dlog_topics_get(int);

int
main(int argc, char *argv[])
{
	static struct option options[] = {
		{"add", no_argument, 0, 'a'},
		{"delete", no_argument, NULL, 'd'},
		{"get", no_argument, NULL, 'c'},
		{"debug", no_argument, NULL, 'X'},
		{0, 0, 0, 0}
	};
	/* Work around for incorrect getsubopt parameter types. */
	char add_opts_topic[] = "topic";
	char * const add_opts[] =
	{
		[0] = add_opts_topic,
		[2] = NULL
	};
	/* Work around for incorrect getsubopt parameter types. */
	char del_opts_topic[] = "topic";
	char * const del_opts[] =
	{
		[0] = del_opts_topic,
		[1] = NULL
	};
	int c, dlog, rc;

	/* Configure syslog to copy error messages to stderr. */
	openlog(dlog_topics_name, LOG_PERROR, LOG_USER);
	
	dlog_topics_name = basename(argv[0]); 	

	/* Parse the debug command line argument */
	while ((c = getopt_long(argc, argv, "ad:gs:X", options, NULL)) != -1) {
		switch(c) {
		case 'X':
			break;
		}
	}

	/* Open the DLog device */
	if (debug_lvl > 0)
		DLOGTR0(PRIO_LOW, "Opening distributed log.\n");
	dlog = open(DLOG_DEV, O_RDWR);
	if (dlog == -1)  {

		errx(EXIT_FAILURE, "Error opening %s (%d)\n", DLOG_DEV, errno);
	}
	
	/* Parse the configuration file. */
	char config_file_default[] = "/etc/dlogd/dlogd.cfg";

	rc = dl_config_new(config_file_default, debug_lvl);

	/* Parse the rest of the command line arguments */
	optind = 1;
	while ((c = getopt_long(argc, argv, "a:d:gs:X", options, NULL)) != -1) {
		switch(c) {
		case 'a': {
			char *subopts = optarg, *value, *topic = NULL;

			while (*subopts != '\0') {
				switch (getsubopt(&subopts, add_opts, &value)) {
				case 0:
					topic = value;
					break;
				}
			}

			if (topic != NULL) {
				if (debug_lvl > 0)
					DLOGTR1(PRIO_LOW, "Adding topic: %s\n", topic);

				dlog_topics_add(dlog, topic);
			} else {
				errx(EXIT_FAILURE, "Usage: %s -a topic=topic-name\n",
				    dlog_topics_name);
			}
			break;
		}
		case 'd': {
			char *subopts = optarg, *value, *topic;

			while (*subopts != '\0') {
				switch (getsubopt(&subopts, del_opts, &value)) {
				case 0:
					topic = value;
					break;
				}
			}

			if (topic != NULL) {
				if (debug_lvl > 0)
					DLOGTR1(PRIO_LOW, "Deleting topic: %s\n", topic);

				dlog_topics_delete(dlog, topic);
			} else {
				errx(EXIT_FAILURE, "Usage: %s -d topic=topic-name\n",
				    dlog_topics_name);
			}
			break;
		}
		case 'g': {
			if (debug_lvl > 0)
				DLOGTR0(PRIO_LOW, "Getting topics\n");

			dlog_topics_get(dlog);
			break;
		}
		case 'X':
			/* Ignore */
			break;
		case '?':
		default:
			errx(EXIT_FAILURE, "Usage: %s\n", dlog_topics_name);
		}
	}

	/* Close the distibuted log. */	
	if (debug_lvl > 0)
		DLOGTR0(PRIO_LOW, "Closing distributed log.\n");
	rc = close(dlog);
	if (rc != 0)
		DLOGTR1(PRIO_HIGH, "Error closing distributed log %d\n",
		    errno);
	
	nvlist_destroy(dlogd_props);
	
	return EXIT_SUCCESS;
}

static int 
dlog_topics_add(int dlog, char *name)
{
	struct dl_topic_desc *desc;
	size_t packed_len;
	int rc;

	desc = (struct dl_topic_desc *) dlog_alloc(
	    sizeof(struct dl_topic_desc));
	if (desc == NULL)  {

		DLOGTR2(PRIO_HIGH, "Error adding topic %s: %d\n", name, errno);
		return -1;
	}

	strncpy(desc->dltd_name, name, 255);
	desc->dltd_conf.dlcc_packed_nvlist = nvlist_pack(dlogd_props, &packed_len); 
	desc->dltd_conf.dlcc_packed_nvlist_len = packed_len;
	desc->dltd_active_seg.dlsd_offset = 0;
	desc->dltd_active_seg.dlsd_base_offset = 0;

	rc = ioctl(dlog, DLOGIOC_ADDTOPICPART, &desc);	
	if (rc != 0) {

		DLOGTR2(PRIO_HIGH, "Error adding topic %s: %d\n", name, errno);
		dlog_free(desc);
		return -1;
	}

	dlog_free(desc);
	return 0;
}

static int 
dlog_topics_delete(int dlog, char *topic)
{
	struct dl_topic_desc *desc;
	int rc;

	/* Firtst read the number of topics. */
	desc = (struct dl_topic_desc *) dlog_alloc(sizeof(struct dl_topic_desc));
	DL_ASSERT(desc != NULL, (""));
	if (desc == NULL) {

	}	

	strncpy(desc->dltd_name, topic, 255);

	rc = ioctl(dlog, DLOGIOC_DELTOPICPART, &desc);	
	if (rc == 0) {
	} else {
		DLOGTR2(PRIO_HIGH, "Error deleting topic %s: %d\n", topic, errno);
	}

	return 0;
}

static int 
dlog_topics_get(int dlog)
{
	struct dl_topics_desc *topics_desc;
	int rc;

	/* Firtst read the number of topics. */
	topics_desc = (struct dl_topics_desc *) dlog_alloc(sizeof(struct dl_topics_desc));
		
	topics_desc->dltsd_ntopics = 1;

	rc = ioctl(dlog, DLOGIOC_GETTOPICS, &topics_desc);	
	if (rc == 0) {
		rc = ioctl(dlog, DLOGIOC_GETTOPICS, &topics_desc);	
		if (rc == 0) {
			for (size_t i = 0; i < topics_desc->dltsd_ntopics; i++) {
			
				DLOGTR1(PRIO_LOW, "Topic name = %s\n",
				    topics_desc->dltsd_topic_desc[i].dltd_name);
				DLOGTR1(PRIO_LOW, "\tBase offset = %zu\n",
				    topics_desc->dltsd_topic_desc[i].dltd_active_seg.dlsd_base_offset);
				DLOGTR1(PRIO_LOW, "\tOffset = %u\n",
				    topics_desc->dltsd_topic_desc[i].dltd_active_seg.dlsd_offset);
			}
		} else {
			DLOGTR1(PRIO_HIGH, "Error getting topic names: %d\n", errno);
		}
	} else {
		DLOGTR1(PRIO_HIGH, "Error getting topic names: %d\n", errno);
	}

	return 0;
}
