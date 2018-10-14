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

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/sbuf.h>

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <ncurses.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>

#include "dl_producer.h"

static char *g_pname;
static bool stop  = false;
static struct dl_producer_stats *stats;

static inline void
usage(FILE * fp)
{

	(void) fprintf(fp,
	    "Usage: %s -p log_path -t topic\n", g_pname);
}

static void
display_stats()
{

	move(0, 0);
	printw("CADETS - dlogd statistics\n");
	printw("Producer topic = %s\n", stats->dlps_topic_name);
	printw("State = %s\n", stats->dlps_state_name);
	printw("TCP connected = %s\n",
	    stats->dlps_tcp_connected ? "true" : "false");
	printw("TLS connected = %s\n",
	    stats->dlps_tls_connected ? "true" : "false");
	printw("Queued requests = %d\n", stats->dlps_queued_requests);
	printw("Unacknowledged requests = %d\n",
	    stats->dlps_unackd_requests);
	printw("Total bytes sent = %ld\n",
		stats->dlps_bytes_sent);
	printw("Total bytes received = %ld\n",
		stats->dlps_bytes_received);
	refresh();
}

static void
dlogdstat_stop(int sig __attribute__((unused)))
{

	stop = true;
}

static void
dlogdstat_update(int sig __attribute__((unused)))
{

	display_stats();
}

int
main(int argc, char **argv)
{
	struct sbuf *stats_path;
	char *topic = NULL, *log_path = NULL;
	static struct option options[] = {
		{"log_path", required_argument, NULL, 'p'},
		{"topic", required_argument, NULL, 't'},
		{0, 0, 0, 0}
	};
	int c, stats_fd;

	g_pname = basename(argv[0]);

	while ((c = getopt_long(argc, argv, "p:t:",
	   options, NULL)) != -1) {
		switch (c) {
		case 'p':
			/* Log database path */
			log_path = optarg;
			break;
		case 't':
			/* Topic to monitor */
			topic = optarg;
			break;
		case '?':
			/* FALLTHROUGH */
		default:
			usage(stderr);
			exit(EXIT_FAILURE);
			break;
		}
	};

	if (topic == NULL || log_path == NULL) {
		usage(stderr);
		exit(EXIT_FAILURE);
	}

	signal(SIGINT, dlogdstat_stop);
	signal(SIGINFO, dlogdstat_update);

	/* Open a memory mapped file for the Producer stats. */
	stats_path = sbuf_new_auto();
	sbuf_printf(stats_path, "%s/%s/stats", log_path, topic);
	sbuf_finish(stats_path);
	stats_fd = open(sbuf_data(stats_path), O_RDONLY , 0200);
	if (stats_fd == -1) {

		fprintf(stderr,
		    "Failed opening Producer stats file %d.\n", errno);
		sbuf_delete(stats_path);
		exit(EXIT_FAILURE);
	}
	sbuf_delete(stats_path);
	ftruncate(stats_fd, sizeof(struct dl_producer_stats));

	stats = (struct dl_producer_stats *) mmap(
	    NULL, sizeof(struct dl_producer_stats), PROT_READ,
	    MAP_SHARED, stats_fd, 0);
	if (stats == NULL) {

		fprintf(stderr,
		    "Failed mmap of Producer stats file %d.\n", errno);
		exit(EXIT_FAILURE);
	}

	/* NCurses scren initialization. */
	initscr();

	/* Display producer statistics until requested to stop. */
	while (!stop) {

		display_stats();
		sleep(1);

	}

	/* Restore terminal */
	endwin();

	/* Close and unmap the stats file. */
	munmap(stats, sizeof(struct dl_producer_stats));
	close(stats_fd);

	return 0;
}
