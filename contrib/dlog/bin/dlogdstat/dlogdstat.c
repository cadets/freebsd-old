/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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

#include <getopt.h>
#include <libgen.h>
#include <ncurses.h>
#include <signal.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include "dl_memory.h"
#include "dl_producer_stats.h"

static char const * const DLPS_STATE_NAME[] =
    {"INITIAL", "IDLE", "SYNCING", "OFFLINE", "ONLINE", "CONNECTING",
    "FINAL" };

const dlog_malloc_func dlog_alloc = malloc;
const dlog_free_func dlog_free = free;

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
	time_t now;
	char time_buf[20]; /*2018-10-28 12:00:00 */
	time_t sent_ts, received_ts;

	now = time(NULL);

	move(0, 0);
	printw("dlogd statistics\n");
	printw("================\n");
	printw("Producer:\n");
	printw("\tTopic = %s\n", dlps_get_topic_name(stats));
	printw("\tState = %s\n", DLPS_STATE_NAME[dlps_get_state(stats)]);
	printw("\tTCP status = %s\n",
	    dlps_get_tcp_connect(stats) ? "connected" : "disconnected");
	printw("\tTLS status = %s\n",
	    dlps_get_tls_connect(stats) ? "established" : "none");
	printw("\tResend = %s\n",
	    dlps_get_resend(stats) ? "enabled" : "disabled");
	if (dlps_get_resend(stats)) {
		printw("\tResend after = %d secs\n",
		    dlps_get_resend_timeout(stats));
	}
	printw("\tQueue capacity = %d\n",
	    dlps_get_queue_capacity(stats));
	printw("\tEnqueued = %d\n",
	    dlps_get_queue_requests(stats));
	printw("\tUnacknowledged = %d\n",
	    dlps_get_queue_unackd(stats));
	if (dlps_get_bytes_sent(stats) > 1048576) {
		printw("\tTotal MiB sent = %ld\n",
		    dlps_get_bytes_sent(stats)/1048576);
	} else {
		printw("\tTotal KiB sent = %ld\n",
		    dlps_get_bytes_sent(stats)/1024);
	}
	if (dlps_get_bytes_received(stats) > 1048576) {
		printw("\tTotal MiB received = %ld\n",
		    dlps_get_bytes_received(stats)/1048576);
	} else {
		printw("\tTotal KiB received = %ld\n",
		    dlps_get_bytes_received(stats)/1025);
	}
	printw("ProduceRequests:\n");
	printw("\tLatest id = %ld\n", dlps_get_sent_cid(stats));
	sent_ts = dlps_get_sent_timestamp(stats);
	strftime(time_buf, 20, "%Y-%m-%d %H:%M:%S", localtime(&sent_ts));
	printw("\tLast sent = %s (%.0lf secs)\n",
	    time_buf, difftime(now, sent_ts));
	printw("\tStatus = %s\n",
	    dlps_get_sent_error(stats) ? "failed" : "OK");
	printw("ProduceResponses:\n");
	printw("\tLatest id = %ld\n", dlps_get_received_cid(stats));
	received_ts = dlps_get_received_timestamp(stats);
	strftime(time_buf, 20, "%Y-%m-%d %H:%M:%S",
	    localtime(&received_ts));
	printw("\tLast received = %s (%.0lf secs)\n",
	    time_buf, difftime(now, received_ts));
	printw("\tRTT = %d us\n", dlps_get_rtt(stats)),
	printw("\tStatus = %s\n",
	    dlps_get_received_error(stats) ? "failed" : "OK");
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
	struct sbuf * t;
	char *topic = NULL, *log_path = NULL;
	static struct option options[] = {
		{"log_path", required_argument, NULL, 'p'},
		{"topic", required_argument, NULL, 't'},
		{0, 0, 0, 0}
	};
	int c; //, stats_fd;

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
	t = sbuf_new_auto();
	sbuf_cat(t, topic);
	sbuf_finish(t);
	if (dl_producer_stats_new(&stats, log_path, t))
		goto err_dlogdstat;

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
	dl_producer_stats_delete(stats);

	/* Free the sbuf containing the topic name. */
	sbuf_delete(t);

	return EXIT_SUCCESS;

err_dlogdstat:	
	/* Restore terminal */
	endwin();
	
	/* Free the sbuf containing the topic name. */
	sbuf_delete(t);

	return EXIT_FAILURE;
}
