/*-
 * Copyright (c) 2020 Domagoj Stolfa
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
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
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libutil.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#include "dtraced.h"
#include "dtraced_errmsg.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define LOCK_FILE                "/var/run/dtraced.pid"

#define NEXISTS                  0
#define EXISTS_CHANGED           1
#define EXISTS_EQUAL             2

char version_str[128];

/*
 * Awful global variable, but is here because of the signal handler.
 */
static struct dtd_state state;
static const char *program_name;
static unsigned long threadpool_size = 1;

static void
sig_term(int __unused signo)
{

	dump_debugmsg("SIGTERM, shutdown!");
	atomic_store(&state.shutdown, 1);
	SIGNAL(&state.joblistcv);
	SIGNAL(&state.killcv);
}

static void
sig_int(int __unused signo)
{

	dump_debugmsg("SIGINT, shutdown!");
	atomic_store(&state.shutdown, 1);
	SIGNAL(&state.joblistcv);
	SIGNAL(&state.killcv);
}

static void
sig_pipe(int __unused signo)
{
}

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s [-dhmOqvZ] [-D directory]\n", program_name);

	fprintf(stderr, "\n"
	    "\t-d  run dtraced in daemon mode.\n"
	    "\t-D  specify the directory to use for dtraced state.\n"
	    "\t-h  display this help page.\n"
	    "\t-m  run dtraced in 'minion' mode.\n"
	    "\t-O  run dtraced in 'overlord' mode.\n"
	    "\t-q  quiet mode.\n"
	    "\t-t  specify threadpool size.\n"
	    "\t-v  print dtraced version.\n"
	    "\t-Z  do not checksum DTrace programs when transmitting them.\n");
}

static char *
version(void)
{
	sprintf(version_str, "%u.%u.%u-%s", DTRACED_MAJOR, DTRACED_MINOR,
	    DTRACED_PATCH, DTRACED_EXTRA_IDENTIFIER);

	return (version_str);
}

static void
print_version(void)
{

	printf("dtraced: version %s", version());
}

int
main(int argc, char **argv)
{
	char elfpath[MAXPATHLEN] = "/var/ddtrace";
	__cleanup(closefd_generic) int efd = -1;
	int errval, retry, nosha = 0;
	size_t i;
	char ch;
	char pidstr[256];
	char hypervisor[128];
	int debug_mode = 0;
	size_t len = sizeof(hypervisor);
	size_t optlen;
	__cleanup(cleanup_pidfile) struct pidfh *pfh = NULL;
	pid_t otherpid;
	int ctrlmachine = -1;

	program_name = argv[0];

	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));
	memset(hypervisor, 0, sizeof(hypervisor));

	while ((ch = getopt(argc, argv, "D:Odhmvt:qZ")) != -1) {
		switch (ch) {
		case 'h':
			print_help();
			return (-1);

		case 'v':
			print_version();
			return (0);

		case 'D':
			optlen = strlen(optarg);
			strcpy(elfpath, optarg);
			strcpy(DTRACED_INBOUNDDIR, optarg);
			strcpy(DTRACED_INBOUNDDIR + optlen, "/inbound/");
			strcpy(DTRACED_OUTBOUNDDIR, optarg);
			strcpy(DTRACED_OUTBOUNDDIR + optlen, "/outbound/");
			strcpy(DTRACED_BASEDIR, optarg);
			strcpy(DTRACED_BASEDIR + optlen, "/base/");
			break;

		/*
		 * Run the daemon in 'overlord' mode. An overlord daemon in this
		 * case also spawns a minion thread which is going to spawn
		 * DTrace instances on the host in order to do the necessary
		 * linking.
		 */
		case 'O':
			if (sysctlbyname("kern.vm_guest", hypervisor, &len,
			    NULL, 0)) {
				dump_errmsg(
				    "Failed to get kern.vm_guest: %m");
				return (EX_OSERR);
			}

			if (strcmp(hypervisor, "none") != 0) {
				/*
				 * We are virtualized, so we can't be an
				 * overlord. Virtual machines don't have
				 * minions.
				 */
				dump_warnmsg(
				    "Specified '-O' (overlord mode) on a "
				    "virtual machine. This is not (really) "
				    "supported... Don't report bugs.");
			}

			ctrlmachine = 1;
			break;

		/*
		 * Run the daemon in 'minion' mode.
		 */
		case 'm':
			if (sysctlbyname("kern.vm_guest", hypervisor, &len,
			    NULL, 0)) {
				dump_errmsg(
				    "Failed to get kern.vm_guest: %m");
				return (EX_OSERR);
			}

			if (strcmp(hypervisor, "bhyve") != 0) {
				/*
				 * Warn the user that this makes very little
				 * sense on a non-virtualized machine...
				 *
				 * XXX: We only support bhyve for now.
				 */

				dump_warnmsg(
				    "Specified '-m' (minion mode) on a native "
				    "(bare metal) machine. Did you mean to make"
				    " this machine an overlord ('-O')?");
			}
			ctrlmachine = 0;
			break;

		case 'd':
			debug_mode = 1;
			break;

		case 't':
			optlen = strlen(optarg);
			threadpool_size = strtoul(optarg, optarg + optlen, 10);
			if (errno != 0) {
				dump_errmsg(
				    "Invalid argument (-t): failed to parse %s "
				    "as a number",
				    optarg);
				return (EXIT_FAILURE);
			}

			dump_debugmsg("Setting threadpool size to %lu",
			    threadpool_size);
			break;

		case 'Z':
			nosha = 1;
			break;

		case 'q':
			be_quiet();
			break;

		default:
			print_version();
			return (-1);
		}
	}

	pfh = pidfile_open(LOCK_FILE, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			dump_errmsg(
			    "dtraced is already running as pid %jd (check %s)",
			    (intmax_t)otherpid, LOCK_FILE);
			return (EX_OSERR);
		}

		dump_errmsg("Could not open %s: %m", LOCK_FILE);
		return (EX_OSERR);
	}

	if (ctrlmachine != 0 && ctrlmachine != 1) {
		dump_errmsg(
		    "You must either specify whether to run the daemon in "
		    "minion ('-m') or overlord ('-O') mode");
		return (EX_OSERR);
	}

	if (!debug_mode && daemon(0, 0) != 0) {
		dump_errmsg("Failed to daemonize %m");
		return (EX_OSERR);
	}

	if (pidfile_write(pfh)) {
		dump_errmsg("Failed to write PID to %s: %m", LOCK_FILE);
		return (EX_OSERR);
	}

againefd:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(elfpath, 0700) != 0)
				dump_errmsg("Failed to mkdir %s: %m", elfpath);
			else {
				retry = 1;
				goto againefd;
			}
		}

		dump_errmsg("Failed to open %s: %m", elfpath);
		return (EX_OSERR);
	}

	if (signal(SIGTERM, sig_term) == SIG_ERR) {
		dump_errmsg("Failed to install SIGTERM handler");
		return (EX_OSERR);
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		dump_errmsg("Failed to install SIGINT handler");
		return (EX_OSERR);
	}

	if (siginterrupt(SIGTERM, 1) != 0) {
		dump_errmsg(
		    "Failed to enable system call interrupts for SIGTERM");
		return (EX_OSERR);
	}

	errval = init_state(&state, ctrlmachine, nosha,
	    threadpool_size, (char **)argv);
	if (errval != 0) {
		dump_errmsg("Failed to initialize the state");
		return (EXIT_FAILURE);
	}

	if (listen_dir(state.outbounddir) == NULL) {
		dump_errmsg("listen_dir() on %s failed",
		    state.outbounddir->dirpath);
		return (EXIT_FAILURE);
	}

	errval = destroy_state(&state);
	if (errval != 0) {
		dump_errmsg("Failed to clean up state");
		return (EXIT_FAILURE);
	}

	return (0);
}
