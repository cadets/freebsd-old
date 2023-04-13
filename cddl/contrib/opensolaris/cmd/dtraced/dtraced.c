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
static struct dtraced_state state;
static const char *program_name;
static unsigned long threadpool_size = 1;

static void
sig_term(int __unused signo)
{

	atomic_store(&state.shutdown, 1);
	SIGNAL(&state.joblistcv);
	SIGNAL(&state.killcv);
}

static void
sig_int(int __unused signo)
{

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
	    "\t-d  run dtraced in debug (foreground) mode.\n"
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
main(int argc, const char **argv)
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
	int ctrlmachine = 1; /* default to control machine (-O) */
	char *end;

	program_name = argv[0];

	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));

	if (sysctlbyname("kern.vm_guest", hypervisor, &len, NULL, 0)) {
		ERR("%d: %s(): Failed to get kern.vm_guest: %m", __LINE__, __func__);
		return (EX_OSERR);
	}

	/* If we're running under bhyve, assume minion mode */
	if (strcmp(hypervisor, "bhyve") == 0)
		ctrlmachine = 0;

	if (ctrlmachine == 0)
		DEBUG("%d: %s(): Running in minion mode.", __LINE__, __func__);
	else
		DEBUG("%d: %s(): Running in overlord mode.", __LINE__,
		    __func__);

	while ((ch = getopt(argc, (char *const *)argv, "D:Odhmvt:qZ")) != -1) {
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
			if (strcmp(hypervisor, "none") != 0) {
				/*
				 * We are virtualized, so we can't be an
				 * overlord. Virtual machines don't have
				 * minions.
				 */
				WARN(
				    "%d: %s(): Specified '-O' (overlord mode) "
				    "on a virtual machine. This is not (really)"
				    " supported... Don't report bugs.",
				    __LINE__, __func__);
			}

			ctrlmachine = 1;
			break;

		/*
		 * Run the daemon in 'minion' mode.
		 */
		case 'm':
			if (strcmp(hypervisor, "none") == 0) {
				/*
				 * Warn the user that this makes very little
				 * sense on a non-virtualized machine...
				 *
				 * XXX: We only support bhyve for now.
				 */
				WARN(
				    "%d: %s(): Specified '-m' (minion mode) on "
				    "a native (bare metal) machine. Did you "
				    "mean to make this machine an "
				    "overlord ('-O')?",
				    __LINE__, __func__);
			}
			ctrlmachine = 0;
			break;

		case 'd':
			debug_mode = 1;
			break;

		case 't':
			optlen = strlen(optarg);
			threadpool_size = strtoul(optarg, &end, 10);
			if (errno != 0) {
				ERR("%d: %s(): Invalid argument (-t): "
				    "failed to parse %s as a number",
				    __LINE__, __func__, optarg);
				return (EXIT_FAILURE);
			}

			DEBUG("%d: %s(): Setting threadpool size to %lu",
			    __LINE__, __func__, threadpool_size);
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
			ERR("%d: %s(): dtraced is already running as pid %jd (check %s)",
			    __LINE__, __func__, (intmax_t)otherpid, LOCK_FILE);
			return (EX_OSERR);
		}

		ERR("%d: %s(): Could not open %s: %m", __LINE__, __func__,
		    LOCK_FILE);
		return (EX_OSERR);
	}

	if (ctrlmachine != 0 && ctrlmachine != 1) {
		ERR("%d: %s(): You must either specify whether to run the daemon in "
		    "minion ('-m') or overlord ('-O') mode",
		    __LINE__, __func__);
		return (EX_OSERR);
	}

	if (!debug_mode && daemon(0, 0) != 0) {
		ERR("%d: %s(): Failed to daemonize %m", __LINE__, __func__);
		return (EX_OSERR);
	}

	if (pidfile_write(pfh)) {
		ERR("%d: %s(): Failed to write PID to %s: %m", __LINE__,
		    __func__, LOCK_FILE);
		return (EX_OSERR);
	}

againefd:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(elfpath, 0700) != 0)
				ERR("%d: %s(): Failed to mkdir %s: %m",
				    __LINE__, __func__, elfpath);
			else {
				retry = 1;
				goto againefd;
			}
		}

		ERR("%d: %s(): Failed to open %s: %m", __LINE__, __func__,
		    elfpath);
		return (EX_OSERR);
	}

	if (signal(SIGTERM, sig_term) == SIG_ERR) {
		ERR("%d: %s(): Failed to install SIGTERM handler", __LINE__,
		    __func__);
		return (EX_OSERR);
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		ERR("%d: %s(): Failed to install SIGINT handler", __LINE__,
		    __func__);
		return (EX_OSERR);
	}

	if (siginterrupt(SIGTERM, 1) != 0) {
		ERR("%d: %s(): Failed to enable system call interrupts for SIGTERM",
		    __LINE__, __func__);
		return (EX_OSERR);
	}

	errval = init_state(&state, ctrlmachine, nosha,
	    threadpool_size, argv);
	if (errval != 0) {
		ERR("%d: %s(): Failed to initialize the state", __LINE__,
		    __func__);
		return (EXIT_FAILURE);
	}

	if (listen_dir(state.outbounddir) == NULL) {
		ERR("%d: %s(): listen_dir() on %s failed", __LINE__, __func__,
		    state.outbounddir->dirpath);
		return (EXIT_FAILURE);
	}

	errval = destroy_state(&state);
	if (errval != 0) {
		ERR("%d: %s(): Failed to clean up state", __LINE__, __func__);
		return (EXIT_FAILURE);
	}

	return (0);
}
