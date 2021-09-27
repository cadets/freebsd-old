/*-
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
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

#include <dtraced.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

static const char *program_name;

enum {
	CLEANUP_STATE = 1000,
	HELP_PAGE,
	SHOW_STATS
};

static struct option longopts[] = {
	{ "cleanup-state",     optional_argument,    NULL,   	CLEANUP_STATE },
	{ "help"         ,     no_argument      ,    NULL,      HELP_PAGE     },
	{ "show-stats"   ,     optional_argument,    NULL,      SHOW_STATS    },
	{ NULL           ,     0                ,    NULL,      0             }
};

static void
print_help(void)
{
	fprintf(stderr, "Usage: %s\n"
	    "\t--cleanup-state  clean state in VM (all if not set).\n"
	    "\t--help           display this help page.\n"
	    "\t--show-stats     show statistics for a VM (all if not set).\n",
	    program_name);
}

int
main(int argc, const char **argv)
{
	int ch, show_all = 0, cleanup_all = 0;

	program_name = argv[0];

	while ((ch = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
		switch (ch) {
		case 0:
			break;

		case HELP_PAGE:
			print_help();
			break;

		case CLEANUP_STATE:
			if (optarg == NULL) {
				cleanup_all = 1;
				break;
			}
			break;

		case SHOW_STATS:
			if (optarg == NULL) {
				show_all = 1;
				break;
			}
			break;

		default:
			print_help();
			break;
		}
	}

	return (0);
}
