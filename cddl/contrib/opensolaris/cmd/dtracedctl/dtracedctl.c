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

#include <sys/socket.h>
#include <sys/un.h>

#include <errno.h>
#include <dtraced.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define __cleanup(fn) __attribute__((__cleanup__(fn)))

enum {
	CLEAN = 1,
	STAT
};

static const char *program_name;

enum {
	CLEANUP_STATE = 1000,
	HELP_PAGE,
	SHOW_STATS
};

static struct option longopts[] = {
	{ "cleanup-state",     optional_argument,    NULL,      CLEANUP_STATE },
	{ "help"         ,     no_argument      ,    NULL,      HELP_PAGE     },
	{ "show-stats"   ,     optional_argument,    NULL,      SHOW_STATS    },
	{ NULL           ,     0                ,    NULL,      0             }
};

typedef struct handle {
	int sockfd;
} handle_t;

typedef struct name {
	char   **str;
	size_t n_strs;
} names_t;

static void
freenames(names_t *name)
{
	size_t i;

	for (i = 0; i < name->n_strs; i++)
		free(name->str[i]);

	free(name->str);
}

static void
freehdl(handle_t *hdl)
{

	close(hdl->sockfd);
}

static names_t
parse_names(char *str)
{
	size_t num_commas = 0;
	char *c, **strings;
	size_t i = 0;

	/*
	 * We expect comma-separated names here. First, we will simply count
	 * them up.
	 */
	for (c = str; *c != '\0'; c++)
		if (*c == ',')
			num_commas++;

	strings = malloc((num_commas + 1) * sizeof(char *));
	if (strings == NULL)
		abort();

	c = str;
	/*
	 * For every comma (+ 1 for the last string or if no commas), terminate
	 * it with a NULL character and strdup it into our array.
	 */
	for (i = 0; i < num_commas + 1; i++) {
		c = strsep(&str, ",");

		strings[i] = strdup(c);
		if (strings[i] == NULL)
			abort();
	}

	return ((names_t) { .str = strings, .n_strs = num_commas + 1 });
}

/*
 * Debug printing function for names.
 */
static void
dprint_names(names_t *n)
{
	size_t i;

	if (n == NULL)
		return;

	fprintf(stderr, "names:\n");
	for (i = 0; i < n->n_strs; i++)
		fprintf(stderr, "\t- %s\n", n->str[i]);
}

static handle_t
open_dtraced(const char *sockpath)
{
	struct sockaddr_un addr;
	size_t l;
	dtd_initmsg_t initmsg;
	int sock;

	sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sock == -1) {
		fprintf(stderr, "Could not create a socket\n");
		abort();
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		fprintf(stderr, "strlcpy() failed: %zu >= %zu\n", l,
		    sizeof(addr.sun_path));
		abort();
	}

	if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		if (errno == ENOENT)
			fprintf(stderr,
			    "connect() failed: is dtraced running?\n");
		else
			fprintf(stderr,
			    "connect() failed: %s\n", strerror(errno));
		exit(EX_UNAVAILABLE);
	}

	if (recv(sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "recv() failed: %s\n", strerror(errno));
		abort();
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		fprintf(stderr, "received unknown kind: %x\n", initmsg.kind);
		abort();
	}

	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_READDATA;
	snprintf(initmsg.ident, DTRACED_FDIDENTLEN, "dtracedctl-%d", getpid());

	if (send(sock, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "send() failed: %s", strerror(errno));
		abort();
	}

	return ((handle_t) { .sockfd = sock });
}

static void
send_clean(handle_t *hdl, names_t *n)
{
	dtraced_hdr_t header;
	unsigned char data;
	size_t buflen, i, hdrlen;

	memset(&header, 0, sizeof(header));
	/*
	 * Prepare the header. If 'n_strs' is 0, it simply means "clean
	 * everything".
	 */
	DTRACED_MSG_TYPE(header)       = DTRACED_MSG_CLEANUP;
	DTRACED_MSG_NUMENTRIES(header) = n->n_strs;

	hdrlen = sizeof(header);
	if (send(hdl->sockfd, &hdrlen, sizeof(hdrlen), 0) < 0) {
		close(hdl->sockfd);
		fprintf(stderr, "send() failed: %s\n", strerror(errno));
		fprintf(stderr, "Consider restarting dtraced.\n");
		exit(EX_IOERR);
	}

	if (send(hdl->sockfd, &header, hdrlen, 0) < 0) {
		close(hdl->sockfd);
		fprintf(stderr, "send() failed: %s\n", strerror(errno));
		fprintf(stderr, "Consider restarting dtraced.\n");
		exit(EX_IOERR);
	}

	for (i = 0; i < n->n_strs; i++) {
		buflen = strlen(n->str[i]) + 1;

		if (send(hdl->sockfd, &buflen, sizeof(buflen), 0) < 0) {
			close(hdl->sockfd);
			fprintf(stderr, "send() failed: %s\n", strerror(errno));
			fprintf(stderr, "Consider restarting dtraced.\n");
			exit(EX_IOERR);
		}

		if (send(hdl->sockfd, n->str[i], buflen, 0) < 0) {
			close(hdl->sockfd);
			fprintf(stderr, "send() failed: %s\n", strerror(errno));
			fprintf(stderr, "Consider restarting dtraced.\n");
			exit(EX_IOERR);
		}
	}

	if (recv(hdl->sockfd, &data, 1, 0) < 0) {
		close(hdl->sockfd);
		fprintf(stderr, "recv() failed: %s\n", strerror(errno));
		fprintf(stderr, "Consider restarting dtraced.\n");
		exit(EX_IOERR);
	}

	if (data != 1) {
		close(hdl->sockfd);
		fprintf(stderr, "Data was NAK'd by dtraced... exiting.\n");
		exit(EX_UNAVAILABLE);
	}
}

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
	__cleanup(freenames) names_t names_to_stat  = { 0, 0 };
	__cleanup(freenames) names_t names_to_clean = { 0, 0 };
	int action = -1;
	__cleanup(freehdl) handle_t hdl = { 0 };

	program_name = argv[0];

	while ((ch = getopt_long(argc,
	    (char *const *)argv, "", longopts, NULL)) != -1) {
		switch (ch) {
		case 0:
			break;

		case HELP_PAGE:
			print_help();
			return (EX_OK);

		case CLEANUP_STATE:
			if (action != -1) {
				print_help();
				return (EX_USAGE);
			}

			action = CLEAN;
			if (optarg == NULL) {
				cleanup_all = 1;
				break;
			}

			names_to_clean = parse_names(optarg);
			break;

		case SHOW_STATS:
			if (action != -1) {
				print_help();
				return (EX_USAGE);
			}

			if (optarg == NULL) {
				show_all = 1;
				break;
			}

			action = STAT;
			names_to_stat = parse_names(optarg);
			break;

		default:
			print_help();
			return (EXIT_FAILURE);
		}
	}

	hdl = open_dtraced(DTRACED_SOCKPATH);

	switch (action) {
	case CLEAN:
		send_clean(&hdl, &names_to_clean);
		break;

	case STAT:
		break;

	default:
		print_help();
		break;
	}

	return (EX_OK);
}
