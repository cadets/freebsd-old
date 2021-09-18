/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <assert.h>
#include <dt_elf.h>
#include <dt_prog_link.h>
#include <dt_resolver.h>
#include <dtrace.h>
#include <dttransport.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <libutil.h>
#include <limits.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <unistd.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define LOCK_FILE                "/var/run/dtraced.pid"
#define THREADPOOL_SIZE          4

#define NEXISTS                  0
#define EXISTS_CHANGED           1
#define EXISTS_EQUAL             2

char version_str[128];
struct dtd_state;

typedef struct pidlist {
	dt_list_t list; /* next element */
	pid_t pid;
} pidlist_t;

/*
 * Awful global variable, but is here because of the signal handler.
 */
static struct dtd_state state;
static int nosha = 0;

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

static void *
manage_children(void *_s)
{
	struct dtd_state *s = (struct dtd_state *)_s;
	pidlist_t *kill_entry;
	int status;

	while (atomic_load(&s->shutdown) == 0) {
		/*
		 * Wait for a notification that we need to kill a process
		 */
		LOCK(&s->killcvmtx);
		LOCK(&s->kill_listmtx);
		while (dt_list_next(&s->kill_list) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			UNLOCK(&s->kill_listmtx);
			WAIT(&s->killcv, pmutex_of(&s->killcvmtx));
			LOCK(&s->kill_listmtx);
		}
		UNLOCK(&s->kill_listmtx);
		UNLOCK(&s->killcvmtx);

		if (atomic_load(&s->shutdown) == 1)
			pthread_exit(_s);

		LOCK(&s->kill_listmtx);
		kill_entry = dt_list_next(&s->kill_list);
		if (kill_entry == NULL) {
			fprintf(stderr, "kill message pulled from under us");
			UNLOCK(&s->kill_listmtx);
			continue;
		}

		dt_list_delete(&s->kill_list, kill_entry);
		UNLOCK(&s->kill_listmtx);

		if (kill(kill_entry->pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH) {
				dump_errmsg("pid %d does not exist",
				    kill_entry->pid);
			}
		}

		free(kill_entry);
	}

	return (_s);
}

static void *
reap_children(void *_s)
{
	struct dtd_state *s = _s;
	int status, rv;

	for (;;) {
		sleep(30);
		do {
			rv = waitpid(-1, &status, WNOHANG);
		} while (rv != -1 && rv != 0);

		if (atomic_load(&s->shutdown) != 0)
			pthread_exit(_s);
	}
}

/*
 * Runs in its own thread. Reads ELF files from dttransport and puts them in
 * the inbound directory.
 */
static void *
listen_dttransport(void *_s)
{
	int err;
	int fd;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtt_entry_t e;
	char *path = NULL;
	char *elf = NULL;
	size_t len, offs;
	char donepath[MAXPATHLEN] = { 0 };
	uintptr_t aux1, aux2;
	size_t dirlen;
	size_t donepathlen;
	pidlist_t *kill_entry;

	err = 0;
	fd = 0;
	offs = len = 0;
	
	memset(&e, 0, sizeof(e));

	LOCK(&s->inbounddir->dirmtx);
	dirlen = strlen(s->inbounddir->dirpath);
	UNLOCK(&s->inbounddir->dirmtx);

	while (atomic_load(&s->shutdown) == 0) {
		if (read(s->dtt_fd, &e, sizeof(e)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			dump_errmsg("Failed to read an entry: %m");
			continue;
		}

		switch (e.event_kind) {
		case DTT_ELF:
			if (fd == -1)
				continue;

retry:
			/*
			 * At this point we have the /var/ddtrace/inbound
			 * open and created, so we can just create new files in
			 * it without too much worry of failure because
			 * directory does not exist.
			 */
			if (fd == 0) {
				LOCK(&s->inbounddir->dirmtx);
				path = gen_filename(s->inbounddir->dirpath);
				UNLOCK(&s->inbounddir->dirmtx);

				if (path == NULL) {
					dump_errmsg(
					    "gen_filename() failed with %s",
					    strerror(errno));
					goto retry;
				}
				fd = open(path, O_CREAT | O_WRONLY, 0600);

				if (fd == -1) {
					dump_errmsg("Failed to open %s: %m",
					    path);
					continue;
				}

				elf = malloc(e.u.elf.totallen);
				memset(elf, 0, e.u.elf.totallen);
				len = e.u.elf.totallen;
			}

			assert(offs < len);
			memcpy(elf + offs, e.u.elf.data, e.u.elf.len);
			offs += e.u.elf.len;

			if (e.u.elf.hasmore == 0) {
				if (write(fd, elf, len) < 0) {
					if (errno == EINTR)
						pthread_exit(s);

					dump_errmsg(
					    "Failed to write data to %s: %m",
					    path);
				}

				donepathlen = strlen(path) - 1;
				assert(donepathlen < MAXPATHLEN);
				memset(donepath, 0, donepathlen);
				memcpy(donepath, path, dirlen);
				memcpy(donepath + dirlen, path + dirlen + 1,
				    donepathlen - dirlen);

				if (rename(path, donepath)) {
					dump_errmsg(
					    "Failed to move %s to %s: %m", path,
					    donepath);
				}

				len = 0;
				offs = 0;
				free(elf);
				close(fd);
				free(path);
				donepathlen = 0;
				fd = 0;
				path = NULL;
			}
			break;
		case DTT_KILL:
			kill_entry = malloc(sizeof(pidlist_t));
			if (kill_entry == NULL)
				break;

			kill_entry->pid = e.u.kill.pid;
			LOCK(&s->kill_listmtx);
			dt_list_append(&s->kill_list, kill_entry);
			UNLOCK(&s->kill_listmtx);

			LOCK(&s->killcvmtx);
			SIGNAL(&s->killcv);
			UNLOCK(&s->killcvmtx);

			break;

		default:
			dump_errmsg("got unknown event (%d) from dttransport",
			    e.event_kind);
			break;
		}
	}

	pthread_exit(s);
}

static void *
write_dttransport(void *_s)
{
	ssize_t rval;
	int sockfd;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtt_entry_t e;
	size_t l, lentoread, len, totallen;
	struct sockaddr_un addr;
	dtd_initmsg_t initmsg;
	uint32_t identifier;
	dtraced_hdr_t header;
	ssize_t r;
	uintptr_t msg_ptr;
	unsigned char *msg;

	rval = 0;
	sockfd = 0;
	l = lentoread = len = totallen = 0;
	memset(&initmsg, 0, sizeof(initmsg));

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		dump_errmsg("Failed creating a socket: %m");
		pthread_exit(NULL);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		dump_errmsg("Failed setting addr.sun_path"
		    " to /var/ddtrace/sub.sock");
		sockfd = -1;
		pthread_exit(NULL);
	}

	SEMWAIT(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		dump_errmsg("connect to /var/ddtrace/sub.sock failed: %m");
		sockfd = -1;
		pthread_exit(NULL);
	}

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		pthread_exit(NULL);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		dump_errmsg("Expected dtraced kind, got %d",
		    initmsg.kind);
		close(sockfd);
		pthread_exit(NULL);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		dump_errmsg("Failed to write initmsg to sockfd: %m");
		pthread_exit(NULL);
	}


	while (atomic_load(&s->shutdown) == 0) {
		if ((rval = recv(sockfd, &len, sizeof(size_t), 0)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			dump_errmsg("Failed to recv from sub.sock: %m");
			continue;
		}

		msg = malloc(len);
		if (msg == NULL) {
			dump_errmsg("Failed to allocate a new message: %m");
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		totallen = len;
		identifier = arc4random();
		msg_ptr = (uintptr_t)msg;
		while ((r = recv(sockfd, (void *)msg_ptr, len, 0)) != len) {
			if (r < 0) {
				atomic_store(&s->shutdown, 1);
				pthread_exit(NULL);
			}

			len -= r;
			msg_ptr += r;
		}

		memcpy(&header, msg, DTRACED_MSGHDRSIZE);
		if (DTRACED_MSG_TYPE(header) != DTRACED_MSG_ELF) {
			dump_errmsg("Received unknown message type: %lu",
			    DTRACED_MSG_TYPE(header));
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		assert(DTRACED_MSG_TYPE(header) == DTRACED_MSG_ELF);

		msg_ptr = (uintptr_t)msg;
		msg += DTRACED_MSGHDRSIZE;

		totallen -= DTRACED_MSGHDRSIZE;
		len = totallen;
		while (len != 0) {
			memset(&e, 0, sizeof(e));
			lentoread = len > DTT_MAXDATALEN ? DTT_MAXDATALEN : len;

			e.event_kind = DTT_ELF;
			e.u.elf.identifier = identifier;
			e.u.elf.hasmore = len > DTT_MAXDATALEN ? 1 : 0;
			e.u.elf.len = lentoread;
			e.u.elf.totallen = totallen;
			memcpy(e.u.elf.data, msg, lentoread);

			if (write(s->dtt_fd, &e, sizeof(e)) < 0) {
				if (errno == EINTR)
					pthread_exit(s);
				/*
				 * If we don't have dttransport opened,
				 * we just move on. It might get opened
				 * at some point.
				 */
				continue;
			}

			len -= lentoread;
			msg += lentoread;

			assert(len >= 0 && len < totallen);
			assert((uintptr_t)msg >= msg_ptr);
			assert((uintptr_t)msg <=
			    (msg_ptr + totallen + DTRACED_MSGHDRSIZE));
		}

		assert(len == 0);

		free((void *)msg_ptr);
	}

	pthread_exit(s);
}

static int
setup_threads(struct dtd_state *s)
{
	int err;
	pthread_t *threads, *sockthread;
	size_t i;

	threads = malloc(sizeof(pthread_t) * THREADPOOL_SIZE);
	if (threads == NULL) {
		dump_errmsg("Failed to allocate thread array");
		return (-1);
	}
	memset(threads, 0, sizeof(pthread_t) * THREADPOOL_SIZE);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		err = pthread_create(&threads[i], NULL, process_joblist, s);
		if (err != 0) {
			dump_errmsg("Failed to create a new thread: %m");
			return (-1);
		}
	}

	s->workers = threads;

	sem_init(&s->socksema, 0, 0);

	if (s->ctrlmachine == 0) {
		err = pthread_create(
		    &s->dtt_listentd, NULL, listen_dttransport, s);
		if (err != 0) {
			dump_errmsg(
			    "Failed to create the dttransport thread: %m");
			return (-1);
		}

		/*
		 * The socket can't be connected at this point because
		 * accept_subs is not running. Need a semaphore.
		 */
		err = pthread_create(
		    &s->dtt_writetd, NULL, write_dttransport, s);
		if (err != 0) {
			dump_errmsg(
			    "Failed to create the dttransport thread: %m");
			return (-1);
		}
	}

	err = pthread_create(&s->socktd, NULL, process_consumers, s);
	if (err != 0) {
		dump_errmsg("Failed to create the socket thread: %m");
		return (-1);
	}

	err = pthread_create(&s->inboundtd, NULL, listen_dir, s->inbounddir);
	if (err != 0) {
		dump_errmsg("Failed to create inbound listening thread: %m");
		return (-1);
	}

	err = pthread_create(&s->basetd, NULL, listen_dir, s->basedir);
	if (err != 0) {
		dump_errmsg("Failed to create base listening thread: %m");
		return (-1);
	}

	err = pthread_create(&s->killtd, NULL, manage_children, s);
	if (err != 0) {
		dump_errmsg("Failed to create a child management thread: %m");
		return (-1);
	}

	err = pthread_create(&s->reaptd, NULL, reap_children, s);
	if (err != 0) {
		dump_errmsg("Failed to create reaper thread: %m");
		return (-1);
	}

	return (0);
}

static void
print_help(void)
{
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
	int efd, errval, rval, kq, retry;
	DIR *elfdir;
	size_t i;
	char ch;
	char pidstr[256];
	struct kevent ev, ev_data;
	struct dtd_state *retval;
	int optidx = 0;
	char hypervisor[128];
	int daemonize = 0;
	size_t len = sizeof(hypervisor);
	size_t optlen;
	struct pidfh *pfh;
	pid_t otherpid;
	int ctrlmachine = -1;

	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));
	memset(hypervisor, 0, sizeof(hypervisor));

	while ((ch = getopt(argc, argv, "D:Oa:de:hmvqZ")) != -1) {
		switch (ch) {
		case 'h':
			print_help();
			exit(0);

		case 'v':
			print_version();
			exit(0);

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

		case 'e':
			/*
			 * Option specifies that we want to ignore certain file
			 * names. We simply add them to the list of ignored
			 * names and later on when we notify our consumers check
			 * if it should be ignored.
			 */
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
				dump_errmsg(
				    "Specified '-O' (overlord mode) on a "
				    "virtual machine. This is not supported... "
				    "exiting.");

				exit(EXIT_FAILURE);
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
			daemonize = 1;
			break;

		case 'Z':
			nosha = 1;
			break;

		case 'q':
			be_quiet();
			break;

		default:
			break;
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

	state.ctrlmachine = ctrlmachine;
	state.pid_fileh = pfh;

	if (state.ctrlmachine != 0 && state.ctrlmachine != 1) {
		dump_errmsg(
		    "You must either specify whether to run the daemon in "
		    "minion ('-m') or overlord ('-O') mode");
		return (EX_OSERR);
	}

	if (daemonize && daemon(0, 0) != 0) {
		dump_errmsg("Failed to daemonize %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (pidfile_write(pfh)) {
		dump_errmsg("Failed to write PID to %s: %m", LOCK_FILE);
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

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
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	state.dirfd = efd;
	elfdir = fdopendir(efd);

	errval = init_state(&state);
	if (errval != 0) {
		dump_errmsg("Failed to initialize the state");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	state.nosha = nosha;

	if (signal(SIGTERM, sig_term) == SIG_ERR) {
		dump_errmsg("Failed to install SIGTERM handler");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		dump_errmsg("Failed to install SIGINT handler");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (siginterrupt(SIGTERM, 1) != 0) {
		dump_errmsg(
		    "Failed to enable system call interrupts for SIGTERM");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = setup_sockfd(&state);
	if (errval != 0) {
		dump_errmsg("Failed to set up the socket");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = file_foreach(
	    state.outbounddir->dir, populate_existing, state.outbounddir);
	if (errval != 0) {
		dump_errmsg("Failed to populate outbound existing files");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = file_foreach(
	    state.inbounddir->dir, populate_existing, state.inbounddir);
	if (errval != 0) {
		dump_errmsg("Failed to populate inbound existing files");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = file_foreach(
	    state.basedir->dir, populate_existing, state.basedir);
	if (errval != 0) {
		dump_errmsg("Failed to populate base existing files");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = setup_threads(&state);
	if (errval != 0) {
		dump_errmsg("Failed to set up threads");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (listen_dir(state.outbounddir) == NULL) {
		dump_errmsg("listen_dir() on %s failed",
		    state.outbounddir->dirpath);
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = pthread_kill(state.socktd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt socktd: %m");

	errval = pthread_join(state.socktd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join socktd: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_listentd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt dtt_listentd: %m");

	errval = pthread_join(state.dtt_listentd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join dtt_listentd: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_writetd, SIGTERM);
	if (errval != 0 && errval != ESRCH)
		dump_errmsg("Failed to interrupt dtt_writetd: %m");

	errval = pthread_join(state.dtt_writetd, (void **)&retval);
	if (errval != 0 && errval != ESRCH) {
		dump_errmsg("Failed to join dtt_writetd: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.inboundtd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt inboundtd: %m");

	errval = pthread_join(state.inboundtd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join inboundtd: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.basetd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt basetd: %m");

	errval = pthread_join(state.basetd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join basetd: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	LOCK(&state.joblistcvmtx);
	BROADCAST(&state.joblistcv);
	UNLOCK(&state.joblistcvmtx);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		errval = pthread_join(state.workers[i], (void **)&retval);
		if (errval != 0) {
			dump_errmsg("Failed to join threads: %m");
			if (pidfile_remove(pfh))
				dump_errmsg("Could not remove %s: %m",
				    LOCK_FILE);

			return (EX_OSERR);
		}
	}

	errval = pthread_kill(state.killtd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt killtd: %m");

	errval = pthread_join(state.killtd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join child management thread: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.reaptd, SIGTERM);
	if (errval != 0)
		dump_errmsg("Failed to interrupt reaptd: %m");

	errval = pthread_join(state.reaptd, (void **)&retval);
	if (errval != 0) {
		dump_errmsg("Failed to join reaper thread: %m");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}


	errval = destroy_state(&state);
	if (errval != 0) {
		dump_errmsg("Failed to clean up state");
		if (pidfile_remove(pfh))
			dump_errmsg("Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	if (closedir(elfdir))
		dump_errmsg("Could not close directory %s: %m", elfpath);

	if (close(efd))
		dump_errmsg("Could not close %s: %m", elfpath);

	if (pidfile_remove(pfh))
		dump_errmsg("Could not remove %s: %m", LOCK_FILE);

	return (0);
}
