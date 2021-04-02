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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/event.h>

#include <dtrace.h>
#include <dt_elf.h>
#include <dt_resolver.h>

#include "dtdaemon.h"
#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <limits.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>
#include <pthread.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <dirent.h>
#include <getopt.h>
#include <semaphore.h>

#include <dttransport.h>

#include <openssl/sha.h>

#include <spawn.h>
#include <dt_prog_link.h>

#define	DTDAEMON_INBOUNDDIR	"/var/ddtrace/inbound/"
#define	DTDAEMON_OUTBOUNDDIR	"/var/ddtrace/outbound/"
#define	DTDAEMON_BASEDIR	"/var/ddtrace/base/"

#define	LOCK_FILE	"/var/dtdaemon.lock"
#define	SOCKFD_NAME	"sub.sock"
#define	THREADPOOL_SIZE	4

#define	NEXISTS		0
#define	EXISTS_CHANGED	1
#define	EXISTS_EQUAL	2

/*
 * Macros with sanity checks. This should be used everywhere in dtdaemon.
 */
#define	LOCK(m) {						\
	int err;						\
	err = pthread_mutex_lock(m);				\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to lock mutex: %m");	\
	}							\
	}
#define	UNLOCK(m) {						\
	int err;						\
	err = pthread_mutex_unlock(m);				\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to unlock mutex: %m");	\
	}							\
	}

#define	SIGNAL(c) {						\
	int err;						\
	err = pthread_cond_signal(c);				\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to signal cv: %m");	\
	}							\
	}

#define	WAIT(c, m) {						\
	int err;						\
	err = pthread_cond_wait(c, m);				\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to wait for cv: %m");	\
	}							\
	}

#define	BROADCAST(c) {						\
	int err;						\
	err = pthread_cond_broadcast(c);			\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to broadcast cv: %m");	\
	}							\
	}

#define	SWAIT(s) {						\
	int err;						\
	err = sem_wait(s);					\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to wait for sema: %m");	\
	}							\
	}

#define	SPOST(s) {						\
	int err;						\
	err = sem_post(s);					\
	if (err != 0) {						\
		syslog(LOG_ERR, "Failed to post for sema: %m");	\
	}							\
	}


struct dtd_state;
struct dtd_dir;
typedef int (*foreach_fn_t)(struct dirent *, struct dtd_dir *);

typedef struct dtd_dir {
	char			*dirpath;
	int			dirfd;
	DIR			*dir;

	char			**existing_files;
	size_t			efile_size;
	size_t			efile_len;

	pthread_mutex_t		dirmtx;

	foreach_fn_t		processfn;

	struct dtd_state	*state;
} dtd_dir_t;

static int	file_foreach(DIR *, foreach_fn_t, dtd_dir_t *);
static int	process_outbound(struct dirent *, dtd_dir_t *);
static int	process_inbound(struct dirent *, dtd_dir_t *);

/*
 * dtdaemon state structure. This contains everything relevant to dtdaemon's
 * state management, such as files that exist, connected sockets, etc.
 */
struct dtd_state {
	dtd_dir_t	*inbounddir;
	dtd_dir_t	*outbounddir;
	dtd_dir_t	*basedir;

	pthread_t	inboundtd;
	pthread_t	basetd;

	/*
	 * Sockets.
	 */
	pthread_mutex_t	socklistmtx;
	dt_list_t	sockfds;

	/*
	 * Configuration socket.
	 */
	pthread_mutex_t	sockmtx;
	pthread_t	socktd;
	int		sockfd;
	sem_t		socksema;

	/*
	 * dttransport fd and threads
	 */
	int		dtt_fd;
	pthread_t	dtt_listentd;
	pthread_t	dtt_writetd;

	/*
	 * Thread pool management.
	 */
	pthread_t	*workers;
	pthread_mutex_t	joblistcvmtx;
	pthread_cond_t	joblistcv;
	pthread_mutex_t	joblistmtx;
	dt_list_t	joblist;

	/*
	 * Are we shutting down?
	 */
	int		shutdown;

	/*
	 * File descriptor of /var/ddtrace
	 */
	int		dirfd;

	/*
	 * In case we don't want checksumming.
	 */
	int		nosha;

	int		lockfd;
};

struct dtd_fdlist {
	dt_list_t	list;
	int		fd;
	int		kind;
};

struct dtd_joblist {
	dt_list_t	list;

#define	NOTIFY_ELFWRITE	1
	int		job;

	union {
		struct {
			int		connsockfd;
			size_t		pathlen;
			char		*path;
			dtd_dir_t	*dir;
			int		nosha;
		} notify_elfwrite;
	} j;
};

/*
 * Awful global variable, but is here because of the signal handler.
 */
static struct dtd_state state;
static int nosha = 0;
static int g_ctrlmachine = -1;

static const struct option long_opts[] = {
	{"help",		no_argument,		NULL,		0},
	{"exclude",		required_argument,	NULL,		'e'},
	{"version",		no_argument,		NULL,		'v'},
	{"no-checksum",		no_argument,		&nosha,		1},
	{"ctrl-machine",	no_argument,		&g_ctrlmachine,	1},
	{"not-ctrl-machine",	no_argument,		&g_ctrlmachine,	0},
	{0,			0,			0,		0}
};

static void
sig_hdlr(int signo)
{
	if (signo == SIGTERM)
		state.shutdown = 1;
	if (signo == SIGINT)
		state.shutdown = 1;
	if (signo == SIGPIPE)
		return;
}

/*
 * Used for generating a random name of the outbound ELF file.
 */
static void
get_randname(char *b, size_t len)
{
	size_t i;

	/*
	 * Generate lower-case random characters.
	 */
	for (i = 0; i < len; i++)
		b[i] = arc4random_uniform(25) + 97;
}

static char *
gen_filename(const char *dir)
{
	char *filename;
	char *elfpath;
	size_t len;

	len = (MAXPATHLEN - strlen(dir)) / 64;
	assert(len > 10);

	filename = malloc(len);
	if (filename == NULL)
		return (NULL);
	
	filename[0] = '.';
	get_randname(filename + 1, len - 2);
	filename[len - 1] = '\0';

	elfpath = malloc(MAXPATHLEN);
	strcpy(elfpath, dir);
	strcpy(elfpath + strlen(dir), filename);

	while (access(elfpath, F_OK) != -1) {
		filename[0] = '.';
		get_randname(filename + 1, len - 2);
		filename[len - 1] = '\0';
		strcpy(elfpath + strlen(dir), filename);
	}

	free(filename);

	return (elfpath);
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

	err = 0;
	fd = 0;
	offs = len = 0;
	
	memset(&e, 0, sizeof(e));

	dirlen = strlen(s->inbounddir->dirpath);

	while (s->shutdown == 0) {
		if (read(s->dtt_fd, &e, sizeof(e)) < 0) {
			if (errno == EINTR && s->shutdown == 1)
				pthread_exit(s);

			syslog(LOG_ERR, "Failed to read an entry: %m");
			continue;
		}

		if (fd == -1)
			continue;

	retry:
		/*
		 * At this point we have the /var/ddtrace/inbound
		 * open and created, so we can just create new files in it
		 * without too much worry of failure because directory does
		 * not exist.
		 */
		if (fd == 0) {
			path = gen_filename(s->inbounddir->dirpath);
			if (path == NULL) {
				syslog(LOG_ERR, "gen_filename() failed with %s\n",
				    strerror(errno));
				goto retry;
			}
			fd = open(path, O_CREAT | O_WRONLY, 0600);

			if (fd == -1) {
				syslog(LOG_ERR, "Failed to open %s%s: %m",
				    s->inbounddir->dirpath, path);
				continue;
			}

			elf = malloc(e.totallen);
			memset(elf, 0, e.totallen);
			len = e.totallen;
		}

		assert(offs < len);
		memcpy(elf + offs, e.data, e.len);
		offs += e.len;

		if (e.hasmore == 0) {
			if (write(fd, elf, len) < 0) {
				if (errno == EINTR && s->shutdown == 1)
					pthread_exit(s);

				syslog(LOG_ERR,
				    "Failed to write data to %s: %m", path);
			}

 			donepathlen = strlen(path) - 1;
			memset(donepath, 0, donepathlen);
			memcpy(donepath, path, dirlen);
			memcpy(donepath + dirlen, path + dirlen + 1,
			    donepathlen - dirlen);

			if (rename(path, donepath)) {
				syslog(LOG_ERR, "Failed to move %s to %s: %m",
				    path, donepath);
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
	int kind;

	rval = 0;
	sockfd = 0;
	l = lentoread = len = totallen = 0;
	kind = 0;

	sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (sockfd == -1) {
		syslog(LOG_ERR, "Failed creating a socket: %m");
		pthread_exit(NULL);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTDAEMON_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		syslog(LOG_ERR, "Failed setting addr.sun_path"
		    " to /var/ddtrace/sub.sock");
		sockfd = -1;
		pthread_exit(NULL);
	}

	SWAIT(&s->socksema);

	if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		syslog(LOG_ERR, "connect to /var/ddtrace/sub.sock failed: %m");
		sockfd = -1;
		pthread_exit(NULL);
	}

	if (recv(sockfd, &kind, sizeof(kind), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		pthread_exit(NULL);
	}

	if (kind != DTDAEMON_KIND_DTDAEMON) {
		syslog(LOG_ERR, "Expected dtdaemon kind, got %d\n", kind);
		close(sockfd);
		pthread_exit(NULL);
	}

	kind = DTDAEMON_KIND_FORWARDER;
	if (send(sockfd, &kind, sizeof(kind), 0) < 0) {
		syslog(LOG_ERR, "Failed to write %d to sockfd: %m",
		    kind);
		pthread_exit(NULL);
	}

	while (s->shutdown == 0) {
		if ((rval = recv(sockfd, &len, sizeof(size_t), 0)) < 0) {
			if (errno == EINTR && s->shutdown == 1)
				pthread_exit(s);
			
			syslog(LOG_ERR, "Failed to recv from sub.sock: %m");
			continue;
		}

		totallen = len;

		while (len != 0) {
			memset(&e, 0, sizeof(e));
			lentoread = len > DTT_MAXDATALEN ? DTT_MAXDATALEN : len;

			if ((rval = recv(sockfd, e.data, lentoread, 0)) < 0) {
				if (errno == EINTR && s->shutdown == 1)
					pthread_exit(s);
				/*
				 * If the device is not configured, we don't
				 * actually care to report an error here.
				 */
				if (errno != ENXIO)
					syslog(LOG_ERR,
					    "Failed to recv from sub.sock: %m");
				continue;
			}

			e.hasmore = len > DTT_MAXDATALEN ? 1 : 0;
			e.len = lentoread;
			e.totallen = totallen;

			if (write(s->dtt_fd, &e, sizeof(e)) < 0) {
				if (errno == EINTR && s->shutdown == 1)
					pthread_exit(s);
	/*
				 * If we don't have dttransport opened,
				 * we just move on. It might get opened
				 * at some point.
				 */
				continue;
			}

			len -= lentoread;
		}
	}

	pthread_exit(s);
}

static void *
listen_dir(void *_dir)
{
	int err, kq, rval;
	struct kevent ev, ev_data;
	struct dtd_state *s;
	dtd_dir_t *dir;

	dir = (dtd_dir_t *)_dir;
	s = dir->state;

	rval = err = kq = 0;

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "Failed to create a kqueue %m");
		pthread_exit(NULL);
	}

	EV_SET(&ev, dir->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE, 0, (void *)dir);

	for (;;) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			if (errno == EINTR && s->shutdown == 1)
				pthread_exit(s);

			syslog(LOG_ERR, "kevent() failed with %m");
			continue;
		}

		if (ev_data.flags == EV_ERROR) {
			syslog(LOG_ERR, "kevent() got EV_ERROR with %m");
			continue;
		}

		if (rval > 0) {
			err = file_foreach(dir->dir, dir->processfn, dir);
			if (err) {
				syslog(LOG_ERR, "Failed to process new files");
				pthread_exit(NULL);
			}
		}
	}

	pthread_exit(s);
}

static void *
process_joblist(void *_s)
{
	int err;
	int _nosha;
	int fd;
	int elffd;
	int i;
	char *path;
	char *contents, *msg;
	size_t msglen;
	size_t pathlen;
	size_t elflen;
	struct dtd_joblist *curjob;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtd_dir_t *dir;
	struct stat stat;

	_nosha = s->nosha;
	dir = NULL;
	memset(&stat, 0, sizeof(stat));

	while (s->shutdown == 0) {
		LOCK(&s->joblistcvmtx);
		while (dt_list_next(&s->joblist) == NULL && s->shutdown == 0) {
			WAIT(&s->joblistcv, &s->joblistcvmtx);
		}
		UNLOCK(&s->joblistcvmtx);
		if (s->shutdown == 1)
			break;

		LOCK(&s->joblistmtx);
		curjob = dt_list_next(&s->joblist);
		if (curjob == NULL) {
			/*
			 * It is possible that another thread already picked
			 * this job up, in which case we simply loop again.
			 */
			UNLOCK(&s->joblistmtx);
			continue;
		}

		dt_list_delete(&s->joblist, curjob);
		UNLOCK(&s->joblistmtx);

		switch (curjob->job) {
		case NOTIFY_ELFWRITE:
			fd = curjob->j.notify_elfwrite.connsockfd;
			path = curjob->j.notify_elfwrite.path;
			pathlen = curjob->j.notify_elfwrite.pathlen;
			dir = curjob->j.notify_elfwrite.dir;
			_nosha = curjob->j.notify_elfwrite.nosha;

			/*
			 * Sanity assertions.
			 */
			assert(fd != -1);
			assert(path != NULL);
			assert(pathlen <= MAXPATHLEN);

			assert(dir->dirfd != -1);

			elffd = openat(dir->dirfd, path, O_RDONLY);
			if (elffd == -1) {
				syslog(LOG_ERR, "Failed to open %s: %m", path);
				free(path);
				break;
			}

			if (fstat(elffd, &stat) != 0) {
				syslog(LOG_ERR, "Failed to fstat %s: %m", path);
				free(path);
				close(elffd);
				break;
			}

			elflen = stat.st_size;
			msglen = _nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
			msg = malloc(msglen);

			if (msg == NULL) {
				syslog(LOG_ERR, "Failed to malloc ELF contents: %m");
				free(path);
				close(elffd);
				break;
			}

			memset(msg, 0, msglen);
			contents = _nosha ? msg : msg + SHA256_DIGEST_LENGTH;
			
			if (read(elffd, contents, elflen) < 0) {
				syslog(LOG_ERR, "Failed to read ELF contents: %m");
				free(path);
				free(msg);
				close(elffd);
				break;
			}

			if (_nosha == 0 &&
			    SHA256(contents, elflen, msg) == NULL) {
				syslog(LOG_ERR, "Failed to create a SHA256 of the file");
				free(path);
				free(msg);
				close(elffd);
				break;
			}

			if (send(fd, &msglen, sizeof(msglen), 0) < 0) {
				if (errno == EPIPE) {
					/*
					 * Get the entry from a socket list to
					 * delete it. This is a bit "slow", but
					 * should be happening rarely enough
					 * that we don't really care. A small
					 * delay here is acceptable, as most
					 * consumers of this event will open the
					 * path sent to them and process the ELF
					 * file.
					 */
					LOCK(&s->socklistmtx);
					fde = dt_in_list(&s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						break;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d (%zu): %m",
					    fd, msglen);
			}

			if (send(fd, msg, msglen, 0) < 0) {
				if (errno == EPIPE) {
					/*
					 * Get the entry from a socket list to
					 * delete it. This is a bit "slow", but
					 * should be happening rarely enough
					 * that we don't really care. A small
					 * delay here is acceptable, as most
					 * consumers of this event will open the
					 * path sent to them and process the ELF
					 * file.
					 */
					LOCK(&s->socklistmtx);
					fde = dt_in_list(&s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						break;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d (%s, %zu): %m",
					    fd, path, pathlen);
			}

			free(path);
			free(msg);
			close(elffd);
			break;

		default:
			pthread_exit(NULL);
		}

		free(curjob);
	}

	pthread_exit(s);
}

static void *
accept_subs(void *_s)
{
	int err;
	int kind;
	int connsockfd;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;

	kind = 0;

	/*
	 * Sanity checks on the state.
	 */
	if (s == NULL)
		pthread_exit(NULL);

	if (s->socktd == NULL)
		pthread_exit(NULL);

	if (s->sockfd == -1)
		pthread_exit(NULL);

	err = listen(s->sockfd, SHA256_DIGEST_LENGTH);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to listen on %d: %m", s->sockfd);
		pthread_exit(NULL);
	}

	SPOST(&s->socksema);

	while (s->shutdown == 0) {
		connsockfd = accept(s->sockfd, NULL, 0);
		if (connsockfd == -1) {
			/*
			 * EINTR will only happen if a signal was received.
			 * The only time we really expect a signal to be
			 * received on this thread is when we explicitly
			 * call pthread_kill() on shutdown.
			 */
			if (errno == EINTR && state.shutdown == 1)
				goto exit;

			syslog(LOG_ERR, "Failed to accept a connection: %m");
			pthread_exit(NULL);
		}

		kind = DTDAEMON_KIND_DTDAEMON;
		if (send(connsockfd, &kind, sizeof(kind), 0) < 0) {
			fprintf(stderr, "Failed to send %zu to connsockfd: %s",
			    kind, strerror(errno));
			pthread_exit(NULL);
		}

		kind = 0;
		if (recv(connsockfd, &kind, sizeof(kind), 0) < 0) {
			free(fde);
			syslog(LOG_ERR, "Failed to read what kind of subscriber"
			    " is being accepted: %m");
			pthread_exit(NULL);
		}

		fde = malloc(sizeof(struct dtd_fdlist));
		if (fde == NULL) {
			syslog(LOG_ERR, "Failed to malloc a fdlist entry");
			pthread_exit(NULL);
		}
		
		memset(fde, 0, sizeof(struct dtd_fdlist));
		fde->fd = connsockfd;
		fde->kind = kind;

		LOCK(&s->socklistmtx);
		dt_list_append(&s->sockfds, fde);
		UNLOCK(&s->socklistmtx);
	}

exit:
	pthread_exit(s);
}

static int
setup_sockfd(struct dtd_state *s)
{
	int err;
	struct sockaddr_un addr;
	size_t l;
	
	s->sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if (s->sockfd == -1) {
		syslog(LOG_ERR, "Failed to create unix: %m");
		return (-1);
	}

	memset(&addr, 0, sizeof(addr));

	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTDAEMON_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		syslog(LOG_ERR,
		    "Failed to copy %s into sockaddr (%zu)",
		    DTDAEMON_SOCKPATH, l);
		s->sockfd = -1;
		err = pthread_mutex_destroy(&s->sockmtx);
		if (err != 0)
			syslog(LOG_ERR, "Failed to destroy sockmtx: %m");

		return (-1);
	}

	err = bind(s->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		syslog(LOG_ERR, "Failed to bind to %d: %m", s->sockfd);
		if (close(s->sockfd) != 0) {
			syslog(LOG_ERR, "Failed to close %d: %m", s->sockfd);
			return (-1);
		}

		s->sockfd = -1;
		err = pthread_mutex_destroy(&s->sockmtx);
		if (err != 0)
			syslog(LOG_ERR, "Failed to destroy sockmtx: %m");

		return (-1);
	}

	return (0);
}

static int
destroy_sockfd(struct dtd_state *s)
{
	int err;

	if (close(s->sockfd) != 0) {
		syslog(LOG_ERR, "Failed to close %d: %m", s->sockfd);
		return (-1);
	}

	s->sockfd = -1;

	if (unlink(DTDAEMON_SOCKPATH) != 0)
		syslog(LOG_ERR, "Failed to unlink %s: %m", DTDAEMON_SOCKPATH);

	return (0);
}

static int
findpath(const char *p, dtd_dir_t *dir)
{
	int i;
	
	for (i = 0; i < dir->efile_len; i++) {
		if (strcmp(p, dir->existing_files[i]) == 0)
			return (i);
	}

	return (-1);
}

static int
expand_paths(dtd_dir_t *dir)
{
	char **newpaths;
	struct dtd_state *s;

	if (dir == NULL) {
		syslog(LOG_ERR, "Expand paths called with dir == NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		syslog(LOG_ERR, "Expand paths called with state == NULL");
		return (-1);
	}

	if (dir->efile_size <= dir->efile_len) {
		dir->efile_size = dir->efile_size == 0 ?
		    16 : (dir->efile_size << 1);

		/*
		 * Assert sanity after we multiply the size by two.
		 */
		if (dir->efile_size <= dir->efile_len) {
			syslog(LOG_ERR, "dir->efile_size <= dir->efile_len"
			    " (%zu <= %zu)\n", dir->efile_size, dir->efile_len);
			return (-1);
		}

		/*
		 * Copy over the pointers to paths that were previously
		 * allocated in the old array.
		 */
		newpaths = malloc(dir->efile_size * sizeof(char *));
		if (newpaths == NULL) {
			syslog(LOG_ERR, "Failed to malloc newpaths");
			return (-1);
		}

		memset(newpaths, 0, dir->efile_size * sizeof(char *));
		if (dir->existing_files) {
			memcpy(newpaths, dir->existing_files,
			    dir->efile_len * sizeof(char *));
			free(dir->existing_files);
		}

		dir->existing_files = newpaths;
	}

	return (0);
}

static int
process_inbound(struct dirent *f, dtd_dir_t *dir)
{
	int err;
	struct dtd_fdlist *fd_list;
	struct dtd_joblist *job;
	struct dtd_state *s;
	int idx;
	pid_t pid, parent;
	char fullpath[MAXPATHLEN] = { 0 };
	int status;
	size_t l, dirpathlen, filepathlen;
	char *argv[4] = { 0 };

	status = 0;
	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL");
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	idx = findpath(f->d_name, dir);
	if (idx >= 0)
		return (0);

	l = strlcpy(fullpath, dir->dirpath, sizeof(fullpath));
	if (l >= sizeof(fullpath)) {
		syslog(LOG_ERR, "Failed to copy %s into a path string",
		    dir->dirpath);
		return (-1);
	}

	dirpathlen = strlen(dir->dirpath);
	l = strlcpy(fullpath + dirpathlen,
	    f->d_name, sizeof(fullpath) - dirpathlen);
	if (l >= sizeof(fullpath) - dirpathlen) {
		syslog(LOG_ERR, "Failed to copy %s into a path string",
		    f->d_name);
		return (-1);
	}
	filepathlen = strlen(fullpath);

	assert(g_ctrlmachine == 1 || g_ctrlmachine == 0);
	if (g_ctrlmachine == 1) {
		/*
		 * If we have a host configuration of dtdaemon
		 * we simply send off the ELF file to dtrace(1).
		 *
		 * We iterate over all our known dtrace(1)s that have
		 * registered with dtdaemon and send off the file path
		 * to them. They will parse said file path (we assume
		 * they won't be writing over it since this requires root
		 * anyway) and decide if the file is meant for them to
		 * process. There may be more dtrace(1) instances that
		 * want to process the same file in the future.
		 */
		LOCK(&s->socklistmtx);
		for (fd_list = dt_list_next(&s->sockfds);
		    fd_list; fd_list = dt_list_next(fd_list)) {
			if (fd_list->kind != DTDAEMON_KIND_CONSUMER)
				continue;
			
			job = malloc(sizeof(struct dtd_joblist));
			if (job == NULL) {
				syslog(LOG_ERR, "Failed to malloc a new job");
				UNLOCK(&s->socklistmtx);
				return (-1);
			}
			
			memset(job, 0, sizeof(struct dtd_joblist));
			job->job = NOTIFY_ELFWRITE;
			job->j.notify_elfwrite.connsockfd = fd_list->fd;
			job->j.notify_elfwrite.path = strdup(f->d_name);
			job->j.notify_elfwrite.pathlen = strlen(f->d_name);
			job->j.notify_elfwrite.dir = dir;
			job->j.notify_elfwrite.nosha = 1;

			LOCK(&s->joblistmtx);
			dt_list_append(&s->joblist, job);
			UNLOCK(&s->joblistmtx);

			LOCK(&s->joblistcvmtx);
			SIGNAL(&s->joblistcv);
			UNLOCK(&s->joblistcvmtx);
		}
		UNLOCK(&s->socklistmtx);
	} else {
		parent = getpid();
		pid = fork();

		if (pid == -1) {
			syslog(LOG_ERR, "Failed to fork: %m");
			return (-1);
		} else if (pid > 0)
			waitpid(pid, &status, 0);
		else {
			argv[0] = strdup("/usr/sbin/dtrace");
			argv[1] = strdup("-Y");
			argv[2] = strdup(fullpath);
			argv[3] = NULL;
			execve("/usr/sbin/dtrace", argv, NULL);
			exit(EXIT_FAILURE);
		}
	}

	err = expand_paths(dir);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);

	return (0);
}

static void
dtdaemon_copyfile(const char *src, const char *dst)
{
	int fd, newfd;
	struct stat sb;
	void *buf;
	size_t len, donepathlen, dirlen;
	char donepath[MAXPATHLEN] = { 0 };

	memset(&sb, 0, sizeof(struct stat));

	fd = open(src, O_RDONLY);
	if (fd == -1)
		syslog(LOG_ERR, "Failed to open %s: %m", src);
	
	if (fstat(fd, &sb)) {
		syslog(LOG_ERR, "Failed to fstat %s (%d): %m", src, fd);
		close(fd);
		return;
	}

	len = sb.st_size;
	buf = malloc(len);

	if (read(fd, buf, len) < 0) {
		syslog(LOG_ERR, "Failed to read %zu bytes from %s (%d): %m",
		    len, src, fd);
		close(fd);
		free(buf);
		return;
	}

	close(fd);

	newfd = open(dst, O_WRONLY | O_CREAT);
	if (newfd == -1) {
		syslog(LOG_ERR, "Failed to open and create %s: %m", dst);
		free(buf);
		return;
	}

	if (write(newfd, buf, len) < 0) {
		syslog(LOG_ERR, "Failed to write %zu bytes to %s (%d): %m",
		    len, dst, newfd);
		close(newfd);
		free(buf);
		return;
	}

	close(newfd);
	free(buf);

	dirlen = strlen(dirname(dst)) + 1;
	donepathlen = strlen(dst) - 1;
	memset(donepath, 0, donepathlen);
	memcpy(donepath, dst, dirlen);
	memcpy(donepath + dirlen, dst + dirlen + 1,
	    donepathlen - dirlen);

	if (rename(dst, donepath))
		syslog(LOG_ERR, "Failed to rename %s to %s: %m", dst, dst + 1);

}

static int
process_base(struct dirent *f, dtd_dir_t *dir)
{
	struct dtd_state *s;
	int idx, err;
	char *newname;
	char fullpath[MAXPATHLEN] = { 0 };
	int status = 0;
	pid_t pid, parent;
	char *argv[4];
	char fullarg[MAXPATHLEN*2 + 1] = { 0 };
	size_t offset;
	char donename[MAXPATHLEN] = { 0 };
	size_t dirpathlen = 0;
	
	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}
	
	s = dir->state;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	idx = findpath(f->d_name, dir);
	if (idx >= 0)
		return (0);

	newname = gen_filename(s->outbounddir->dirpath);
	dirpathlen = strlen(s->outbounddir->dirpath);
	strcpy(fullpath, dir->dirpath);
	strcpy(fullpath + strlen(fullpath), f->d_name);
	dtdaemon_copyfile(fullpath, newname);
	strcpy(donename, s->outbounddir->dirpath);
	strcpy(donename + dirpathlen, newname + dirpathlen + 1);
	if (rename(newname, donename))
		syslog(LOG_ERR, "Failed to rename %s to %s: %m", newname, donename);
	free(newname);

	parent = getpid();
	pid = fork();

	if (pid == -1) {
		syslog(LOG_ERR, "Failed to fork: %m");
		return (-1);
	} else if (pid > 0)
		waitpid(pid, &status, 0);
	else {
		argv[0] = strdup("/usr/sbin/dtrace");
		argv[1] = strdup("-Y");
		strcpy(fullarg, fullpath);
		offset = strlen(fullarg);
		strcpy(fullarg + offset, ",/var/ddtrace/inbound/");
		argv[2] = strdup(fullarg);
		argv[3] = NULL;
		execve("/usr/sbin/dtrace", argv, NULL);
		exit(EXIT_FAILURE);
	}

	err = expand_paths(dir);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);

	return (0);
}

static int
process_outbound(struct dirent *f, dtd_dir_t *dir)
{
	int err;
	struct dtd_fdlist *fd_list;
	struct dtd_joblist *job;
	struct dtd_state *s;
	int idx, ch;
	char *newname = NULL;
	char fullpath[MAXPATHLEN] = { 0 };

	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL");
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	idx = findpath(f->d_name, dir);

	if (idx >= 0)
		return (0);

	LOCK(&s->socklistmtx);
	for (fd_list = dt_list_next(&s->sockfds);
	    fd_list; fd_list = dt_list_next(fd_list)) {
		if (fd_list->kind != DTDAEMON_KIND_FORWARDER)
			continue;
		
		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			syslog(LOG_ERR, "Failed to malloc a new job");
			UNLOCK(&s->socklistmtx);
			return (-1);
		}
		memset(job, 0, sizeof(struct dtd_joblist));

		job->job = NOTIFY_ELFWRITE;
		job->j.notify_elfwrite.connsockfd = fd_list->fd;
		job->j.notify_elfwrite.path = strdup(f->d_name);
		job->j.notify_elfwrite.pathlen = strlen(f->d_name);
		job->j.notify_elfwrite.dir = dir;
		job->j.notify_elfwrite.nosha = s->nosha;

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);
	}
	UNLOCK(&s->socklistmtx);

	err = expand_paths(dir);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);

	return (0);
}

static int
populate_existing(struct dirent *f, dtd_dir_t *dir)
{
	int err;

	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL\n");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL\n");
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);
	
	if (f->d_name[0] == '.')
		return (0);

	err = expand_paths(dir);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths in initialization");
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);

	return (0);
}

static int
file_foreach(DIR *d, foreach_fn_t f, dtd_dir_t *dir)
{
	struct dirent *file;
	int err;

	while ((file = readdir(d)) != NULL) {
		err = f(file, dir);
		if (err)
			return (err);
	}

	rewinddir(d);

	return (0);
}

static int
setup_threads(struct dtd_state *s)
{
	int err;
	pthread_t *threads, *sockthread;
	size_t i;

	threads = malloc(sizeof(pthread_t) * THREADPOOL_SIZE);
	if (threads == NULL) {
		syslog(LOG_ERR, "Failed to allocate thread array");
		return (-1);
	}
	memset(threads, 0, sizeof(pthread_t) * THREADPOOL_SIZE);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		err = pthread_create(&threads[i], NULL, process_joblist, s);
		if (err != 0) {
			syslog(LOG_ERR, "Failed to create a new thread: %m");
			return (-1);
		}
	}

	s->workers = threads;

	sem_init(&s->socksema, 0, 0);

	err = pthread_create(&s->dtt_listentd, NULL, listen_dttransport, s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create the dttransport thread: %m");
		return (-1);
	}

	/*
	 * The socket can't be connected at this point because accept_subs is not
	 * running. Need a semaphore.
	 */
	err = pthread_create(&s->dtt_writetd, NULL, write_dttransport, s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create the dttransport thread: %m");
		return (-1);
	}

	err = pthread_create(&s->socktd, NULL, accept_subs, s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create the socket thread: %m");
		return (-1);
	}

	err = pthread_create(&s->inboundtd, NULL, listen_dir, s->inbounddir);
	if (err != 0) {
		syslog(LOG_ERR,
		    "Failed to create inbound listening thread: %m");
		return (-1);
	}

	err = pthread_create(&s->basetd, NULL, listen_dir, s->basedir);
	if (err != 0) {
		syslog(LOG_ERR,
		    "Failed to create base listening thread: %m");
		return (-1);
	}

	return (0);
}

dtd_dir_t *
dtd_mkdir(const char *path, foreach_fn_t fn)
{
	dtd_dir_t *dir;
	int retry;
	int err;

	err = 0;

	dir = malloc(sizeof(dtd_dir_t));
	if (dir == NULL)
		return (NULL);

	memset(dir, 0, sizeof(dtd_dir_t));

	dir->dirpath = strdup(path);
	if ((err = pthread_mutex_init(&dir->dirmtx, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create dir mutex: %m");
		return (NULL);
	}

	retry = 0;
againmkdir:
	dir->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dir->dirfd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(path, 0700) != 0) {
				syslog(LOG_ERR, "Failed to mkdir %s: %m", path);
				free(dir->dirpath);
				free(dir);

				return (NULL);
			} else {
				retry = 1;
				goto againmkdir;
			}
		}

		syslog(LOG_ERR, "Failed to open %s: %m", path);
		free(dir->dirpath);
		free(dir);

		return (NULL);
	}

	dir->processfn = fn;
	dir->dir = fdopendir(dir->dirfd);

	return (dir);
}

static int
init_state(struct dtd_state *s)
{
	int err;

	memset(s, 0, sizeof(struct dtd_state));
	s->sockfd = -1;

	if ((err = pthread_mutex_init(&s->socklistmtx, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create sock list mutex: %m");
		return (-1);
	}

	if ((err = pthread_mutex_init(&s->sockmtx, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create socket mutex: %m");
		return (-1);
	}

	if ((err = pthread_mutex_init(&s->joblistcvmtx, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist condvar mutex: %m");
		return (-1);
	}

	if ((err = pthread_mutex_init(&s->joblistmtx, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist mutex: %m");
		return (-1);
	}

	if ((err = pthread_cond_init(&s->joblistcv, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist condvar: %m");
		return (-1);
	}

	s->dtt_fd = open("/dev/dttransport", O_RDWR);
	if (s->dtt_fd == -1) {
		syslog(LOG_ERR, "Failed to open /dev/dttransport: %m");
		return (-1);
	}

	s->outbounddir = dtd_mkdir(DTDAEMON_OUTBOUNDDIR, &process_outbound);
	s->inbounddir = dtd_mkdir(DTDAEMON_INBOUNDDIR, &process_inbound);
	s->basedir = dtd_mkdir(DTDAEMON_BASEDIR, &process_base);

	s->outbounddir->state = s;
	s->inbounddir->state = s;
	s->basedir->state = s;

	return (0);
}

static void
dtd_closedir(dtd_dir_t *dir)
{
	size_t i;
	int err;
	
	free(dir->dirpath);
	close(dir->dirfd);
	closedir(dir->dir);

	for (i = 0; i < dir->efile_len; i++)
		free(dir->existing_files[i]);

	free(dir->existing_files);

	err = pthread_mutex_destroy(&dir->dirmtx);
	if (err != 0)
		syslog(LOG_ERR, "Failed to destroy dirmtx: %m");

	dir->efile_size = 0;
	dir->efile_len = 0;

	free(dir);
}

static int
destroy_state(struct dtd_state *s)
{
	int err;
	size_t i;
	char *path;
	struct dtd_joblist *j, *next;

	LOCK(&s->joblistmtx);
	for (j = dt_list_next(&s->joblist); j; j = next) {
		next = dt_list_next(j);
		free(j);
	}
	UNLOCK(&s->joblistmtx);

	if ((err = pthread_mutex_destroy(&s->socklistmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy sock list mutex: %m");
		return (-1);
	}
	if ((err = pthread_mutex_destroy(&s->sockmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy socket mutex: %m");
		return (-1);
	}
	if ((err = pthread_mutex_destroy(&s->joblistcvmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist condvar mutex: %m");
		return (-1);
	}
	if ((err = pthread_mutex_destroy(&s->joblistmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist mutex: %m");
		return (-1);
	}
	if ((err = pthread_cond_destroy(&s->joblistcv)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist condvar mutex: %m");
		return (-1);
	}

	dtd_closedir(s->outbounddir);
	dtd_closedir(s->inbounddir);

	sem_destroy(&s->socksema);

	destroy_sockfd(s);
	s->sockfd = -1;

	free(s->workers);

	close(s->dtt_fd);
	s->dtt_fd = -1;

	return (0);
}

static void
print_help(void)
{

}

static void
print_version(void)
{
	
}

int
main(int argc, char **argv)
{
	const char elfpath[MAXPATHLEN] = "/var/ddtrace";
	int efd, errval, rval, kq, retry;
	DIR *elfdir;
	size_t i;
	char ch;
	char pidstr[256];
	struct kevent ev, ev_data;
	struct dtd_state *retval;
	int optidx = 0;
	int lockfd;

	lockfd = 0;
	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));

	while ((ch = getopt_long(argc, argv, "Ca:ce:hvZ", long_opts, &optidx)) != -1) {
		switch (ch) {
		case 'h':
			print_help();
			exit(0);

		case 'v':
			print_version();
			exit(0);

		case 'e':
			/*
			 * Option specifies that we want to ignore certain file
			 * names. We simply add them to the list of ignored
			 * names and later on when we notify our consumers check
			 * if it should be ignored.
			 */
			break;

		case 'C':
			g_ctrlmachine = 1;
			break;

		case 'c':
			g_ctrlmachine = 0;
			break;

		case 'Z':
			nosha = 1;
			break;

		default:
			break;
		}
	}

	lockfd = open(LOCK_FILE, O_RDWR | O_CREAT, 0640);
	if (lockfd == -1)
		err(EXIT_FAILURE, "Could not open %s", LOCK_FILE);

	if (lockf(lockfd, F_TLOCK, 0) < 0)
		err(EXIT_FAILURE, "Could not lock %s", LOCK_FILE);

	sprintf(pidstr, "%d\n", getpid());

	if (write(lockfd, pidstr, strlen(pidstr)) < 0)
		err(EXIT_FAILURE, "Failed to write pid to %s", LOCK_FILE);

	state.lockfd = lockfd;
	assert(state.lockfd != -1);

	if (g_ctrlmachine != 0 && g_ctrlmachine != 1)
		errx(EXIT_FAILURE, "You must either specify -c or -C");
#if 0
	if (daemon(0, 0) != 0) {
		syslog(LOG_ERR, "Failed to daemonize %m");
		return (EX_OSERR);
	}
#endif

againefd:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(elfpath, 0700) != 0)
				syslog(LOG_ERR,
				    "Failed to mkdir %s: %m", elfpath);
			else {
				retry = 1;
				goto againefd;
			}
		}

		syslog(LOG_ERR, "Failed to open %s: %m", elfpath);
		return (EX_OSERR);
	}

	state.dirfd = efd;
	elfdir = fdopendir(efd);

	errval = init_state(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to initialize the state");
		return (EXIT_FAILURE);
	}

	state.nosha = nosha;

	if (signal(SIGTERM, sig_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGTERM handler");
		return (EX_OSERR);
	}

	if (signal(SIGINT, sig_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGINT handler");
		return (EX_OSERR);
	}

	if (signal(SIGPIPE, sig_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGPIPE handler");
		return (EX_OSERR);
	}

	if (siginterrupt(SIGTERM, 1) != 0) {
		syslog(LOG_ERR,
		    "Failed to enable system call interrupts for SIGTERM");
		return (EX_OSERR);
	}

	errval = setup_sockfd(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to set up the socket");
		return (EX_OSERR);
	}

	errval = file_foreach(state.outbounddir->dir,
	    populate_existing, state.outbounddir);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to populate outbound existing files");
		return (EXIT_FAILURE);
	}

	errval = file_foreach(state.inbounddir->dir,
	    populate_existing, state.inbounddir);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to populate inbound existing files");
		return (EXIT_FAILURE);
	}

	errval = setup_threads(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to set up threads");
		return (EX_OSERR);
	}

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "Failed to create a kqueue %m");
		return (EX_OSERR);
	}

	EV_SET(&ev, state.outbounddir->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE, 0, (void *)state.outbounddir);

	for (;;) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			if (errno == EINTR && state.shutdown == 1)
				goto cleanup;

			syslog(LOG_ERR, "kevent() failed with %m");
			return (EX_OSERR);
		}

		if (ev_data.flags == EV_ERROR) {
			syslog(LOG_ERR, "kevent() got EV_ERROR with %m");
			return (EX_OSERR);
		}

		if (rval > 0) {
			errval = file_foreach(state.outbounddir->dir,
			    process_outbound, state.outbounddir);
			if (errval) {
				syslog(LOG_ERR, "Failed to process new files");
				return (EXIT_FAILURE);
			}
		}
	}

cleanup:
	errval = pthread_kill(state.socktd, SIGTERM);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to interrupt socktd: %m");
		return (EX_OSERR);
	}

	errval = pthread_join(state.socktd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join socktd: %m");
		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_listentd, SIGTERM);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to interrupt dtt_listentd: %m");
		return (EX_OSERR);
	}

	errval = pthread_join(state.dtt_listentd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join dtt_listentd: %m");
		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_writetd, SIGTERM);
	if (errval != 0 && errval != ESRCH) {
		syslog(LOG_ERR, "Failed to interrupt dtt_writetd: %m");
		return (EX_OSERR);
	}

	errval = pthread_join(state.dtt_writetd, (void **)&retval);
	if (errval != 0 && errval != ESRCH) {
		syslog(LOG_ERR, "Failed to join dtt_writetd: %m");
		return (EX_OSERR);
	}

	errval = pthread_kill(state.inboundtd, SIGTERM);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to interrupt inboundtd: %m");
		return (EX_OSERR);
	}

	errval = pthread_join(state.inboundtd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join inboundtd: %m");
		return (EX_OSERR);
	}

	LOCK(&state.joblistcvmtx);
	BROADCAST(&state.joblistcv);
	UNLOCK(&state.joblistcvmtx);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		errval = pthread_join(state.workers[i], (void **)&retval);
		if (errval != 0) {
			syslog(LOG_ERR, "Failed to join threads: %m");
			return (EX_OSERR);
		}
	}

	errval = destroy_state(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to clean up state");
		return (EXIT_FAILURE);
	}

	closedir(elfdir);
	close(efd);

	close(lockfd);
	return (0);
}
