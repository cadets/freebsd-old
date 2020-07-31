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

#include <openssl/sha.h>

#include <spawn.h>
#include <dt_prog_link.h>

#define	SOCKFD_PATH	"/var/ddtrace/sub.sock"
#define	SOCKFD_NAME	"sub.sock"
#define	THREADPOOL_SIZE	4

#define	NEXISTS		0
#define	EXISTS_CHANGED	1
#define	EXISTS_EQUAL	2

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

struct dtd_state {
	/*
	 * Path-related members.
	 *
	 * Concurrency behaviour: Never accessed by anything except for the main
	 *                        loop. Does not require locking.
	 */
	char		**paths;
	time_t		*ctimes;
	size_t		size;
	size_t		len;

	/*
	 * Sockets.
	 *
	 * Concurrency behaviour: Accessed by both the main loop and the socket
	 *                        control thread. Locked in both when traversed.
	 */
	pthread_mutex_t	socklistmtx;
	dt_list_t	sockfds;

	/*
	 * Configuration socket.
	 *
	 * Concurrency behaviour: Accessed by the shutdown code and the socket
	 *                        control thread. Needs to be locked in both.
	 */
	pthread_mutex_t	sockmtx;
	pthread_t	socktd;
	int		sockfd;

	/*
	 * Thread pool management.
	 *
	 * Concurrency behaviour: The threads are created at startup time and
	 *                        torn down at shutdown of the daemon. However,
	 *                        the list of jobs is accessed from the socket
	 *                        control thread and each of the threads in the
	 *                        worker pool.
	 */
	pthread_t	*workers;
	pthread_mutex_t	joblistcvmtx;
	pthread_cond_t	joblistcv;
	pthread_mutex_t	joblistmtx;
	dt_list_t	joblist;

	int		shutdown;

	int		dirfd;

	int		nosha;
};

struct dtd_fdlist {
	dt_list_t	list;
	int		fd;
};

struct dtd_joblist {
	dt_list_t	list;

#define	NOTIFY_ELFWRITE	1
	int		job;

	union {
		struct {
			int	connsockfd;
			size_t	pathlen;
			char	*path;
		} notify_elfwrite;
	} j;
};

typedef int (*foreach_fn_t)(struct dirent *, struct dtd_state *);

/*
 * Awful global variable, but is here because of the signal handler.
 */
static struct dtd_state state;
static int nosha = 0;

static const struct option long_opts[] = {
	{"help",		no_argument,		NULL,		0},
	{"exclude",		required_argument,	NULL,		'e'},
	{"version",		no_argument,		NULL,		'v'},
	{"no-checksum",		no_argument,		&nosha,		1},
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

static void *
process_joblist(void *_s)
{
	int err;
	int fd;
	int elffd;
	char *path;
	char *contents, *msg;
	size_t msglen;
	size_t pathlen;
	size_t elflen;
	struct dtd_joblist *curjob;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	struct stat stat;

	memset(&stat, 0, sizeof(stat));

	while (s->shutdown == 0) {
		LOCK(&s->joblistcvmtx);
		while (dt_list_next(&s->joblist) == NULL && s->shutdown == 0)
			WAIT(&s->joblistcv, &s->joblistcvmtx);
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

			/*
			 * Sanity assertions.
			 */
			assert(fd != -1);
			assert(path != NULL);
			assert(pathlen <= MAXPATHLEN);

			assert(s->dirfd != -1);

			elffd = openat(s->dirfd, path, O_RDONLY);
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
			msglen = s->nosha ? elflen : elflen + 32;
			msg = malloc(msglen);

			if (msg == NULL) {
				syslog(LOG_ERR, "Failed to malloc ELF contents: %m");
				free(path);
				close(elffd);
				break;
			}

			memset(msg, 0, msglen);
			contents = s->nosha ? msg : msg + 32;
			
			if (read(elffd, contents, elflen) < 0) {
				syslog(LOG_ERR, "Failed to read ELF contents: %m");
				free(path);
				free(contents);
				close(elffd);
				break;
			}

			if (s->nosha == 0 &&
			    SHA256(contents, elflen, msg) == NULL) {
				syslog(LOG_ERR, "Failed to create a SHA256 of the file");
				free(path);
				free(contents);
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
	int connsockfd;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;

	/*
	 * Sanity checks on the state.
	 */
	if (s == NULL)
		pthread_exit(NULL);

	if (s->socktd == NULL)
		pthread_exit(NULL);

	if (s->sockfd == -1)
		pthread_exit(NULL);

	err = listen(s->sockfd, 32);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to listen on %d: %m", s->sockfd);
		pthread_exit(NULL);
	}

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

		fde = malloc(sizeof(struct dtd_fdlist));
		if (fde == NULL) {
			syslog(LOG_ERR, "Failed to malloc a fdlist entry");
			pthread_exit(NULL);
		}
		
		memset(fde, 0, sizeof(struct dtd_fdlist));
		fde->fd = connsockfd;

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
	l = strlcpy(addr.sun_path, SOCKFD_PATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		syslog(LOG_ERR,
		    "Failed to copy %s into sockaddr (%zu)", SOCKFD_PATH, l);
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

	if (unlink(SOCKFD_PATH) != 0)
		syslog(LOG_ERR, "Failed to unlink %s: %m", SOCKFD_PATH);

	return (0);
}

static int
findpath(const char *p, struct dtd_state *s, struct stat *st)
{
	int i;
	
	for (i = 0; i < s->len; i++) {
		if (strcmp(p, s->paths[i]) == 0) {
			if (fstatat(s->dirfd, p, st, AT_SYMLINK_NOFOLLOW) != 0) {
				syslog(LOG_ERR, "Failed to stat %s: %m", p);
				/*
				 * Return -2 to indicate a failed syscall
				 */
				return (-2);
			}

			return (i);
		}
	}

	return (-1);
}

static int
waschanged(struct stat *st, int idx, struct dtd_state *s)
{
	if (idx < 0)
		return (1);

	/*
	 * It would be nonesense if it was changed earlier than what
	 * we've seen it change.
	 */
	assert(s->ctimes[idx] <= st->st_ctime);

	if (s->ctimes[idx] < st->st_ctime)
		return (1);

	assert(s->ctimes[idx] == st->st_ctime);
	return (0);
}

static int
expand_paths(struct dtd_state *s)
{
	char **newpaths;
	time_t *newctimes;

	if (s == NULL) {
		syslog(LOG_DEBUG, "Expand paths called with state == NULL");
		return (-1);
	}

	if (s->size <= s->len) {
		s->size = s->size == 0 ? 16 : (s->size << 1);

		/*
		 * Assert sanity after we multiply the size by two.
		 */
		if (s->size <= s->len) {
			syslog(LOG_ERR, "s->size <= s->len (%zu <= %zu)\n",
			    s->size, s->len);
			return (-1);
		}

		/*
		 * Copy over the pointers to paths that were previously
		 * allocated in the old array.
		 */
		newpaths = malloc(s->size * sizeof(char *));
		if (newpaths == NULL) {
			syslog(LOG_ERR, "Failed to malloc newpaths");
			return (-1);
		}

		memset(newpaths, 0, s->size * sizeof(char *));
		if (s->paths) {
			memcpy(newpaths, s->paths, s->len * sizeof(char *));
			free(s->paths);
		}

		newctimes = malloc(s->size * sizeof(time_t));
		if (newctimes == NULL) {
			syslog(LOG_ERR, "Failed to malloc newctimes");
			return (-1);
		}

		memset(newctimes, 0, s->size * sizeof(time_t));
		if (s->ctimes) {
			memcpy(newctimes, s->ctimes, s->len * sizeof(time_t));
			free(s->ctimes);
		}

		/*
		 * Assign the paths and ctimes
		 */
		s->paths = newpaths;
		s->ctimes = newctimes;
	}

	return (0);
}

static int
process_new(struct dirent *f, struct dtd_state *s)
{
	int err;
	struct dtd_fdlist *fd_list;
	struct dtd_joblist *job;
	struct stat st;
	int idx, ch;

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

	if (strcmp(f->d_name, ".") == 0)
		return (0);

	if (strcmp(f->d_name, "..") == 0)
		return (0);

	/*
	 * Get the index (if exists) of the path. We will use this to check
	 * if the file has already been processed by comparing the last changed
	 * time to the one we have stored. If our time is in the past, we need
	 * to resend the file and update our state.
	 */
	idx = findpath(f->d_name, s, &st);
	ch = waschanged(&st, idx, s);

	if (idx >= 0 && ch == 0)
		return (0);

	if (idx == -2) {
		syslog(LOG_ERR, "Failed to process new entry: %m");
		return (-1);
	}

	LOCK(&s->socklistmtx);
	for (fd_list = dt_list_next(&s->sockfds);
	    fd_list; fd_list = dt_list_next(fd_list)) {
		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			syslog(LOG_ERR, "Failed to malloc a new job");
			return (-1);
		}
		memset(job, 0, sizeof(struct dtd_joblist));

		job->job = NOTIFY_ELFWRITE;
		job->j.notify_elfwrite.connsockfd = fd_list->fd;
		job->j.notify_elfwrite.path = strdup(f->d_name);
		job->j.notify_elfwrite.pathlen = strlen(f->d_name);

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);
	}
	UNLOCK(&s->socklistmtx);

	if (idx == -1) {
		/*
		 * We have now written this file out to every single process that
		 * asked to get informed about it. We will now simply add it to
		 * the path array.
		 */
		err = expand_paths(s);
		if (err != 0) {
			syslog(LOG_ERR, "Failed to expand paths after processing %s",
			    f->d_name);
			return (-1);
		}

		assert(s->size > s->len);
		s->ctimes[s->len] = st.st_ctime;
		s->paths[s->len++] = strdup(f->d_name);
	} else {
		assert(ch != 0);
		s->ctimes[idx] = st.st_ctime;
	}

	return (0);
}

static int
populate_existing(struct dirent *f, struct dtd_state *s)
{
	int err;
	struct stat st;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL\n");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL\n");
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);
	
	if (strcmp(f->d_name, ".") == 0)
		return (0);
	if (strcmp(f->d_name, "..") == 0)
		return (0);

	err = expand_paths(s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths in initialization");
		return (-1);
	}

	assert(s->size > s->len);

	if (fstatat(s->dirfd, f->d_name, &st, AT_SYMLINK_NOFOLLOW)) {
		syslog(LOG_ERR, "Failed to fstatat %s: %m", f->d_name);
		return (-1);
	}

	s->ctimes[s->len] = st.st_ctime;
	s->paths[s->len++] = strdup(f->d_name);

	return (0);
}

static int
file_foreach(DIR *d, foreach_fn_t f, void *uarg)
{
	struct dirent *file;
	int err;

	while ((file = readdir(d)) != NULL) {
		err = f(file, uarg);
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

	err = pthread_create(&s->socktd, NULL, accept_subs, s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create the socket thread: %m");
		return (-1);
	}

	return (0);
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


	return (0);
}

static int
destroy_state(struct dtd_state *s)
{
	int err;
	size_t i;
	char *path;
	struct dtd_joblist *j, *next;

	for (i = 0; i < s->len; i++) {
		path = s->paths[i];
		assert(path != NULL);

		free(path);
	}
	free(s->paths);

	s->paths = NULL;
	s->len = 0;
	s->size = 0;

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


	destroy_sockfd(s);
	s->sockfd = -1;

	free(s->workers);

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
	int efd, err, rval, kq, retry;
	DIR *elfdir;
	size_t i;
	char ch;
	struct kevent ev, ev_data;
	struct dtd_state *retval;
	int optidx = 0;

	retry = 0;

	while ((ch = getopt_long(argc, argv, "a::e:hvZ", long_opts, &optidx)) != -1) {
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
		case 'Z':
			nosha = 1;
			break;

		default:
			break;
		}
	}

	if (daemon(0, 0) != 0) {
		syslog(LOG_ERR, "Failed to daemonize %m");
		return (EX_OSERR);
	}

	err = init_state(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to initialize the state");
		return (EXIT_FAILURE);
	}

	state.nosha = nosha;

	if (signal(SIGTERM, sig_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGTERM handler");
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

again:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == EINVAL) {
			if (mkdir(elfpath, 0700) != 0)
				syslog(LOG_ERR,
				    "Failed to mkdir %s: %m", elfpath);
			else {
				retry = 1;
				goto again;
			}
		}
		syslog(LOG_ERR, "Failed to open %s: %m", elfpath);
		return (EX_OSERR);
	}

	state.dirfd = efd;
	elfdir = fdopendir(efd);

	err = setup_sockfd(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to set up the socket");
		return (EX_OSERR);
	}

	err = file_foreach(elfdir, populate_existing, &state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to populate existing files");
		return (EXIT_FAILURE);
	}

	err = setup_threads(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to set up threads");
		return (EX_OSERR);
	}

	if ((kq = kqueue()) == -1) {
		syslog(LOG_ERR, "Failed to create a kqueue %m");
		return (EX_OSERR);
	}

	EV_SET(&ev, efd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE, 0, (void *)elfpath);

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
			err = file_foreach(elfdir, process_new, &state);
			if (err) {
				syslog(LOG_ERR, "Failed to process new files");
				return (EXIT_FAILURE);
			}
		}
	}

cleanup:
	err = pthread_kill(state.socktd, SIGTERM);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to interrupt socktd: %m");
		return (EX_OSERR);
	}

	err = pthread_join(state.socktd, (void **)&retval);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to join threads: %m");
		return (EX_OSERR);
	}


	LOCK(&state.joblistcvmtx);
	BROADCAST(&state.joblistcv);
	UNLOCK(&state.joblistcvmtx);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		err = pthread_join(state.workers[i], (void **)&retval);
		if (err != 0) {
			syslog(LOG_ERR, "Failed to join threads: %m");
			return (EX_OSERR);
		}
	}

	err = destroy_state(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to clean up state");
		return (EXIT_FAILURE);
	}

	closedir(elfdir);
	close(efd);

	return (0);
}
