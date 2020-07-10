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
#include <dt_vtdtr.h>

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

#include <spawn.h>
#include <dt_prog_link.h>

#define	SOCKFD_PATH	"/var/ddtrace/sub.sock"
#define	THREADPOOL_SIZE	4

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
struct dtd_state state;

static void
shutdown_hdlr(int signo)
{
	if (signo == SIGTERM)
		state.shutdown = 1;
	else if (signo == SIGINT)
		return;
}

static void *
process_joblist(void *_s)
{
	int err;
	int fd;
	char *path;
	size_t pathlen;
	struct dtd_joblist *curjob;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	
	for (;;) {
		LOCK(&s->joblistcvmtx);
		while (dt_list_next(&s->joblist) == NULL && s->shutdown == 0)
			WAIT(&s->joblistcv, &s->joblistcvmtx);
		UNLOCK(&s->joblistcvmtx);

		if (s->shutdown == 1)
			break;

		LOCK(&s->joblistmtx);
		curjob = dt_list_next(&s->joblist);
		assert(curjob != NULL);

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

			if (write(fd, path, pathlen) < 0) {
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
					assert(fde != NULL);
					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d (%s, %zu): %m",
					    fd, path, pathlen);
			}

			free(path);
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

	for (;;) {
		connsockfd = accept(s->sockfd, NULL, 0);
		if (connsockfd == -1) {
			/*
			 * EINTR will only happen if a signal was received.
			 * The only time we really expect a signal to be
			 * received on this thread is when we explicitly
			 * call pthread_kill() on shutdown.
			 */
			if (errno == EINTR && s->shutdown == 1)
				break;
			
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

	err = shutdown(s->sockfd, SHUT_RDWR);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to shutdown %d: %m", s->sockfd);
		return (-1);
	}

	if (close(s->sockfd) != 0) {
		syslog(LOG_ERR, "Failed to close %d: %m", s->sockfd);
		return (-1);
	}

	s->sockfd = -1;
	err = pthread_mutex_destroy(&s->sockmtx);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to destroy sockmtx: %m");
		return (-1);
	}

	return (0);
}

static int
exists(const char *p, struct dtd_state *s)
{
	size_t i;
	
	for (i = 0; i < s->len; i++) {
		if (strcmp(p, s->paths[i]) == 0)
			return (1);
	}

	return (0);
}

static int
expand_paths(struct dtd_state *s)
{
	char **newpaths;

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
			memcpy(newpaths, s->paths, s->len);
			free(s->paths);
		}

		/*
		 * newpaths is now our new s->paths.
		 */
		s->paths = newpaths;
	}

	return (0);
}

static int
process_new(struct dirent *f, struct dtd_state *s)
{
	int err;
	struct dtd_fdlist *fd_list;
	struct dtd_joblist *job;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL");
		return (-1);
	}

	/*
	 * If this file already exists, we simply don't process it for now.
	 */
	if (exists(f->d_name, s)) {
		syslog(LOG_DEBUG, "%s already exists in state", f->d_name);
		return (0);
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
	s->paths[s->len++] = strdup(f->d_name);

	return (0);
}

static int
populate_existing(struct dirent *f, struct dtd_state *s)
{
	int err;

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL\n");
		return (-1);
	}

	if (f == NULL) {
		syslog(LOG_ERR, "dirent is NULL\n");
		return (-1);
	}

	err = expand_paths(s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to expand paths in initialization");
		return (-1);
	}

	assert(s->size > s->len);
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

int
main(int argc, char **argv)
{
	const char elfpath[MAXPATHLEN] = "/var/ddtrace";
	int efd, err, rval, kq;
	DIR *elfdir;
	size_t i;
	struct kevent ev, ev_data;
	struct dtd_state *retval;

	if (daemon(0, 0) != 0) {
		syslog(LOG_ERR, "Failed to daemonize %m");
		return (EX_OSERR);
	}

	err = init_state(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to initialize the state");
		return (EXIT_FAILURE);
	}

	if (signal(SIGTERM, shutdown_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGTERM handler");
		return (EX_OSERR);
	}

	if (signal(SIGINT, shutdown_hdlr) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGINT handler");
		return (EX_OSERR);
	}

	efd = open(elfpath, O_CREAT | O_RDWR);
	if (efd == -1) {
		syslog(LOG_ERR, "Failed to open /var/ddtrace");
		return (EX_OSERR);
	}

	elfdir = fdopendir(efd);

	err = file_foreach(elfdir, populate_existing, &state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to populate existing files");
		return (EXIT_FAILURE);
	}

	err = setup_sockfd(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to set up the socket");
		return (EX_OSERR);
	}

	err = setup_threads(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to set up threads");
		return (EX_OSERR);
	}

	if ((kq = kqueue()) != 0) {
		syslog(LOG_ERR, "Failed to create a kqueue %m");
		return (EX_OSERR);
	}

	EV_SET(&ev, efd, EVFILT_VNODE, EV_ADD | EV_CLEAR,
	    NOTE_WRITE, 0, (void *)elfpath);

	for (;;) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			if (rval == EINTR && state.shutdown == 1)
				break;

			syslog(LOG_ERR, "kevent() failed with %m");
			return (EX_OSERR);
		}

		if (ev_data.flags == EV_ERROR) {
			syslog(LOG_ERR, "kevent() got EV_ERROR with %m");
			return (EX_OSERR);
		}

		if (rval > 0) {
			syslog(LOG_DEBUG, "Event %" PRIdPTR
			    " occurred. Filter %d, flags %d, filter flags %u"
			    ", filter data %" PRIdPTR ", path %s\n",
			    ev_data.ident, ev_data.filter, ev_data.flags,
			    ev_data.fflags, ev_data.data,
			    ev_data.udata);
			
			err = file_foreach(elfdir, process_new, &state);
			if (err) {
				syslog(LOG_ERR, "Failed to process new files");
				return (EXIT_FAILURE);
			}
		}
	}

	err = pthread_kill(state.socktd, SIGINT);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to interrupt socktd: %m");
		return (EX_OSERR);
	}

	err = pthread_join(state.socktd, (void **)&retval);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to join threads: %m");
		return (EX_OSERR);
	}

	if (retval != &state)
		syslog(LOG_ERR,
		    "Socket thread failed to return the correct state");

	LOCK(&state.joblistcvmtx);
	BROADCAST(&state.joblistcv);
	UNLOCK(&state.joblistcvmtx);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		err = pthread_join(state.workers[i], (void **)&retval);
		if (err != 0) {
			syslog(LOG_ERR, "Failed to join threads: %m");
			return (EX_OSERR);
		}

		if (retval != &state)
			syslog(LOG_ERR,
			    "Worker thread failed to return the correct state");

	}

	err = destroy_state(&state);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to clean up state");
		return (EXIT_FAILURE);
	}

	return (0);
}
