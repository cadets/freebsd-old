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
#include <dirent.h>
#include <dt_elf.h>
#include <dt_prog_link.h>
#include <dt_resolver.h>
#include <dtrace.h>
#include <dttransport.h>
#include <err.h>
#include <errno.h>
#include <execinfo.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <libutil.h>
#include <limits.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sysexits.h>
#include <syslog.h>
#include <unistd.h>

#include "dtraced.h"

#define DTRACED_INBOUNDDIR      "/var/ddtrace/inbound/"
#define DTRACED_OUTBOUNDDIR     "/var/ddtrace/outbound/"
#define DTRACED_BASEDIR         "/var/ddtrace/base/"
#define DTRACED_BACKTRACELEN    128
#define DTRACED_BACKLOG_SIZE    4

#define LOCK_FILE                "/var/run/dtraced.pid"
#define SOCKFD_NAME              "sub.sock"
#define THREADPOOL_SIZE          4

#define NEXISTS                  0
#define EXISTS_CHANGED           1
#define EXISTS_EQUAL             2

#define OWNED(m)    (atomic_load(&(m)->_owner) == pthread_self())

#define SIGNAL(c)						   \
	{							   \
		int err;					   \
		err = pthread_cond_signal(c);			   \
		if (err != 0) {					   \
			syslog(LOG_ERR,"Failed to signal cv: %m"); \
		}						   \
	}

#define WAIT(c,m)						     \
	{							     \
		int err;					     \
		err = pthread_cond_wait(c,m);			     \
		if (err != 0) {					     \
			syslog(LOG_ERR,"Failed to wait for cv: %m"); \
		}						     \
	}

#define BROADCAST(c)						      \
	{							      \
		int err;					      \
		err = pthread_cond_broadcast(c);		      \
		if (err != 0) {					      \
			syslog(LOG_ERR,"Failed to broadcast cv: %m"); \
		}						      \
	}

#define SWAIT(s)						       \
	{							       \
		int err;					       \
		err = sem_wait(s);				       \
		if (err != 0) {					       \
			syslog(LOG_ERR,"Failed to wait for sema: %m"); \
		}						       \
	}

#define SPOST(s)						       \
	{							       \
		int err;					       \
		err = sem_post(s);				       \
		if (err != 0) {					       \
			syslog(LOG_ERR,"Failed to post for sema: %m"); \
		}						       \
	}

typedef struct mutex {
	pthread_mutex_t _m;       /* pthread mutex */
	_Atomic pthread_t _owner; /* owner thread of _m */
	char _name[32];           /* name of the mutex */
	int _checkowner;          /* do we want to check who owns the mutex? */
#define CHECKOWNER_NO     0
#define CHECKOWNER_YES    1
} mutex_t;

char version_str[128];
struct dtd_state;
struct dtd_dir;
typedef int (*foreach_fn_t)(struct dirent *, struct dtd_dir *);

typedef struct dtd_dir {
	char *dirpath;		 /* directory path */
	int dirfd;		 /* directory filedesc */
	DIR *dir;		 /* directory pointer */
	char **existing_files;	 /* files that exist in the dir */
	size_t efile_size;	 /* vector size */
	size_t efile_len;	 /* number of elements */
	mutex_t dirmtx;		 /* directory mutex */
	foreach_fn_t processfn;	 /* function to process the dir */
	struct dtd_state *state; /* backpointer to state */
} dtd_dir_t;

static int file_foreach(DIR *, foreach_fn_t, dtd_dir_t *);
static int process_outbound(struct dirent *, dtd_dir_t *);
static int process_inbound(struct dirent *, dtd_dir_t *);

typedef struct pidlist {
	dt_list_t list; /* next element */
	pid_t pid;
} pidlist_t;

/*
 * dtraced state structure. This contains everything relevant to dtraced's
 * state management, such as files that exist, connected sockets, etc.
 */
struct dtd_state {
	dtd_dir_t *inbounddir;  /* /var/ddtrace/inbound */
	dtd_dir_t *outbounddir; /* /var/ddtrace/outbound */
	dtd_dir_t *basedir;     /* /var/ddtrace/base */

	pthread_t inboundtd;    /* inbound monitoring thread */
	pthread_t basetd;       /* base monitoring thread */
	/* the outbound monitoring thread is the main thread */

	/*
	 * Sockets.
	 */
	mutex_t socklistmtx; /* mutex fos sockfds */
	dt_list_t sockfds;   /* list of sockets we know about */

	/*
	 * Configuration socket.
	 */
	mutex_t sockmtx;  /* config socket mutex */
	pthread_t socktd; /* config socket thread */
	int sockfd;       /* config socket filedesc */
	sem_t socksema;   /* config socket semaphore */

	/*
	 * dttransport fd and threads
	 */
	int dtt_fd;             /* dttransport filedesc */
	pthread_t dtt_listentd; /* read() on dtt_fd */
	pthread_t dtt_writetd;  /* write() on dtt_fd */

	/*
	 * Thread pool management.
	 */
	pthread_t *workers;       /* thread pool for the joblist */
	mutex_t joblistcvmtx;     /* joblist condvar mutex */
	pthread_cond_t joblistcv; /* joblist condvar */
	mutex_t joblistmtx;       /* joblist mutex */
	dt_list_t joblist;        /* the joblist itself */

	/*
	 * Children management.
	 */
	pthread_t killtd;      /* handle sending kill(SIGTERM) to the guest */
	mutex_t kill_listmtx;  /* mutex of the kill list */
	mutex_t killcvmtx;     /* kill list condvar mutex */
	dt_list_t kill_list;   /* a list of pids to kill */
	pthread_cond_t killcv; /* kill list condvar */

	/*
	 * Consumer threads
	 */
	pthread_t consumer_listentd; /* handle consumer messages */
	pthread_t consumer_writetd;  /* send messages to consumers */

	_Atomic int shutdown;        /* shutdown flag */
	int dirfd;                   /* /var/ddtrace */
	int nosha;                   /* do we want to checksum? */
	struct pidfh *pid_fileh;     /* lockfile */
	int kq_hdl;                  /* event loop kqueue */
};

struct dtd_fdlist {
	dt_list_t list; /* next element */
	int fd;         /* the actual filedesc */
	int kind;       /* consumer/forwarder */
	uint64_t subs;  /* events that efd subscribed to */
};

struct dtd_joblist {
	dt_list_t list; /* next element */
	int job;        /* job kind */
	int connsockfd; /* which socket do we send this on? */
#define NOTIFY_ELFWRITE    1
#define KILL               2
#define READ_DATA          3
#define JOB_LAST           3

	union {
		struct {
			size_t pathlen; /* how long is path? */
			char *path;     /* path to file (based on dir) */
			dtd_dir_t *dir; /* base directory of path */
			int nosha;      /* do we want to checksum? */
		}
		notify_elfwrite;

		struct {
			pid_t pid;      /* pid to kill */
		}
		kill;

		struct {
		}
		read;
	}
	j;
};

/*
 * Awful global variable, but is here because of the signal handler.
 */
static struct dtd_state state;
static int nosha = 0;
static int g_ctrlmachine = -1;

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
dump_errormsg(const char *msg, ...)
{
	va_list ap;

	va_start(ap, msg);
	if (msg) {
		vfprintf(stderr, msg, ap);
		vsyslog(LOG_ERR, msg, ap);
	}
	va_end(ap);
}

static int
mutex_init(mutex_t *m, const pthread_mutexattr_t *restrict attr,
    const char *name, int checkowner)
{
	size_t l;

	assert(m != NULL);

	if (name == NULL)
		return (-1);

	l = strlcpy(m->_name, name, 32);
	if (l >= 32)
		return (-1);

	m->_checkowner = checkowner;

	atomic_store(&m->_owner, NULL);
	return (pthread_mutex_init(&m->_m, attr));
}

static int
mutex_destroy(mutex_t *m)
{

	assert(atomic_load(&m->_owner) == NULL);
	return (pthread_mutex_destroy(&m->_m));
}

static pthread_mutex_t *
pmutex_of(mutex_t *m)
{

	return (&m->_m);
}

static void
LOCK(mutex_t *m)
{
	int err;

	err = pthread_mutex_lock(&(m)->_m);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to lock mutex: %m");
		exit(EXIT_FAILURE);
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&(m)->_owner, pthread_self());
}

static void
dump_backtrace(void)
{
	int nptrs;
	void *buffer[DTRACED_BACKTRACELEN];
	char **strings;

	nptrs = backtrace(buffer, DTRACED_BACKTRACELEN);
	strings = backtrace_symbols(buffer, nptrs);

	if (strings == NULL) {
		syslog(LOG_ERR, "Failed to get backtrace symbols: %m");
		exit(EXIT_FAILURE);
	}

	for (int j = 0; j < nptrs; j++)
		dump_errormsg("%s\n", strings[j]);

	free(strings);
}

static void
UNLOCK(mutex_t *m)
{
	int err;

	if (m->_checkowner != CHECKOWNER_NO) {
		if (OWNED(m) == 0) {
			dump_errormsg(
			    "attempted unlock of %s which is not owned\n",
			    m->_name);
			dump_backtrace();
			exit(EXIT_FAILURE);
		}

		assert(OWNED(m));
		if (atomic_load(&m->_owner) != pthread_self()) {
			dump_errormsg(
			    "attempted unlock of %s by thread %p (!= %p)\n",
			    m->_name, pthread_self(), atomic_load(&m->_owner));
			dump_backtrace();
			exit(EXIT_FAILURE);
		}
	}

	err = pthread_mutex_unlock(&(m)->_m);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to unlock mutex: %m");
		return;
	}

	if (m->_checkowner != CHECKOWNER_NO)
		atomic_store(&m->_owner, NULL);
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

static void *
manage_children(void *_s)
{
	struct dtd_state *s = (struct dtd_state *)_s;
	pidlist_t *kill_entry;

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
			fprintf(stderr, "kill message pulled from under us\n");
			UNLOCK(&s->kill_listmtx);
			continue;
		}

		dt_list_delete(&s->kill_list, kill_entry);
		UNLOCK(&s->kill_listmtx);

		if (kill(kill_entry->pid, SIGTERM)) {
			assert(errno != EINVAL);
			assert(errno != EPERM);

			if (errno == ESRCH) {
				fprintf(stderr, "pid %d does not exist\n",
				    kill_entry->pid);
			}
		}

		free(kill_entry);
	}

	return (_s);
}

static int
write_data(dtd_dir_t *dir, unsigned char *data, size_t nbytes)
{
	struct dtd_state *s;
	char *dirpath, *newname;
	char donename[MAXPATHLEN];
	size_t dirpathlen;
	int fd;

	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL in write_data()");
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

	if (s == NULL) {
		syslog(LOG_ERR, "state is NULL in write_data()");
		return (-1);
	}

	LOCK(&dir->dirmtx);
	dirpath = strdup(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	dirpathlen = strlen(dirpath);
	newname = gen_filename(dirpath);
	strcpy(donename, dirpath);
	strcpy(donename + dirpathlen, newname + dirpathlen + 1);
	free(dirpath);

	fd = open(newname, O_WRONLY | O_CREAT);
	if (fd == -1) {
		syslog(LOG_ERR, "open() failed with: %m");
		return (-1);
	}

	if (write(fd, data, nbytes) < 0) {
		syslog(LOG_ERR, "write() failed with: %m");
		return (-1);
	}

	if (rename(newname, donename)) {
		syslog(
		    LOG_ERR, "rename() failed %s -> %s: %m", newname, donename);
		return (-1);
	}

	return (0);
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

			syslog(LOG_ERR, "Failed to read an entry: %m");
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
					syslog(LOG_ERR,
					    "gen_filename() failed with %s\n",
					    strerror(errno));
					goto retry;
				}
				fd = open(path, O_CREAT | O_WRONLY, 0600);

				if (fd == -1) {
					syslog(LOG_ERR, "Failed to open %s: %m",
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

					syslog(LOG_ERR,
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
					syslog(LOG_ERR,
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
			syslog(LOG_WARNING,
			    "got unknown event (%d) from dttransport",
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
		syslog(LOG_ERR, "Failed creating a socket: %m");
		pthread_exit(NULL);
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;

	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
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

	if (recv(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		fprintf(stderr, "Failed to read from sockfd: %m");
		pthread_exit(NULL);
	}

	if (initmsg.kind != DTRACED_KIND_DTRACED) {
		syslog(LOG_ERR, "Expected dtraced kind, got %d\n",
		    initmsg.kind);
		close(sockfd);
		pthread_exit(NULL);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	initmsg.kind = DTRACED_KIND_FORWARDER;
	initmsg.subs = DTD_SUB_ELFWRITE;
	if (send(sockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		syslog(LOG_ERR, "Failed to write initmsg to sockfd: %m");
		pthread_exit(NULL);
	}


	while (atomic_load(&s->shutdown) == 0) {
		if ((rval = recv(sockfd, &len, sizeof(size_t), 0)) < 0) {
			if (errno == EINTR)
				pthread_exit(s);

			syslog(LOG_ERR, "Failed to recv from sub.sock: %m");
			continue;
		}

		msg = malloc(len);
		if (msg == NULL) {
			syslog(
			    LOG_ERR, "Failed to allocate a new message: %m\n");
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
			syslog(LOG_ERR, "Received unknown message type: %lu\n",
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
		return (NULL);
	}

	EV_SET(&ev, dir->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE,
	    NOTE_WRITE, 0, (void *)dir);

	while (atomic_load(&s->shutdown) == 0) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			syslog(LOG_ERR, "kevent() failed on %s: %m",
			    dir->dirpath);
			if (errno == EINTR)
				return (s);

			return (NULL);
		}

		if (ev_data.flags == EV_ERROR) {
			syslog(LOG_ERR, "kevent() got EV_ERROR on %s: %m",
			    dir->dirpath);
			continue;
		}

		if (rval > 0) {
			err = file_foreach(dir->dir, dir->processfn, dir);
			if (err) {
				syslog(LOG_ERR,
				    "Failed to process new files in %s",
				    dir->dirpath);
				return (NULL);
			}
		}
	}

	return (s);
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
	char *contents, *msg, *_msg;
	size_t msglen;
	size_t pathlen;
	size_t elflen;
	struct dtd_joblist *curjob;
	struct dtd_fdlist *fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	dtd_dir_t *dir;
	ssize_t r;
	pid_t pid;
	struct stat stat;
	unsigned char *buf, *_buf;
	size_t nbytes, totalbytes;
	dtraced_hdr_t header;
	struct kevent change_event[1];
	unsigned char ack = 1;
	struct dtd_joblist *job;
	struct dtd_fdlist *fd_list;
	const char *jobname[] = {
		[0]               = "NONE",
		[NOTIFY_ELFWRITE] = "NOTIFY_ELFWRITE",
		[KILL]            = "KILL",
		[READ_DATA]       = "READ_DATA"
	};

	_nosha = s->nosha;
	dir = NULL;
	memset(&stat, 0, sizeof(stat));

	while (atomic_load(&s->shutdown) == 0) {
		LOCK(&s->joblistcvmtx);
		LOCK(&s->joblistmtx);
		while (dt_list_next(&s->joblist) == NULL &&
		    atomic_load(&s->shutdown) == 0) {
			UNLOCK(&s->joblistmtx);
			WAIT(&s->joblistcv, pmutex_of(&s->joblistcvmtx));
			LOCK(&s->joblistmtx);
		}
		UNLOCK(&s->joblistmtx);
		UNLOCK(&s->joblistcvmtx);
		if (atomic_load(&s->shutdown) == 1)
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

		if (curjob->job >= 0 && curjob->job <= JOB_LAST)
			syslog(LOG_DEBUG, "Job: %s", jobname[curjob->job]);
		else
			syslog(LOG_WARNING, "Job %u out of bounds", curjob->job);

		switch (curjob->job) {
		case READ_DATA:
			fd = curjob->connsockfd;
			nbytes = 0;
			totalbytes = 0;

			if ((r =
			    recv(fd, &totalbytes, sizeof(totalbytes), 0)) < 0) {
				syslog(LOG_ERR, "recv() failed with: %m");
				break;
			}

			assert(r == sizeof(totalbytes));

			nbytes = totalbytes;

			buf = malloc(nbytes);
			if (buf == NULL) {
				syslog(LOG_ERR, "malloc() failed with: %m");
				break;
			}

			_buf = buf;
			while ((r = recv(fd, _buf, nbytes, 0)) != nbytes) {
				if (r < 0) {
					syslog(
					    LOG_ERR, "recv() failed with: %m");
					free(buf);
					buf = NULL;
					break;
				}

				assert(r != 0);

				_buf += r;
				nbytes -= r;
			}

			assert(nbytes == r);

			ack = 1;
			if (send(fd, &ack, 1, 0) < 0) {
				syslog(LOG_ERR, "send() failed with: %m");
				if (buf)
					free(buf);
				break;
			}

			/*
			 * We are done receiving the data and nothing failed,
			 * re-enable the event and keep going.
			 */
			EV_SET(change_event, fd, EVFILT_READ,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL)) {
				syslog(LOG_ERR, "kevent() failed with: %m");
				free(buf);
				break;
			}

			if (r < 0) {
				if (buf)
					free(buf);
				break;
			}

			nbytes = totalbytes;
			_buf = buf;

			/*
			 * We now have our data (ELF file) in buf. Create an ELF
			 * file in /var/ddtrace/base. This will kick off the
			 * listen_dir thread for process_base.
			 */

			memcpy(&header, buf, DTRACED_MSGHDRSIZE);
			switch (DTRACED_MSG_TYPE(header)) {
			case DTRACED_MSG_ELF:
				_buf += DTRACED_MSGHDRSIZE;
				nbytes -= DTRACED_MSGHDRSIZE;

				if (strcmp(
				    DTRACED_MSG_LOC(header), "base") == 0)
					dir = s->basedir;
				else if (strcmp(
				    DTRACED_MSG_LOC(header), "outbound") == 0)
					dir = s->outbounddir;
				else if (strcmp(
				    DTRACED_MSG_LOC(header), "inbound") == 0)
					dir = s->inbounddir;
				else
					dir = NULL;

				if (dir == NULL) {
					syslog(LOG_ERR,
					    "unrecognized location: %s",
					    DTRACED_MSG_LOC(header));

					free(buf);
					pthread_exit(NULL);
				}

				if (write_data(dir, _buf, nbytes))
					syslog(LOG_ERR, "write_data() failed");
				break;
			case DTRACED_MSG_KILL:
				/*
				 * We enqueue a KILL message in the joblist
				 * (another thread will simply pick this up). We
				 * need to only do it for FORWARDERs.
				 */

				LOCK(&s->socklistmtx);
				for (fd_list = dt_list_next(&s->sockfds);
				     fd_list; fd_list = dt_list_next(fd_list)) {
					if (fd_list->kind !=
					    DTRACED_KIND_FORWARDER)
						continue;

					if ((fd_list->subs & DTD_SUB_KILL) == 0)
						continue;

					job =
					    malloc(sizeof(struct dtd_joblist));
					if (job == NULL) {
						syslog(LOG_ERR,
						    "malloc() failed with: %m");
						UNLOCK(&s->socklistmtx);
						break;
					}

					memset(
					    job, 0, sizeof(struct dtd_joblist));

					job->job = KILL;
					job->connsockfd = fd_list->fd;
					job->j.kill.pid =
					    DTRACED_MSG_KILLPID(header);

					LOCK(&s->joblistmtx);
					dt_list_append(&s->joblist, job);
					UNLOCK(&s->joblistmtx);
				}
				UNLOCK(&s->socklistmtx);
				break;
			default:
				assert(0);
			}

			free(buf);
			break;
		case KILL:
			fd = curjob->connsockfd;
			pid = curjob->j.kill.pid;

			assert(fd != -1);
			/*
			 * If we end up with pid <= 1, something went wrong.
			 */
			assert(pid > 1);
			msglen = sizeof(pid_t) + DTRACED_MSGHDRSIZE;
			msg = malloc(msglen);
			if (msg == NULL) {
				syslog(LOG_ERR,
				    "Failed to allocate a kill message: %m");
				break;
			}

			/*
			 * For now the header only includes the message kind, so
			 * we don't really make it a structure. In the future,
			 * this might change.
			 */
			DTRACED_MSG_TYPE(header) = DTRACED_MSG_KILL;
			memcpy(msg, &header, DTRACED_MSGHDRSIZE);
			contents = msg + DTRACED_MSGHDRSIZE;

			memcpy(contents, &pid, sizeof(pid));

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
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto killcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d (%zu): %m",
					    fd, msglen);

				goto killcleanup;
			}

			if ((r = send(fd, msg, msglen, 0)) < 0) {
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
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto killcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d: %m", fd);

				goto killcleanup;
			}

			EV_SET(change_event, fd, EVFILT_WRITE,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL)) {
				syslog(LOG_WARNING,
				    "process_joblist: kevent() "
				    "failed with: %m");
				free(msg);
				break;
			}

killcleanup:
			free(msg);
			break;

		case NOTIFY_ELFWRITE:
			fd = curjob->connsockfd;
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
			msglen =
			    _nosha ? elflen : elflen + SHA256_DIGEST_LENGTH;
			msglen += DTRACED_MSGHDRSIZE;
			msg = malloc(msglen);

			if (msg == NULL) {
				syslog(LOG_ERR,
				    "Failed to allocate ELF contents: %m");
				free(path);
				close(elffd);
				break;
			}

			DTRACED_MSG_TYPE(header) = DTRACED_MSG_ELF;
			memset(msg, 0, msglen);
			memcpy(msg, &header, DTRACED_MSGHDRSIZE);

			_msg = msg + DTRACED_MSGHDRSIZE;
			contents = _nosha ? _msg : _msg + SHA256_DIGEST_LENGTH;

			if ((r = read(elffd, contents, elflen)) < 0) {
				syslog(
				    LOG_ERR, "Failed to read ELF contents: %m");
				free(path);
				free(msg);
				close(elffd);
				break;
			}

			if (_nosha == 0 &&
			    SHA256(contents, elflen, _msg) == NULL) {
				syslog(LOG_ERR,
				    "Failed to create a SHA256 of the file");
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
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto elfcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d (%zu): %m",
					    fd, msglen);

				goto elfcleanup;
			}

			if ((r = send(fd, msg, msglen, 0)) < 0) {
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
					fde = dt_in_list(
					    &s->sockfds, &fd, sizeof(int));
					if (fde == NULL) {
						UNLOCK(&s->socklistmtx);
						goto elfcleanup;
					}

					dt_list_delete(&s->sockfds, fde);
					UNLOCK(&s->socklistmtx);
				} else
					syslog(LOG_ERR,
					    "Failed to write to %d "
					    "(%s, %zu): %m",
					    fd, path, pathlen);

				goto elfcleanup;
			}

			EV_SET(change_event, fd, EVFILT_WRITE,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL))
				syslog(LOG_WARNING,
				    "process_joblist: kevent() "
				    "failed with: %m");
elfcleanup:
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

static int
accept_new_connection(struct dtd_state *s)
{
	int connsockfd;
	int on = 1;
	int kq = s->kq_hdl;
	struct dtd_fdlist *fde;
	dtd_initmsg_t initmsg;
	struct kevent change_event[4];

	memset(&initmsg, 0, sizeof(initmsg));

	connsockfd = accept(s->sockfd, NULL, 0);
	if (connsockfd == -1) {
		syslog(LOG_ERR, "accept() failed: %m");
		return (-1);
	}

	if (setsockopt(connsockfd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof(on))) {
		close(connsockfd);
		syslog(LOG_ERR, "setsockopt() failed: %m");
		return (-1);
	}

	initmsg.kind = DTRACED_KIND_DTRACED;
	if (send(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		syslog(LOG_ERR, "send() initmsg to connsockfd failed: %m");
		return (-1);
	}

	memset(&initmsg, 0, sizeof(initmsg));
	if (recv(connsockfd, &initmsg, sizeof(initmsg), 0) < 0) {
		close(connsockfd);
		syslog(LOG_ERR, "recv() get initmsg failed: %m");
		return (-1);
	}

	fde = malloc(sizeof(struct dtd_fdlist));
	if (fde == NULL) {
		close(connsockfd);
		syslog(LOG_ERR, "malloc() failed with: %m");
		return (-1);
	}

	memset(fde, 0, sizeof(struct dtd_fdlist));
	fde->fd = connsockfd;
	fde->kind = initmsg.kind;
	fde->subs = initmsg.subs;

	EV_SET(change_event, connsockfd, EVFILT_READ,
	    EV_ADD | EV_ENABLE, 0, 0, fde);
	if (kevent(kq, change_event, 1, NULL, 0, NULL) < 0) {
		close(connsockfd);
		free(fde);
		syslog(LOG_ERR, "kevent() adding new connection failed: %m");
		return (-1);
	}

	EV_SET(change_event, connsockfd, EVFILT_WRITE,
	    EV_ADD | EV_ENABLE, 0, 0, fde);
	if (kevent(kq, change_event, 1, NULL, 0, NULL) < 0) {
		close(connsockfd);
		free(fde);
		syslog(LOG_ERR, "kevent() adding new connection failed: %m");
		return (-1);
	}

	LOCK(&s->socklistmtx);
	dt_list_append(&s->sockfds, fde);
	UNLOCK(&s->socklistmtx);

	return (0);
}

/*
 * NOTE: dispatch_event assumes that event has already been handled correctly in
 * the main loop.
 */
static int
dispatch_event(struct dtd_state *s, struct kevent *ev)
{
	struct dtd_joblist *job;

	if (ev->filter == EVFILT_READ) {
		/*
		 * Read is a little bit more complicated than write, because we
		 * have to read in the actual event and put it in the
		 * /var/ddtrace/base directory for the directory monitoring
		 * kqueues to wake up and process it further.
		 */
		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			syslog(LOG_ERR, "malloc() failed with: %m");
			return (-1);
		}

		job->job = READ_DATA;
		job->connsockfd = ev->ident;

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);

	} else if (ev->filter == EVFILT_WRITE) {
		/*
		 * Because we are in a state where we know that:
		 *  (1) There is a consumer waiting for an event and we can
		 *      write to
		 * and
		 *  (2) We have said event
		 *
		 * we can signal the condition variable and rely on one of our
		 * workers to pick up and process the event.
		 */
		LOCK(&s->joblistcvmtx);
		SIGNAL(&s->joblistcv);
		UNLOCK(&s->joblistcvmtx);
	} else {
		free(job);
		syslog(LOG_ERR, "unexpected event flags: %d", ev->flags);
		return (-1);
	}

	return (0);
}

static void *
process_consumers(void *_s)
{
	int err;
	int connsockfd;
	int on = 1;
	int new_events;
	int kq;
	int efd;
	int dispatch;
	size_t i;
	struct dtd_fdlist *fde, *udata_fde;
	struct dtd_state *s = (struct dtd_state *)_s;
	struct dtd_joblist *jle;

	struct kevent change_event[4], event[4];

	dispatch = 0;

	/*
	 * Sanity checks on the state.
	 */
	if (s == NULL)
		pthread_exit(NULL);

	if (s->socktd == NULL)
		pthread_exit(NULL);

	if (s->sockfd == -1)
		pthread_exit(NULL);

	err = listen(s->sockfd, DTRACED_BACKLOG_SIZE);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to listen on %d: %m", s->sockfd);
		pthread_exit(NULL);
	}

	kq = kqueue();
	if (kq == -1) {
		syslog(LOG_ERR, "Failed to create dtraced socket kqueue: %m");
		pthread_exit(NULL);
	}

	EV_SET(
	    change_event, s->sockfd, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	if (kevent(kq, change_event, 1, NULL, 0, NULL)) {
		syslog(
		    LOG_ERR, "Failed to register listening socket kevent: %m");
		close(kq);
		pthread_exit(NULL);
	}

	s->kq_hdl = kq;
	SPOST(&s->socksema);

	while (atomic_load(&s->shutdown) == 0) {
		new_events = kevent(kq, NULL, 0, event, 1, NULL);
		if (new_events == -1) {
			/*
			 * Because kevent failed, we are no longer reliably able
			 * to accept any new connections, therefore the daemon
			 * must exit and report an error.
			 */
			syslog(LOG_ERR, "kevent() failed with %m");
			atomic_store(&s->shutdown, 1);
			pthread_exit(NULL);
		}

		for (i = 0; i < new_events; i++) {
			efd = event[i].ident;

			if (event[i].flags & EV_ERROR) {
				/*
				 * XXX: We could add some checks here to make
				 * sure we're not doing something bad and
				 * segfaulting.
				 */
				LOCK(&s->socklistmtx);
				dt_list_delete(&s->sockfds, event[i].udata);
				UNLOCK(&s->socklistmtx);
				free(event[i].udata);
				close(efd);
				syslog(LOG_ERR, "event error: %m");
				continue;
			}

			if (event[i].flags & EV_EOF) {
				LOCK(&s->socklistmtx);
				dt_list_delete(&s->sockfds, event[i].udata);
				UNLOCK(&s->socklistmtx);
				free(event[i].udata);

				close(efd);
				continue;
			}

			if (efd == s->sockfd) {
				/*
				 * New connection incoming
				 */
				if (accept_new_connection(s))
					pthread_exit(NULL);
				continue;
			}

			if (event[i].filter == EVFILT_READ) {
				/*
				 * assert that we are in a sane state.
				 */
				udata_fde = event[i].udata;
				assert(udata_fde->fd == efd);

				/*
				 * Disable the EVFILT_READ event so we don't get
				 * spammed by it.
				 */
				EV_SET(change_event, event[i].ident, EVFILT_READ,
				    EV_DISABLE, 0, 0, event[i].udata);
				if (kevent(s->kq_hdl, change_event, 1, NULL, 0,
					NULL)) {
					syslog(LOG_ERR,
					    "kevent() failed with: %m");
					pthread_exit(NULL);
				}

				/*
				 * If efd did not state it ever wants READDATA
				 * to work on dtraced, we will simply ignore
				 * it and report a warning.
				 */
				if ((udata_fde->subs & DTD_SUB_READDATA) == 0) {
					syslog(LOG_WARNING,
					    "socket %d tried to READDATA, but "
					    "is not subscribed (%lx)",
					    efd, udata_fde->subs);
					continue;
				}

				if (dispatch_event(s, &event[i])) {
					syslog(
					    LOG_ERR, "dispatch_event() failed");
					pthread_exit(NULL);
				}

				continue;
			}

			if (event[i].filter == EVFILT_WRITE) {
				EV_SET(change_event, efd, EVFILT_WRITE,
				    EV_DISABLE, 0, 0, event[i].udata);
				if (kevent(
				    kq, change_event, 1, NULL, 0, NULL)) {
					syslog(LOG_ERR,
					    "kevent() failed with: %m");
					pthread_exit(NULL);
				}

				dispatch = 0;

				LOCK(&s->joblistmtx);
				for (jle = dt_list_next(&s->joblist); jle;
				     jle = dt_list_next(jle))
					if (jle->connsockfd == efd) {
						/*
						 * Short sanity check before we
						 * say that we should dispatch
						 * the event.
						 */
						udata_fde = event[i].udata;
						assert(udata_fde->fd == efd);
						dispatch = 1;
					}
				UNLOCK(&s->joblistmtx);

				/*
				 * If we have a job to dispatch to the socket,
				 * we tell a worker thread to actually do the
				 * action.
				 */
				if (dispatch != 0) {
					if (dispatch_event(s, &event[i])) {
						syslog(LOG_ERR,
						    "dispatch_event() failed");
						pthread_exit(NULL);
					}

					continue;
				}
			}
		}
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
	l = strlcpy(addr.sun_path, DTRACED_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		syslog(LOG_ERR,
		    "Failed to copy %s into sockaddr (%zu)",
		    DTRACED_SOCKPATH, l);
		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
		if (err != 0)
			syslog(LOG_ERR, "Failed to destroy sockmtx: %m");

		return (-1);
	}

	if (remove(DTRACED_SOCKPATH) != 0) {
		if (errno != ENOENT) {
			syslog(LOG_ERR, "Failed to remove %s: %m",
			    DTRACED_SOCKPATH);
			return (-1);
		}
	}

	err = bind(s->sockfd, (struct sockaddr *)&addr, sizeof(addr));
	if (err != 0) {
		syslog(LOG_ERR, "Failed to bind to %d: %m", s->sockfd);
		if (close(s->sockfd) != 0) {
			syslog(LOG_ERR, "Failed to close %d: %m", s->sockfd);
			return (-1);
		}

		s->sockfd = -1;
		err = mutex_destroy(&s->sockmtx);
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

	if (remove(DTRACED_SOCKPATH) != 0)
		syslog(LOG_ERR, "Failed to remove %s: %m", DTRACED_SOCKPATH);

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

	assert(OWNED(&dir->dirmtx));

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
	struct kevent change_event[1];

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

	LOCK(&dir->dirmtx);
	idx = findpath(f->d_name, dir);
	if (idx >= 0) {
		UNLOCK(&dir->dirmtx);
		return (0);
	}

	l = strlcpy(fullpath, dir->dirpath, sizeof(fullpath));
	if (l >= sizeof(fullpath)) {
		syslog(LOG_ERR, "Failed to copy %s into a path string",
		    dir->dirpath);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	dirpathlen = strlen(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	l = strlcpy(
	    fullpath + dirpathlen, f->d_name, sizeof(fullpath) - dirpathlen);
	if (l >= sizeof(fullpath) - dirpathlen) {
		syslog(
		    LOG_ERR, "Failed to copy %s into a path string", f->d_name);
		return (-1);
	}
	filepathlen = strlen(fullpath);

	assert(g_ctrlmachine == 1 || g_ctrlmachine == 0);
	if (g_ctrlmachine == 1) {
		/*
		 * If we have a host configuration of dtraced
		 * we simply send off the ELF file to dtrace(1).
		 *
		 * We iterate over all our known dtrace(1)s that have
		 * registered with dtraced and send off the file path
		 * to them. They will parse said file path (we assume
		 * they won't be writing over it since this requires root
		 * anyway) and decide if the file is meant for them to
		 * process. There may be more dtrace(1) instances that
		 * want to process the same file in the future.
		 */
		LOCK(&s->socklistmtx);
		for (fd_list = dt_list_next(&s->sockfds); fd_list;
		    fd_list = dt_list_next(fd_list)) {
			if (fd_list->kind != DTRACED_KIND_CONSUMER)
				continue;

			if ((fd_list->subs & DTD_SUB_ELFWRITE) == 0)
				continue;

			job = malloc(sizeof(struct dtd_joblist));
			if (job == NULL) {
				syslog(LOG_ERR, "Failed to malloc a new job");
				UNLOCK(&s->socklistmtx);
				return (-1);
			}

			memset(job, 0, sizeof(struct dtd_joblist));
			job->job = NOTIFY_ELFWRITE;
			job->connsockfd = fd_list->fd;
			job->j.notify_elfwrite.path = strdup(f->d_name);
			job->j.notify_elfwrite.pathlen = strlen(f->d_name);
			job->j.notify_elfwrite.dir = dir;
			job->j.notify_elfwrite.nosha = 1;

			LOCK(&s->joblistmtx);
			dt_list_append(&s->joblist, job);
			UNLOCK(&s->joblistmtx);

			EV_SET(change_event, job->connsockfd, EVFILT_WRITE,
			    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
			if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL))
				syslog(LOG_WARNING,
				    "process_inbound: kevent() "
				    "failed with: %m");
		}
		UNLOCK(&s->socklistmtx);
	} else {
		parent = getpid();
		pid = fork();

		/*
		 * We don't wait for the process as we don't really care about
		 * it. We will just save the pid as running and kill it whenever
		 * a message arrives to do so.
		 */
		if (pid == -1) {
			syslog(LOG_ERR, "Failed to fork: %m");
			return (-1);
		} else if (pid > 0) {
			/*
			 * Send the pid back to the host... somehow.
			 */
		} else if (pid == 0) {
			argv[0] = strdup("/usr/sbin/dtrace");
			argv[1] = strdup("-Y");
			argv[2] = strdup(fullpath);
			argv[3] = NULL;
			execve("/usr/sbin/dtrace", argv, NULL);
			exit(EXIT_FAILURE);
		}
	}

cleanup:
	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	return (0);
}

static void
dtraced_copyfile(const char *src, const char *dst)
{
	int fd, newfd;
	struct stat sb;
	void *buf;
	size_t len;

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
	char *dirpath, *outbounddirpath;
	char donename[MAXPATHLEN] = { 0 };
	size_t dirpathlen = 0;

	if (dir == NULL) {
		syslog(LOG_ERR, "dir is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

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

	LOCK(&dir->dirmtx);
	idx = findpath(f->d_name, dir);
	if (idx >= 0) {
		UNLOCK(&dir->dirmtx);
		return (0);
	}

	dirpath = strdup(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	LOCK(&s->outbounddir->dirmtx);
	outbounddirpath = strdup(s->outbounddir->dirpath);
	UNLOCK(&s->outbounddir->dirmtx);

	newname = gen_filename(outbounddirpath);
	dirpathlen = strlen(outbounddirpath);
	strcpy(fullpath, dirpath);
	strcpy(fullpath + strlen(fullpath), f->d_name);
	dtraced_copyfile(fullpath, newname);
	strcpy(donename, outbounddirpath);
	strcpy(donename + dirpathlen, newname + dirpathlen + 1);
	if (rename(newname, donename))
		syslog(LOG_ERR, "Failed to rename %s to %s: %m", newname,
		    donename);
	free(newname);
	free(dirpath);
	free(outbounddirpath);

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
		strcpy(fullarg + offset, ",host");
		argv[2] = strdup(fullarg);
		argv[3] = NULL;
		execve("/usr/sbin/dtrace", argv, NULL);
		exit(EXIT_FAILURE);
	}

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

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
	struct kevent change_event[1];

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

	LOCK(&dir->dirmtx);
	idx = findpath(f->d_name, dir);
	UNLOCK(&dir->dirmtx);

	if (idx >= 0)
		return (0);

	LOCK(&s->socklistmtx);
	for (fd_list = dt_list_next(&s->sockfds); fd_list;
	    fd_list = dt_list_next(fd_list)) {
		if (fd_list->kind != DTRACED_KIND_FORWARDER)
			continue;

		if ((fd_list->subs & DTD_SUB_ELFWRITE) == 0)
			continue;

		job = malloc(sizeof(struct dtd_joblist));
		if (job == NULL) {
			syslog(LOG_ERR, "Failed to malloc a new job");
			UNLOCK(&s->socklistmtx);
			return (-1);
		}
		memset(job, 0, sizeof(struct dtd_joblist));

		job->job = NOTIFY_ELFWRITE;
		job->connsockfd = fd_list->fd;
		job->j.notify_elfwrite.path = strdup(f->d_name);
		job->j.notify_elfwrite.pathlen = strlen(f->d_name);
		job->j.notify_elfwrite.dir = dir;
		job->j.notify_elfwrite.nosha = s->nosha;

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		EV_SET(change_event, job->connsockfd, EVFILT_WRITE,
		    EV_ENABLE | EV_KEEPUDATA, 0, 0, 0);
		if (kevent(s->kq_hdl, change_event, 1, NULL, 0, NULL))
			syslog(LOG_WARNING,
			    "process_outbound:kevent() failed with: %m");
	}
	UNLOCK(&s->socklistmtx);

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		syslog(LOG_ERR, "Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

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

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		syslog(LOG_ERR, "Failed to expand paths in initialization");
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

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

	if (g_ctrlmachine == 0) {
		err = pthread_create(
		    &s->dtt_listentd, NULL, listen_dttransport, s);
		if (err != 0) {
			syslog(LOG_ERR,
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
			syslog(LOG_ERR,
			    "Failed to create the dttransport thread: %m");
			return (-1);
		}
	}

	err = pthread_create(&s->socktd, NULL, process_consumers, s);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create the socket thread: %m");
		return (-1);
	}

	err = pthread_create(&s->inboundtd, NULL, listen_dir, s->inbounddir);
	if (err != 0) {
		syslog(
		    LOG_ERR, "Failed to create inbound listening thread: %m");
		return (-1);
	}

	err = pthread_create(&s->basetd, NULL, listen_dir, s->basedir);
	if (err != 0) {
		syslog(LOG_ERR, "Failed to create base listening thread: %m");
		return (-1);
	}

	err = pthread_create(&s->killtd, NULL, manage_children, s);
	if (err != 0) {
		syslog(
		    LOG_ERR, "Failed to create a child management thread: %m");
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
	if ((err = mutex_init(
	    &dir->dirmtx, NULL, dir->dirpath, CHECKOWNER_YES)) != 0) {
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

	if ((err = mutex_init(
	    &s->socklistmtx, NULL, "socklist", CHECKOWNER_YES)) != 0) {
		syslog(LOG_ERR, "Failed to create sock list mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->sockmtx, NULL, "socket", CHECKOWNER_YES)) != 0) {
		syslog(LOG_ERR, "Failed to create socket mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistcvmtx, NULL, "joblist condvar", CHECKOWNER_NO)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist condvar mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->joblistmtx, NULL, "joblist", CHECKOWNER_YES)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->kill_listmtx, NULL, "kill list", CHECKOWNER_YES)) != 0) {
		syslog(LOG_ERR, "Failed to create kill list mutex: %m");
		return (-1);
	}

	if ((err = mutex_init(
	    &s->killcvmtx, NULL, "", CHECKOWNER_NO)) != 0) {
		syslog(LOG_ERR, "Failed to create kill condvar mutex: %m");
		return (-1);
	}

	if ((err = pthread_cond_init(&s->killcv, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create kill list condvar: %m");
		return (-1);
	}

	if ((err = pthread_cond_init(&s->joblistcv, NULL)) != 0) {
		syslog(LOG_ERR, "Failed to create joblist condvar: %m");
		return (-1);
	}

	if (g_ctrlmachine == 0) {
		s->dtt_fd = open("/dev/dttransport", O_RDWR);
		if (s->dtt_fd == -1) {
			syslog(LOG_ERR, "Failed to open /dev/dttransport: %m");
			return (-1);
		}
	}

	s->outbounddir = dtd_mkdir(DTRACED_OUTBOUNDDIR, &process_outbound);
	s->inbounddir = dtd_mkdir(DTRACED_INBOUNDDIR, &process_inbound);
	s->basedir = dtd_mkdir(DTRACED_BASEDIR, &process_base);

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
	
	LOCK(&dir->dirmtx);
	free(dir->dirpath);
	close(dir->dirfd);
	closedir(dir->dir);

	for (i = 0; i < dir->efile_len; i++)
		free(dir->existing_files[i]);

	free(dir->existing_files);

	dir->efile_size = 0;
	dir->efile_len = 0;
	UNLOCK(&dir->dirmtx);

	err = mutex_destroy(&dir->dirmtx);
	if (err != 0)
		syslog(LOG_ERR, "Failed to destroy dirmtx: %m");

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

	if ((err = mutex_destroy(&s->socklistmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy sock list mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->sockmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy socket mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->joblistcvmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist condvar mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->joblistmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->kill_listmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy kill list mutex: %m");
		return (-1);
	}

	if ((err = mutex_destroy(&s->killcvmtx)) != 0) {
		syslog(LOG_ERR, "Failed to destroy kill list cv mutex: %m");
		return (-1);
	}

	if ((err = pthread_cond_destroy(&s->killcv)) != 0) {
		syslog(LOG_ERR, "Failed to destroy kill condvar: %m");
		return (-1);
	}

	if ((err = pthread_cond_destroy(&s->joblistcv)) != 0) {
		syslog(LOG_ERR, "Failed to destroy joblist condvar: %m");
		return (-1);
	}

	dtd_closedir(s->outbounddir);
	dtd_closedir(s->inbounddir);
	dtd_closedir(s->basedir);

	sem_destroy(&s->socksema);

	destroy_sockfd(s);
	s->sockfd = -1;

	free(s->workers);

	if (g_ctrlmachine == 0) {
		close(s->dtt_fd);
		s->dtt_fd = -1;
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

	printf("dtraced: version %s\n", version());
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
	char hypervisor[128];
	int daemonize = 0;
	size_t len = sizeof(hypervisor);
	struct pidfh *pfh;
	pid_t otherpid;

	retry = 0;
	memset(pidstr, 0, sizeof(pidstr));
	memset(hypervisor, 0, sizeof(hypervisor));

	while ((ch = getopt(argc, argv, "Oa:de:hmvZ")) != -1) {
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

		/*
		 * Run the daemon in 'overlord' mode. An overlord daemon in this
		 * case also spawns a minion thread which is going to spawn
		 * DTrace instances on the host in order to do the necessary
		 * linking.
		 */
		case 'O':
			if (sysctlbyname("kern.vm_guest", hypervisor, &len,
			    NULL, 0)) {
				syslog(LOG_ERR,
				    "Failed to get kern.vm_guest: %m\n");
				return (EX_OSERR);
			}

			if (strcmp(hypervisor, "none") != 0) {
				/*
				 * We are virtualized, so we can't be an
				 * overlord. Virtual machines don't have
				 * minions.
				 */
				syslog(LOG_ERR,
				    "Specified '-O' (overlord mode) on a "
				    "virtual machine. This is not supported... "
				    "exiting.");

				exit(EXIT_FAILURE);
			}

			g_ctrlmachine = 1;
			break;

		/*
		 * Run the daemon in 'minion' mode.
		 */
		case 'm':
			if (sysctlbyname("kern.vm_guest", hypervisor, &len,
			    NULL, 0)) {
				syslog(LOG_ERR,
				    "Failed to get kern.vm_guest: %m\n");
				return (EX_OSERR);
			}

			if (strcmp(hypervisor, "bhyve") != 0) {
				/*
				 * Warn the user that this makes very little
				 * sense on a non-virtualized machine...
				 *
				 * XXX: We only support bhyve for now.
				 */

				syslog(LOG_WARNING,
				    "Specified '-m' (minion mode) on a native "
				    "(bare metal) machine. Did you mean to make"
				    " this machine an overlord ('-O')?");
			}
			g_ctrlmachine = 0;
			break;

		case 'd':
			daemonize = 1;
			break;

		case 'Z':
			nosha = 1;
			break;

		default:
			break;
		}
	}

	pfh = pidfile_open(LOCK_FILE, 0600, &otherpid);
	if (pfh == NULL) {
		if (errno == EEXIST) {
			syslog(LOG_ERR,
			    "dtraced is already running as pid %jd (check %s)",
			    (intmax_t)otherpid, LOCK_FILE);
			return (EX_OSERR);
		}

		syslog(LOG_ERR, "Could not open %s: %m", LOCK_FILE);
		return (EX_OSERR);
	}

	state.pid_fileh = pfh;

	if (g_ctrlmachine != 0 && g_ctrlmachine != 1) {
		syslog(LOG_ERR,
		    "You must either specify whether to run the daemon in "
		    "minion ('-m') or overlord ('-O') mode");
		return (EX_OSERR);
	}

	if (daemonize && daemon(0, 0) != 0) {
		syslog(LOG_ERR, "Failed to daemonize %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (pidfile_write(pfh)) {
		syslog(LOG_ERR, "Failed to write PID to %s: %m", LOCK_FILE);
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

againefd:
	efd = open(elfpath, O_RDONLY | O_DIRECTORY);
	if (efd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(elfpath, 0700) != 0)
				syslog(
				    LOG_ERR, "Failed to mkdir %s: %m", elfpath);
			else {
				retry = 1;
				goto againefd;
			}
		}

		syslog(LOG_ERR, "Failed to open %s: %m", elfpath);
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	state.dirfd = efd;
	elfdir = fdopendir(efd);

	errval = init_state(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to initialize the state");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	state.nosha = nosha;

	if (signal(SIGTERM, sig_term) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGTERM handler");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (signal(SIGINT, sig_int) == SIG_ERR) {
		syslog(LOG_ERR, "Failed to install SIGINT handler");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (siginterrupt(SIGTERM, 1) != 0) {
		syslog(LOG_ERR,
		    "Failed to enable system call interrupts for SIGTERM");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = setup_sockfd(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to set up the socket");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = file_foreach(
	    state.outbounddir->dir, populate_existing, state.outbounddir);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to populate outbound existing files");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = file_foreach(
	    state.inbounddir->dir, populate_existing, state.inbounddir);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to populate inbound existing files");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = file_foreach(
	    state.basedir->dir, populate_existing, state.basedir);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to populate base existing files");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = setup_threads(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to set up threads");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	if (listen_dir(state.outbounddir) == NULL) {
		syslog(LOG_ERR, "listen_dir() on %s failed",
		    state.outbounddir->dirpath);
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	errval = pthread_kill(state.socktd, SIGTERM);
	if (errval != 0)
		syslog(LOG_ERR, "Failed to interrupt socktd: %m");

	errval = pthread_join(state.socktd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join socktd: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_listentd, SIGTERM);
	if (errval != 0)
		syslog(LOG_ERR, "Failed to interrupt dtt_listentd: %m");

	errval = pthread_join(state.dtt_listentd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join dtt_listentd: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.dtt_writetd, SIGTERM);
	if (errval != 0 && errval != ESRCH)
		syslog(LOG_ERR, "Failed to interrupt dtt_writetd: %m");

	errval = pthread_join(state.dtt_writetd, (void **)&retval);
	if (errval != 0 && errval != ESRCH) {
		syslog(LOG_ERR, "Failed to join dtt_writetd: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.inboundtd, SIGTERM);
	if (errval != 0)
		syslog(LOG_ERR, "Failed to interrupt inboundtd: %m");

	errval = pthread_join(state.inboundtd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join inboundtd: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = pthread_kill(state.basetd, SIGTERM);
	if (errval != 0)
		syslog(LOG_ERR, "Failed to interrupt basetd: %m");

	errval = pthread_join(state.basetd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join basetd: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	LOCK(&state.joblistcvmtx);
	BROADCAST(&state.joblistcv);
	UNLOCK(&state.joblistcvmtx);

	for (i = 0; i < THREADPOOL_SIZE; i++) {
		errval = pthread_join(state.workers[i], (void **)&retval);
		if (errval != 0) {
			syslog(LOG_ERR, "Failed to join threads: %m");
			if (pidfile_remove(pfh))
				syslog(LOG_ERR, "Could not remove %s: %m",
				    LOCK_FILE);

			return (EX_OSERR);
		}
	}

	errval = pthread_kill(state.killtd, SIGTERM);
	if (errval != 0)
		syslog(LOG_ERR, "Failed to interrupt killtd: %m");

	errval = pthread_join(state.killtd, (void **)&retval);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to join child management thread: %m");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EX_OSERR);
	}

	errval = destroy_state(&state);
	if (errval != 0) {
		syslog(LOG_ERR, "Failed to clean up state");
		if (pidfile_remove(pfh))
			syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

		return (EXIT_FAILURE);
	}

	if (closedir(elfdir))
		syslog(LOG_ERR, "Could not close directory %s: %m",
		    elfpath);

	if (close(efd))
		syslog(LOG_ERR, "Could not close %s: %m", elfpath);

	if (pidfile_remove(pfh))
		syslog(LOG_ERR, "Could not remove %s: %m", LOCK_FILE);

	return (0);
}
