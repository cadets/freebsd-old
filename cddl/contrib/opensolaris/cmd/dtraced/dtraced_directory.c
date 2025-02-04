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
#include <sys/param.h>
#include <sys/event.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_chld.h"
#include "dtraced_connection.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

#define SOCKFD_NAME "sub.sock"

char DTRACED_INBOUNDDIR[MAXPATHLEN]  = "/var/ddtrace/inbound/";
char DTRACED_OUTBOUNDDIR[MAXPATHLEN] = "/var/ddtrace/outbound/";
char DTRACED_BASEDIR[MAXPATHLEN]     = "/var/ddtrace/base/";

int
write_data(dtd_dir_t *dir, unsigned char *data, size_t nbytes)
{
	struct dtraced_state *s;
	__cleanup(freep) char *dirpath = NULL;
	__cleanup(freep) char *newname = NULL;
	char donename[MAXPATHLEN];
	size_t dirpathlen;
	__cleanup(closefd_generic) int fd = -1;

	if (dir == NULL) {
		ERR("%d: %s(): dir is NULL in write_data()", __LINE__,
		    __func__);
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

	if (s == NULL) {
		ERR("%d: %s(): state is NULL in write_data()", __LINE__,
		    __func__);
		return (-1);
	}

	LOCK(&dir->dirmtx);
	dirpath = strdup(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	if (dirpath == NULL) {
		ERR("%d: %s(): Failed to strdup() dirpath: %m", __LINE__,
		    __func__);
		abort();
	}

	dirpathlen = strlen(dirpath);
	newname = gen_filename(dirpath);
	strcpy(donename, dirpath);
	strcpy(donename + dirpathlen, newname + dirpathlen + 1);

	fd = open(newname, O_WRONLY | O_CREAT);
	if (fd == -1) {
		ERR("%d: %s(): open() failed with: %m", __LINE__, __func__);
		return (-1);
	}

	if (write(fd, data, nbytes) < 0) {
		ERR("%d: %s(): write() failed with: %m", __LINE__, __func__);
		return (-1);
	}

	if (rename(newname, donename)) {
		ERR("%d: %s(): rename() failed %s -> %s: %m", __LINE__,
		    __func__, newname, donename);
		return (-1);
	}

	return (0);
}

void *
listen_dir(void *_dir)
{
	int err, rval;
	__cleanup(closefd_generic) int kq = -1;
	struct kevent ev, ev_data;
	struct dtraced_state *s;
	dtd_dir_t *dir;

	dir = (dtd_dir_t *)_dir;
	s = dir->state;

	if ((kq = kqueue()) == -1) {
		ERR("%d: %s(): Failed to create a kqueue %m", __LINE__,
		    __func__);
		return (NULL);
	}

	EV_SET(&ev, dir->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE,
	    NOTE_WRITE, 0, (void *)dir);

	while (atomic_load(&s->shutdown) == 0) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			ERR("%d: %s(): kevent() failed on %s: %m", __LINE__,
			    __func__, dir->dirpath);
			if (errno == EINTR)
				return (s);

			return (NULL);
		}

		if (ev_data.flags == EV_ERROR) {
			ERR("%d: %s(): kevent() got EV_ERROR on %s: %m",
			    __LINE__, __func__, dir->dirpath);
			continue;
		}

		if (rval > 0) {
			err = file_foreach(dir->dir, dir->processfn, dir);
			if (err) {
				ERR("%d: %s(): Failed to process new files in %s",
				    __LINE__, __func__, dir->dirpath);
				return (NULL);
			}
		}
	}

	return (s);
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
rmpath(const char *p, dtd_dir_t *dir)
{
	int i;

	for (i = 0; i < dir->efile_len; i++) {
		if (strcmp(p, dir->existing_files[i]) == 0) {
			free(dir->existing_files[i]);
			dir->existing_files[i] = NULL;
			return (0);
		}
	}

	return (-1);
}

static int
expand_paths(dtd_dir_t *dir)
{
	char **newpaths;
	struct dtraced_state *s;

	if (dir == NULL) {
		ERR("%d: %s(): Expand paths called with dir == NULL", __LINE__,
		    __func__);
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		ERR("%d: %s(): Expand paths called with state == NULL",
		    __LINE__, __func__);
		return (-1);
	}

	if (dir->efile_size <= dir->efile_len) {
		dir->efile_size = dir->efile_size == 0 ?
		    16 : (dir->efile_size << 1);

		/*
		 * Assert sanity after we multiply the size by two.
		 */
		if (dir->efile_size <= dir->efile_len) {
			ERR("%d: %s(): dir->efile_size <= dir->efile_len (%zu <= %zu)",
			    __LINE__, __func__, dir->efile_size,
			    dir->efile_len);
			return (-1);
		}

		/*
		 * Copy over the pointers to paths that were previously
		 * allocated in the old array.
		 */
		newpaths = malloc(dir->efile_size * sizeof(char *));
		if (newpaths == NULL) {
			ERR("%d: %s(): Failed to malloc newpaths", __LINE__,
			    __func__);
			abort();
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

int
populate_existing(struct dirent *f, dtd_dir_t *dir)
{
	int err;

	if (dir == NULL) {
		ERR("%d: %s(): dir is NULL", __LINE__, __func__);
		return (-1);
	}

	if (f == NULL) {
		ERR("%d: %s(): dirent is NULL", __LINE__, __func__);
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
		ERR("%d: %s(): Failed to expand paths in initialization",
		    __LINE__, __func__);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	if (dir->existing_files[dir->efile_len++] == NULL) {
		ERR("%d: %s(): failed to strdup f->d_name: %m", __LINE__,
		    __func__);
		abort();
	}

	return (0);
}

int
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

dtd_dir_t *
dtd_mkdir(const char *path, foreach_fn_t fn)
{
	dtd_dir_t *dir;
	int retry;
	int err;

	dir = malloc(sizeof(dtd_dir_t));
	if (dir == NULL) {
		ERR("%d: %s(): failed to allocate directory: %m", __LINE__,
		    __func__);
		abort();
	}

	memset(dir, 0, sizeof(dtd_dir_t));

	dir->dirpath = strdup(path);
	if (dir->dirpath == NULL) {
		ERR("%d: %s(): failed to strdup() dirpath: %m", __LINE__,
		    __func__);
		abort();
	}

	if ((err = mutex_init(
	    &dir->dirmtx, NULL, dir->dirpath, CHECKOWNER_YES)) != 0) {
		ERR("%d: %s(): Failed to create dir mutex: %m", __LINE__,
		    __func__);
		return (NULL);
	}

	retry = 0;
againmkdir:
	dir->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dir->dirfd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(path, 0700) != 0) {
				ERR("%d: %s(): Failed to mkdir %s: %m",
				    __LINE__, __func__, path);
				free(dir->dirpath);
				free(dir);

				return (NULL);
			} else {
				retry = 1;
				goto againmkdir;
			}
		}

		ERR("%d: %s(): Failed to open %s: %m", __LINE__, __func__,
		    path);
		free(dir->dirpath);
		free(dir);

		return (NULL);
	}

	dir->processfn = fn;
	dir->dir = fdopendir(dir->dirfd);
	if (dir->dir == NULL) {
		(void)close(dir->dirfd);
		free(dir->dirpath);
		free(dir);

		dir = NULL;
	}

	return (dir);
}

void
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
		ERR("%d: %s(): Failed to destroy dirmtx: %m", __LINE__,
		    __func__);

	free(dir);
}


int
process_inbound(struct dirent *f, dtd_dir_t *dir)
{
	int err, jfd;
	dtraced_fd_t *dfd;
	struct dtraced_job *job;
	struct dtraced_state *s;
	int idx;
	pid_t pid;
	char fullpath[MAXPATHLEN];
	int status;
	size_t l, dirpathlen;
	char *argv[7] = { 0 };
	identlist_t *ident_entry;
	unsigned char ident_to_delete[DTRACED_PROGIDENTLEN];
	pidlist_t *pe;

	memset(ident_to_delete, 0, sizeof(ident_to_delete));

	status = 0;
	if (dir == NULL) {
		ERR("%d: %s(): dir is NULL", __LINE__, __func__);
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		ERR("%d: %s(): state is NULL", __LINE__, __func__);
		return (-1);
	}

	if (f == NULL) {
		ERR("%d: %s(): dirent is NULL", __LINE__, __func__);
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	LOCK(&dir->dirmtx);

	/*
	 * Exit early if the file doesn't exist. There is definitely multiple
	 * race conditions here, but it doesn't really matter as we don't expect
	 * this to ever happen if communication happens through dtraced itself.
	 */
	if (faccessat(dir->dirfd, f->d_name, F_OK, 0) != 0) {
		ERR("%d: %s(): %s%s does not exist", __LINE__, __func__,
		    dir->dirpath, f->d_name);
		rmpath(f->d_name, dir);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	idx = findpath(f->d_name, dir);
	if (idx >= 0) {
		UNLOCK(&dir->dirmtx);
		return (0);
	}

	l = strlcpy(fullpath, dir->dirpath, sizeof(fullpath));
	if (l >= sizeof(fullpath)) {
		ERR("%d: %s(): Failed to copy %s into a path string", __LINE__,
		    __func__, dir->dirpath);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	dirpathlen = strlen(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	l = strlcpy(fullpath + dirpathlen, f->d_name,
	    sizeof(fullpath) - dirpathlen);
	if (l >= sizeof(fullpath) - dirpathlen) {
		ERR("%d: %s(): Failed to copy %s into a path string", __LINE__,
		    __func__, f->d_name);
		return (-1);
	}

	assert(s->ctrlmachine == 1 || s->ctrlmachine == 0);
	if (s->ctrlmachine == 1) {
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
		for (dfd = dt_list_next(&s->sockfds); dfd;
		    dfd = dt_list_next(dfd)) {
			fd_acquire(dfd);
			if (dfd->kind != DTRACED_KIND_CONSUMER) {
				fd_release(dfd);
				continue;
			}

			if ((dfd->subs & DTD_SUB_ELFWRITE) == 0) {
				fd_release(dfd);
				continue;
			}

			jfd = dfd->fd;
			job = malloc(sizeof(struct dtraced_job));
			if (job == NULL) {
				ERR("%d: %s(): Failed to malloc a new job: %m",
				    __LINE__, __func__);
				abort();
			}

			memset(job, 0, sizeof(struct dtraced_job));
			job->job = NOTIFY_ELFWRITE;
			job->connsockfd = dfd;
			job->j.notify_elfwrite.path = strdup(f->d_name);
			job->j.notify_elfwrite.pathlen = strlen(f->d_name);
			job->j.notify_elfwrite.dir = dir;
			job->j.notify_elfwrite.nosha = 1;

			if (job->j.notify_elfwrite.path == NULL) {
				ERR("%d: %s(): failed to strdup() f->d_name: %m",
				    __LINE__, __func__);
				abort();
			}

			LOCK(&s->joblistmtx);
			dt_list_append(&s->joblist, job);
			UNLOCK(&s->joblistmtx);

			if (reenable_fd(s->kq_hdl, jfd, EVFILT_WRITE))
				ERR("%d: %s(): process_inbound: kevent() failed with: %m",
				    __LINE__, __func__);
		}
		UNLOCK(&s->socklistmtx);
	} else {
		int stdout_rdr[2];
		int stdin_rdr[2];
		size_t num_idents;

		if (pipe(stdout_rdr) != 0) {
			ERR("%d: %s(): pipe(stdout) failed: %m", __LINE__,
			    __func__);
			return (-1);
		}

		if (pipe(stdin_rdr) != 0) {
			ERR("%d: %s(): pipe(stdin) failed: %m", __LINE__,
			    __func__);
			return (-1);
		}

		/*
		 * Count up how many identifiers we have. We will need to use
		 * this both in the child and parent.
		 */
		num_idents = 0;
		LOCK(&s->identlistmtx);
		for (ident_entry = dt_list_next(&s->identlist); ident_entry;
		     ident_entry = dt_list_next(ident_entry))
			num_idents++;
		UNLOCK(&s->identlistmtx);

		pid = fork();

		/*
		 * We don't wait for the process as we don't really care about
		 * it. We will just save the pid as running and kill it whenever
		 * a message arrives to do so.
		 */
		if (pid == -1) {
			ERR("%d: %s(): Failed to fork: %m", __LINE__, __func__);
			return (-1);
		} else if (pid > 0) {
			size_t current;
			int wait_for_pid = 0;
			struct timespec timeout = { 0 };
			int remove = 1, rv = 0;
			char msg[] = "DEL ident";
			__cleanup(closefd_generic) int kq = kqueue();
			struct kevent ev, ev_data;

			if (kq == -1) {
				ERR("%d: %s(): Failed to create timeout kq, __LINE__, __func__");
				return (-1);
			}

			close(stdin_rdr[0]);
			close(stdout_rdr[1]);

			if (write(stdin_rdr[1], &num_idents,
			    sizeof(num_idents)) == -1) {
				ERR("%d: %s(): write(%zu) failed: %m", __LINE__,
				    __func__, num_idents);
				return (-1);
			}

			/*
			 * There is a race condition between the fork and
			 * traversal of this list. We could have added a new
			 * identifier to our list. However, because we always
			 * append to the list rather than randomly insert them,
			 * we can simply count up how many identifiers we've
			 * sent and don't need to worry about snapshotting the
			 * original state of the list in another list.
			 */
			LOCK(&s->identlistmtx);
			for (ident_entry = dt_list_next(&s->identlist),
			     current = 0;
			     ident_entry && current < num_idents;
			     ident_entry = dt_list_next(ident_entry),
			     current++) {
				if (write(stdin_rdr[1], ident_entry->ident,
				    DTRACED_PROGIDENTLEN) == -1) {
					ERR("%d: %s(): write(stdin) failed: %m",
					    __LINE__, __func__);
					return (-1);
				}
			}
			UNLOCK(&s->identlistmtx);
			close(stdin_rdr[1]);

			/*
			 * This will give us the identifier that matched and
			 * needs to be deleted. We give the child 5 seconds to
			 * give us the identifier, otherwise we simply kill it.
			 * This avoids a deadlock in dtraced in the case of a
			 * bug in dtrace(1).
			 */
			timeout.tv_sec = 5;
			timeout.tv_nsec = 0;

			EV_SET(&ev, stdout_rdr[0], EVFILT_READ,
			    EV_ADD | EV_CLEAR | EV_ENABLE, 0, 0, 0);
			ERR("%d: %s(): Waiting for %d", __LINE__, __func__, pid);
			rv = kevent(kq, &ev, 1, &ev_data, 1, &timeout);

			if (rv < 0) {
				ERR("%d: %s(): kevent() failed: %m, __LINE__, __func__");
				return (-1);
			} else if (rv == 0) {
				/* Timeout */
				ERR("%d: %s(): killing %d", __LINE__, __func__,
				    pid);
				kill(pid, SIGKILL);
				waitpid(pid, &status, 0);
				return (0);
			}

			/*
			 * It should be safe to read at this point due to the
			 * select above, ensuring that we have data to read
			 * here.
			 */
			if ((rv = read(stdout_rdr[0], msg,
			    sizeof(msg))) == -1) {
				ERR("%d: %s(): read() failed: %m", __LINE__,
				    __func__);
				remove = 0;
			}

			if (rv != sizeof(msg) && rv != 0) {
				WARN("%d: %s(): Expected a read of %zu bytes, "
				     "but got %zu. Not removing ident",
				    __LINE__, __func__, sizeof(msg), rv, pid);
				return (0);
			}

			msg[sizeof(msg) - 1] = '\0';

			if (strcmp(msg, "FAIL FAIL") == 0) {
				remove = 0;
				wait_for_pid = 1;
				goto failmsg;
			}

			if (strcmp(msg, "DEL ident") != 0) {
				kill(pid, SIGKILL);
				WARN("%d: %s(): Expected DEL ident, but got %s",
				    __LINE__, __func__, msg);
				return (0);
			}

			/*
			 * It should be safe to read at this point due to the
			 * select above, ensuring that we have data to read
			 * here.
			 */
			if ((rv = read(stdout_rdr[0], ident_to_delete,
			    DTRACED_PROGIDENTLEN)) == -1) {
				ERR("%d: %s(): read() failed: %m", __LINE__,
				    __func__);
				remove = 0;
			}

			if (rv != DTRACED_PROGIDENTLEN && rv != 0) {
				WARN("%d: %s(): Expected a read of %zu bytes, "
				     "but got %zu. Not removing ident.",
				    __LINE__, __func__, DTRACED_PROGIDENTLEN,
				    rv, pid);
				return (0);
			}

failmsg:
			close(stdout_rdr[0]);

			/*
			 * Remove the entry that the child tells us from the
			 * identlist.
			 */
			if (remove) {
				LOCK(&s->identlistmtx);
				for (ident_entry = dt_list_next(&s->identlist);
				     ident_entry;
				     ident_entry = dt_list_next(ident_entry)) {
					if (memcmp(ident_to_delete,
					    ident_entry->ident,
					    DTRACED_PROGIDENTLEN) == 0) {
						dt_list_delete(
						    &s->identlist, ident_entry);
						free(ident_entry);
						break;
					}
				}
				UNLOCK(&s->identlistmtx);
			}

			if (num_idents == 0 || wait_for_pid != 0) {
				DEBUG("%d: %s(): waitpid(%d)", __LINE__, __func__, pid);
				waitpid(pid, &status, 0);
				DEBUG("%d: %s(): joined %d, status %d", __LINE__, __func__, pid, status);
			}
			else {
				pe = malloc(sizeof(pidlist_t));
				if (pe == NULL)
					abort();

				pe->pid = pid;
				LOCK(&s->pidlistmtx);
				dt_list_append(&s->pidlist, pe);
				UNLOCK(&s->pidlistmtx);
			}

		} else if (pid == 0) {
			char *curptr;
			char *ident;

			close(stdout_rdr[0]);
			if (dup2(stdout_rdr[1], STDOUT_FILENO) == -1) {
				ERR("%d: %s(): dup2(stdout) failed: %m",
				    __LINE__, __func__);
				exit(EXIT_FAILURE);
			}

			close(stdin_rdr[1]);
			if (dup2(stdin_rdr[0], STDIN_FILENO) == -1) {
				ERR("%d: %s(): dup2(stdin) failed: %m",
				    __LINE__, __func__);
				exit(EXIT_FAILURE);
			}

			/*
			 * We want dtrace to be as quiet as possible, so we pass
			 * the '-q' flag.
			 */
			argv[0] = strdup("/usr/sbin/dtrace");
			if (argv[0] == NULL)
				abort();

			argv[1] = strdup("-Y");
			if (argv[1] == NULL)
				abort();

			argv[2] = strdup(fullpath);
			if (argv[2] == NULL)
				abort();

			argv[3] = strdup("-q");
			if (argv[3] == NULL)
				abort();

			argv[4] = strdup("-q");
			if (argv[4] == NULL)
				abort();

			if (num_idents > 0) {
				argv[5] = strdup("-N");
				if (argv[5] == NULL)
					abort();

			} else
				argv[5] = NULL;

			argv[6] = NULL;

			execve("/usr/sbin/dtrace", argv, NULL);
			exit(EXIT_FAILURE);
		}
	}

cleanup:
	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		ERR("%d: %s(): Failed to expand paths after processing %s",
		    __LINE__, __func__, f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	if (dir->existing_files[dir->efile_len++] == NULL) {
		ERR("%d: %s(): failed to strdup f->d_name: %m", __LINE__,
		    __func__);
		abort();
	}

	return (0);
}

static void
dtraced_copyfile(const char *src, const char *dst)
{
	__cleanup(closefd_generic) int fd = -1;
	__cleanup(closefd_generic) int newfd = -1;
	struct stat sb;
	__cleanup(freep) void *buf = NULL;
	size_t len;

	memset(&sb, 0, sizeof(struct stat));

	fd = open(src, O_RDONLY);
	if (fd == -1)
		ERR("%d: %s(): Failed to open %s: %m", __LINE__, __func__, src);

	if (fstat(fd, &sb)) {
		ERR("%d: %s(): Failed to fstat %s (%d): %m", __LINE__, __func__,
		    src, fd);
		return;
	}

	len = sb.st_size;
	buf = malloc(len);
	if (buf == NULL) {
		ERR("%d: %s(): failed to allocate buf: %m", __LINE__, __func__);
		abort();
	}

	if (read(fd, buf, len) < 0) {
		ERR("%d: %s(): Failed to read %zu bytes from %s (%d): %m",
		    __LINE__, __func__, len, src, fd);
		return;
	}

	newfd = open(dst, O_WRONLY | O_CREAT);
	if (newfd == -1) {
		ERR("%d: %s(): Failed to open and create %s: %m", __LINE__,
		    __func__, dst);
		return;
	}

	if (write(newfd, buf, len) < 0) {
		ERR("%d: %s(): Failed to write %zu bytes to %s (%d): %m",
		    __LINE__, __func__, len, dst, newfd);
		return;
	}
}

int
process_base(struct dirent *f, dtd_dir_t *dir)
{
	struct dtraced_state *s;
	int idx, err;
	__cleanup(freep) char *newname = NULL;
	char fullpath[MAXPATHLEN] = { 0 };
	int status = 0;
	pid_t pid;
	char *argv[5];
	char fullarg[MAXPATHLEN*2 + 1] = { 0 };
	size_t offset;
	__cleanup(freep) char *dirpath = NULL;
	__cleanup(freep) char *outbounddirpath = NULL;
	char donename[MAXPATHLEN] = { 0 };
	size_t dirpathlen = 0;

	if (dir == NULL) {
		ERR("%d: %s(): dir is NULL in base directory monitoring thread",
		    __LINE__, __func__);
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

	if (s == NULL) {
		ERR("%d: %s(): state is NULL in base directory monitoring thread",
		    __LINE__, __func__);
		return (-1);
	}

	if (f == NULL) {
		ERR("%d: %s(): dirent is NULL in base directory monitoring thread",
		    __LINE__, __func__);
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	LOCK(&dir->dirmtx);

	/*
	 * Exit early if the file doesn't exist. There is definitely multiple
	 * race conditions here, but it doesn't really matter as we don't expect
	 * this to ever happen if communication happens through dtraced itself.
	 */
	if (faccessat(dir->dirfd, f->d_name, F_OK, 0) != 0) {
		ERR("%d: %s(): %s%s does not exist", __LINE__, __func__,
		    dir->dirpath, f->d_name);
		rmpath(f->d_name, dir);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	idx = findpath(f->d_name, dir);
	if (idx >= 0) {
		UNLOCK(&dir->dirmtx);
		return (0);
	}

	dirpath = strdup(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	if (dirpath == NULL) {
		ERR("%d: %s(): failed to strdup() dirpath: %m", __LINE__,
		    __func__);
		abort();
	}

	LOCK(&s->outbounddir->dirmtx);
	outbounddirpath = strdup(s->outbounddir->dirpath);
	UNLOCK(&s->outbounddir->dirmtx);

	if (outbounddirpath == NULL) {
		ERR("%d: %s(): failed to strdup() outbounddirpath: %m",
		    __LINE__, __func__);
		abort();
	}

	newname = gen_filename(outbounddirpath);
	dirpathlen = strlen(outbounddirpath);
	strcpy(fullpath, dirpath);
	strcpy(fullpath + strlen(fullpath), f->d_name);
	dtraced_copyfile(fullpath, newname);
	strcpy(donename, outbounddirpath);
	strcpy(donename + dirpathlen, newname + dirpathlen + 1);
	DEBUG("%d: %s(): Renaming %s -> %s", __LINE__, __func__, newname,
	    donename);
	if (rename(newname, donename))
		ERR("%d: %s(): Failed to rename %s to %s: %m", __LINE__,
		    __func__, newname, donename);

	pid = fork();

	if (pid == -1) {
		ERR("%d: %s(): Failed to fork: %m", __LINE__, __func__);
		return (-1);
	} else if (pid > 0) {
		waitpid(pid, &status, 0);
	} else {
		argv[0] = strdup("/usr/sbin/dtrace");
		if (argv[0] == NULL)
			abort();

		argv[1] = strdup("-q");
		if (argv[1] == NULL)
			abort();

		argv[2] = strdup("-Y");
		if (argv[2] == NULL)
			abort();

		strcpy(fullarg, fullpath);
		offset = strlen(fullarg);
		strcpy(fullarg + offset, ",host");
		argv[3] = strdup(fullarg);
		if (argv[3] == NULL)
			abort();

		argv[4] = NULL;
		execve("/usr/sbin/dtrace", argv, NULL);
		exit(EXIT_FAILURE);
	}

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		ERR("%d: %s(): Failed to expand paths after processing %s",
		    __LINE__, __func__, f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	if (dir->existing_files[dir->efile_len++] == NULL) {
		ERR("%d: %s(): Failed to strdup f->d_name: %m", __LINE__,
		    __func__);
		abort();
	}

	return (0);
}

int
process_outbound(struct dirent *f, dtd_dir_t *dir)
{
	int err, jfd;
	dtraced_fd_t *dfd;
	struct dtraced_job *job;
	struct dtraced_state *s;
	int idx, ch;
	char *newname = NULL;

	if (dir == NULL) {
		ERR("%d: %s(): dir is NULL", __LINE__, __func__);
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		ERR("%d: %s(): state is NULL", __LINE__, __func__);
		return (-1);
	}

	if (f == NULL) {
		ERR("%d: %s(): dirent is NULL", __LINE__, __func__);
		return (-1);
	}

	if (strcmp(f->d_name, SOCKFD_NAME) == 0)
		return (0);

	if (f->d_name[0] == '.')
		return (0);

	LOCK(&dir->dirmtx);

	/*
	 * Exit early if the file doesn't exist. There is definitely multiple
	 * race conditions here, but it doesn't really matter as we don't expect
	 * this to ever happen if communication happens through dtraced itself.
	 */
	if (faccessat(dir->dirfd, f->d_name, F_OK, 0) != 0) {
		ERR("%d: %s(): %s%s does not exist", __LINE__, __func__,
		    dir->dirpath, f->d_name);
		rmpath(f->d_name, dir);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	idx = findpath(f->d_name, dir);
	UNLOCK(&dir->dirmtx);

	if (idx >= 0)
		return (0);

	LOCK(&s->socklistmtx);
	for (dfd = dt_list_next(&s->sockfds); dfd; dfd = dt_list_next(dfd)) {
		fd_acquire(dfd);
		if (dfd->kind != DTRACED_KIND_FORWARDER) {
			fd_release(dfd);
			continue;
		}

		if ((dfd->subs & DTD_SUB_ELFWRITE) == 0) {
			fd_release(dfd);
			continue;
		}

		jfd = dfd->fd;
		job = malloc(sizeof(struct dtraced_job));
		if (job == NULL) {
			ERR("%d: %s(): Failed to malloc a new job: %m",
			    __LINE__, __func__);
			abort();
		}

		memset(job, 0, sizeof(struct dtraced_job));

		job->job = NOTIFY_ELFWRITE;
		job->connsockfd = dfd;
		job->j.notify_elfwrite.path = strdup(f->d_name);
		job->j.notify_elfwrite.pathlen = strlen(f->d_name);
		job->j.notify_elfwrite.dir = dir;
		job->j.notify_elfwrite.nosha = s->nosha;

		if (job->j.notify_elfwrite.path == NULL) {
			ERR("%d: %s(): Failed to strdup() f->d_name: %m",
			    __LINE__, __func__);
			abort();
		}

		LOCK(&s->joblistmtx);
		dt_list_append(&s->joblist, job);
		UNLOCK(&s->joblistmtx);

		if (reenable_fd(s->kq_hdl, jfd, EVFILT_WRITE))
			ERR("%d: %s(): reenable_fd() failed with: %m", __LINE__,
			    __func__);
	}
	UNLOCK(&s->socklistmtx);

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		ERR("%d: %s(): Failed to expand paths after processing %s",
		    __LINE__, __func__, f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	if (dir->existing_files[dir->efile_len++] == NULL) {
		ERR("%d: %s(): Failed to strdup f->d_name: %m", __LINE__,
		    __func__);
		abort();
	}

	return (0);
}

