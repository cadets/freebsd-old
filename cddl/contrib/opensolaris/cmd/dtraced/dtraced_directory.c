#include <sys/types.h>
#include <sys/param.h>
#include <sys/event.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"

int
write_data(dtd_dir_t *dir, unsigned char *data, size_t nbytes)
{
	struct dtd_state *s;
	char *dirpath, *newname;
	char donename[MAXPATHLEN];
	size_t dirpathlen;
	int fd;

	if (dir == NULL) {
		dump_errmsg("dir is NULL in write_data()");
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

	if (s == NULL) {
		dump_errmsg("state is NULL in write_data()");
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
		dump_errmsg("open() failed with: %m");
		return (-1);
	}

	if (write(fd, data, nbytes) < 0) {
		dump_errmsg("write() failed with: %m");
		return (-1);
	}

	if (rename(newname, donename)) {
		dump_errmsg("rename() failed %s -> %s: %m", newname, donename);
		return (-1);
	}

	return (0);
}

void *
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
		dump_errmsg("Failed to create a kqueue %m");
		return (NULL);
	}

	EV_SET(&ev, dir->dirfd, EVFILT_VNODE, EV_ADD | EV_CLEAR | EV_ENABLE,
	    NOTE_WRITE, 0, (void *)dir);

	while (atomic_load(&s->shutdown) == 0) {
		rval = kevent(kq, &ev, 1, &ev_data, 1, NULL);
		assert(rval != 0);

		if (rval < 0) {
			dump_errmsg("kevent() failed on %s: %m",
			    dir->dirpath);
			if (errno == EINTR)
				return (s);

			return (NULL);
		}

		if (ev_data.flags == EV_ERROR) {
			dump_errmsg("kevent() got EV_ERROR on %s: %m",
			    dir->dirpath);
			continue;
		}

		if (rval > 0) {
			err = file_foreach(dir->dir, dir->processfn, dir);
			if (err) {
				dump_errmsg("Failed to process new files in %s",
				    dir->dirpath);
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
expand_paths(dtd_dir_t *dir)
{
	char **newpaths;
	struct dtd_state *s;

	assert(OWNED(&dir->dirmtx));

	if (dir == NULL) {
		dump_errmsg("Expand paths called with dir == NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		dump_errmsg("Expand paths called with state == NULL");
		return (-1);
	}

	if (dir->efile_size <= dir->efile_len) {
		dir->efile_size = dir->efile_size == 0 ?
		    16 : (dir->efile_size << 1);

		/*
		 * Assert sanity after we multiply the size by two.
		 */
		if (dir->efile_size <= dir->efile_len) {
			dump_errmsg("dir->efile_size <= dir->efile_len"
			    " (%zu <= %zu)", dir->efile_size, dir->efile_len);
			return (-1);
		}

		/*
		 * Copy over the pointers to paths that were previously
		 * allocated in the old array.
		 */
		newpaths = malloc(dir->efile_size * sizeof(char *));
		if (newpaths == NULL) {
			dump_errmsg("Failed to malloc newpaths");
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

int
populate_existing(struct dirent *f, dtd_dir_t *dir)
{
	int err;

	if (dir == NULL) {
		dump_errmsg("dir is NULL");
		return (-1);
	}

	if (f == NULL) {
		dump_errmsg("dirent is NULL");
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
		dump_errmsg("Failed to expand paths in initialization");
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

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

	err = 0;

	dir = malloc(sizeof(dtd_dir_t));
	if (dir == NULL)
		return (NULL);

	memset(dir, 0, sizeof(dtd_dir_t));

	dir->dirpath = strdup(path);
	if ((err = mutex_init(
	    &dir->dirmtx, NULL, dir->dirpath, CHECKOWNER_YES)) != 0) {
		dump_errmsg("Failed to create dir mutex: %m");
		return (NULL);
	}

	retry = 0;
againmkdir:
	dir->dirfd = open(path, O_RDONLY | O_DIRECTORY);
	if (dir->dirfd == -1) {
		if (retry == 0 && errno == ENOENT) {
			if (mkdir(path, 0700) != 0) {
				dump_errmsg("Failed to mkdir %s: %m", path);
				free(dir->dirpath);
				free(dir);

				return (NULL);
			} else {
				retry = 1;
				goto againmkdir;
			}
		}

		dump_errmsg("Failed to open %s: %m", path);
		free(dir->dirpath);
		free(dir);

		return (NULL);
	}

	dir->processfn = fn;
	dir->dir = fdopendir(dir->dirfd);

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
		dump_errmsg("Failed to destroy dirmtx: %m");

	free(dir);
}


int
process_inbound(struct dirent *f, dtd_dir_t *dir)
{
	int err;
	struct dtd_fdlist *fd_list;
	struct dtd_joblist *job;
	struct dtd_state *s;
	int idx;
	pid_t pid;
	char fullpath[MAXPATHLEN] = { 0 };
	int status;
	size_t l, dirpathlen, filepathlen;
	char *argv[6] = { 0 };
	identlist_t *ident_entry;
	struct kevent change_event[1];
	unsigned char ident_to_delete[DTRACED_PROGIDENTLEN];

	memset(ident_to_delete, 0, sizeof(ident_to_delete));

	status = 0;
	if (dir == NULL) {
		dump_errmsg("dir is NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		dump_errmsg("state is NULL");
		return (-1);
	}

	if (f == NULL) {
		dump_errmsg("dirent is NULL");
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
		dump_errmsg("Failed to copy %s into a path string",
		    dir->dirpath);
		UNLOCK(&dir->dirmtx);
		return (-1);
	}

	dirpathlen = strlen(dir->dirpath);
	UNLOCK(&dir->dirmtx);

	l = strlcpy(
	    fullpath + dirpathlen, f->d_name, sizeof(fullpath) - dirpathlen);
	if (l >= sizeof(fullpath) - dirpathlen) {
		dump_errmsg("Failed to copy %s into a path string", f->d_name);
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
				dump_errmsg("Failed to malloc a new job");
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
				dump_errmsg("process_inbound: kevent() "
					    "failed with: %m");
		}
		UNLOCK(&s->socklistmtx);
	} else {
		int stdout_rdr[2];
		int stdin_rdr[2];
		size_t num_idents;

		if (pipe(stdout_rdr) != 0) {
			dump_errmsg("pipe(stdout) failed: %m");
			return (-1);
		}

		if (pipe(stdin_rdr) != 0) {
			dump_errmsg("pipe(stdin) failed: %m");
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
			dump_errmsg("Failed to fork: %m");
			return (-1);
		} else if (pid > 0) {
			size_t current;

			close(stdin_rdr[0]);
			close(stdout_rdr[1]);

			if (write(stdin_rdr[1], &num_idents,
			    sizeof(num_idents)) == -1) {
				dump_errmsg("write(%zu) failed: %m",
				    num_idents);
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
					dump_errmsg("write(stdin) failed: %m");
					return (-1);
				}
			}
			UNLOCK(&s->identlistmtx);
			close(stdin_rdr[1]);

			/*
			 * This will give us the identifier that matched and
			 * needs to be deleted.
			 */
			if (read(stdout_rdr[0], ident_to_delete,
			    DTRACED_PROGIDENTLEN) == -1) {
				dump_errmsg("read() failed: %m");
				return (-1);
			}

			close(stdout_rdr[0]);

			/*
			 * Remove the entry that the child tells us from the
			 * pidlist.
			 */
			LOCK(&s->identlistmtx);
			for (ident_entry = dt_list_next(&s->identlist);
			     ident_entry;
			     ident_entry = dt_list_next(ident_entry)) {
				if (memcmp(ident_to_delete, ident_entry->ident,
				    DTRACED_PROGIDENTLEN) == 0) {
					dt_list_delete(
					    &s->identlist, ident_entry);
					free(ident_entry);
					break;
				}
			}
			UNLOCK(&s->identlistmtx);
		} else if (pid == 0) {
			char *curptr;
			char *ident;

			close(stdout_rdr[0]);
			if (dup2(stdout_rdr[1], STDOUT_FILENO) == -1) {
				dump_errmsg("dup2(stdout) failed: %m");
				exit(EXIT_FAILURE);
			}

			close(stdin_rdr[1]);
			if (dup2(stdin_rdr[0], STDIN_FILENO) == -1) {
				dump_errmsg("dup2(stdin) failed: %m");
				exit(EXIT_FAILURE);
			}

			/*
			 * We want dtrace to be as quiet as possible, so we pass
			 * the '-q' flag.
			 */
			argv[0] = strdup("/usr/sbin/dtrace");
			argv[1] = strdup("-Y");
			argv[2] = strdup(fullpath);
			argv[3] = strdup("-q");
			
			if (num_idents > 0)
				argv[4] = strdup("-N");
			else
				argv[4] = NULL;

			argv[5] = NULL;

			execve("/usr/sbin/dtrace", argv, NULL);
			exit(EXIT_FAILURE);
		}
	}

cleanup:
	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		dump_errmsg("Failed to expand paths after processing %s",
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
		dump_errmsg("Failed to open %s: %m", src);

	if (fstat(fd, &sb)) {
		dump_errmsg("Failed to fstat %s (%d): %m", src, fd);
		close(fd);
		return;
	}

	len = sb.st_size;
	buf = malloc(len);

	if (read(fd, buf, len) < 0) {
		dump_errmsg("Failed to read %zu bytes from %s (%d): %m",
		    len, src, fd);
		close(fd);
		free(buf);
		return;
	}

	close(fd);

	newfd = open(dst, O_WRONLY | O_CREAT);
	if (newfd == -1) {
		dump_errmsg("Failed to open and create %s: %m", dst);
		free(buf);
		return;
	}

	if (write(newfd, buf, len) < 0) {
		dump_errmsg("Failed to write %zu bytes to %s (%d): %m",
		    len, dst, newfd);
		close(newfd);
		free(buf);
		return;
	}

	close(newfd);
	free(buf);
}

int
process_base(struct dirent *f, dtd_dir_t *dir)
{
	struct dtd_state *s;
	int idx, err;
	char *newname;
	char fullpath[MAXPATHLEN] = { 0 };
	int status = 0;
	pid_t pid;
	char *argv[4];
	char fullarg[MAXPATHLEN*2 + 1] = { 0 };
	size_t offset;
	char *dirpath, *outbounddirpath;
	char donename[MAXPATHLEN] = { 0 };
	size_t dirpathlen = 0;

	if (dir == NULL) {
		dump_errmsg("dir is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}

	LOCK(&dir->dirmtx);
	s = dir->state;
	UNLOCK(&dir->dirmtx);

	if (s == NULL) {
		dump_errmsg("state is NULL in base "
		    "directory monitoring thread");
		return (-1);
	}

	if (f == NULL) {
		dump_errmsg("dirent is NULL in base "
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
		dump_errmsg("Failed to rename %s to %s: %m", newname,
		    donename);
	free(newname);
	free(dirpath);
	free(outbounddirpath);

	pid = fork();

	if (pid == -1) {
		dump_errmsg("Failed to fork: %m");
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
		dump_errmsg("Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	return (0);
}

int
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
		dump_errmsg("dir is NULL");
		return (-1);
	}

	s = dir->state;

	if (s == NULL) {
		dump_errmsg("state is NULL");
		return (-1);
	}

	if (f == NULL) {
		dump_errmsg("dirent is NULL");
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
			dump_errmsg("Failed to malloc a new job");
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
			dump_errmsg(
			    "process_outbound:kevent() failed with: %m");
	}
	UNLOCK(&s->socklistmtx);

	LOCK(&dir->dirmtx);
	err = expand_paths(dir);
	if (err != 0) {
		UNLOCK(&dir->dirmtx);
		dump_errmsg("Failed to expand paths after processing %s",
		    f->d_name);
		return (-1);
	}

	assert(dir->efile_size > dir->efile_len);
	dir->existing_files[dir->efile_len++] = strdup(f->d_name);
	UNLOCK(&dir->dirmtx);

	return (0);
}

