/*-
 * Copyright (c) 2017 (Ilia Shumailov)
 * Copyright (c) 2018 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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
 */

#ifdef _KERNEL
#include <sys/libkern.h>
#else
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#endif

#include "dl_assert.h"
#include "dl_utils.h"

#ifdef _KERNEL
int
dl_make_folder(struct sbuf *path)
{
	DL_ASSERT(path != NULL, ("File path to create cannot be NULL."));
	// TODO
	return -1;
}

int
dl_del_folder(struct sbuf *path)
{
	DL_ASSERT(path != NULL, ("File path to delete cannot be NULL."));

	// TODO
	return -1;
}

#else /* !KERNEL */

// Adopted from http://www.doc.ic.ac.uk/~rn710/Installs/otp_src_17.0/erts/emulator/drivers/unix/unix_efile.c
//
extern int
dl_alloc_big_file(int fd __attribute((unused)),
    long int offset __attribute((unused)),
    long int length __attribute((unused)))
{
#if defined HAVE_FALLOCATE
	/* Linux specific, more efficient than posix_fallocate. */
	int ret;

	do {
		ret = fallocate(fd, FALLOC_FL_KEEP_SIZE, (off_t) offset,
		    (off_t) length);
	} while (ret != 0 && errno == EINTR);

#if defined HAVE_POSIX_FALLOCATE
	/* Fallback to posix_fallocate if available. */
	if (ret != 0) {
        	ret = dl_call_posix_fallocate(fd, offset, length);
    	}
#endif

	return check_error(ret, errInfo);
#elif defined F_PREALLOCATE
	/* Mac OS X specific, equivalent to posix_fallocate. */
	int ret;
	fstore_t fs;

	memset(&fs, 0, sizeof(fs));
	fs.fst_flags = F_ALLOCATECONTIG;
	fs.fst_posmode = F_VOLPOSMODE;
	fs.fst_offset = (off_t) offset;
	fs.fst_length = (off_t) length;

	dl_debug(PRIO_LOW, "Preallocating the file for mac ... ");
	ret = fcntl(fd, F_PREALLOCATE, &fs);
	if (ret == -1) {
		dl_debug(PRIO_NORMAL, "Failed to preallocate... Trying to allocate all...\n");
		fs.fst_flags = F_ALLOCATEALL;
		ret = fcntl(fd, F_PREALLOCATE, &fs);
		dl_debug(PRIO_NORMAL, "Returncode: %d\n", ret);

#if defined HAVE_POSIX_FALLOCATE
		/* Fallback to posix_fallocate if available. */
		if (ret == -1) {
			ret = dl_call_posix_fallocate(fd, offset, length);
		}
#endif
	}

	return ret < 0 ? 0 : 1;
#elif defined HAVE_POSIX_FALLOCATE
	/* Other Unixes, use posix_fmake_dirallocate if available. */
	return dl_call_posix_fallocate(fd, offset, length) < 0 ? 0 : 1;
#else
	return -1;
#endif
}

#ifdef HAVE_POSIX_FALLOCATE
extern int
dl_call_posix_fallocate(int fd, Sint64 offset, Sint64 length)
{
	int ret;

	/*
	* On Linux and Solaris for example, posix_fallocate() returns
	* a positive error number on error and it does not set errno.
	* On FreeBSD however (9.0 at least), it returns -1 on error
	* and it sets errno.
	*/
	do {
		ret = posix_fallocate(fd, (off_t) offset, (off_t) length);
		if (ret > 0) {
			errno = ret;
			ret = -1;
		}
	} while (ret != 0 && errno == EINTR);

	return ret;
}
#endif /* HAVE_POSIX_FALLOCATE */


// adapted from https://stackoverflow.com/questions/2256945/removing-a-non-empty-directory-programmatically-in-c-or-c
static int
dl_remove_directory(struct sbuf *path)
{
	DIR *d;
	int r = -1;

	DL_ASSERT(path != NULL, ("File path to delete cannot be NULL."));

	d = opendir(sbuf_data(path));
	if (d) {
		struct dirent *p;
		struct sbuf *filename;

		filename = sbuf_new_auto();
		r = 0;
		while (!r && (p=readdir(d))) {
			struct stat statbuf;
			int r2 = -1;

			/* Skip the names "." and ".." as we don't want to recurse on them. */
			if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, "..")) {
				continue;
			}

			sbuf_printf(filename, "%s/%s", sbuf_data(path), p->d_name);
			if (!stat(sbuf_data(filename), &statbuf)) {
				if (S_ISDIR(statbuf.st_mode)) {
					r2 = dl_remove_directory(filename);
				} else {
					r2 = unlink(sbuf_data(filename));
				}
			}
			sbuf_clear(filename);
			r = r2;
		}
		sbuf_delete(filename);
		closedir(d);
	}

	if (!r) {
		r = rmdir(sbuf_data(path));
	}
	return r;
}

// Method used to create a partition folder
int
dl_make_folder(struct sbuf *path)
{
	struct stat st;

	DL_ASSERT(path != NULL, ("File path to create cannot be NULL."));

	if (stat(sbuf_data(path), &st) == -1) {

		return mkdir(sbuf_data(path), 0777);
	}

	return 0;
}

int
dl_del_folder(struct sbuf *path)
{
	struct stat st;

	DL_ASSERT(path != NULL, ("File path to delete cannot be NULL."));

	if (stat(sbuf_data(path), &st) != -1) {
		return dl_remove_directory(path);
	}

	return -1;
}

void
dl_debug(int priority, const char *format, ...)
{
	va_list args;

	va_start(args, format);

	if (priority <= PRIO_LOG)
		vprintf(format, args);

	va_end(args);
}
#endif /* _KERNEL */
