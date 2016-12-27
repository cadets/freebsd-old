/*-
 * Copyright (c) 2016 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <sys/metaio.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/uuid.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <termios.h>
#include <unistd.h>
#include <uuid.h>

/*
 * Simple test suite for metaio(2) on various file-descriptor-backed I/O
 * objects.  These tests confirm only that the UUID returned by fgetuuid(2)
 * corresponds to the UUID appearing in the struct metaio returned by read and
 * receive system calls.  While there, the test framework also validates that
 * each object type is returning a non-nil UUID.
 */

struct metaio_test;
typedef void (mt_create_fn)(const char *, int *, int *);
typedef void (mt_test_fn)(const char *, int, struct metaio *);

static mt_create_fn	create_devzero;
static mt_create_fn	create_file;
static mt_create_fn	create_pipe;
static mt_create_fn	create_posixshm;
static mt_create_fn	create_socket;
static mt_create_fn	create_ttypts;

#define	OBJECT_CANSEEK		0x00000001
#define	OBJECT_CANMAP		0x00000002
#define	OBJECT_CANRECV		0x00000004

struct metaio_test_object {
	const char	*mto_name;
	mt_create_fn	*mto_create;
	u_int		 mto_flags_have;
};

static struct metaio_test_object metaio_test_objects[] = {
	{ .mto_name = "devzero",
	  .mto_create = create_devzero,
	  .mto_flags_have = (OBJECT_CANSEEK | OBJECT_CANMAP), },

	{ .mto_name = "file",
	  .mto_create = create_file,
	  .mto_flags_have = (OBJECT_CANSEEK | OBJECT_CANMAP), },

	{ .mto_name = "pipe",
	  .mto_create = create_pipe,
	  .mto_flags_have = 0, },

	{ .mto_name = "posixshm",
	  .mto_create = create_posixshm,
	  .mto_flags_have = (OBJECT_CANSEEK | OBJECT_CANMAP), },

	{ .mto_name = "socket",
	  .mto_create = create_socket,
	  .mto_flags_have = OBJECT_CANRECV, },

	{ .mto_name = "ttypts",
	  .mto_create = create_ttypts,
	  .mto_flags_have = 0, },
};
static u_int metaio_test_objects_len = sizeof(metaio_test_objects) /
    sizeof(metaio_test_objects[0]);

static mt_test_fn	test_mmap;
static mt_test_fn	test_read;
static mt_test_fn	test_readv;
static mt_test_fn	test_pread;
static mt_test_fn	test_preadv;
static mt_test_fn	test_recvfrom;
static mt_test_fn	test_recvmsg;

struct metaio_test_method {
	const char	*mtm_name;
	mt_test_fn	*mtm_test;
	u_int		 mtm_flags_required;
};

static struct metaio_test_method metaio_test_methods[] = {
	{ .mtm_name = "mmap",
	  .mtm_test = test_mmap,
	  .mtm_flags_required = OBJECT_CANMAP, },

	{ .mtm_name = "read",
	  .mtm_test = test_read,
	  .mtm_flags_required = 0, },

	{ .mtm_name = "readv",
	  .mtm_test = test_readv,
	  .mtm_flags_required = 0, },

	{ .mtm_name = "pread",
	  .mtm_test = test_pread,
	  .mtm_flags_required = OBJECT_CANSEEK, },

	{ .mtm_name = "preadv",
	  .mtm_test = test_preadv,
	  .mtm_flags_required = OBJECT_CANSEEK, },

	{ .mtm_name = "recvfrom",
	  .mtm_test = test_recvfrom,
	  .mtm_flags_required = OBJECT_CANRECV, },

	{ .mtm_name = "recvmsg",
	  .mtm_test = test_recvmsg,
	  .mtm_flags_required = OBJECT_CANRECV, },
};
static u_int metaio_test_methods_len = sizeof(metaio_test_methods) /
    sizeof(metaio_test_methods[0]);

/*
 * Routines to create various potential file-descritor origins for I/O.  For
 * each type, ensure that there is sufficient data to satisfy one test against
 * it.  For files and POSIX shared memory, this means enough content to memory
 * map a page.  For stream types (e.g., pipes, sockets, ...), simply put one
 * byte of data into the object from the send end so that there is a byte
 * available to receive.
 *
 * Some object types have two file descriptors; where appropriate, return the
 * 'send' file descriptor as well so that the caller can close it when the
 * test has finished running.
 */
static void
create_devzero(const char *testname, int *fdp, int *fdclosep)
{
	int fd;

	fd = open("/dev/zero", O_RDWR);
	if (fd < 0)
		err(EX_OSERR, "%s: %s: /dev/zero - open", testname, __func__);
	*fdp = fd;
	*fdclosep = -1;
}

/*
 * Create a temporary file; write a page of data.
 */
static void
create_file(const char *testname, int *fdp, int *fdclosep)
{
	char pathbuf[1024];
	uint8_t buffer[getpagesize()];
	ssize_t len;
	int fd;

	snprintf(pathbuf, sizeof(pathbuf), "/tmp/metaio_test.XXXXXXXXXXXX");
	fd = mkstemp(pathbuf);
	if (fd < 0)
		err(EX_CANTCREAT, "%s: %s: mkstemp", testname, __func__);
	len = pwrite(fd, buffer, getpagesize(), 0);
	if (len < 0)
		err(EX_IOERR, "%s: %s: pwrite", testname, __func__);
	if (len != getpagesize())
		errx(EX_IOERR, "%s: %s: pwrite length mismatch", testname,
		    __func__);
	*fdp = fd;
	*fdclosep = -1;
}

/*
 * Create a pipe; write a byte of data.
 */
static void
create_pipe(const char *testname, int *fdp, int *fdclosep)
{
	int fds[2];
	ssize_t len;
	uint8_t ch;

	if (pipe(fds) < 0)
		err(EX_OSERR, "%s: %s: pipe", testname, __func__);
	ch = 0;
	len = write(fds[1], &ch, sizeof(ch));
	if (len < 0)
		err(EX_IOERR, "%s: %s: write", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: write length mismatch", testname,
		    __func__);
	*fdp = fds[0];
	*fdclosep = fds[1];
}

/*
 * Create an anonymous POSIX shared memory object; write a page of data.
 */
static void
create_posixshm(const char *testname, int *fdp, int *fdclosep)
{
	uint8_t buffer[getpagesize()];
	ssize_t len;
	int fd;

	fd = shm_open(SHM_ANON, O_RDWR | O_CREAT, 0600);
	if (fd < 0)
		err(EX_OSERR, "%s: %s: shm_open", testname, __func__);
	if (ftruncate(fd, getpagesize()) < 0)
		err(EX_IOERR, "%s: %s: ftruncate", testname, __func__);
	len = pwrite(fd, buffer, getpagesize(), 0);
	if (len < 0)
		err(EX_IOERR, "%s: %s: pwrite", testname, __func__);
	if (len != getpagesize())
		errx(EX_IOERR, "%s: %s: pwrite length mismatch", testname,
		    __func__);
	*fdp = fd;
	*fdclosep = -1;
}

/*
 * Create a socket pair; write a byte of data.
 */
static void
create_socket(const char *testname, int *fdp, int *fdclosep)
{
	ssize_t len;
	int fds[2];
	uint8_t ch;

	if (socketpair(PF_LOCAL, SOCK_STREAM, 0, fds) < 0)
		err(EX_OSERR, "%s: %s: socketpair", testname, __func__);
	ch = 0;
	len = write(fds[1], &ch, sizeof(ch));
	if (len < 0)
		err(EX_IOERR, "%s: %s: write", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: write length mismatch", testname,
		    __func__);
	*fdp = fds[0];
	*fdclosep = fds[1];
}

/*
 * Create a pseudoterminal; write a byte of data.
 */
static void
create_ttypts(const char *testname, int *fdp, int *fdclosep)
{
	struct termios tios;
	const char *pathname;
	ssize_t len;
	int pts, ptm;
	uint8_t ch;

	ptm = posix_openpt(O_RDWR);
	if (ptm < 0)
		err(EX_OSERR, "%s: %s: posix_openpt", testname, __func__);
	if (grantpt(ptm) < 0)
		err(EX_OSERR, "%s: %s: grantpt", testname, __func__);
	if (unlockpt(ptm) < 0)
		err(EX_OSERR, "%s: %s: unlockpt", testname, __func__);
	pathname = ptsname(ptm);
	if (pathname == NULL)
		err(EX_OSERR, "%s: %s: ptsname", testname, __func__);
	pts = open(pathname, O_RDWR);
	if (pts < 0)
		err(EX_OSERR, "%s: %s: %s - open", testname, __func__,
		    pathname);

	/*
	 * Configure 'raw' mode so that the reader won't block with only one
	 * character waiting.
	 */
	if (tcgetattr(ptm, &tios) < 0)
		err(EX_IOERR, "%s: %s: tcgetattr", testname, __func__);
	cfmakeraw(&tios);
        if (tcsetattr(ptm, TCSANOW, &tios) < 0)
		err(EX_IOERR, "%s: %s: tcsetattr", testname, __func__);
	ch = 0;
	len = write(ptm, &ch, sizeof(ch));
	if (len < 0)
		err(EX_IOERR, "%s: %s: write", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: write length mismatch", testname,
		    __func__);
	*fdp = pts;
	*fdclosep = ptm;
}

/*
 * Test functions performing various read/receive operations and confirming
 * that UUIDs are as expected (queried from the objects earlier).
 */
static void
test_mmap(const char *testname, int fd, struct metaio *miop)
{
	uint8_t *cp;

	cp = (uint8_t *)metaio_mmap(NULL, getpagesize(), PROT_READ,
	    MAP_SHARED, fd, 0, miop);
	if (cp == MAP_FAILED)
		err(EX_OSERR, "%s: %s: metaio_mmap", testname, __func__);
	if (munmap(cp, getpagesize()) < 0)
		err(EX_OSERR, "%s: %s: munmap", testname, __func__);
}

static void
test_pread(const char *testname, int fd, struct metaio *miop)
{
	ssize_t len;
	uint8_t ch;

	len = metaio_pread(fd, &ch, sizeof(ch), 0, miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_pread", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_pread length mismatch",
		    testname, __func__);
}

static void
test_preadv(const char *testname, int fd, struct metaio *miop)
{
	struct iovec iov;
	ssize_t len;
	uint8_t ch;

	iov.iov_base = &ch;
	iov.iov_len = sizeof(ch);
	len = metaio_preadv(fd, &iov, 1, 0, miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_preadv", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_preadv length mismatch",
		    testname, __func__);
}

static void
test_read(const char *testname, int fd, struct metaio *miop)
{
	ssize_t len;
	uint8_t ch;

	len = metaio_read(fd, &ch, sizeof(ch), miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_read", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_read length mismatch",
		    testname, __func__);
}

static void
test_readv(const char *testname, int fd, struct metaio *miop)
{
	struct iovec iov;
	ssize_t len;
	uint8_t ch;

	iov.iov_base = &ch;
	iov.iov_len = sizeof(ch);
	len = metaio_readv(fd, &iov, 1, miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_readv", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_readv length mismatch",
		    testname, __func__);
}

static void
test_recvfrom(const char *testname, int fd, struct metaio *miop)
{
	ssize_t len;
	uint8_t ch;

	len = metaio_recvfrom(fd, (void *)&ch, sizeof(ch), MSG_WAITALL, NULL,
	    NULL, miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_recvfrom", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_recvfrom length mismatch",
		    testname, __func__);
}

static void
test_recvmsg(const char *testname, int fd, struct metaio *miop)
{
	struct msghdr msghdr;
	struct iovec iov;
	ssize_t len;
	uint8_t ch;

	iov.iov_base = &ch;
	iov.iov_len = sizeof(ch);
	bzero(&msghdr, sizeof(msghdr));
	msghdr.msg_iov = &iov;
	msghdr.msg_iovlen = 1;
	len = metaio_recvmsg(fd, &msghdr, MSG_WAITALL, miop);
	if (len < 0)
		err(EX_IOERR, "%s: %s: metaio_recvmsg", testname, __func__);
	if (len != sizeof(ch))
		errx(EX_IOERR, "%s: %s: metaio_recvmsg length mismatch",
		    testname, __func__);
}

/*
 * Confirm that a returned UUID is non-nil.
 */
static void
validate_uuid(const char *testname, struct uuid *uuidp)
{
	uint8_t *cp;
	u_int i;

	cp = (uint8_t *)uuidp;
	for (i = 0; i < sizeof(*uuidp); i++) {
		if (cp[i] != 0)
			return;
	}
	errx(EX_SOFTWARE, "%s: %s: nil UUID", testname, __func__);
}

static void
test_uuid(const char *testname, struct metaio *miop, struct uuid *uuidp)
{
	char *mio_uuid_str, *file_uuid_str;
	uint32_t status;

	if (memcmp(uuidp, &miop->mio_uuid, sizeof(*uuidp)) != 0) {
		uuid_to_string(uuidp, &file_uuid_str, &status);
		if (status != uuid_s_ok)
			errx(EX_OSERR, "uuid_to_string");
		uuid_to_string(&miop->mio_uuid, &mio_uuid_str, &status);
		if (status != uuid_s_ok)
			errx(EX_OSERR, "uuid_to_string");
		free(file_uuid_str);
		free(mio_uuid_str);
		errx(EX_SOFTWARE, "%s: %s: UUID mismatch (fd: %s; mio: %s)",
		    testname, __func__, file_uuid_str, mio_uuid_str);
	}
}

static void
test_run(struct metaio_test_object *mtop, struct metaio_test_method *mtmp)
{
	struct metaio mio;
	struct uuid uuid;
	char *testname;
	int fd, fdclose;

	if (asprintf(&testname, "%s.%s", mtop->mto_name, mtmp->mtm_name) < 0)
		err(EX_OSERR, "asprintf");

	/*
	 * Create I/O or IPC object.
	 */
	fd = -1;
	fdclose = -1;
	mtop->mto_create(testname, &fd, &fdclose);

	/*
	 * Query a UUID on the file descriptor, and check that it's valid
	 * (i.e., non-nil).
	 */
	if (fgetuuid(fd, &uuid) < 0)
		err(EX_OSERR, "%s: %s: fgetuuid", testname, __func__);
	validate_uuid(testname, &uuid);

	/*
	 * Run test.
	 */
	mtmp->mtm_test(testname, fd, &mio);
	test_uuid(testname, &mio, &uuid);

	/*
	 * Close file descriptor(s).
	 */
	if (fd != -1)
		close(fd);
	if (fdclose != -1)
		close(fdclose);

	/*
	 * Declare victory.
	 */
	fprintf(stderr, "%s: OK\n", testname);
	free(testname);
}

int
main(int argc, char *argv[])
{
	struct metaio_test_object *mtop;
	struct metaio_test_method *mtmp;
	int mto, mtm;

	/*
	 * Iterate over object types and methods, exercising combinations
	 * permitted by their respective flags.
	 */
	for (mto = 0; mto < metaio_test_objects_len; mto++) {
		for (mtm = 0; mtm < metaio_test_methods_len; mtm++) {
			mtop = &metaio_test_objects[mto];
			mtmp = &metaio_test_methods[mtm];
			if ((mtop->mto_flags_have & mtmp->mtm_flags_required)
			    != mtmp->mtm_flags_required)
				continue;
			test_run(mtop, mtmp);
		}
	}
}
