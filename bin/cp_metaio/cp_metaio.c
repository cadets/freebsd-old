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
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/metaio.h>

#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <unistd.h>

/*
 * Simplistic "multi-copy" demonstration program for metaio: audit trails
 * should show userspace annotations on file writes to show from what file
 * they originated.
 */

static void __dead2
usage(void) 
{

	fprintf(stderr, "usage: cp_metaio from_filename1 to_filename1 "
	    "from_filename2 to_filename2\n");
	exit(EX_USAGE);
}

static void
copyfile(int fd_from, int fd_to)
{
	uint8_t buffer[1024];
	struct metaio mio;
	ssize_t len_read, len_write, written;

	do {
		len_read = metaio_read(fd_from, buffer, sizeof(buffer), &mio);
		if (len_read < 0)
			err(EX_IOERR, "metaio_read");
		written = 0;
		while (written < len_read) {
			len_write = metaio_write(fd_to, buffer + written,
			    len_read - written, &mio);
			if (len_write < 0)
				err(EX_IOERR, "metaio_write");
			written += len_write;
		}
	} while (len_read > 0);
}

int
main(int argc, char *argv[])
{
	int fd_from, fd_to;

	if (argc != 5)
		usage();

	/*
	 * Copy first file, preserving I/O metadata.
	 */
	fd_from = open(argv[1], O_RDONLY);
	if (fd_from < 0)
		err(EX_OSERR, "open: %s", argv[1]);
	fd_to = open(argv[2], O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd_to < 0)
		err(EX_OSERR, "open: %s", argv[2]);
	copyfile(fd_from, fd_to);
	close(fd_from);
	close(fd_to);

	/*
	 * Copy second file, preserving I/O metadata.
	 */
	fd_from = open(argv[3], O_RDONLY);
	if (fd_from < 0)
		err(EX_OSERR, "open: %s", argv[3]);
	fd_to = open(argv[4], O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd_to < 0)
		err(EX_OSERR, "open: %s", argv[4]);
	copyfile(fd_from, fd_to);
	close(fd_from);
	close(fd_to);

	exit(EX_OK);
}
