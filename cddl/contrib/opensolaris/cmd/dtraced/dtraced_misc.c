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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_misc.h"

/*
 * Used for generating a random name of the outbound ELF file.
 */
void
get_randname(char *b, size_t len)
{
	size_t i;

	/*
	 * Generate lower-case random characters.
	 */
	for (i = 0; i < len; i++)
		b[i] = arc4random_uniform(25) + 97;
}

char *
gen_filename(const char *dir)
{
	__cleanup(freep) char *filename = NULL;
	char *elfpath;
	size_t len;

	len = (MAXPATHLEN - strlen(dir)) / 64;
	assert(len > 10);

	filename = malloc(len);
	if (filename == NULL) {
		ERR("%d: %s(): Failed to malloc filename: %m", __LINE__,
		    __func__);
		abort();
	}

	filename[0] = '.';
	get_randname(filename + 1, len - 2);
	filename[len - 1] = '\0';

	elfpath = malloc(MAXPATHLEN);
	if (elfpath == NULL) {
		ERR("%d: %s(): Failed to malloc elfpath: %m", __LINE__,
		    __func__);
		abort();
	}

	strcpy(elfpath, dir);
	strcpy(elfpath + strlen(dir), filename);

	while (access(elfpath, F_OK) != -1) {
		filename[0] = '.';
		get_randname(filename + 1, len - 2);
		filename[len - 1] = '\0';
		strcpy(elfpath + strlen(dir), filename);
	}

	return (elfpath);
}

void
freep(void *mem)
{

	free(*(void **) mem);
}

void
closefd_generic(int *fd)
{

	if (*fd != -1)
		close(*fd);
}

void
closedir_generic(DIR **dir)
{

	if (*dir)
		closedir(*dir);
}

void
cleanup_pidfile(struct pidfh **pfh)
{

	if (*pfh)
		if (pidfile_remove(*pfh))
			ERR("%d: %s(): Could not remove pidfile: %m", __LINE__,
			    __func__);
}

void
releasefd(dtraced_fd_t **dfd)
{

	if (*dfd)
		fd_release(*dfd);
}
