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

#ifndef _DTRACED_JOB_H_
#define _DTRACED_JOB_H_

#include <sys/event.h>

#include <dt_list.h>

#include "dtraced.h"
#include "_dtraced_connection.h"
#include "dtraced_directory.h"

typedef struct identlist {
	dt_list_t list;
	unsigned char ident[DTRACED_PROGIDENTLEN];
} identlist_t;


typedef struct dtraced_job {
	dt_list_t    list;       /* next element */
	int          job;        /* job kind */
	dtraced_fd_t *connsockfd; /* which socket do we send this on? */
#define NOTIFY_ELFWRITE    1
#define KILL               2
#define READ_DATA          3
#define CLEANUP            4
#define SEND_INFO          5
#define JOB_LAST           5

	union {
		struct {
			size_t    pathlen; /* how long is path? */
			char      *path;   /* path to file (based on dir) */
			dtd_dir_t *dir;    /* base directory of path */
			int       nosha;   /* do we want to checksum? */
		} notify_elfwrite;

		struct {
			pid_t    pid;   /* pid to kill */
			uint16_t vmid;  /* vmid to kill the pid on */
		} kill;

		struct {
		} read;

		struct {
			char **entries;   /* each entry to cleanup */
			size_t n_entries; /* number of entries */
		} cleanup;
	} j;
} dtraced_job_t;

int  dispatch_event(struct dtraced_state *, struct kevent *);
void *process_joblist(void *);

#endif // _DTRACED_JOB_H_
