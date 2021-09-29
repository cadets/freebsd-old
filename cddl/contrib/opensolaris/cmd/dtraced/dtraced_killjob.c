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
#include <sys/socket.h>

#include <dt_list.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced.h"
#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_killjob.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

void
handle_kill(struct dtd_state *s, struct dtd_joblist *curjob)
{
	int fd;
	pid_t pid;
	uint16_t vmid;
	size_t msglen;
	ssize_t r;
	dtraced_hdr_t header;
	struct dtd_fdlist *fde;
	__cleanup(freep) unsigned char *msg;
	
	fd = curjob->connsockfd;
	pid = curjob->j.kill.pid;
	vmid = curjob->j.kill.vmid;

	dump_debugmsg("    kill pid %d to %d", pid, fd);

	assert(fd != -1);
	/*
	 * If we end up with pid <= 1, something went wrong.
	 */
	assert(pid > 1);
	msglen = DTRACED_MSGHDRSIZE;
	msg = malloc(msglen);
	if (msg == NULL) {
		dump_errmsg("Failed to allocate a kill message: %m");
		abort();
	}

	/*
	 * For now the header only includes the message kind, so
	 * we don't really make it a structure. In the future,
	 * this might change.
	 */
	DTRACED_MSG_TYPE(header) = DTRACED_MSG_KILL;
	DTRACED_MSG_KILLPID(header) = pid;
	DTRACED_MSG_KILLVMID(header) = vmid;

	memcpy(msg, &header, DTRACED_MSGHDRSIZE);

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
				return;
			}

			dt_list_delete(&s->sockfds, fde);
			UNLOCK(&s->socklistmtx);
		} else
			dump_errmsg(
			    "Failed to write to %d (%zu): %m", fd, msglen);

		return;
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
			fde = dt_in_list(&s->sockfds, &fd, sizeof(int));
			if (fde == NULL) {
				UNLOCK(&s->socklistmtx);
				return;
			}

			dt_list_delete(&s->sockfds, fde);
			UNLOCK(&s->socklistmtx);
		} else
			dump_errmsg("Failed to write to %d: %m", fd);

		return;
	}

	if (reenable_fd(s->kq_hdl, fd, EVFILT_WRITE))
		dump_errmsg("process_joblist: reenable_fd() failed with: %m");
}
