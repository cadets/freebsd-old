/*-
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

#include <sys/socket.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced.h"
#include "dtraced_cleanupjob.h"
#include "dtraced_connection.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_misc.h"
#include "dtraced_state.h"

void
handle_sendinfo(struct dtraced_state *s, struct dtraced_job *curjob)
{
	dtraced_hdr_t hdr = { 0 };
	__cleanup(releasefd) dtraced_fd_t *dfd = curjob->connsockfd;
	dtraced_fd_t *client;
	int fd = dfd->fd;
	size_t info_count = 0;
	dtraced_infomsg_t *imsgs;
	size_t i;

	for (client = dt_list_next(&s->sockfds); client;
	     client = dt_list_next(client))
		info_count++;

	imsgs = malloc(info_count * sizeof(dtraced_infomsg_t));
	if (imsgs == NULL)
		abort();

	memset(imsgs, 0, info_count * sizeof(dtraced_infomsg_t));

	i = 0;
	for (client = dt_list_next(&s->sockfds); client;
	     client = dt_list_next(client)) {
		imsgs[i].client_kind = client->kind;
		memcpy(
		    imsgs[i++].client_name, client->ident, DTRACED_FDIDENTLEN);
	}

	hdr.msg_type = DTRACED_MSG_INFO;
	hdr.info.count = info_count;

	if (send(fd, &hdr, DTRACED_MSGHDRSIZE, 0) < 0) {
		ERR("%d: %s(): Failed to write header to %d : %m", __LINE__,
		    __func__, fd);
		return;
	}

	if (send(fd, imsgs, info_count * sizeof(dtraced_infomsg_t), 0) < 0) {
		ERR("%d: %s(): Failed to write imsgs to %d: %m", __LINE__,
		    __func__, fd);
		return;
	}
}
