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

#include <dt_list.h>
#include <stdlib.h>
#include <string.h>

#include "dtraced.h"
#include "dtraced_directory.h"
#include "dtraced_errmsg.h"
#include "dtraced_job.h"
#include "dtraced_lock.h"
#include "dtraced_misc.h"
#include "dtraced_readjob.h"
#include "dtraced_state.h"

int
handle_elfmsg(struct dtd_state *s, dtraced_hdr_t *h,
    unsigned char *buf, size_t bsize)
{
	dtd_dir_t *dir;
	identlist_t *newident;

	dump_debugmsg("        ELF file");

	if (strcmp(DTRACED_MSG_LOC(*h), "base") == 0)
		dir = s->basedir;
	else if (strcmp(DTRACED_MSG_LOC(*h), "outbound") == 0)
		dir = s->outbounddir;
	else if (strcmp(DTRACED_MSG_LOC(*h), "inbound") == 0)
		dir = s->inbounddir;
	else
		dir = NULL;

	if (dir == NULL) {
		dump_errmsg("unrecognized location: %s", DTRACED_MSG_LOC(*h));
		return (-1);
	}

	if (s->ctrlmachine == 0) {
		newident = malloc(sizeof(identlist_t));
		if (newident == NULL) {
			dump_errmsg("Failed to allocate new"
				    " identifier: %m");
			abort();
		}

		if (DTRACED_MSG_IDENT_PRESENT(*h)) {
			memcpy(newident->ident, DTRACED_MSG_IDENT(*h),
			    DTRACED_PROGIDENTLEN);

			LOCK(&s->identlistmtx);
			dt_list_append(&s->identlist, newident);
			UNLOCK(&s->identlistmtx);
		}
	}

	if (write_data(dir, buf, bsize))
		dump_errmsg("write_data() failed");

	return (0);
}
