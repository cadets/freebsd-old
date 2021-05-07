/*-
 * Copyright (c) 2016-2017 Robert N. M. Watson
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
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/capsicum.h>
#include <sys/ipc.h>
#include <sys/mount.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/un.h>
#include <sys/vnode.h>
#include <sys/msgid.h>

#include <netinet/in.h>
#include <netinet/in_pcb.h>

#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

/*
 * Calls to manipulate elements of the audit record structure from system
 * call code.  Macro wrappers will prevent this functions from being entered
 * if auditing is disabled, avoiding the function call cost.  We check the
 * thread audit record pointer anyway, as the audit condition could change,
 * and pre-selection may not have allocated an audit record for this event.
 *
 * XXXAUDIT: Should we assert, in each case, that this field of the record
 * hasn't already been filled in?
 */
#ifdef KDTRACE_HOOKS
void
audit_ret_fd1(int fd)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;
	ar->k_ar.ar_ret_fd1 = fd;
	RET_SET_VALID(ar, RET_FD1);
}

void
audit_ret_fd2(int fd)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;
	ar->k_ar.ar_ret_fd2 = fd;
	RET_SET_VALID(ar, RET_FD2);
}

void
audit_ret_msgid(msgid_t *msgidp)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;
	if (!msgid_isvalid(msgidp))
		return;
	ar->k_ar.ar_ret_msgid = *msgidp;
	RET_SET_VALID(ar, RET_MSGID);
}

void
audit_ret_mbufid(mbufid_t *mbufidp)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;
	if (!mbufid_isvalid(mbufidp))
		return;
	ar->k_ar.ar_ret_mbufid = *mbufidp;
	RET_SET_VALID(ar, RET_MSGID);
}
#endif

void
audit_ret_svipc_id(int id)
{
	struct kaudit_record *ar;

	ar = currecord();
	if (ar == NULL)
		return;

	ar->k_ar.ar_ret_svipc_id = id;
	RET_SET_VALID(ar, RET_SVIPC_ID);
}
