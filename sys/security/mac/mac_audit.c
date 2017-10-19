/*-
 * Copyright (c) 1999-2002, 2009, 2017 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001-2004 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory with support from a grant from Google, Inc. 
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/mac.h>
#include <sys/mutex.h>
#include <sys/module.h>
#include <sys/selinfo.h>
#include <sys/pipe.h>
#include <sys/proc.h>
#include <sys/queue.h>
#include <sys/rwlock.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sdt.h>
#include <sys/vnode.h>

#include <security/audit/audit.h>

#include <security/mac/mac_framework.h>
#include <security/mac/mac_internal.h>
#include <security/mac/mac_policy.h>

/*
 * There are two parts to audit support in the MAC Framework: (1) access
 * control for audit-related operations, such as setting audit properties on a
 * process credential; and (2) auditing of MAC labels.  Both are in this file.
 */

/*
 * Access control checks for audit-related system calls.
 */
MAC_CHECK_PROBE_DEFINE2(cred_check_setaudit, "struct ucred *",
    "struct auditinfo *");

int
mac_cred_check_setaudit(struct ucred *cred, struct auditinfo *ai)
{
	int error;

	MAC_POLICY_CHECK_NOSLEEP(cred_check_setaudit, cred, ai);
	MAC_CHECK_PROBE2(cred_check_setaudit, error, cred, ai);

	return (error);
}

MAC_CHECK_PROBE_DEFINE2(cred_check_setaudit_addr, "struct ucred *",
    "struct auditinfo_addr *");

int
mac_cred_check_setaudit_addr(struct ucred *cred, struct auditinfo_addr *aia)
{
	int error;

	MAC_POLICY_CHECK_NOSLEEP(cred_check_setaudit_addr, cred, aia);
	MAC_CHECK_PROBE2(cred_check_setaudit_addr, error, cred, aia);

	return (error);
}

MAC_CHECK_PROBE_DEFINE2(cred_check_setauid, "struct ucred *", "uid_t");

int
mac_cred_check_setauid(struct ucred *cred, uid_t auid)
{
	int error;

	MAC_POLICY_CHECK_NOSLEEP(cred_check_setauid, cred, auid);
	MAC_CHECK_PROBE2(cred_check_setauid, error, cred, auid);

	return (error);
}

MAC_CHECK_PROBE_DEFINE3(system_check_audit, "struct ucred *", "void *",
    "int");

int
mac_system_check_audit(struct ucred *cred, void *record, int length)
{
	int error;

	MAC_POLICY_CHECK_NOSLEEP(system_check_audit, cred, record, length);
	MAC_CHECK_PROBE3(system_check_audit, error, cred, record, length);

	return (error);
}

MAC_CHECK_PROBE_DEFINE2(system_check_auditctl, "struct ucred *",
    "struct vnode *");

int
mac_system_check_auditctl(struct ucred *cred, struct vnode *vp)
{
	int error;
	struct label *vl;

	ASSERT_VOP_LOCKED(vp, "mac_system_check_auditctl");

	vl = (vp != NULL) ? vp->v_label : NULL;
	MAC_POLICY_CHECK(system_check_auditctl, cred, vp, vl);
	MAC_CHECK_PROBE2(system_check_auditctl, error, cred, vp);

	return (error);
}

MAC_CHECK_PROBE_DEFINE2(system_check_auditon, "struct ucred *", "int");

int
mac_system_check_auditon(struct ucred *cred, int cmd)
{
	int error;

	MAC_POLICY_CHECK_NOSLEEP(system_check_auditon, cred, cmd);
	MAC_CHECK_PROBE2(system_check_auditon, error, cred, cmd);

	return (error);
}

/*
 * Support for auditing MAC labels on subjects and objects.
 *
 * Globals configuring which labels are audited for which object types.  If
 * NULL, then no auditing is requested for the obect type; otherwise, it
 * contains a string suitable to query the labels on objects of that type.
 *
 * XXXRW: Need syscalls or sysctls to set these.  How will synchronisation
 * work..?
 */

static struct rwlock mac_audit_elements_lock;
RW_SYSINIT(mac_audit_elements_lock, &mac_audit_elements_lock,
    "mac_audit_elements_lock");

static const char *mac_cred_label_audit_elements =
    "?biba,?lomac,?mls,?partition,?sebsd";
static const char *mac_pipe_label_audit_elements =
    "?biba,?lomac,?mls,?sebsd";
static const char *mac_socket_label_audit_elements =
    "?biba,?lomac,?mls,?sebsd";
static const char *mac_vnode_label_audit_elements =
    "?biba,?lomac,?mls,?sebsd";

/*
 * Elements-list parsing in mac_*_externalize_label() routines is destructive,
 * so we stack allocate a short buffer to contain a copy of the elements
 * string for the type.  If too long a string is passed, return an error.
 */
#define	MAX_MAC_LABEL_AUDIT_ELEMENTS_STR	64

int
mac_cred_audit(struct ucred *cred, char *buf, size_t buflen)
{
	char elements[MAX_MAC_LABEL_AUDIT_ELEMENTS_STR];

	rw_rlock(&mac_audit_elements_lock);
	if (strlcpy(elements, mac_cred_label_audit_elements,
	    sizeof(elements)) >= sizeof(elements)) {
		rw_runlock(&mac_audit_elements_lock);
		return (EINVAL);
	}
	rw_runlock(&mac_audit_elements_lock);
	return (mac_cred_externalize_label(cred->cr_label, elements, buf,
	    buflen));
}

int
mac_pipe_audit(struct pipepair *pp, char *buf, size_t buflen)
{
	char elements[MAX_MAC_LABEL_AUDIT_ELEMENTS_STR];

	rw_rlock(&mac_audit_elements_lock);
	if (strlcpy(elements, mac_pipe_label_audit_elements,
	    sizeof(elements)) >= sizeof(elements)) {
		rw_runlock(&mac_audit_elements_lock);
		return (EINVAL);
	}
	rw_runlock(&mac_audit_elements_lock);
	return (mac_pipe_externalize_label(pp->pp_label, elements, buf,
	    buflen));
}

int
mac_socket_audit(struct socket *so, char *buf, size_t buflen)
{
	char elements[MAX_MAC_LABEL_AUDIT_ELEMENTS_STR];

	rw_rlock(&mac_audit_elements_lock);
	if (strlcpy(elements, mac_socket_label_audit_elements,
	    sizeof(elements)) >= sizeof(elements)) {
		rw_runlock(&mac_audit_elements_lock);
		return (EINVAL);
	}
	rw_runlock(&mac_audit_elements_lock);
	return (mac_socket_externalize_label(so->so_label, elements, buf,
	    buflen));
}

int
mac_vnode_audit(struct vnode *vp, char *buf, size_t buflen)
{
	char elements[MAX_MAC_LABEL_AUDIT_ELEMENTS_STR];

	rw_rlock(&mac_audit_elements_lock);
	if (strlcpy(elements, mac_vnode_label_audit_elements,
	    sizeof(elements)) >= sizeof(elements)) {
		rw_runlock(&mac_audit_elements_lock);
		return (EINVAL);
	}
	rw_runlock(&mac_audit_elements_lock);
	return (mac_vnode_externalize_label(vp->v_label, elements, buf,
	    buflen));
}
