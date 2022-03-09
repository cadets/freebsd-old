/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2021 Lucian Carata
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
/* $FreeBSD$ */

#ifndef	_NFS_SRVKDTRACE_H_
#define	_NFS_SRVKDTRACE_H_

/* Forward definitions: */
struct vnode;
struct ucred;
struct nfsrv_descript;
struct __rpc_svcxprt;

/* dtnfsserver NFSv[234] RPC provider hooks. */
typedef void (*dtrace_nfsserver_op_probe_func_t)(
    uint32_t,                       /* probe_id */
    struct __rpc_svcxprt *,         /* SVCXPRT, RPC handle */ 
    struct nfsrv_descript *,        /* nfs rcp descriptor */
    int xid, 
    struct vnode *, 
    struct ucred *, 
    int                             /* probenum, index into NFS RPC table */
);

extern dtrace_nfsserver_op_probe_func_t
  dtrace_nfssrv_start_op_probe,
  dtrace_nfssrv_done_op_probe;

/*
 * Declare registered NFS probes by version and RPC type.
 */
extern uint32_t	  	nfssrv_nfs2_start_probes[42];
extern uint32_t			nfssrv_nfs2_done_probes[42];

extern uint32_t			nfssrv_nfs3_start_probes[42];
extern uint32_t			nfssrv_nfs3_done_probes[42];

extern uint32_t  		nfssrv_nfs4_start_probes[42];
extern uint32_t			nfssrv_nfs4_done_probes[42];

#ifdef	KDTRACE_HOOKS

#else /* !KDTRACE_HOOKS */

#endif /* KDTRACE_HOOKS */

#endif /* _NFS_SRVKDTRACE_H_ */
