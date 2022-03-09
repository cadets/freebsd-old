/*
 * Copyright (c) 2021 Lucian Carata
 * All rights reserved.
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
 * THIS SOFTWARE IS rqstROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXrqstRESS OR IMrqstLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMrqstLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A rqstARTICULAR rqstURrqstOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SrqstECIAL, EXEMrqstLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, rqstROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR rqstROFITS; OR BUSINESS INTERRUrqstTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE rqstOSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 *
 * Translators for making the nfssrv provider compatible with the solaris one.
 * FreeBSD specific code.
 */

#pragma	D depends_on library ip.d
#pragma	D depends_on library net.d
#pragma D depends_on module kernel

translator conninfo_t < struct __rpc_svcxprt *xprt > {
	ci_protocol = xprt != NULL ? xprt->xp_netid == "tcp" ? "ipv4" :
	    xprt->xp_netid == "udp" ? "ipv4" :
	    xprt->xp_netid == "tcp6" ? "ipv6" :
	    xprt->xp_netid == "udp6" ? "ipv6" :
	    "<unknown>" : "<unknown: null server transport hdl>";

	ci_local = xprt != NULL ? 
    (xprt->xp_netid == "tcp" || xprt->xp_netid == "udp") ?
	    inet_ntoa(&((struct sockaddr_in *)
	                &xprt->xp_ltaddr)->sin_addr.s_addr) :
	  (xprt->xp_netid == "tcp6" || xprt->xp_netid == "udp6") ?
	    inet_ntoa6(&((struct sockaddr_in6 *)
	                 &xprt->xp_ltaddr)->sin6_addr) :
	    "unknown" : "<unknown: null server transport hdl>";

	ci_remote = xprt != NULL ? 
    (xprt->xp_netid == "tcp" || xprt->xp_netid == "udp") ?
	    inet_ntoa(&((struct sockaddr_in *)
	                &xprt->xp_rtaddr)->sin_addr.s_addr) :
	  (xprt->xp_netid == "tcp6" || xprt->xp_netid == "udp6") ?
	    inet_ntoa6(&((struct sockaddr_in6 *)
	                 &xprt->xp_rtaddr)->sin6_addr) :
	    "unknown" : "<unknown: null server transport hdl>";

};

typedef struct nfsv3opinfo {
	uint64_t noi_xid;	/* unique transation ID */
	cred_t *noi_cred;	/* credentials for operation */
	string noi_curpath;	/* current file handle path (if any) */
} nfsv3opinfo_t;

typedef struct nfsv3opinfo nfsv4opinfo_t;
typedef struct nfsv3oparg nfsv3oparg_t;

translator nfsv3opinfo_t < nfsv3oparg_t *_unused > {
	noi_xid = arg2;
	noi_cred = NULL;
  /* only get the filename from the vnode cache, if possible */
	noi_curpath = ((struct vnode *)arg3 == NULL 
      || ((struct vnode *)arg3)->v_cache_dst.tqh_first == NULL 
      || ((struct vnode *)arg3)->v_cache_dst.tqh_first->nc_name == NULL ) ?
	    "<unknown>" : ((struct vnode *)arg3)->v_cache_dst.tqh_first->nc_name;
};
