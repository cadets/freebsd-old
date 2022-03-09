/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2009 Robert N. M. Watson
 * Copyright (c) 2022 Lucian Carata
 * All rights reserved.
 *
 * This software was developed at the University of Cambridge Computer
 * Laboratory
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
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>

#include <sys/dtrace.h>

#include <fs/nfs/nfsproto.h>
#include <fs/nfsserver/nfs_srvkdtrace.h>

static void	dtnfsserver_getargdesc(void *, dtrace_id_t, void *,
		    dtrace_argdesc_t *);
static void	dtnfsserver_provide(void *, dtrace_probedesc_t *);
static void	dtnfsserver_destroy(void *, dtrace_id_t, void *);
static void	dtnfsserver_enable(void *, dtrace_id_t, void *);
static void	dtnfsserver_disable(void *, dtrace_id_t, void *);
static void	dtnfsserver_load(void *);
static int	dtnfsserver_unload(void);


/*
 * Description of NFSv4, NFSv3 and (optional) NFSv2 probes for a procedure.
 */
struct dtnfsserver_rpc {
	char		*nr_v4_name;
	char		*nr_v3_name;	/* Or NULL if none. */
	char		*nr_v2_name;	/* Or NULL if none. */

	/*
	 * IDs for the start and done cases, for NFSv2, NFSv3 and NFSv4.
	 */
	uint32_t	 nr_v2_id_start, nr_v2_id_done;
	uint32_t	 nr_v3_id_start, nr_v3_id_done;
	uint32_t	 nr_v4_id_start, nr_v4_id_done;
};

/*
 * This table is indexed by NFSv3 procedure number, but also used for NFSv2
 * procedure names and NFSv4 operations.
 */
static struct dtnfsserver_rpc	dtnfsserver_rpcs[NFSV4_NPROCS + 1] = {
	{ "null", "null", "null" },
	{ "getattr", "getattr", "getattr" },
	{ "setattr", "setattr", "setattr" },
	{ "lookup", "lookup", "lookup" },
	{ "access", "access", "noop" },
	{ "readlink", "readlink", "readlink" },
	{ "read", "read", "read" },
	{ "write", "write", "write" },
	{ "create", "create", "create" },
	{ "mkdir", "mkdir", "mkdir" },
	{ "symlink", "symlink", "symlink" },
	{ "mknod", "mknod" },
	{ "remove", "remove", "remove" },
	{ "rmdir", "rmdir", "rmdir" },
	{ "rename", "rename", "rename" },
	{ "link", "link", "link" },
	{ "readdir", "readdir", "readdir" },
	{ "readdirplus", "readdirplus" },
	{ "fsstat", "fsstat", "statfs" },
	{ "fsinfo", "fsinfo" },
	{ "pathconf", "pathconf" },
	{ "commit", "commit" },
	{ "lookupp" },
	{ "setclientid" },
	{ "setclientidcfrm" },
	{ "lock" },
	{ "locku" },
	{ "open" },
	{ "close" },
	{ "openconfirm" },
	{ "lockt" },
	{ "opendowngrade" },
	{ "renew" },
	{ "putrootfh" },
	{ "releaselckown" },
	{ "delegreturn" },
	{ "retdelegremove" },
	{ "retdelegrename1" },
	{ "retdelegrename2" },
	{ "getacl" },
	{ "setacl" },
	{ "noop", "noop", "noop" }
};

static dtrace_pattr_t dtnfsserver_attr = {
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_UNSTABLE, DTRACE_STABILITY_UNSTABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

/*
 * Module name strings.
 */
// static char	*dtnfsserver_accesscache_str = "accesscache";
// static char	*dtnfsserver_attrcache_str = "attrcache";
static char	*dtnfsserver_nfs2_str = "nfs2";
static char	*dtnfsserver_nfs3_str = "nfs3";
static char	*dtnfsserver_nfs4_str = "nfs4";

/*
 * Name strings.
 */
static char	*dtnfsserver_done_str = "done";
static char	*dtnfsserver_start_str = "start";

static dtrace_pops_t dtnfsserver_pops = {
	.dtps_provide =		dtnfsserver_provide,
	.dtps_provide_module =	NULL,
	.dtps_enable =		dtnfsserver_enable,
	.dtps_disable =		dtnfsserver_disable,
	.dtps_suspend =		NULL,
	.dtps_resume =		NULL,
	.dtps_getargdesc =	dtnfsserver_getargdesc,
	.dtps_getargval =	NULL,
	.dtps_usermode =	NULL,
	.dtps_destroy =		dtnfsserver_destroy
};

static dtrace_provider_id_t	dtnfsserver_id;

/*
 * When tracing on a procedure is enabled, the DTrace ID for an RPC event is
 * stored in one of these two NFS client-allocated arrays; 0 indicates that
 * the event is not being traced so probes should not be called.
 *
 * For simplicity, we allocate both v2, v3 and v4 arrays as NFSV4_NPROCS + 1,
 * and the v2, v3 arrays are simply sparse.
 */
extern uint32_t			nfssrv_nfs2_start_probes[NFSV4_NPROCS + 1];
extern uint32_t			nfssrv_nfs2_done_probes[NFSV4_NPROCS + 1];

extern uint32_t			nfssrv_nfs3_start_probes[NFSV4_NPROCS + 1];
extern uint32_t			nfssrv_nfs3_done_probes[NFSV4_NPROCS + 1];

extern uint32_t			nfssrv_nfs4_start_probes[NFSV4_NPROCS + 1];
extern uint32_t			nfssrv_nfs4_done_probes[NFSV4_NPROCS + 1];


/*
 * Look up a DTrace probe ID to see if it's associated with a "done" event --
 * if so, we will return a fourth argument type of "int".
 */
static int
dtnfssrv234_isdoneprobe(dtrace_id_t id)
{
	int i;

	for (i = 0; i < NFSV4_NPROCS + 1; i++) {
		if (dtnfsserver_rpcs[i].nr_v4_id_done == id ||
		    dtnfsserver_rpcs[i].nr_v3_id_done == id ||
		    dtnfsserver_rpcs[i].nr_v2_id_done == id)
			return (1);
	}
	return (0);
}

static void
dtnfsserver_getargdesc(void *arg, dtrace_id_t id, void *parg,
    dtrace_argdesc_t *desc)
{
	const char *native_type = NULL;
	const char *xlate_type = NULL;
  int mapping = -1;

  switch (desc->dtargd_ndx) {
  case 0:
    native_type = "struct __rpc_svcxprt *";
    xlate_type = "conninfo_t *";
    mapping = 0;
    break;
  case 1:
    native_type = "nfsv3oparg_t *";
    xlate_type = "nfsv3opinfo_t *";
    mapping = 1;
    break;
  case 2:
    native_type = "struct ucred *";
    mapping = 4;
    break;
  case 3: /* RPC procedure number */
    native_type = "int";
    mapping = 5;
    break;
  default:
    desc->dtargd_ndx = DTRACE_ARGNONE;
    break;
  }

  if (desc->dtargd_ndx != DTRACE_ARGNONE) {
    if (native_type != NULL)
      strlcpy(desc->dtargd_native, native_type, sizeof(desc->dtargd_native));
    if (xlate_type != NULL)
      strlcpy(desc->dtargd_xlate, xlate_type, sizeof(desc->dtargd_xlate));
    if (mapping != -1)
      desc->dtargd_mapping = mapping;
    else
      desc->dtargd_mapping = desc->dtargd_ndx;
  }
}

static void
dtnfsserver_provide(void *arg, dtrace_probedesc_t *desc)
{
  int i;

  if (desc != NULL)
    // no probes created on the fly
    return;

	/*
	 * Register NFSv2 RPC probes; note sparseness check for each slot
	 * in the NFSv3, NFSv4 procnum-indexed array.
	 */
	for (i = 0; i < NFSV4_NPROCS + 1; i++) {
    // start probe
		if (dtnfsserver_rpcs[i].nr_v2_name != NULL &&
		    dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs2_str,
		    dtnfsserver_rpcs[i].nr_v2_name, dtnfsserver_start_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v2_id_start =
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs2_str,
			    dtnfsserver_rpcs[i].nr_v2_name,
			    dtnfsserver_start_str, 0,
			    &nfssrv_nfs2_start_probes[i]);
		}
    // done probe
		if (dtnfsserver_rpcs[i].nr_v2_name != NULL &&
		    dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs2_str,
		    dtnfsserver_rpcs[i].nr_v2_name, dtnfsserver_done_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v2_id_done = 
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs2_str,
			    dtnfsserver_rpcs[i].nr_v2_name,
			    dtnfsserver_done_str, 0,
			    &nfssrv_nfs2_done_probes[i]);
		}
	}

	/*
	 * Register NFSv3 RPC probes; note sparseness check for each slot
	 * in the NFSv4 procnum-indexed array.
	 */
	for (i = 0; i < NFSV4_NPROCS + 1; i++) {
    // start probe
		if (dtnfsserver_rpcs[i].nr_v3_name != NULL &&
		    dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs3_str,
		    dtnfsserver_rpcs[i].nr_v3_name, dtnfsserver_start_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v3_id_start =
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs3_str,
			    dtnfsserver_rpcs[i].nr_v3_name,
			    dtnfsserver_start_str, 0,
			    &nfssrv_nfs3_start_probes[i]);
		}
    // done probe
		if (dtnfsserver_rpcs[i].nr_v3_name != NULL &&
		    dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs3_str,
		    dtnfsserver_rpcs[i].nr_v3_name, dtnfsserver_done_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v3_id_done = 
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs3_str,
			    dtnfsserver_rpcs[i].nr_v3_name,
			    dtnfsserver_done_str, 0,
			    &nfssrv_nfs3_done_probes[i]);
		}
	}

	/*
	 * Register NFSv4 RPC probes.
	 */
	for (i = 0; i < NFSV4_NPROCS + 1; i++) {
    // start probe
		if (dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs4_str,
		    dtnfsserver_rpcs[i].nr_v4_name, dtnfsserver_start_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v4_id_start =
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs4_str,
			    dtnfsserver_rpcs[i].nr_v4_name,
			    dtnfsserver_start_str, 0,
			    &nfssrv_nfs4_start_probes[i]);
		}
    // done probe
		if (dtrace_probe_lookup(HYPERTRACE_HOSTID,
		    dtnfsserver_id, dtnfsserver_nfs4_str,
		    dtnfsserver_rpcs[i].nr_v4_name, dtnfsserver_done_str) ==
		    0) {
			dtnfsserver_rpcs[i].nr_v4_id_done = 
			    dtrace_probe_create(dtnfsserver_id,
			    dtnfsserver_nfs4_str,
			    dtnfsserver_rpcs[i].nr_v4_name,
			    dtnfsserver_done_str, 0,
			    &nfssrv_nfs4_done_probes[i]);
		}
	}
}

static void
dtnfsserver_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static void
dtnfsserver_enable(void *arg, dtrace_id_t id, void *parg)
{
	uint32_t *p = parg;

	*p = id;
}

static void
dtnfsserver_disable(void *arg, dtrace_id_t id, void *parg)
{
	uint32_t *p = parg;

	*p = 0;
}

static void
dtnfsserver_load(void *dummy)
{

	if (dtrace_register("nfssrv", &dtnfsserver_attr,
	    DTRACE_PRIV_USER, NULL, &dtnfsserver_pops, NULL,
	    &dtnfsserver_id) != 0)
		return;

	dtrace_nfssrv_start_op_probe =
	    (dtrace_nfsserver_op_probe_func_t)dtrace_probe;
	dtrace_nfssrv_done_op_probe =
	    (dtrace_nfsserver_op_probe_func_t)dtrace_probe;
}

static int
dtnfsserver_unload()
{

	dtrace_nfssrv_start_op_probe = NULL;
	dtrace_nfssrv_done_op_probe = NULL;

	return (dtrace_unregister(dtnfsserver_id));
}

static int
dtnfsserver_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		break;

	case MOD_UNLOAD:
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSINIT(dtnfsserver_load, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY,
    dtnfsserver_load, NULL);
SYSUNINIT(dtnfsserver_unload, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY,
    dtnfsserver_unload, NULL);

DEV_MODULE(dtnfssrv, dtnfsserver_modevent, NULL);
MODULE_VERSION(dtnfssrv, 1);
MODULE_DEPEND(dtnfssrv, dtrace, 1, 1, 1);
MODULE_DEPEND(dtnfssrv, opensolaris, 1, 1, 1);
MODULE_DEPEND(dtnfssrv, nfscommon, 1, 1, 1);
