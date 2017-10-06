/*-
 * Copyright (c) 2017 Domagoj Stolfa
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
 *
 * $FreeBSD$
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/systm.h>
#include <sys/tree.h>
#include <sys/dtvirt.h>

#include <machine/vmm_dtrace.h>

struct dtvirt_prov {
	RB_ENTRY(dtvirt_prov)	 node;
	dtrace_provider_id_t	 dtvp_id;
	struct uuid		*dtvp_uuid;
	char			 dtvp_instance[DTRACE_INSTANCENAMELEN];
};

static void	dtvirt_load(void);
static void	dtvirt_unload(void);
static void	dtvirt_commit(const char *, dtrace_id_t,
           	    uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);
static int	dtvirt_probe_create(struct uuid *, const char *, const char *,
          	    const char *);
static int	dtvirt_provider_register(const char *,
          	    const char *, struct uuid *,
		    dtrace_pattr_t *, uint32_t, dtrace_pops_t *);
static int	dtvirt_priv_unregister(struct dtvirt_prov *);
static int	dtvirt_provider_unregister(struct uuid *);
static void	dtvirt_enable(void *, dtrace_id_t, void *);
static void	dtvirt_disable(void *, dtrace_id_t, void *);
static void	dtvirt_getargdesc(void *, dtrace_id_t, void *, dtrace_argdesc_t *);
static uint64_t	dtvirt_getargval(void *, dtrace_id_t, void *, uint64_t, int);
static void	dtvirt_destroy(void *, dtrace_id_t, void *);
static int	dtvirt_prov_cmp(struct dtvirt_prov *p1, struct dtvirt_prov *p2);

RB_HEAD(dtvirt_provtree, dtvirt_prov) dtvirt_provider_tree =
    RB_INITIALIZER(_dtvirt_prov);

RB_GENERATE_STATIC(dtvirt_provtree, dtvirt_prov, node,
    dtvirt_prov_cmp);

static MALLOC_DEFINE(M_DTVIRT, "dtvirt", "DTvirt memory");


static int
dtvirt_handler(module_t mod, int what, void *arg)
{
	int error;
	switch (what) {
	case MOD_LOAD:
		dtvirt_load();
		error = 0;
		break;
	case MOD_UNLOAD:
		dtvirt_unload();
		error = 0;
		break;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t dtvirt_kmod = {
	"dtvirt",
	dtvirt_handler,
	NULL
};

MODULE_VERSION(dtvirt, 1);
MODULE_DEPEND(dtvirt, dtrace, 1, 1, 1);
MODULE_DEPEND(dtvirt, vmm, 1, 1, 1);

DECLARE_MODULE(dtvirt, dtvirt_kmod, SI_SUB_DTRACE, SI_ORDER_ANY);

static void
dtvirt_load(void)
{
	dtvirt_hook_commit = dtvirt_commit;
	dtvirt_hook_register = dtvirt_provider_register;
	dtvirt_hook_unregister = dtvirt_provider_unregister;
	dtvirt_hook_create = dtvirt_probe_create;
	dtvirt_hook_enable = dtvirt_enable;
	dtvirt_hook_disable = dtvirt_disable;
	dtvirt_hook_getargdesc = dtvirt_getargdesc;
	dtvirt_hook_getargval = dtvirt_getargval;
	dtvirt_hook_destroy = dtvirt_destroy;
}

static void
dtvirt_unload(void)
{
	struct dtvirt_prov *prov, *tmp;
	int error;

	/*
	 * In case we unloaded the module instead of called unregister for every
	 * provider, we need to clean up the tree.
	 */
	RB_FOREACH_SAFE(prov, dtvirt_provtree, &dtvirt_provider_tree, tmp) {
		error = dtvirt_priv_unregister(prov);
		if (error)
			panic("Unregister of a provider failed\n");
	}

	dtvirt_hook_commit = NULL;
	dtvirt_hook_register = NULL;
	dtvirt_hook_unregister = NULL;
	dtvirt_hook_create = NULL;
	dtvirt_hook_enable = NULL;
	dtvirt_hook_disable = NULL;
	dtvirt_hook_getargdesc = NULL;
	dtvirt_hook_getargval = NULL;
	dtvirt_hook_destroy = NULL;
	
}

static void
dtvirt_commit(const char *vm, dtrace_id_t id,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4)
{
	dtrace_distributed_probe(vm, id, arg0, arg1,
	    arg2, arg3, arg4);
}

static int
dtvirt_probe_create(struct uuid *uuid, const char *mod, const char *func,
    const char *name)
{
	dtrace_virt_probe_t *virt_probe;
	struct dtvirt_prov *prov, tmp;
	struct uuid tmpuuid;
	dtrace_provider_id_t provid;

	memcpy(&tmpuuid, uuid, sizeof(struct uuid));

	tmp.dtvp_uuid = &tmpuuid;
	prov = RB_FIND(dtvirt_provtree, &dtvirt_provider_tree, &tmp);

	if (prov == NULL)
		return (ESRCH);

	provid = prov->dtvp_id;

	virt_probe = malloc(sizeof(dtrace_virt_probe_t), M_DTVIRT,
	    M_NOWAIT | M_ZERO);
	
	if (virt_probe == NULL) {
		return (ENOMEM);
	}

	/*
	virt_probe->dtv_argtypes = malloc(nargs * DTRACE_ARGTYPELEN, M_DTVIRT,
	    M_NOWAIT | M_ZERO);

	if (virt_probe->dtv_argtypes == NULL) {
		free(virt_probe, M_DTVIRT);
		return (ENOMEM);
	}

	virt_probe->dtv_argsizes = malloc(sizeof(size_t) * nargs, M_DTVIRT,
	    M_NOWAIT | M_ZERO);

	if (virt_probe->dtv_argsizes == NULL) {
		free(virt_probe->dtv_argtypes, M_DTVIRT);
		free(virt_probe, M_DTVIRT);
		return (ENOMEM);
	}
	*/

	virt_probe->dtv_enabled = 0;
	/*
	virt_probe->dtv_nargs = nargs;
	memcpy(virt_probe->dtv_argtypes, argtypes, DTRACE_ARGTYPELEN * nargs);
	memcpy(virt_probe->dtv_argsizes, argsiz, sizeof(size_t) * nargs);
	*/

	virt_probe->dtv_id = dtrace_probe_create(provid, mod, func,
	    name, 0, virt_probe);
	strlcpy(virt_probe->dtv_vm,
	    prov->dtvp_instance, DTRACE_INSTANCENAMELEN);

	return (0);
}

static int
dtvirt_provider_register(const char *provname, const char *instance,
    struct uuid *uuid, dtrace_pattr_t *pattr, uint32_t priv,
    dtrace_pops_t *pops)
{
	struct dtvirt_prov *prov;
	dtrace_provider_id_t provid;
	int error;

	error = dtrace_distributed_register(provname, instance,
	    uuid, pattr, priv, NULL, pops, NULL, &provid);

	if (error) {
		return (error);
	}

	prov = malloc(sizeof(struct dtvirt_prov), M_DTVIRT, M_NOWAIT | M_ZERO);

	if (prov == NULL)
		return (ENOMEM);

	prov->dtvp_uuid = malloc(sizeof(struct uuid), M_DTVIRT,
	    M_NOWAIT | M_ZERO);

	if (prov->dtvp_uuid == NULL) {
		free(prov, M_DTVIRT);
		return (ENOMEM);
	}

	prov->dtvp_id = provid;
	memcpy(prov->dtvp_uuid, uuid, sizeof(struct uuid));
	strlcpy(prov->dtvp_instance, instance, DTRACE_INSTANCENAMELEN);

	RB_INSERT(dtvirt_provtree, &dtvirt_provider_tree, prov);

	return (0);
}

static int
dtvirt_priv_unregister(struct dtvirt_prov *prov)
{
	int error;
	dtrace_provider_id_t provid;

	provid = prov->dtvp_id;
	/*
	 * We first have to invalidate the provider because in this case, we are
	 * guaranteed to have /dev/dtrace open.
	 */
	dtrace_invalidate(provid);
	error = dtrace_unregister(provid);
	RB_REMOVE(dtvirt_provtree, &dtvirt_provider_tree, prov);
	free(prov->dtvp_uuid, M_DTVIRT);
	free(prov, M_DTVIRT);

	return (error);
}

static int
dtvirt_provider_unregister(struct uuid *uuid)
{
	struct dtvirt_prov *prov, tmp;

	if (uuid == NULL)
		return (EINVAL);

	tmp.dtvp_uuid = uuid;
	prov = RB_FIND(dtvirt_provtree, &dtvirt_provider_tree, &tmp);
	if (prov == NULL)
		return (ESRCH);

	return (dtvirt_priv_unregister(prov));
}

static void
dtvirt_enable(void *arg, dtrace_id_t id, void *parg)
{
	dtrace_virt_probe_t *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (dtrace_virt_probe_t *) parg;
	virt_probe->dtv_enabled = 1;
	vmmdt_hook_add(virt_probe->dtv_vm, id);
}

static void
dtvirt_disable(void *arg, dtrace_id_t id, void *parg)
{
	dtrace_virt_probe_t *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (dtrace_virt_probe_t *) parg;
	virt_probe->dtv_enabled = 0;
	vmmdt_hook_rm(virt_probe->dtv_vm, id);
}

static void
dtvirt_getargdesc(void *arg, dtrace_id_t id,
    void *parg, dtrace_argdesc_t *adesc)
{

	adesc->dtargd_ndx = DTRACE_ARGNONE;
}

static uint64_t
dtvirt_getargval(void *arg, dtrace_id_t id,
    void *parg, uint64_t ndx, int aframes)
{

	return (0);
}

static void
dtvirt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	dtrace_virt_probe_t *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (dtrace_virt_probe_t *) parg;
	free(virt_probe, M_DTVIRT);
}

static int
dtvirt_prov_cmp(struct dtvirt_prov *p1, struct dtvirt_prov *p2)
{
	struct uuid *p1_uuid, *p2_uuid;

	p1_uuid = p1->dtvp_uuid;
	p2_uuid = p2->dtvp_uuid;

	return (uuidcmp(p1_uuid, p2_uuid));
}
