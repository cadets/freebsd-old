/*-
 * Copyright (c) 2017 Domagoj Stolfa <domagoj.stolfa@gmail.com>
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

#include <machine/bhyve_hypercall.h>

#undef BITS
#define BITS 8

/*
 * We use CPARGS to copy all of the hypercall arguments into the structure
 * dtvirt_inflight, where we keep a record of everything and allow the
 * DTrace framework to look up, given it has a nonce.
 *
 * XXX: A big optimization that is possible here is pre-allocating a buffer
 * and keeping in allocation of these arguments internal to DTvirt. This would
 * allow us to reuse the same ones without requiring to allocate memory, as well
 * as give us the ability to garbage collect things via some sort of reference
 * counting.
 */
#define CPARGS(infl, hargs) \
	do { \
		memcpy(infl->args, hargs->args, 10*sizeof(uintptr_t)); \
		infl->n_args = hargs->n_args; \
		infl->tid = hargs->tid; \
		infl->execname = strdup(hargs->execname, M_DTVIRT); \
		infl->ucaller = hargs->ucaller; \
		infl->ppid = hargs->ppid; \
		infl->uid = hargs->uid; \
		infl->gid = hargs->gid; \
		infl->errno = hargs->errno; \
		memcpy(infl->execargs, hargs->execargs, sizeof(struct pargs)); \
	} while (0)

typedef dtrace_id_t dtvirt_nonce_t;

/*
 * Quick note as to why we have a type list and not a probe list. When we
 * have many guests, the number of probes will increase to a ridicuous
 * amount. What we want to have instead is just one list of types where we
 * can associate each type with multiple probes. This does not have to be fast
 * as it is done while compiling and we never actually ask for a type of the
 * argument when we are tracing.
 */
struct dtvirt_typelist {
	struct dtvirt_probe *probeid; /* Array holding all probes for this type */
	char native_type[DTRACE_ARGTYPELEN]; /* The type itself */
	struct dtvirt_typelist *next;
};

struct dtvirt_prov {
	RB_ENTRY(dtvirt_prov) node;
	dtrace_provider_id_t id;
	struct uuid *uuid;
	char instance[DTRACE_INSTANCENAMELEN];
};

struct dtvirt_inflight {
	RB_ENTRY(dtvirt_inflight) node;
	dtvirt_nonce_t nonce;
	uintptr_t args[10];
	size_t n_args;
	lwpid_t tid;
	char *execname;
	uint32_t stackdepth;
	uint64_t ucaller;
	pid_t ppid;
	uid_t uid;
	gid_t gid;
	int errno;
	struct pargs execargs;
};

struct dtvirt_probe {
	struct dtvirt_prov *provider;
	dtrace_id_t id;
	uint8_t enabled;
};

static void dtvirt_load(void);
static void dtvirt_unload(void);
static void dtvirt_commit(const char *, dtrace_id_t, struct hypercall_args *);
static int dtvirt_probe_create(struct uuid *, const char *, const char *,
    const char *);
static int dtvirt_provider_register(const char *,
    const char *, struct uuid *,
    dtrace_pattr_t *, uint32_t, dtrace_pops_t *);
static int dtvirt_priv_unregister(struct dtvirt_prov *);
static int dtvirt_provider_unregister(struct uuid *);
static void dtvirt_enable(void *, dtrace_id_t, void *);
static void dtvirt_disable(void *, dtrace_id_t, void *);
static void dtvirt_getargdesc(void *, dtvirt_nonce_t, void *, dtrace_argdesc_t *);
static uint64_t dtvirt_getargval(void *, dtvirt_nonce_t, void *, uint64_t, int);
static void dtvirt_destroy(void *, dtvirt_nonce_t, void *);
static int dtvirt_prov_cmp(struct dtvirt_prov *, struct dtvirt_prov *);
static int dtvirt_inflight_cmp(struct dtvirt_inflight *, struct dtvirt_inflight *);

struct mtx dtvirt_typelist_mtx;
LIST_HEAD(dtvirt_tlist, dtvirt_typelist) dtvirt_type_list =
    LIST_HEAD_INITIALIZER(_dtvirt_typelist);

struct mtx dtvirt_provtree_mtx;
RB_HEAD(dtvirt_provtree, dtvirt_prov) dtvirt_provider_tree =
		RB_INITIALIZER(_dtvirt_prov);

struct mtx dtvirt_inflight_mtx;
RB_HEAD(dtvirt_infltree, dtvirt_inflight) dtvirt_inflight_tree =
    RB_INITIALIZER(_dtvirt_inflight);

RB_GENERATE_STATIC(dtvirt_provtree, dtvirt_prov, node,
		dtvirt_prov_cmp);

RB_GENERATE_STATIC(dtvirt_infltree, dtvirt_inflight, node,
    dtvirt_inflight_cmp);

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
	/*
	 * Initialize the mutexes
	 */
	mtx_init(&dtvirt_typelist_mtx, "Type list mutex", NULL, MTX_DEF);
	mtx_init(&dtvirt_provtree_mtx, "DTvirt provider tree mutex", NULL, MTX_DEF);
	mtx_init(&dtvirt_inflight_mtx, "In-flight probe mutex", NULL, MTX_DEF);

	/*
	 * Now we expose the hooks to the rest of the system for dtvirt.
	 */
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
	mtx_lock(&dtvirt_provtree_mtx);
	RB_FOREACH_SAFE(prov, dtvirt_provtree, &dtvirt_provider_tree, tmp) {
		error = dtvirt_priv_unregister(prov);
		if (error)
			panic("Unregister of a provider failed\n");
	}
	mtx_unlock(&dtvirt_provtree_mtx);

	/*
	 * Remove the hooks into dtvirt.
	 */
	dtvirt_hook_commit = NULL;
	dtvirt_hook_register = NULL;
	dtvirt_hook_unregister = NULL;
	dtvirt_hook_create = NULL;
	dtvirt_hook_enable = NULL;
	dtvirt_hook_disable = NULL;
	dtvirt_hook_getargdesc = NULL;
	dtvirt_hook_getargval = NULL;
	dtvirt_hook_destroy = NULL;

	/*
	 * Clean up the mutexes.
	 */
	mtx_destroy(&dtvirt_provtree_mtx);
	mtx_destroy(&dtvirt_inflight_mtx);
	mtx_destroy(&dtvirt_typelist_mtx);
}

static dtvirt_nonce_t
dtvirt_add_inflight(struct hypercall_args *args)
{
	/*
	 * If fire a probe, we will mark it as in flight. We have to ensure
	 * that our nonce really is unique. We then add it to a red-black tree that
	 * will then be searched from other functions (getargval, ...) in order to
	 * provide information that DTrace might be asking for.
	 *
	 * FIXME: We currently do not take into account as to what happens when
	 * we have so many probes in flight that we simply exhaust the nonce
	 * space and spin forever.
	 */
	struct dtvirt_inflight *inflight, *res;

	inflight = malloc(sizeof(struct dtvirt_inflight), M_DTVIRT, M_NOWAIT);
	CPARGS(inflight, args);

	/*
	 * We iterate until we find a valid nonce.
	 */
	do {
		arc4rand(&inflight->nonce, sizeof(dtvirt_nonce_t)*BITS, 0);

		mtx_lock(&dtvirt_inflight_mtx);
		res = RB_INSERT(dtvirt_inflight, &dtvirt_inflight_tree, inflight);
		mtx_unlock(&dtvirt_inflight_mtx);
	} while (res != NULL);

	/*
	 * Finally, we return the nonce.
	 */
	return (inflight->nonce);
}

static void
dtvirt_remove_inflight(dtvirt_nonce_t nonce)
{
	/*
	 * Once the probe is done executing, we do not care about it anymore.
	 * We find it in the tree, remove it and free the allocated memory.
	 */
	struct dtvirt_inflight tmp, *found;

	tmp.nonce = nonce;
	found = RB_FIND(dtvirt_infltree, &dtvirt_inflight_tree, &tmp);
	RB_REMOVE(dtvirt_infltree, &dtvirt_inflight_tree, found);
	free(found->execname, M_DTVIRT);
	free(found, M_DTVIRT);
}

static void
dtvirt_commit(const char *vm, struct hypercall_args *args)
{
	dtvirt_nonce_t nonce;

	nonce = dtvirt_add_inflight(args);
	dtrace_distributed_probe(vm, nonce, args->dt.probeid, args->dt.args[0],
	    args->dt.args[1], args->dt.args[2], args->dt.args[3], args->dt.args[4]);
	dtvirt_remove_inflight(nonce);
}

static int
dtvirt_probe_create(struct uuid *uuid, const char *mod, const char *func,
    const char *name, char types[DTRACE_ARGTYPELEN][10])
{
	/*
	 * TODO: Fill the type list in.
	 */
	struct dtvirt_probe *virt_probe;
	struct dtvirt_prov *prov, tmp;
	struct uuid tmpuuid;
	dtrace_provider_id_t provid;

	memcpy(&tmpuuid, uuid, sizeof(struct uuid));

	tmp.uuid = &tmpuuid;
	prov = RB_FIND(dtvirt_provtree, &dtvirt_provider_tree, &tmp);

	if (prov == NULL)
		return (ESRCH);

	provid = prov->id;

	virt_probe = malloc(sizeof(struct dtvirt_probe), M_DTVIRT,
	    M_NOWAIT | M_ZERO);

	if (virt_probe == NULL)
		return (ENOMEM);

	virt_probe->enabled = 0;

	virt_probe->id = dtrace_probe_create(provid, mod, func,
	    name, 0, virt_probe);
	strlcpy(virt_probe->vm,
	    prov->instance, DTRACE_INSTANCENAMELEN);

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
	size_t n;

	/*
	 * Attempt to allocate a new provider and its UUID space. These can fail.
	 */
	prov = malloc(sizeof(struct dtvirt_prov), M_DTVIRT, M_NOWAIT | M_ZERO);
	if (prov == NULL)
		return (ENOMEM);

	prov->uuid = malloc(sizeof(struct uuid), M_DTVIRT,
	    M_NOWAIT | M_ZERO);

	if (prov->uuid == NULL) {
		free(prov, M_DTVIRT);
		return (ENOMEM);
	}

	/*
	 * Attempt to register the provider with the DTrace Framework.
	 */
	error = dtrace_distributed_register(provname, instance,
	    uuid, pattr, priv, NULL, pops, NULL, &provid);

	/*
	 * If it fails, we do not care about this in DTvirt and free everything.
	 */
	if (error) {
		free(prov->uuid, M_DTVIRT);
		free(prov, M_DTVIRT);
		return (error);
	}

	/*
	 * If successful, we assign the provider ID, UUID and the VM name.
	 */
	prov->id = provid;
	memcpy(prov->uuid, uuid, sizeof(struct uuid));
	n = strlcpy(prov->instance, instance, DTRACE_INSTANCENAMELEN);
	/*
	 * If somehow this happened (strlcpy tells us), there is something weird
	 * going on. Free everything and return an overflow errno.
	 */
	if (n >= DTRACE_INSTANCENAMELEN) {
		dtrace_unregister(provid);
		free(prov->uuid);
		free(prov);
		return (EOVERFLOW);
	}

	/*
	 * Allocate the space for a type list. Here, we want to keep a list of all
	 * types for each of the probes.
	 */
	prov->typelist_head = malloc(sizeof(struct dtvirt_typelist),
			M_DTVIRT, M_NOWAIT | M_ZERO);
	if (prov->typelist_head == NULL) {
		dtrace_unregister(provid);
		free(prov->uuid);
		free(prov);
		return (ENOMEM);
	}

	/*
	 * If all is well, insert the provider into the red-black tree and return 0.
	 * FIXME - maybe: We do not currently handle the case where the UUID conflicts.
	 */
	RB_INSERT(dtvirt_provtree, &dtvirt_provider_tree, prov);
	return (0);
}

static int
dtvirt_priv_unregister(struct dtvirt_prov *prov)
{
	int error;

	/*
	 * We first have to invalidate the provider because in this case, we are
	 * guaranteed to have /dev/dtrace open.
	 */
	dtrace_invalidate(prov->id);
	error = dtrace_unregister(prov->id);
	RB_REMOVE(dtvirt_provtree, &dtvirt_provider_tree, prov);
	free(prov->uuid, M_DTVIRT);
	free(prov, M_DTVIRT);

	return (error);
}

static int
dtvirt_provider_unregister(struct uuid *uuid)
{
	/*
	 * Provide a way to unregister a provider with DTvirt.
	 */
	struct dtvirt_prov *prov, tmp;

	if (uuid == NULL)
		return (EINVAL);

	tmp.uuid = uuid;
	prov = RB_FIND(dtvirt_provtree, &dtvirt_provider_tree, &tmp);
	if (prov == NULL)
		return (ESRCH);

	return (dtvirt_priv_unregister(prov));
}

static void
dtvirt_enable(void *arg, dtrace_id_t id, void *parg)
{
	struct dtvirt_probe *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (struct dtvirt_probe *) parg;
	virt_probe->enabled = 1;
	vmmdt_hook_add(virt_probe->vm, id);
}

static void
dtvirt_disable(void *arg, dtrace_id_t id, void *parg)
{
	struct dtvirt_probe *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (struct dtvirt_probe *) parg;
	virt_probe->enabled = 0;
	vmmdt_hook_rm(virt_probe->vm, id);
}

static void
dtvirt_getargdesc(void *arg, dtrace_id_t id,
    void *parg, dtrace_argdesc_t *adesc)
{
	/*
	 * Here, we take the pointer to the provider that is passed to us
	 * via the first argument. We then go through all of the known types
	 * for this provider in a list (this could be optimized if necessary)
	 * and look for the probe ID that DTrace is asking for. We then copy
	 * the native type into the dtrace_argdesc structure so that the
	 * compiler can happily know the size of things.
	 *
	 * FIXME: As it stands, we assume host types == guest types, but this
	 * implementation should provide a basis for the more sophisticated
	 * version without much change.
	 */
	dtvirt_provider_t *prov;
	dtvirt_type_t *t;

	KASSERT(arg, ("%s(%d): arg is NULL", __func__, __LINE__));
	prov = (dtvirt_provider_t *) arg;

	/*
	 * Start from the head.
	 */
	mtx_lock(&prov->typelist_mtx);
	t = prov->type_head;
	while (t) {
		if (t->probeid == id) {
			n = strlcpy(adesc->dtargd_native, t->native_type,
			    sizeof(adesc->dtargd_native));
			if (n >= sizeof(adesc->dtargd_native)) {
				memset(adesc->dtargd_native, 0, sizeof(adesc->dtargd_native));
				adesc->dtargd_ndx = DTRACE_ARGNONE;
			}
			mtx_unlock(&prov->typelist_mtx);
			return;
		}
		t = t->next;
	}

	mtx_unlock(&prov->typelist_mtx);
	adesc->dtargd_ngx = DTRACE_ARGNONE;
}

static uint64_t
dtvirt_getargval(void *arg, dtvirt_nonce_t nonce,
    void *parg, uint64_t ndx, int aframes)
{
	struct dtvirt_inflight *found, tmp;

	found = RB_FIND(dtvirt_infltree, &dtvirt_inflight_tree, &tmp);
	if (found == NULL) {
		return (ESRCH);
	}

	return (0);
}

static void
dtvirt_destroy(void *arg, dtvirt_nonce_t nonce, void *parg)
{
	struct dtvirt_probe *virt_probe;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (struct dtvirt_probe *) parg;
	free(virt_probe, M_DTVIRT);
}

static int
dtvirt_prov_cmp(struct dtvirt_prov *p1, struct dtvirt_prov *p2)
{

	return (uuidcmp(p1->uuid, p2->uuid));
}

static int
dtvirt_inflight_cmp(struct dtvirt_inflight *p1, struct dtvirt_inflight *p2)
{
	if (p1->probeid < p2->probeid)
		return (-1);
	else if (p1->probeid > p2->probeid)
		return (1);

	return (0);
}
