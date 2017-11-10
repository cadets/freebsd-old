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
#define DTVIRT_MAXARGS 10

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

typedef uintptr_t dtvirt_nonce_t;

/*
 * Quick note as to why we have a type list and not a probe list. When we
 * have many guests, the number of probes will increase to a ridicuous
 * amount. What we want to have instead is just one list of types where we
 * can associate each type with multiple probes. This does not have to be fast
 * as it is done while compiling and we never actually ask for a type of the
 * argument when we are tracing.
 */
struct dtvirt_typelist {
	char native_type[DTRACE_ARGTYPELEN]; /* The type itself */
	LIST_ENTRY(dtvirt_type_list) next; /* Next pointer */
	size_t probe_count; /* Number of probes that exist */
};

struct dtvirt_prov {
	RB_ENTRY(dtvirt_prov) node; /* A provider node in the RB tree */
	dtrace_provider_id_t id; /* The DTrace identifier of the provider */
	struct uuid *uuid; /* The UUID of the provider */
	char vm[DTRACE_INSTANCENAMELEN]; /* The VM it resides in */
};

/*
 * The way we identify a nonce for this structure is by its pointer.
 */
struct dtvirt_inflight {
	uintptr_t args[DTVIRT_MAXARGS]; /* All of the arguments */
	size_t n_args; /* Number of arguments */
	lwpid_t tid; /* Guest thread id */
	char *execname; /* execname in the guest */
	uint32_t stackdepth; /* Guest stack depth */
	uint64_t ucaller; /* Guest ucaller */
	pid_t ppid; /* Guest ppid */
	uid_t uid; /* Guest uid */
	gid_t gid; /* Guest gid */
	int errno; /* Guest errno */
	struct pargs execargs; /* Guest execargs */
};

struct dtvirt_probe {
	struct dtvirt_prov *provider; /* Back-pointer to the provider */
	struct dtvirt_typelist (*types)[DTVIRT_MAXARGS]; /* All of the types */
	dtrace_id_t id; /* The DTrace probe ID */
	uint8_t enabled; /* Enabled flag */
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
static void dtvirt_getargdesc(void *,
    dtvirt_nonce_t, void *, dtrace_argdesc_t *);
static uint64_t dtvirt_getargval(void *, dtvirt_nonce_t, void *, uint64_t, int);
static void dtvirt_destroy(void *, dtvirt_nonce_t, void *);
static int dtvirt_prov_cmp(struct dtvirt_prov *, struct dtvirt_prov *);

struct mtx dtvirt_typelist_mtx;
LIST_HEAD(dtvirt_tlist, dtvirt_typelist) dtvirt_type_list =
    LIST_HEAD_INITIALIZER(_dtvirt_typelist);

struct mtx dtvirt_provtree_mtx;
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
	/*
	 * Initialize the mutexes
	 */
	mtx_init(&dtvirt_typelist_mtx, "Type list mutex", NULL, MTX_DEF);
	mtx_init(&dtvirt_provtree_mtx, "DTvirt provider tree mutex", NULL, MTX_DEF);
	LIST_INIT(&dtvirt_type_list);

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
	mtx_destroy(&dtvirt_typelist_mtx);
}

static dtvirt_nonce_t
dtvirt_add_inflight(struct hypercall_args *args)
{
	/*
	 * For all in-flight probes, we generate a "nonce", which is currently
	 * just its pointer. We can be sure that it's unique due to the memory
	 * allocator being unique and gives is O(1) access to everything we need
	 * whenever DTrace needs us to access data.
	 */
	struct dtvirt_inflight *inflight;

	inflight = malloc(sizeof(struct dtvirt_inflight), M_DTVIRT, M_NOWAIT);
	/*
	 * In case we can't allocate this -- too many probes firing.
	 */
	if (inflight == NULL)
		return (NULL);

	CPARGS(inflight, args);

	/*
	 * Our nonce is just the pointer to the in-flight probe.
	 */
	return ((uintptr_t)inflight);
}

static void
dtvirt_remove_inflight(dtvirt_nonce_t nonce)
{
	struct dtvirt_inflight *probe

	probe = (struct dtvirt_inflight *)nonce;

	free(probe->execname, M_DTVIRT);
	free(probe, M_DTVIRT);
}

static void
dtvirt_commit(const char *vm, struct hypercall_args *args)
{
	/*
	 * A simple intermediate layer for firing DTrace probes from the guest.
	 * We first grab a nonce to the probe that is firing and pass it in to
	 * the DTrace Framework. This allows us to call dtps_* functions in DTvirt
	 * and get information easily for each in-flight probe. After we have fired
	 * the probe, we don't actually need the information anymore, so we delete
	 * the in-flight probe.
	 */
	dtvirt_nonce_t nonce;

	nonce = dtvirt_add_inflight(args);
	dtrace_distributed_probe(vm, nonce, args->dt.probeid, args->dt.args[0],
	    args->dt.args[1], args->dt.args[2], args->dt.args[3], args->dt.args[4]);
	dtvirt_remove_inflight(nonce);
}

static int
dtvirt_probe_create(struct uuid *uuid, const char *mod, const char *func,
    const char *name, char types[DTRACE_ARGTYPELEN][DTVIRT_MAXARGS])
{
	struct dtvirt_probe *virt_probe;
	struct dtvirt_prov *prov, tmp;
	struct uuid tmpuuid;
	struct dtvirt_typelist *type;
	dtrace_provider_id_t provid;
	int i;

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

	n = strlcpy(virt_probe->vm,
		prov->vm, DTRACE_INSTANCENAMELEN);

	if (n >= DTRACE_INSTANCENAMELEN) {
		free(virt_probe, M_DTVIRT);
		return (ENOMEM);
	}

	/*
	 * FIXME: This should be optimized a bit eventually. Instead of going
	 * through the types that were passed in, we should be going through the
	 * list and comparing to the types. That way we have better caching and
	 * in turn, a decent speed-up given that the list will be large and we will
	 * only traverse it once.
	 */
	mtx_lock(&dtvirt_typelist_mtx);
	for (i = 0; i < DTVIRT_MAXARGS; i++) {
		type = LIST_HEAD(&dtvirt_type_list);
		for (type = LIST_HEAD(&dtvirt_type_list);
		    type != NULL; type = LIST_NEXT(type, next)) {
			if (strcmp(type->native_type, types[i]) == 0)
				break;
		}
		if (type == NULL) {
			type = malloc(sizeof(struct dtvirt_typelist),
			    M_DTVIRT, M_NOWAIT | M_ZERO);
			if (type == NULL) {
				free(virt_probe, M_DTVIRT);
				return (ENOMEM);
			}

			n = strlcpy(type->native_type, types[i], DTRACE_ARGTYPELEN);
			if (n >= DTRACE_ARGTYPELEN) {
				free(virt_probe, M_DTVIRT);
				free(type, M_DTVIRT);
				return (EOVERFLOW);
			}

			LIST_INSERT_HEAD(&dtvirt_type_list, type, next);
		}

		type->probe_count++;
	}
	mtx_unlock(&dtvirt_typelist_mtx);

	virt_probe->id = dtrace_probe_create(provid, mod, func,
			name, 0, virt_probe);
	virt_probe->provider = prov;

	return (0);
}

static int
dtvirt_provider_register(const char *provname, const char *vm,
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
	error = dtrace_distributed_register(provname, vm,
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
	n = strlcpy(prov->vm, vm, DTRACE_INSTANCENAMELEN);
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
	 * If all is well, insert the provider into the red-black tree and return 0.
	 * FIXME - maybe: We do not currently handle the case where the UUID
	 * conflicts.
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
	 *
	 * XXX: Is it safe to not acquire the list mutex here?
	 */
	struct dtvirt_probe *probe;
	struct dtvirt_typelist *t;

	KASSERT(parg, ("%s(%d): parg is NULL", __func__, __LINE__));
	probe = (dtvirt_provider_t *) parg;

	/*
	 * Check if DTrace is being sane here.
	 */
	if (adesc->dtargd_ndx > probe->n_args) {
		adesc->dtargd_ndx = DTRACE_ARGNONE;
		return;
	}

	/*
	 * If so, let's give it a type.
	 */
	t = probe->types[adesc->dtargd_ndx];
	n = strlcpy(adesc->dtargd_native, t->native_type,
			sizeof(adesc->dtargd_native));

	/*
	 * There's a possibility that something weird is happening here. If so,
	 * we will notify DTrace of an overflow.
	 */
	if (n >= sizeof(adesc->dtargd_native)) {
		memcpy(adesc->dtargd_native, 0, sizeof(adesc->dtargd_native));
		adesc->dtargd_ndx = DTRACE_ARGNONE;
	}
}

static uint64_t
dtvirt_getargval(void *arg, dtvirt_nonce_t nonce,
    void *parg, uint64_t ndx, int aframes)
{
	/*
	 * We take a nonce and follow up by simply returning the argument that
	 * the DTrace Framework is asking for (unless out of bounds).
	 */
	struct dtvirt_inflight *probe;

	probe = (struct dtvirt_inflight *)nonce;
	if (probe == NULL)
		return (0);

	if (probe->n_args < ndx)
		return (0);

	return (probe->args[ndx]);
}

static void
dtvirt_destroy(void *arg, dtrace_id_t id, void *parg)
{
	struct dtvirt_probe *virt_probe;
	struct dtvirt_typelist *type;

	KASSERT(parg != NULL, ("%s: parg is NULL", __func__));

	virt_probe = (struct dtvirt_probe *) parg;
	mtx_lock(&dtvirt_typelist_mtx);
	for (i = 0, type = virt_probe->types[i]; i != DTVIRT_MAXARGS; i++)
		if (--type->probe_count == 0) {
			LIST_REMOVE(&dtvirt_type_list, type);
			free(type, M_DTVIRT);
		}
	mtx_unlock(&dtvirt_typelist_mtx);

	free(virt_probe, M_DTVIRT);
}

static int
dtvirt_prov_cmp(struct dtvirt_prov *p1, struct dtvirt_prov *p2)
{

	return (uuidcmp(p1->uuid, p2->uuid));
}
