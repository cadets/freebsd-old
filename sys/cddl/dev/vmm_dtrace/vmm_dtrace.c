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
#include <sys/types.h>
#include <sys/kernel.h>
#include <sys/libkern.h>
#include <sys/module.h>
#include <sys/malloc.h>
#include <sys/hash.h>
#include <sys/tree.h>

#include <sys/dtvirt.h>

#include <machine/vmm.h>
#include <machine/vmm_dtrace.h>

/*
 * Identifying information of a probe
 */
struct vmmdt_probe {
	RB_ENTRY(vmmdt_probe)	vmdtp_node;
	uint64_t		vmdtp_args[VMMDT_MAXARGS];
	int			vmdtp_id;
};

/*
 * Holds our red-black tree
 */
struct vmdtree {
	RB_HEAD(vmmdt_probetree, vmmdt_probe)	vmdtree_head;
	struct mtx				vmdtree_mtx;
	char					vmdtree_vmname[VM_MAX_NAMELEN];
};

/*
 * Holds the hash table of all of the red-black trees
 */
struct vmmdt_vmlist {
	struct vmdtree				**vm_list;
	struct mtx				  vm_listmtx;
#define	VMMDT_INITSIZ		 		  4096
#define	VMMDT_MASK				  (VMMDT_INITSIZ - 1)
};

static MALLOC_DEFINE(M_VMMDT, "VMM DTrace buffer",
    "Holds the data related to the VMM layer for DTvirt");

static struct vmmdt_vmlist vmmdt_vms;
static int vmmdt_initialized = 0;

static int	vmmdt_init(void);
static int	vmmdt_alloc_vmlist(void);
static void	vmmdt_cleanup(void);
static struct vmdtree * vmmdt_alloc_vmdtree(const char *, uint32_t);
static void	vmmdt_free_vmdtree(struct vmdtree *);
static int	vmmdt_add_probe(const char *, int);
static int	vmmdt_rm_probe(const char *, int);
static int	vmmdt_enabled(const char *, int);
static void	vmmdt_fire_probe(const char *, int,
           	    uintptr_t, uintptr_t, uintptr_t,
		    uintptr_t, uintptr_t);
static struct vmdtree * vmmdt_hash_lookup(const char *, uint32_t *);
static int	vmmdt_probe_cmp(struct vmmdt_probe *, struct vmmdt_probe *);

RB_GENERATE_STATIC(vmmdt_probetree, vmmdt_probe, vmdtp_node,
    vmmdt_probe_cmp);

/*
 * Probing constants
 */
static const uint8_t c1 = 2;
static const uint8_t c2 = 2;

/*
 * Initial hash, different every time the module gets loaded
 */
static uint32_t init_hash;

static int
vmmdt_handler(module_t mod, int what, void *arg)
{
	int error;

	switch (what) {
	case MOD_LOAD:
		error = vmmdt_init();
		if (error == 0)
			vmmdt_initialized = 1;
		break;
	case MOD_UNLOAD:
		vmmdt_cleanup();
		error = 0;
		vmmdt_initialized = 0;
	default:
		error = 0;
		break;
	}

	return (error);
}

static moduledata_t vmmdt_kmod = {
	"vmmdt",
	vmmdt_handler,
	NULL
};

MODULE_VERSION(vmmdt, 1);
MODULE_DEPEND(vmmdt, vmm, 1, 1, 1);
MODULE_DEPEND(vmmdt, dtrace, 1, 1, 1);

DECLARE_MODULE(vmmdt, vmmdt_kmod, SI_SUB_SMP + 1, SI_ORDER_ANY);

/*
 * Set up all of the hooks and allocate the hash table
 */
static int
vmmdt_init(void)
{
	int error;

	error = 0;

	init_hash = arc4random();

	vmmdt_hook_add = vmmdt_add_probe;
	vmmdt_hook_rm = vmmdt_rm_probe;
	vmmdt_hook_fire_probe = vmmdt_fire_probe;

	error = vmmdt_alloc_vmlist();

	return (error);
}

/*
 * Here we allocate the hash table and it's mutex
 */
static int
vmmdt_alloc_vmlist(void)
{
	vmmdt_vms.vm_list = malloc(sizeof(struct vmdtree *) * VMMDT_INITSIZ,
	    M_VMMDT, M_ZERO | M_NOWAIT);

	if (vmmdt_vms.vm_list == NULL)
		return (ENOMEM);

	mtx_init(&vmmdt_vms.vm_listmtx, "vmlistmtx", NULL, MTX_DEF);
	return (0);
}

/*
 * Set all of the hooks to NULL, iterate through the hash table, and for every
 * red-black tree that exists, delete all of it's probes and destroy the tree.
 * Following that, we destroy the hash table itself and set it to NULL.
 */
static void
vmmdt_cleanup(void)
{
	struct vmmdt_probetree *rbhead;
	struct vmmdt_probe *tmp, *probe;
	struct vmdtree *vm_tree;
	int i;
	if (vmmdt_vms.vm_list == NULL)
		return;

	vmmdt_hook_add = NULL;
	vmmdt_hook_rm = NULL;
	vmmdt_hook_fire_probe = NULL;

	mtx_lock(&vmmdt_vms.vm_listmtx);
	for (i = 0; i < VMMDT_INITSIZ; i++) {
		vm_tree = vmmdt_vms.vm_list[i];
		if (vm_tree == NULL)
			continue;
		mtx_lock(&vm_tree->vmdtree_mtx);
		rbhead = &vm_tree->vmdtree_head;
		RB_FOREACH_SAFE(probe, vmmdt_probetree, rbhead, tmp) {
			if (probe != NULL) {
				free(probe, M_VMMDT);
			}
		}

		mtx_unlock(&vm_tree->vmdtree_mtx);
		mtx_destroy(&vm_tree->vmdtree_mtx);
		free(vm_tree, M_VMMDT);
		vmmdt_vms.vm_list[i] = NULL;
	}
	mtx_unlock(&vmmdt_vms.vm_listmtx);

	mtx_destroy(&vmmdt_vms.vm_listmtx);
	free(vmmdt_vms.vm_list, M_VMMDT);

	vmmdt_vms.vm_list = NULL;
}

static struct vmdtree *
vmmdt_alloc_vmdtree(const char *vm, uint32_t idx)
{
	struct vmdtree *new;
	char mtxname[32];
	size_t n;

	new = malloc(sizeof(struct vmdtree), M_VMMDT, M_ZERO | M_NOWAIT);
	if (new == NULL)
		goto end;

	n = strlcpy(new->vmdtree_vmname, vm, VM_MAX_NAMELEN);
	if (n >= VM_MAX_NAMELEN) {
		free(new, M_VMMDT);
		new = NULL;
		goto end;
	}

	snprintf(mtxname, sizeof(mtxname), "vmdtree_mtx-%u\n", idx);
	mtx_init(&new->vmdtree_mtx, mtxname, NULL, MTX_DEF);
end:
	return (new);
}

static void
vmmdt_free_vmdtree(struct vmdtree *old)
{
	mtx_destroy(&old->vmdtree_mtx);
	free(old, M_VMMDT);
}

static int
vmmdt_add_probe(const char *vm, int id)
{
	struct vmdtree *vtree;
	struct vmmdt_probe *probe;
	uint32_t idx;

	probe = malloc(sizeof(struct vmmdt_probe),
	    M_VMMDT, M_ZERO | M_NOWAIT);

	if (probe == NULL)
		return (ENOMEM);

	probe->vmdtp_id = id;
	vtree = vmmdt_hash_lookup(vm, &idx);

	if (vtree == NULL) {
		vtree = vmmdt_alloc_vmdtree(vm, idx);
	}

	mtx_lock(&vtree->vmdtree_mtx);
	RB_INSERT(vmmdt_probetree, &vtree->vmdtree_head, probe);
	mtx_unlock(&vtree->vmdtree_mtx);

	vmmdt_vms.vm_list[idx] = vtree;

	return (0);
}

static int
vmmdt_rm_probe(const char *vm, int id)
{
	struct vmdtree *vtree;
	struct vmmdt_probe *probe, tmp;
	uint32_t idx;

	vtree = vmmdt_hash_lookup(vm, &idx);

	if (vtree == NULL)
		return (EINVAL);

	tmp.vmdtp_id = id;

	mtx_lock(&vtree->vmdtree_mtx);
	probe = RB_FIND(vmmdt_probetree, &vtree->vmdtree_head, &tmp);
	if (probe == NULL) {
		mtx_unlock(&vtree->vmdtree_mtx);
		return (ESRCH);
	}

	RB_REMOVE(vmmdt_probetree, &vtree->vmdtree_head, probe);
	mtx_unlock(&vtree->vmdtree_mtx);

	free(probe, M_VMMDT);

	if (RB_EMPTY(&vtree->vmdtree_head)) {
		vmmdt_free_vmdtree(vtree);
		vmmdt_vms.vm_list[idx] = NULL;
	}

	return (0);
}

static __inline int
vmmdt_enabled(const char *vm, int probeid)
{
	/*
	 * TODO:
	 * Make a big table of pointers to radix trees that are indexed with the
	 * probe id, get the necessary radix tree, walk down the enabled VMs and
	 * find the one we want
	 */
	struct vmdtree *vtree;
	struct vmmdt_probe tmp, *probe;

	tmp.vmdtp_id = probeid;
	vtree = vmmdt_hash_lookup(vm, NULL);
	if (vtree == NULL)
		return (0);

	mtx_lock(&vtree->vmdtree_mtx);
	probe = RB_FIND(vmmdt_probetree, &vtree->vmdtree_head, &tmp);
	mtx_unlock(&vtree->vmdtree_mtx);

	return (probe != NULL);
}

static  __inline void
vmmdt_fire_probe(const char *vm, int probeid,
    uintptr_t arg0, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4)
{
	/*if (vmmdt_enabled(vm, probeid))*/
	dtvirt_hook_commit(vm, probeid, arg0, arg1,
	    arg2, arg3, arg4);
}

static struct vmdtree *
vmmdt_hash_lookup(const char *vm, uint32_t *par_idx)
{
	uint32_t idx;
	uint32_t hash_res;
	uint32_t i;
	struct vmdtree *vm_tree;

	i = 0;
	hash_res = murmur3_32_hash(vm, strlen(vm), init_hash) & VMMDT_MASK;
	idx = hash_res;
	vm_tree = vmmdt_vms.vm_list[idx];

	mtx_lock(&vmmdt_vms.vm_listmtx);
	while (vm_tree != NULL &&
	    strcmp(vm, vm_tree->vmdtree_vmname) != 0) {
		i++;
		idx = hash_res + i/c1 + i*i/c2;
		vm_tree = vmmdt_vms.vm_list[idx];
	}
	mtx_unlock(&vmmdt_vms.vm_listmtx);

	if (par_idx)
		*par_idx = idx;

	return (vmmdt_vms.vm_list[idx]);
}

static int
vmmdt_probe_cmp(struct vmmdt_probe *p1, struct vmmdt_probe *p2)
{
	if (p1->vmdtp_id == p2->vmdtp_id)
		return (0);

	return ((p1->vmdtp_id > p2->vmdtp_id) ? 1 : -1);
}
