/*-
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

/*
 * The HyperTrace module is meant to be called from a tracing framework, such as
 * DTrace. It is responsible for managing virtual probes and providers in a way
 * that allows the tracing system to enable and disable virtual probes in a
 * race-free way (assuming the system relies on memory barriers and syncs with
 * an asynchronous way to fully disable tracing).
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dtrace.h>
#include <sys/dtrace_bsd.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <machine/vmm.h>

#include "hypertrace.h"

static MALLOC_DEFINE(M_HYPERTRACE, "HyperTrace", "");

static lwpid_t    hypertrace_priv_gettid(const void *);
static uint16_t   hypertrace_priv_getns(const void *);
static const char *hypertrace_priv_getname(const void *);
static int        hypertrace_priv_rmprobe(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_is_enabled(uint16_t, hypertrace_id_t);
static int        hypertrace_priv_create_probes(uint16_t, void *, size_t);
static void       hypertrace_priv_enable(uint16_t, hypertrace_id_t);
static void       hypertrace_priv_disable(uint16_t, hypertrace_id_t);
static void       hypertrace_priv_suspend(uint16_t, hypertrace_id_t);
static void       hypertrace_priv_resume(uint16_t, hypertrace_id_t);

lwpid_t    (*vmm_gettid)(const void *);
uint16_t   (*vmm_getid)(const void *);
const char *(*vmm_getname)(const void *);

static d_open_t hypertrace_open;
static int      hypertrace_unload(void);
static void     hypertrace_load(void *);

static struct cdevsw hypertrace_cdevsw = {
	.d_version         = D_VERSION,
	.d_open            = hypertrace_open,
	.d_name            = "hypertrace",
};

/*
 * A sensible hash size seems to be around 4096 (for providers, anyway).
 *
 * FIXME: Currently, there is an attack on this hash table where a guest could
 * just find a provider that matches and simply keep appending a number to it so
 * that the hash table fills up and the host creates a bunch of providers. We
 * need a few heuristics in the kernel that will prevent this -- e.g. allowing a
 * maximum number of providers on each guest and simply kicking everything out
 * if it's exceeded.
 */
#define HASH_SIZE 4096
#define HASH_MASK (HASH_SIZE - 1)

static struct cdev            *hypertrace_cdev;
static int         __unused   hypertrace_verbose = 0;
static hypertrace_map_t       *hypertrace_map;
static hypertrace_vprovider_t **provtab;

static void
hypertrace_load(void *dummy __unused)
{
	/*
	 * Create the device node.
	 */
	hypertrace_cdev = make_dev(&hypertrace_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "dtrace/hypertrace");

	/*
	 * TODO: Initialize the map.
	 */
}

static int
hypertrace_unload()
{

	destroy_dev(hypertrace_cdev);
	return (0);
}

static int
hypertrace_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
		/*
		 * Initialize the provtab and initialize the probe map.
		 */
		provtab = kmem_zalloc(
		    sizeof(hypertrace_vprovider_t *) * HASH_SIZE, KM_SLEEP);

		hypertrace_map = map_init();
		/*
		 * Set up the hooks.
		 */
		hypertrace_gettid        = hypertrace_priv_gettid;
		hypertrace_getns         = hypertrace_priv_getns;
		hypertrace_getname       = hypertrace_priv_getname;
		hypertrace_rmprobe       = hypertrace_priv_rmprobe;
		hypertrace_is_enabled    = hypertrace_priv_is_enabled;
		hypertrace_create_probes = hypertrace_priv_create_probes;
		hypertrace_enable        = hypertrace_priv_enable;
		hypertrace_disable       = hypertrace_priv_disable;
		hypertrace_suspend       = hypertrace_priv_suspend;
		hypertrace_resume        = hypertrace_priv_resume;
		break;

	case MOD_UNLOAD:
		/*
		 * Destroy the hooks.
		 */
		hypertrace_gettid        = NULL;
		hypertrace_getns         = NULL;
		hypertrace_getname       = NULL;
		hypertrace_rmprobe       = NULL;
		hypertrace_is_enabled    = NULL;
		hypertrace_create_probes = NULL;
		hypertrace_enable        = NULL;
		hypertrace_disable       = NULL;
		hypertrace_suspend       = NULL;
		hypertrace_resume        = NULL;

		/*
		 * Free the provtab and tear down the probe map.	
		 */
		kmem_free(
		    provtab, sizeof(hypertrace_vprovider_t *) * HASH_SIZE);
		map_teardown(hypertrace_map);
		break;

	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;

	}

	return (error);
}

/*
 * Placeholder for future things.
 */
static int
hypertrace_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{
	
	return (0);
}

static int
hypertrace_priv_is_enabled(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	return (ht_probe->htpb_enabled);
}

static void
hypertrace_priv_enable(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	ht_probe->htpb_enabled = 1;
	ht_probe->htpb_running = 1;
}

static void
hypertrace_priv_disable(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	ht_probe->htpb_running = 0;
	ht_probe->htpb_enabled = 0;
}

static void
hypertrace_priv_suspend(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	ht_probe->htpb_running = 0;
}

static void
hypertrace_priv_resume(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_probe_t *ht_probe;

	ht_probe = map_get(hypertrace_map, vmid, id);
	ht_probe->htpb_running = 1;
}

void
hypertrace_probe(const void *vmhdl, hypertrace_id_t id, hypertrace_args_t *dtv_args)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	vmid = hypertrace_priv_getns(vmhdl);

	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return;

	if (ht_probe->htpb_enabled != 0 && ht_probe->htpb_running == 1)
		dtrace_vprobe(vmhdl, id, dtv_args);
}

/*
 * Get the thread ID of the VM.
 */
static lwpid_t
hypertrace_priv_gettid(const void *vmhdl)
{

	return (vmm_gettid == NULL ? 0 : vmm_gettid(vmhdl));
}

/*
 * Get a unique identifier of each vm (uint16_t). This is used to scope
 * thread-local storage in the DTrace probe context.
 */
static uint16_t
hypertrace_priv_getns(const void *vmhdl)
{

	return (vmm_getid == NULL ? 0 : vmm_getid(vmhdl));
}

static const char *
hypertrace_priv_getname(const void *vmhdl)
{

	return (vmm_getname == NULL ? 0 : vmm_getname(vmhdl));
}

/*
 * Get a vprovider with a given provider name. We assume provider names are
 * unique and correctly deduplicated already. This subroutine is meant to be as
 * a main interface to allocate, or get an existing vprovider.
 */
static hypertrace_vprovider_t *
hypertrace_get_vprovider(const char *provider)
{
	hypertrace_vprovider_t *vprov;
	uint32_t hash;
	uint32_t hash_ndx;

	hash = HASHINIT;
	do {
		hash = murmur3_32_hash(provider, DTRACE_PROVNAMELEN, HASHINIT);
		hash_ndx = hash & HASH_MASK;
		vprov = provtab[hash_ndx];
	} while (vprov &&
	    memcmp(provider, vprov->name, DTRACE_PROVNAMELEN) != 0);

	if (vprov != NULL)
		return (vprov);

	vprov = kmem_zalloc(sizeof(hypertrace_vprovider_t), KM_SLEEP);
	ASSERT(vprov != NULL);

	memcpy(vprov->name, provider, DTRACE_PROVNAMELEN);
	ASSERT(vprov->name != NULL);

	vprov->hash_ndx = hash_ndx;

	/*
	 * Insert the provider into our provider table.
	 */
	provtab[hash_ndx] = vprov;

	return (vprov);
}

static int
hypertrace_priv_create_probes(uint16_t vmid, void *_vprobes, size_t nvprobes)
{
	size_t i;
	dtrace_probedesc_t *vprobe;
	hypertrace_probe_t *htp;
	hypertrace_vprovider_t *vprov = NULL;
	dtrace_id_t id;
	dtrace_probedesc_t *vprobes = (dtrace_probedesc_t *)_vprobes;

	for (i = 0; i < nvprobes; i++) {
		vprobe = &vprobes[i];

		if (vprobe == NULL)
			continue;

		vprov = hypertrace_get_vprovider(vprobe->dtpd_provider);
		ASSERT(vprov != NULL);

		id = dtrace_vprobe_create(vmid, vprobe->dtpd_id,
		    vprobe->dtpd_provider, vprobe->dtpd_mod, vprobe->dtpd_func,
		    vprobe->dtpd_name);
		if (id == DTRACE_IDNONE)
			return (EINVAL);

		htp = kmem_zalloc(sizeof(hypertrace_probe_t), KM_SLEEP);
		ASSERT(htp != NULL);

		htp->htpb_provider = vprov;
		htp->htpb_id = id;
		htp->htpb_vmid = vmid;

		/*
		 * Probes are enabled by default.
		 *
		 * XXX: Implement a user-controlled thing based on
		 * /dev/dtrace/hypertrace.
		 */
		htp->htpb_enabled = 1;
		htp->htpb_running = 1;
		map_insert(hypertrace_map, htp);
		vprov->nprobes++;
	}

	return (0);
}

static int
hypertrace_priv_rmprobe(uint16_t vmid, hypertrace_id_t id)
{
	hypertrace_vprovider_t *vprov;
	hypertrace_probe_t *ht_probe;
	
	ht_probe = map_get(hypertrace_map, vmid, id);
	if (ht_probe == NULL)
		return (ESRCH);

	if (ht_probe->htpb_enabled)
		return (EAGAIN);

	map_rm(hypertrace_map, ht_probe);

	vprov = ht_probe->htpb_provider;
	if (vprov == NULL)
		panic("probe's provider is NULL.");

	if (--vprov->nprobes == 0) {
		provtab[vprov->hash_ndx] = NULL;
		kmem_free(vprov, sizeof(hypertrace_vprovider_t));
	}

	kmem_free(ht_probe, sizeof(hypertrace_probe_t));
	return (0);
}

SYSINIT(hypertrace_load, SI_SUB_DTRACE_PROVIDER,
    SI_ORDER_ANY, hypertrace_load, NULL);
SYSUNINIT(hypertrace_unload, SI_SUB_DTRACE_PROVIDER,
    SI_ORDER_ANY, hypertrace_unload, NULL);

DEV_MODULE(hypertrace, hypertrace_modevent, NULL);
MODULE_VERSION(hypertrace, 1);
MODULE_DEPEND(hypertrace, dtrace, 1, 1, 1);
MODULE_DEPEND(hypertrace, opensolaris, 1, 1, 1);
