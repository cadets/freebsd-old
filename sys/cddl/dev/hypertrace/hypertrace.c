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

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/dtrace.h>
#include <sys/dtrace_bsd.h>
#include <sys/hash.h>
#include <sys/kernel.h>
#include <sys/module.h>

#include <dtvirt.h>

#include "hypertrace.h"

static MALLOC_DEFINE(M_HYPERTRACE, "HyperTrace", "");

static d_open_t hypertrace_open;
static int      hypertrace_unload(void);
static void     hypertrace_destroy(void *, dtrace_id_t, void *);
static void     hypertrace_enable(void *, dtrace_id_t, void *);
static void     hypertrace_disable(void *, dtrace_id_t, void *);
static void     hypertrace_load(void *);
static void     hypertrace_suspend(void *, dtrace_id_t, void *);
static void     hypertrace_resume(void *, dtrace_id_t, void *);

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
static hypertrace_map_t       hypertrace_map;
static hypertrace_vprovider_t *provtab;

static void
hypertrace_load(void *dummy __unused)
{
	/*
	 * Create the device node.
	 */
	hypertrace_cdev = make_dev(&hypertrace_cdevsw, 0, UID_ROOT, GID_WHEEL,
	    0600, "dtrace/hypertrace");
}

static int
hypertrace_unload()
{
	int error = 0;

	/*
	 * Unregister the provider.
	 */
	if ((error = dtrace_unregister(hypertrace_id)) != 0)
		return (error);

	destroy_dev(hypertrace_cdev);
	return (error);
}


static int
hypertrace_modevent(module_t mod __unused, int type, void *data __unused)
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

/*
 * Placeholder for future things.
 */
static int
hypertrace_open(struct cdev *dev __unused, int oflags __unused,
    int devtype __unused, struct thread *td __unused)
{
	
	return (0);
}

static void
hypertrace_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static void
hypertrace_enable(void *arg, dtrace_id_t id, void *parg)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	if (dtvirt_getns == NULL)
		return;

	vmid = dtvirt_getns(parg);

	ht_probe = map_get(&hypertrace_map, vmid, id);
	ht_probe->htpb_enabled = 1;
	ht_probe->htpb_running = 1;
}

static void
hypertrace_disable(void *arg, dtrace_id_t id, void *parg)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	if (dtvirt_getns == NULL)
		return;

	vmid = dtvirt_getns(parg);
	
	ht_probe = map_get(&hypertrace_map, vmid, id);
	ht_probe->htpb_running = 0;
	ht_probe->htpb_enabled = 0;
}

static void
hypertrace_suspend(void *arg, dtrace_id_t id, void *parg)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	if (dtvirt_getns == NULL)
		return;

	vmid = dtvirt_getns(parg);

	ht_probe = map_get(&hypertrace_map, vmid, id);
	ht_probe->htpb_running = 0;
}

static void
hypertrace_resume(void *arg, dtrace_id_t id, void *parg)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	if (dtvirt_getns == NULL)
		return;

	vmid = dtvirt_getns(parg);

	ht_probe = map_get(&hypertrace_map, vmid, id);
	ht_probe->htpb_running = 1;
}

static void
hypertrace_probe(void *vmhdl, dtrace_id_t id, struct dtvirt_args *dtv_args)
{
	hypertrace_probe_t *ht_probe;
	uint16_t vmid;

	if (dtvirt_getns == NULL)
		return;
	
	vmid = dtvirt_getns(vmhdl);

	ht_probe = map_get(&hypertrace_map, vmid, id);
	if (ht_probe->htpb_enabled != 0 && ht_probe->htpb_running == 1)
		dtrace_vprobe(vmhdl, id, dtv_args);
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
		vprov = &provtab[hash_ndx];
	} while (vprov &&
	    memcmp(provider, vprov->name, DTRACE_PROVNAMELEN) != 0);

	if (vprov != NULL)
		return (vprov);

	vprov = kmem_zalloc(sizeof(hypertrace_vprovider_t), KM_SLEEP);
	ASSERT(vprov != NULL);

	vprov->name = strdup(provider, M_HYPERTRACE);
	ASSERT(vprov->name != NULL);
	
	return (vprov);
}

int
hypertrace_create_probes(void *_vprobes, size_t nvprobes)
{
	size_t i;
	dtrace_probedesc_t *vprobe;
	hypertrace_probe_t *htp;
	hypertrace_vprovider_t *vprov;
	dtrace_id_t id;
	uint16_t vmid;
	dtrace_probedesc_t *vprobes = (dtrace_probedesc_t *)_vprobes;

	for (i = 0; i < nvprobes; i++) {
		vprobe = &vprobes[i];

		/*
		 * We require that all of the vmids match. We don't really do
		 * any cleanup here yet, but we need to.
		 */
		if (i > 0 && vmid != vprobes->dtpd_vmid)
			return (EINVAL);

		vmid = vprobes->dtpd_vmid;

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
	}

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
