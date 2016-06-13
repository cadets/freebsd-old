/*-
 * Copyright (c) 2016 Robert N. M. Watson
 * All rights reserved.
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
#include <sys/conf.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/module.h>
#include <sys/queue.h>
#include <sys/refcount.h>

#include <sys/dtrace.h>
#include <sys/dtrace_bsd.h>

#include <bsm/audit.h>
#include <bsm/audit_internal.h>
#include <bsm/audit_kevents.h>


#include <security/audit/audit.h>
#include <security/audit/audit_private.h>

/*
 * Audit DTrace provider: allow DTrace to request that audit records be
 * generated for various audit events, and then exposed to probes.  The model
 * is that each event type has its own probe, using the event's name to create
 * the probe.  Userspace will push the contents of /etc/security/audit_event
 * into the kernel during audit setup, much as it does
 * /etc/security/audit_class.  We then create a probe for each of those
 * mappings.  If the probe is enabled, then we cause the record to be
 * generated (as both normal audit preselection and audit pipes do), and catch
 * it on the way out during commit by firing the probe with both the in-kernel
 * and BSM representations as arguments.  As such, we hook registration of new
 * names (and renames) so that we can update the probe list, and provide
 * suitable hooking functions in both preselection and commit phases.
 *
 * Further ponderings:
 *
 * - How do we want to handle events for which there are not names -- perhaps
 *   a catch-all probe for those events without mappings?
 *
 * - Do we want to have pre- and post-BSM probs, so that we don't need to
 *   generate BSM if DTrace doesn't want it?  It's not clear that the commit
 *   point is easily set up to do that.
 *
 * - Should the evname code be present even if DTrace isn't loaded...?  Right
 *   now, we arrange that it is so that userspace can usefully maintain the
 *   list in case DTrace is later loaded (and to prevent userspace confusion).
 *
 * - Should we be caching a pointer to the evname_elem structure that caused
 *   a record to be generated, so that we can later find it easily rather than
 *   looking it up again?  We believe evname_elem entries are stable after
 *   allocation, so this would in principle be safe.
 *
 * Note that the evname lock preceeds any DTrace-related locks, as we need to
 * hold the lock as we register/etc DTrace probes.  Is that OK?  (If not, that
 * is a bit awkward, because we need the lock to protect during preselection
 * and commit, and would prefer a non-sleepable lock...?)
 */

static int	dtaudit_unload(void);
static void	dtaudit_getargdesc(void *, dtrace_id_t, void *,
		    dtrace_argdesc_t *);
static void	dtaudit_provide(void *, dtrace_probedesc_t *);
static void	dtaudit_destroy(void *, dtrace_id_t, void *);
static void	dtaudit_enable(void *, dtrace_id_t, void *);
static void	dtaudit_disable(void *, dtrace_id_t, void *);
static void	dtaudit_load(void *);

/* XXXRW: Are these correct?  Lifted from the NFS DTrace provider. */
static dtrace_pattr_t dtaudit_attr = {
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
{ DTRACE_STABILITY_STABLE, DTRACE_STABILITY_STABLE, DTRACE_CLASS_COMMON },
};

/*
 * Strings for the "module" and "function name" portions of the probe.  All
 * dtaudit probes currently take the form audit:event:<event name>:commit.
 */
static char	*dtaudit_event_module = "event";
static char	*dtaudit_event_name = "commit";

static dtrace_pops_t dtaudit_pops = {
	/* dtps_provide */		dtaudit_provide,
	/* dtps_provide_module */	NULL,
	/* dtps_enable */		dtaudit_enable,
	/* dtps_disable */		dtaudit_disable,
	/* dtps_suspend */		NULL,
	/* dtps_resume */		NULL,
	/* dtps_getargdesc */		dtaudit_getargdesc,
	/* dtps_getargval */		NULL,
	/* dtps_usermode */		NULL,
	/* dtps_destroy */		dtaudit_destroy
};

static dtrace_provider_id_t	dtaudit_id;

/*
 * Because looking up entries in the event-to-name mapping is quite expensive,
 * maintain a global flag tracking whether any dtaudit probes are enabled.  If
 * not, don't bother doing all the work whenever potential queries about
 * events turn up during preselection or commit.
 */
static uint_t		dtaudit_probes_enabled;

/*
 * Check dtaudit policy for the event to see whether this is an event we would
 * like to preselect (i.e., cause an audit record to be generated for).  To
 * minimise probe effect when not used at all, we not only check for the probe
 * on the individual event, but also a global flag indicating that at least
 * one probe is enabled, before acquiring locks, searching lists, etc.
 *
 * XXXRW: Should we have a catch-all probe here for events without registered
 * names?
 *
 * XXXRW: Should we be caching the evname_elem pointer in the kaudit_record
 * to avoid a second lookup here?
 */
static int
dtaudit_preselect(au_id_t auid, au_event_t event, au_class_t class, int sorf)
{
	int probe_enabled;

	/*
	 * NB: Lockless read here may return a slightly stale value; this is
	 * considered better than acquiring a lock, however.
	 */
	if (!dtaudit_probes_enabled)
		return (0);
	if (au_event_probe(event, NULL, &probe_enabled) != 0)
		return (0);
	return (probe_enabled);
}

/*
 * An audit record flagged for DTrace consumption has been committed -- expose
 * it to suitable probes.  In principle, we might expose it to multiple probes
 * here if we add additional matching policies -- e.g., to fire on all commits
 * to the trail or a pipe, not just based on event-name probes.
 *
 * XXXRW: Should we have a catch-all probe here for events without registered
 * names?
 */
static void
dtaudit_commit(au_id_t auid, au_event_t event, au_class_t class, int sorf,
    struct kaudit_record *ar, void *bsm_data, size_t bsm_len)
{
	dtrace_id_t probe_id;
	int probe_enabled;

	/*
	 * NB: Lockless read here may return a slightly stale value; this is
	 * considered better than acquiring a lock, however.
	 */
	if (!dtaudit_probes_enabled)
		return;

	/*
	 * XXXRW: Should this be an assertion failure instead?
	 *
	 * XXXRW: Should we just cache the evname_elem pointer in the
	 * kaudit_record to save another lookup?
	 *
	 * XXXRW: We provide the struct audit_record pointer -- but perhaps
	 * should provide the kaudit_record pointer?
	 */
	if (au_event_probe(event, &probe_id, &probe_enabled) != 0)
		return;
	if (probe_enabled)
		dtrace_probe(probe_id, (uintptr_t)&ar->k_ar,
		    (uintptr_t)bsm_data, (uintptr_t)bsm_len, 0, 0);
}

/*
 * A very simple provider: argument types are identical across all probes: the
 * kaudit_record, plus a BSM pointer and length.
 */
static void
dtaudit_getargdesc(void *arg, dtrace_id_t id, void *parg,
    dtrace_argdesc_t *desc)
{
	const char *p = NULL;

	switch (desc->dtargd_ndx) {
	case 0:
		p = "struct audit_record *";
		break;

	case 1:
		p = "const void *";
		break;

	case 2:
		p = "size_t";
		break;

	default:
		desc->dtargd_ndx = DTRACE_ARGNONE;
		break;
	}
	if (p != NULL)
		strlcpy(desc->dtargd_native, p, sizeof(desc->dtargd_native));
}

/*
 * Callback from the event-to-name mapping code when performing
 * evname_foreach().  Note that we may update the entry, so the foreach code
 * must have a write lock.  However, as the synchronisation model is private
 * to the evname code, we cannot easily assert it here.
 *
 * XXXRW: How do we want to handle event rename / collision issues here --
 * e.g., if userspace was using a name to point to one event number, and then
 * changes it so that the name points at another?  For now, paper over this by
 * skipping event numbers that are already registered, and likewise skipping
 * names that are already registered.  However, this could lead to confusing
 * behaviour so possibly needs to be resolved in the longer term.
 */
static void
dtaudit_au_evnamemap_callback(struct evname_elem *ene)
{

	/* Does this event number already have a probe? */
	if (ene->ene_probe_id != 0)
		return;

	/*
	 * Does this event name already have a probe?  This is the papering
	 * over bit.  As nothing in the kernel interface (or config file)
	 * ensures that there are not duplicate names, we just ignore for now.
	 */
	if (dtrace_probe_lookup(dtaudit_id, dtaudit_event_module,
	    ene->ene_name, dtaudit_event_name) != 0)
		return;

	/*
	 * Create the missing probe.
	 *
	 * NB: We don't declare any extra stack frames because stack() will
	 * just return the path to the audit commit code, which is not really
	 * interesting anyway.
	 *
	 * We pass in the pointer to the evnam_elem entry so that we can
	 * easily change its enabled flag in the probe enable/disable
	 * interface.
	 */
	ene->ene_probe_id = dtrace_probe_create(dtaudit_id,
	    dtaudit_event_module, ene->ene_name, dtaudit_event_name, 0, ene);
}

static void
dtaudit_provide(void *arg, dtrace_probedesc_t *desc)
{

	/*
	 * Walk all registered number-to-name mapping entries, and ensure each
	 * is properly registered.
	 */
	au_evnamemap_foreach(dtaudit_au_evnamemap_callback);
}

static void
dtaudit_destroy(void *arg, dtrace_id_t id, void *parg)
{
}

static void
dtaudit_enable(void *arg, dtrace_id_t id, void *parg)
{
	struct evname_elem *ene;

	ene = parg;
	KASSERT(ene->ene_probe_id == id, ("%s: pobe ID mismatch (%u, %u)",
	    __func__, ene->ene_probe_id, id));

	ene->ene_probe_enabled = 1;
	refcount_acquire(&dtaudit_probes_enabled);
}

static void
dtaudit_disable(void *arg, dtrace_id_t id, void *parg)
{
	struct evname_elem *ene;

	ene = parg;
	KASSERT(ene->ene_probe_id == id, ("%s: probe ID mismatch (%u, %u)",
	    __func__, ene->ene_probe_id, id));

	ene->ene_probe_enabled = 0;
	(void)refcount_release(&dtaudit_probes_enabled);
}

static void
dtaudit_load(void *dummy)
{

	if (dtrace_register("audit", &dtaudit_attr, DTRACE_PRIV_USER, NULL,
	    &dtaudit_pops, NULL, &dtaudit_id) != 0)
		return;
	dtaudit_hook_preselect = dtaudit_preselect;
	dtaudit_hook_commit = dtaudit_commit;

#if 0
	/* XXXRW: Is this needed? */
	/* Trigger an initial walk of the audit event list. */
	au_evnamemap_foreach(dtaudit_au_evnamemap_callback);
#endif
}

static int
dtaudit_unload(void)
{

	dtaudit_hook_preselect = NULL;
	dtaudit_hook_commit = NULL;
	return (0);
}

static int
dtaudit_modevent(module_t mod __unused, int type, void *data __unused)
{
	int error = 0;

	switch (type) {
	case MOD_LOAD:
	case MOD_UNLOAD:
	case MOD_SHUTDOWN:
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return (error);
}

SYSINIT(dtaudit_load, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY, dtaudit_load,
    NULL);
SYSUNINIT(dtaudit_unload, SI_SUB_DTRACE_PROVIDER, SI_ORDER_ANY,
    dtaudit_unload, NULL);

DEV_MODULE(dtaudit, dtaudit_modevent, NULL);
MODULE_VERSION(dtaudit, 1);
MODULE_DEPEND(dtnfscl, dtrace, 1, 1, 1);
MODULE_DEPEND(dtnfscl, opensolaris, 1, 1, 1);
