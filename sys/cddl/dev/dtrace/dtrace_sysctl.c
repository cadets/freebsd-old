/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * $FreeBSD$
 *
 */

/* Report registered DTrace providers. */
static int
sysctl_dtrace_providers(SYSCTL_HANDLER_ARGS)
{
	char	*p_name	= NULL;
	dtrace_provider_t
		*prov	= dtrace_provider;
	int	error	= 0;
	size_t	len	= 0;

	mutex_enter(&dtrace_provider_lock);
	mutex_enter(&dtrace_lock);

	/* Compute the length of the space-separated provider name string. */
	while (prov != NULL) {
		len += strlen(prov->dtpv_name) + 1;
		prov = prov->dtpv_next;
	}

	if ((p_name = kmem_alloc(len, KM_SLEEP)) == NULL)
		error = ENOMEM;
	else {
		/* Start with an empty string. */
		*p_name = '\0';

		/* Point to the first provider again. */
		prov = dtrace_provider;

		/* Loop through the providers, appending the names. */
		while (prov != NULL) {
			if (prov != dtrace_provider)
				(void) strlcat(p_name, " ", len);

			(void) strlcat(p_name, prov->dtpv_name, len);

			prov = prov->dtpv_next;
		}
	}

	mutex_exit(&dtrace_lock);
	mutex_exit(&dtrace_provider_lock);

	if (p_name != NULL) {
		error = sysctl_handle_string(oidp, p_name, len, req);

		kmem_free(p_name, 0);
	}

	return (error);
}

static int
sysctl_dtrace_tscinfo(SYSCTL_HANDLER_ARGS)
{
	size_t i;
	uint64_t stack_fullsum, stack_fullcnt, immstack_fullsum,
	    immstack_fullcnt, cache_hits, cache_misses, records, drops,
	    xlate_times, xlates;
	dtrace_tscdata_t val = { 0 };
	int error;

	stack_fullsum = stack_fullcnt = immstack_fullsum = immstack_fullcnt =
	    cache_hits = cache_misses = records = drops =
	    xlate_times = xlates = 0;
	for (i = 0; i < NCPU; i++) {
		stack_fullsum += _dtrace_stack_sum[i];
		stack_fullcnt += _dtrace_stack_avgcnt[i];

		immstack_fullsum += _dtrace_immstack_sum[i];
		immstack_fullcnt += _dtrace_immstack_avgcnt[i];

		cache_hits += _dtrace_immstack_cache_hit[i];
		cache_misses += _dtrace_immstack_cache_miss[i];

		records += _dtrace_records[i];
		drops += _dtrace_drops[i];

		xlate_times += _dtrace_nested_xlate_time[i];
		xlates += _dtrace_nested_xlates[i];

		_dtrace_stack_sum[i] = 0;
		_dtrace_stack_avgcnt[i] = 0;

		_dtrace_immstack_sum[i] = 0;
		_dtrace_immstack_avgcnt[i] = 0;

		_dtrace_immstack_cache_hit[i] = 0;
		_dtrace_immstack_cache_miss[i] = 0;

		_dtrace_records[i] = 0;
		_dtrace_drops[i] = 0;

		_dtrace_nested_xlate_time[i] = 0;
		_dtrace_nested_xlates[i] = 0;
	}

	val.stack_sum = stack_fullsum;
	val.stack_cnt = stack_fullcnt;
	val.immstack_sum = immstack_fullsum;
	val.immstack_cnt = immstack_fullcnt;
	val.cache_hits = cache_hits;
	val.cache_misses = cache_misses;
	val.records = records;
	val.drops = drops;
	val.xlate_times = xlate_times;
	val.xlates = xlates;

	error = sysctl_handle_opaque(oidp, &val, sizeof(val), req);
	return (error);
}

SYSCTL_NODE(_debug, OID_AUTO, dtrace, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "DTrace debug parameters");

SYSCTL_PROC(_debug_dtrace, OID_AUTO, providers,
    CTLTYPE_STRING | CTLFLAG_MPSAFE | CTLFLAG_RD, 0, 0, sysctl_dtrace_providers,
    "A", "available DTrace providers");

SYSCTL_NODE(_kern, OID_AUTO, dtrace, CTLFLAG_RD | CTLFLAG_MPSAFE, 0,
    "DTrace parameters");

SYSCTL_INT(_kern_dtrace, OID_AUTO, err_verbose, CTLFLAG_RW,
    &dtrace_err_verbose, 0,
    "print DIF and DOF validation errors to the message buffer");

SYSCTL_INT(_kern_dtrace, OID_AUTO, immstack_caching_enabled, CTLFLAG_RW,
    &dtrace_immstack_caching_enabled, 1,
    "Enable/disable immstack() symbol caching.");

SYSCTL_INT(_kern_dtrace, OID_AUTO, memstr_max, CTLFLAG_RW, &dtrace_memstr_max,
    0, "largest allowed argument to memstr(), 0 indicates no limit");

SYSCTL_QUAD(_kern_dtrace, OID_AUTO, dof_maxsize, CTLFLAG_RW,
    &dtrace_dof_maxsize, 0, "largest allowed DOF table");

SYSCTL_QUAD(_kern_dtrace, OID_AUTO, helper_actions_max, CTLFLAG_RW,
    &dtrace_helper_actions_max, 0, "maximum number of allowed helper actions");

SYSCTL_INT(_security_bsd, OID_AUTO, allow_destructive_dtrace, CTLFLAG_RDTUN,
    &dtrace_allow_destructive, 1, "Allow destructive mode DTrace scripts");

SYSCTL_PROC(_kern_dtrace, OID_AUTO, tscinfo,
    CTLTYPE_STRING | CTLFLAG_MPSAFE | CTLFLAG_RD, 0, 0,
    sysctl_dtrace_tscinfo, "A", "current measurements");
