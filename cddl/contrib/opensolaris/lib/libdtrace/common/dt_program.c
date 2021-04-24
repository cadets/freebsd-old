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
 */

/*
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2011 by Delphix. All rights reserved.
 */

#include <unistd.h>
#include <strings.h>
#include <stdbool.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <ctype.h>
#ifdef illumos
#include <alloca.h>
#endif

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_printf.h>
#include <dt_provider.h>

void dt_prog_generate_ident(dtrace_prog_t *);

dtrace_prog_t *
dt_program_create(dtrace_hdl_t *dtp)
{
	char buf[DT_PROG_IDENTLEN] = { 0 };
	dtrace_prog_t *pgp = dt_zalloc(dtp, sizeof (dtrace_prog_t));

	/*
	 * Generate our random identifier
	 */
	dt_prog_generate_ident(pgp);

	if (pgp != NULL) {
		dt_list_append(&dtp->dt_programs, pgp);
	} else {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	/*
	 * By default, programs start with DOF version 1 so that output files
	 * containing DOF are backward compatible. If a program requires new
	 * DOF features, the version is increased as needed.
	 */
	pgp->dp_dofversion = DOF_VERSION_1;

	/*
	 * Default to host
	 */
	pgp->dp_vmid = 0;

	return (pgp);
}

void
dt_program_destroy(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp, *next;
	uint_t i;

	if (pgp == NULL)
		return;

	if (pgp->dp_eprobes)
		dt_free(dtp, pgp->dp_eprobes);

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		dtrace_stmt_destroy(dtp, stp->ds_desc);
		dt_free(dtp, stp);
	}

	for (i = 0; i < pgp->dp_xrefslen; i++) {
		if (pgp->dp_xrefs && pgp->dp_xrefs[i])
			dt_free(dtp, pgp->dp_xrefs[i]);
	}

	if (pgp->dp_xrefs)
		dt_free(dtp, pgp->dp_xrefs);
	dt_list_delete(&dtp->dt_programs, pgp);
	dt_free(dtp, pgp);
}

/*ARGSUSED*/
void
dtrace_program_info(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	dt_stmt_t *stp;
	dtrace_actdesc_t *ap;
	dtrace_ecbdesc_t *last = NULL;

	if (pip == NULL)
		return;

	bzero(pip, sizeof (dtrace_proginfo_t));

	if (dt_list_next(&pgp->dp_stmts) != NULL) {
		pip->dpi_descattr = _dtrace_maxattr;
		pip->dpi_stmtattr = _dtrace_maxattr;
	} else {
		pip->dpi_descattr = _dtrace_defattr;
		pip->dpi_stmtattr = _dtrace_defattr;
	}

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		dtrace_ecbdesc_t *edp = stp->ds_desc->dtsd_ecbdesc;

		if (edp == last)
			continue;
		last = edp;

		pip->dpi_descattr =
		    dt_attr_min(stp->ds_desc->dtsd_descattr, pip->dpi_descattr);

		pip->dpi_stmtattr =
		    dt_attr_min(stp->ds_desc->dtsd_stmtattr, pip->dpi_stmtattr);

		/*
		 * If there aren't any actions, account for the fact that
		 * recording the epid will generate a record.
		 */
		if (edp->dted_action == NULL)
			pip->dpi_recgens++;

		for (ap = edp->dted_action; ap != NULL; ap = ap->dtad_next) {
			if (ap->dtad_kind == DTRACEACT_SPECULATE) {
				pip->dpi_speculations++;
				continue;
			}

			if (DTRACEACT_ISAGG(ap->dtad_kind)) {
				pip->dpi_recgens -= ap->dtad_arg;
				pip->dpi_aggregates++;
				continue;
			}

			if (DTRACEACT_ISDESTRUCTIVE(ap->dtad_kind))
				continue;

			if (ap->dtad_kind == DTRACEACT_DIFEXPR &&
			    ap->dtad_difo->dtdo_rtype.dtdt_kind ==
			    DIF_TYPE_CTF &&
			    ap->dtad_difo->dtdo_rtype.dtdt_size == 0)
				continue;

			pip->dpi_recgens++;
		}
	}
}

int
dtrace_program_exec(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_proginfo_t *pip)
{
	dtrace_enable_io_t args;
	void *dof;
	int n, err;
	int i;
	int expected_nprobes = 0;

	dtrace_program_info(dtp, pgp, pip);

	if ((dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP)) == NULL)
		return (-1);

	expected_nprobes = DTRACE_MIN_NPROBES;

	args.dof = dof;
	args.n_matched = 0;
	args.n_desc = 0;
	args.vmid = pgp->dp_vmid;
	args.ps = malloc(sizeof(dtrace_probedesc_t) * expected_nprobes);
	if (args.ps == NULL) {
		fprintf(stderr, "could not allocate args.ps\n");
		return (-1);
	}

	memset(args.ps, 0, sizeof(dtrace_probedesc_t) * expected_nprobes);
	args.ps_bufsize = expected_nprobes * sizeof(dtrace_probedesc_t);
	n = dt_ioctl(dtp, DTRACEIOC_ENABLE, &args);
	dtrace_dof_destroy(dtp, dof);

	if (n == -1) {
		switch (errno) {
		case EINVAL:
			err = EDT_DIFINVAL;
			break;
		case EFAULT:
			err = EDT_DIFFAULT;
			break;
		case E2BIG:
			err = EDT_DIFSIZE;
			break;
		case EBUSY:
			err = EDT_ENABLING_ERR;
			break;
		default:
			err = errno;
		}

		return (dt_set_errno(dtp, err));
	}

	if (pip != NULL)
		pip->dpi_matches += args.n_matched;

	pgp->dp_neprobes = args.n_desc;
	if (pgp->dp_neprobes > 0) {
		pgp->dp_eprobes = malloc(pgp->dp_neprobes *
		    sizeof(dtrace_probedesc_t));

		assert(pgp->dp_eprobes != NULL);
		memcpy(pgp->dp_eprobes, args.ps,
		    pgp->dp_neprobes * sizeof(dtrace_probedesc_t));
	}

	free(args.ps);
	return (0);
}

int
dt_vprobes_create(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	int n;
	dtrace_vprobe_io_t args = { 0 };

	args.eprobes = pgp->dp_eprobes;
	args.neprobes = pgp->dp_neprobes;
	args.vmid = pgp->dp_vmid;

	n = dt_ioctl(dtp, DTRACEIOC_VPROBE_CREATE, &args);
	if (n == -1) {
		fprintf(stderr, "DTRACEIOC_VPROBE_CREATE: %s\n", strerror(errno));
		return (n);
	}

	dt_list_append(&dtp->dt_programs, pgp);
	return (0);
}

int
dt_augment_tracing(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace_enable_io_t args = { 0 };
	void *dof;
	int n, err;
	int i;
	int expected_nprobes = DTRACE_MIN_NPROBES;

	if ((dof = dtrace_dof_create(dtp, pgp, DTRACE_D_STRIP)) == NULL)
		return (-1);

	args.dof = dof;
	args.n_matched = 0;
	args.n_desc = 0;
	args.vmid = pgp->dp_vmid;
	args.ps = malloc(sizeof(dtrace_probedesc_t) * expected_nprobes);
	if (args.ps == NULL) {
		fprintf(stderr, "could not allocate args.ps\n");
		return (-1);
	}

	memset(args.ps, 0, sizeof(dtrace_probedesc_t) * expected_nprobes);
	args.ps_bufsize = sizeof(dtrace_probedesc_t) * expected_nprobes;
	n = dt_ioctl(dtp, DTRACEIOC_AUGMENT, &args);
	dtrace_dof_destroy(dtp, dof);

	if (n == -1) {
		switch (errno) {
		case EINVAL:
			err = EDT_DIFINVAL;
			break;
		case EFAULT:
			err = EDT_DIFFAULT;
			break;
		case E2BIG:
			err = EDT_DIFSIZE;
			break;
		case EBUSY:
			err = EDT_ENABLING_ERR;
			break;
		default:
			err = errno;
		}

		free(args.ps);
		return (dt_set_errno(dtp, err));
	}

	free(args.ps);
	return (0);
}

static void
dt_ecbdesc_hold(dtrace_ecbdesc_t *edp)
{
	edp->dted_refcnt++;
}

void
dt_ecbdesc_release(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	if (--edp->dted_refcnt > 0)
		return;

	dt_difo_free(dtp, edp->dted_pred.dtpdd_difo);
	assert(edp->dted_action == NULL);
	dt_free(dtp, edp);
}

dtrace_ecbdesc_t *
dt_ecbdesc_create(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp)
{
	dtrace_ecbdesc_t *edp;

	if ((edp = dt_zalloc(dtp, sizeof (dtrace_ecbdesc_t))) == NULL) {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	edp->dted_probe = *pdp;
	dt_ecbdesc_hold(edp);
	return (edp);
}

dtrace_stmtdesc_t *
dtrace_stmt_create(dtrace_hdl_t *dtp, dtrace_ecbdesc_t *edp)
{
	dtrace_stmtdesc_t *sdp;

	if ((sdp = dt_zalloc(dtp, sizeof (dtrace_stmtdesc_t))) == NULL)
		return (NULL);

	dt_ecbdesc_hold(edp);
	sdp->dtsd_ecbdesc = edp;
	sdp->dtsd_descattr = _dtrace_defattr;
	sdp->dtsd_stmtattr = _dtrace_defattr;

	return (sdp);
}

dtrace_actdesc_t *
dtrace_stmt_action(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_actdesc_t *new;
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	if ((new = dt_alloc(dtp, sizeof (dtrace_actdesc_t))) == NULL)
		return (NULL);

	if (sdp->dtsd_action_last != NULL) {
		assert(sdp->dtsd_action != NULL);
		assert(sdp->dtsd_action_last->dtad_next == NULL);
		sdp->dtsd_action_last->dtad_next = new;
	} else {
		dtrace_actdesc_t *ap = edp->dted_action;

		assert(sdp->dtsd_action == NULL);
		sdp->dtsd_action = new;

		while (ap != NULL && ap->dtad_next != NULL)
			ap = ap->dtad_next;

		if (ap == NULL)
			edp->dted_action = new;
		else
			ap->dtad_next = new;
	}

	sdp->dtsd_action_last = new;
	bzero(new, sizeof (dtrace_actdesc_t));
	new->dtad_uarg = (uintptr_t)sdp;

	return (new);
}

int
dtrace_stmt_add(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_stmtdesc_t *sdp)
{
	dt_stmt_t *stp = dt_alloc(dtp, sizeof (dt_stmt_t));

	if (stp == NULL)
		return (-1); /* errno is set for us */

	dt_list_append(&pgp->dp_stmts, stp);
	stp->ds_desc = sdp;

	return (0);
}

int
dtrace_stmt_iter(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmt_f *func, void *data)
{
	dt_stmt_t *stp, *next;
	int status = 0;

	for (stp = dt_list_next(&pgp->dp_stmts); stp != NULL; stp = next) {
		next = dt_list_next(stp);
		if ((status = func(dtp, pgp, stp->ds_desc, data)) != 0)
			break;
	}

	return (status);
}

void
dtrace_stmt_destroy(dtrace_hdl_t *dtp, dtrace_stmtdesc_t *sdp)
{
	dtrace_ecbdesc_t *edp = sdp->dtsd_ecbdesc;

	/*
	 * We need to remove any actions that we have on this ECB, and
	 * remove our hold on the ECB itself.
	 */
	if (sdp->dtsd_action != NULL) {
		dtrace_actdesc_t *last = sdp->dtsd_action_last;
		dtrace_actdesc_t *ap, *next;

		assert(last != NULL);

		for (ap = edp->dted_action; ap != NULL; ap = ap->dtad_next) {
			if (ap == sdp->dtsd_action)
				break;

			if (ap->dtad_next == sdp->dtsd_action)
				break;
		}

		assert(ap != NULL);

		if (ap == edp->dted_action)
			edp->dted_action = last->dtad_next;
		else
			ap->dtad_next = last->dtad_next;

		/*
		 * We have now removed our action list from its ECB; we can
		 * safely destroy the list.
		 */
		last->dtad_next = NULL;

		for (ap = sdp->dtsd_action; ap != NULL; ap = next) {
			assert(ap->dtad_uarg == (uintptr_t)sdp);
			dt_difo_free(dtp, ap->dtad_difo);
			next = ap->dtad_next;
			dt_free(dtp, ap);
		}
	}

	if (sdp->dtsd_fmtdata != NULL)
		dt_printf_destroy(sdp->dtsd_fmtdata);
	dt_free(dtp, sdp->dtsd_strdata);

	dt_ecbdesc_release(dtp, sdp->dtsd_ecbdesc);
	dt_free(dtp, sdp);
}

typedef struct dt_header_info {
	dtrace_hdl_t *dthi_dtp;	/* consumer handle */
	FILE *dthi_out;		/* output file */
	char *dthi_pmname;	/* provider macro name */
	char *dthi_pfname;	/* provider function name */
	int dthi_empty;		/* should we generate empty macros */
} dt_header_info_t;

static void
dt_header_fmt_macro(char *buf, const char *str)
{
	for (;;) {
		if (islower(*str)) {
			*buf++ = *str++ + 'A' - 'a';
		} else if (*str == '-') {
			*buf++ = '_';
			str++;
		} else if (*str == '.') {
			*buf++ = '_';
			str++;
		} else if ((*buf++ = *str++) == '\0') {
			break;
		}
	}
}

static void
dt_header_fmt_func(char *buf, const char *str)
{
	for (;;) {
		if (*str == '-') {
			*buf++ = '_';
			*buf++ = '_';
			str++;
		} else if ((*buf++ = *str++) == '\0') {
			break;
		}
	}
}

/*ARGSUSED*/
static int
dt_header_decl(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_header_info_t *infop = data;
	dtrace_hdl_t *dtp = infop->dthi_dtp;
	dt_probe_t *prp = idp->di_data;
	dt_node_t *dnp;
	char buf[DT_TYPE_NAMELEN];
	char *fname;
	const char *p;
	int i;

	p = prp->pr_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	fname = alloca(strlen(prp->pr_name) + 1 + i);
	dt_header_fmt_func(fname, prp->pr_name);

	if (fprintf(infop->dthi_out, "extern void __dtrace_%s___%s(",
	    infop->dthi_pfname, fname) < 0)
		return (dt_set_errno(dtp, errno));

	for (dnp = prp->pr_nargs, i = 0; dnp != NULL; dnp = dnp->dn_list, i++) {
		if (fprintf(infop->dthi_out, "%s",
		    ctf_type_name(dnp->dn_ctfp, dnp->dn_type,
		    buf, sizeof (buf))) < 0)
			return (dt_set_errno(dtp, errno));

		if (i + 1 != prp->pr_nargc &&
		    fprintf(infop->dthi_out, ", ") < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (i == 0 && fprintf(infop->dthi_out, "void") < 0)
		return (dt_set_errno(dtp, errno));

	if (fprintf(infop->dthi_out, ");\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (fprintf(infop->dthi_out,
	    "#ifndef\t__sparc\n"
	    "extern int __dtraceenabled_%s___%s(void);\n"
	    "#else\n"
	    "extern int __dtraceenabled_%s___%s(long);\n"
	    "#endif\n",
	    infop->dthi_pfname, fname, infop->dthi_pfname, fname) < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

/*ARGSUSED*/
static int
dt_header_probe(dt_idhash_t *dhp, dt_ident_t *idp, void *data)
{
	dt_header_info_t *infop = data;
	dtrace_hdl_t *dtp = infop->dthi_dtp;
	dt_probe_t *prp = idp->di_data;
	char *mname, *fname;
	const char *p;
	int i;

	p = prp->pr_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	mname = alloca(strlen(prp->pr_name) + 1);
	dt_header_fmt_macro(mname, prp->pr_name);

	fname = alloca(strlen(prp->pr_name) + 1 + i);
	dt_header_fmt_func(fname, prp->pr_name);

	if (fprintf(infop->dthi_out, "#define\t%s_%s(",
	    infop->dthi_pmname, mname) < 0)
		return (dt_set_errno(dtp, errno));

	for (i = 0; i < prp->pr_nargc; i++) {
		if (fprintf(infop->dthi_out, "arg%d", i) < 0)
			return (dt_set_errno(dtp, errno));

		if (i + 1 != prp->pr_nargc &&
		    fprintf(infop->dthi_out, ", ") < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (!infop->dthi_empty) {
		if (fprintf(infop->dthi_out, ") \\\n\t") < 0)
			return (dt_set_errno(dtp, errno));

		if (fprintf(infop->dthi_out, "__dtrace_%s___%s(",
		    infop->dthi_pfname, fname) < 0)
			return (dt_set_errno(dtp, errno));

		for (i = 0; i < prp->pr_nargc; i++) {
			if (fprintf(infop->dthi_out, "arg%d", i) < 0)
				return (dt_set_errno(dtp, errno));

			if (i + 1 != prp->pr_nargc &&
			    fprintf(infop->dthi_out, ", ") < 0)
				return (dt_set_errno(dtp, errno));
		}
	}

	if (fprintf(infop->dthi_out, ")\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (!infop->dthi_empty) {
		if (fprintf(infop->dthi_out,
		    "#ifndef\t__sparc\n"
		    "#define\t%s_%s_ENABLED() \\\n"
		    "\t__dtraceenabled_%s___%s()\n"
		    "#else\n"
		    "#define\t%s_%s_ENABLED() \\\n"
		    "\t__dtraceenabled_%s___%s(0)\n"
		    "#endif\n",
		    infop->dthi_pmname, mname,
		    infop->dthi_pfname, fname,
		    infop->dthi_pmname, mname,
		    infop->dthi_pfname, fname) < 0)
			return (dt_set_errno(dtp, errno));

	} else {
		if (fprintf(infop->dthi_out, "#define\t%s_%s_ENABLED() (0)\n",
		    infop->dthi_pmname, mname) < 0)
			return (dt_set_errno(dtp, errno));
	}

	return (0);
}

static int
dt_header_provider(dtrace_hdl_t *dtp, dt_provider_t *pvp, FILE *out)
{
	dt_header_info_t info;
	const char *p;
	int i;

	if (pvp->pv_flags & DT_PROVIDER_IMPL)
		return (0);

	/*
	 * Count the instances of the '-' character since we'll need to double
	 * those up.
	 */
	p = pvp->pv_desc.dtvd_name;
	for (i = 0; (p = strchr(p, '-')) != NULL; i++)
		p++;

	info.dthi_dtp = dtp;
	info.dthi_out = out;
	info.dthi_empty = 0;

	info.dthi_pmname = alloca(strlen(pvp->pv_desc.dtvd_name) + 1);
	dt_header_fmt_macro(info.dthi_pmname, pvp->pv_desc.dtvd_name);

	info.dthi_pfname = alloca(strlen(pvp->pv_desc.dtvd_name) + 1 + i);
	dt_header_fmt_func(info.dthi_pfname, pvp->pv_desc.dtvd_name);

#ifdef __FreeBSD__
	if (fprintf(out, "#include <sys/sdt.h>\n\n") < 0)
		return (dt_set_errno(dtp, errno));
#endif
	if (fprintf(out, "#if _DTRACE_VERSION\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (dt_idhash_iter(pvp->pv_probes, dt_header_probe, &info) != 0)
		return (-1); /* dt_errno is set for us */
	if (fprintf(out, "\n\n") < 0)
		return (dt_set_errno(dtp, errno));
	if (dt_idhash_iter(pvp->pv_probes, dt_header_decl, &info) != 0)
		return (-1); /* dt_errno is set for us */

	if (fprintf(out, "\n#else\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	info.dthi_empty = 1;

	if (dt_idhash_iter(pvp->pv_probes, dt_header_probe, &info) != 0)
		return (-1); /* dt_errno is set for us */

	if (fprintf(out, "\n#endif\n\n") < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

int
dtrace_program_header(dtrace_hdl_t *dtp, FILE *out, const char *fname)
{
	dt_provider_t *pvp;
	char *mfname, *p;

	if (fname != NULL) {
		if ((p = strrchr(fname, '/')) != NULL)
			fname = p + 1;

		mfname = alloca(strlen(fname) + 1);
		dt_header_fmt_macro(mfname, fname);
		if (fprintf(out, "#ifndef\t_%s\n#define\t_%s\n\n",
		    mfname, mfname) < 0)
			return (dt_set_errno(dtp, errno));
	}

	if (fprintf(out, "#include <unistd.h>\n\n") < 0)
		return (-1);

	if (fprintf(out, "#ifdef\t__cplusplus\nextern \"C\" {\n#endif\n\n") < 0)
		return (-1);

	for (pvp = dt_list_next(&dtp->dt_provlist);
	    pvp != NULL; pvp = dt_list_next(pvp)) {
		if (dt_header_provider(dtp, pvp, out) != 0)
			return (-1); /* dt_errno is set for us */
	}

	if (fprintf(out, "\n#ifdef\t__cplusplus\n}\n#endif\n") < 0)
		return (dt_set_errno(dtp, errno));

	if (fname != NULL && fprintf(out, "\n#endif\t/* _%s */\n", mfname) < 0)
		return (dt_set_errno(dtp, errno));

	return (0);
}

int
dt_prog_verify_difo(dtrace_hdl_t *dtp,
    dtrace_difo_t *dbase, dtrace_difo_t *dnew)
{
	size_t i, j;
	dif_instr_t ibase, inew;
	uint8_t opbase, opnew;

	i = 0;
	j = 0;
	ibase = 0;
	inew = 0;
	opbase = 0;
	opnew = 0;

	/*
	 * Go through all of the base instructions and compare it to the new
	 * instructions. If we encounter a relocation, we check that it has
	 * been applied correctly and adjust the counter accordingly.
	 */
	for (i = 0; i < dbase->dtdo_len; i++) {
		ibase = dbase->dtdo_buf[i];
		inew = dnew->dtdo_buf[j];

		opbase = DIF_INSTR_OP(ibase);
		switch (opbase) {
		case DIF_OP_USETX:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_SETX)
				return (1);

			break;

		case DIF_OP_ULOAD:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_LDSB && opnew != DIF_OP_LDSH &&
			    opnew != DIF_OP_LDSW && opnew != DIF_OP_LDX  &&
			    opnew != DIF_OP_LDUB && opnew != DIF_OP_LDUH &&
			    opnew != DIF_OP_LDUW)
				return (1);
			break;

		case DIF_OP_UULOAD:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_ULDSB && opnew != DIF_OP_ULDSH &&
			    opnew != DIF_OP_ULDSW && opnew != DIF_OP_ULDX  &&
			    opnew != DIF_OP_ULDUB && opnew != DIF_OP_ULDUH &&
			    opnew != DIF_OP_ULDUW)
				return (1);
			break;

		case DIF_OP_TYPECAST:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_NOP)
				return (1);
			break;

		default:
			if (ibase != inew)
				return (1);
			break;
		}
	}

	return (0);
}

int
dt_prog_verify(dtrace_hdl_t *dtp, dtrace_prog_t *pbase,
    dtrace_prog_t *pnew)
{
	dt_stmt_t *sbase, *snew;
	dtrace_stmtdesc_t *sdbase, *sdnew;
	dtrace_actdesc_t *adbase, *adnew;
	dtrace_ecbdesc_t *enew;
	dtrace_probedesc_t *pdnew;
	static const char testbuf[DT_PROG_IDENTLEN];

	sbase = NULL;
	snew = NULL;
	sdbase = NULL;
	sdnew = NULL;
	adbase = NULL;
	adnew = NULL;
	enew = NULL;
	pdnew = NULL;

	if (pnew == NULL || pbase == NULL) {
		fprintf(stderr, "pbase = %p, pnew = %p (NULL err)\n",
		    pbase, pnew);
		return (1);
	}

	/*
	 * In case this is just a list of probes to enable, we don't need to
	 * actually verify the program (because we won't run it).
	 */
	if (memcmp(testbuf, pbase->dp_srcident, DT_PROG_IDENTLEN))
		return (0);
	
	/*
	 * Iterate through all the statements of both programs and verify
	 * that they match up, or if they are relocations that they are
	 * applied correctly.
	 */
	for (sbase = dt_list_next(&pbase->dp_stmts),
	    snew = dt_list_next(&pnew->dp_stmts);
	    sbase && snew;
	    sbase = dt_list_next(sbase),
	    snew = dt_list_next(snew)) {
		sdbase = sbase->ds_desc;
		sdnew = snew->ds_desc;

		if (sdbase == NULL || sdnew == NULL) {
			fprintf(stderr, "sdbase = %p, sdnew = %p (NULL err)\n",
			    sdbase, sdnew);
			return (1);
		}

		for (adbase = sdbase->dtsd_action,
		    adnew = sdnew->dtsd_action;
		    adbase != sdbase->dtsd_action_last &&
		    adnew != sdnew->dtsd_action_last;
		    adbase = adbase->dtad_next,
		    adnew = adnew->dtad_next) {
			if (adnew == NULL || adbase == NULL) {
				fprintf(stderr, "adbase = %p, adnew = %p "
				    "(NULL) err)\n", adbase, adnew);
				return (1);
			}

			if (dt_prog_verify_difo(dtp,
			    adbase->dtad_difo, adnew->dtad_difo))
				return (1);
		}

		enew = sdnew->dtsd_ecbdesc;
		pdnew = &enew->dted_probe;

		pdnew->dtpd_vmid = pnew->dp_vmid;
	}

	return (0);
}

void
dt_prog_generate_ident(dtrace_prog_t *pgp)
{

	arc4random_buf(pgp->dp_ident, DT_PROG_IDENTLEN);
}

static dtrace_prog_t *
dt_vprog_hcalls(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace_prog_t *newpgp;
	dt_stmt_t *newstmt, *stmt;
	dtrace_stmtdesc_t *newstmtdesc, *curstmtdesc;
	dtrace_ecbdesc_t *newecb, *curecb;
	dtrace_actdesc_t *newact;
	dtrace_difo_t *difo;

	newpgp = dt_program_create(dtp);
	if (newpgp == NULL)
		return (NULL);

	memset(newpgp, 0, sizeof(dtrace_prog_t));

	for (stmt = dt_list_next(&pgp->dp_stmts);
	     stmt; stmt = dt_list_next(stmt)) {
		curstmtdesc = stmt->ds_desc;

		newecb = dt_ecbdesc_create(dtp, &curecb->dted_probe);
		if (newecb == NULL)
			errx(EXIT_FAILURE,
			    "failed to allocate a new dtrace_ecbdesc_t: %s\n",
			    strerror(errno));

		newstmtdesc = dtrace_stmt_create(dtp, newecb);
		if (newstmtdesc == NULL)
			errx(EXIT_FAILURE,
			    "failed to allocate a new dtrace_stmtdesc_t: %s\n",
			    strerror(errno));

		newact = dtrace_stmt_action(dtp, newstmtdesc);
		if (newact == NULL)
			errx(EXIT_FAILURE,
			    "failed to allocate a new dtrace_actdesc_t: %s\n",
			    strerror(errno));

		newact->dtad_difo = malloc(sizeof(dtrace_difo_t));
		difo = newact->dtad_difo;
		if (difo == NULL)
			errx(EXIT_FAILURE,
			    "failed to allocate a new DIFO: %s\n",
			    strerror(errno));

		memset(difo, 0, sizeof(dtrace_difo_t));

		/* 2 instructions: hcall; ret %r0 */
		difo->dtdo_buf = malloc(sizeof(dif_instr_t) * 2);
		assert(difo->dtdo_buf != NULL);

		difo->dtdo_buf[0] = DIF_INSTR_FMT(DIF_OP_HYPERCALL, 0, 0, 0);
		difo->dtdo_buf[1] = DIF_INSTR_RET(0);
		difo->dtdo_len = 2;

		newact->dtad_kind = DTRACEACT_DIFEXPR;

		newecb->dted_action = newact;

		curecb = curstmtdesc->dtsd_ecbdesc;
		memcpy(&newecb->dted_probe, &curecb->dted_probe,
		    sizeof(dtrace_probedesc_t));

		newstmtdesc->dtsd_ecbdesc = newecb;

		if (dtrace_stmt_add(dtp, newpgp, newstmtdesc))
			errx(EXIT_FAILURE,
			    "failed to add a new dtrace_stmtdesc_t: %s\n",
			    strerror(errno));
	}

	newpgp->dp_rflags = pgp->dp_rflags;
	dt_prog_generate_ident(newpgp);

	return (newpgp);
}

dtrace_prog_t *
dt_vprog_from(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, int pgp_kind)
{
	dtrace_prog_t *newpgp;

	newpgp = NULL;

	switch (pgp_kind) {
	case PGP_KIND_HYPERCALLS:
		newpgp = dt_vprog_hcalls(dtp, pgp);
		break;

	default:
		return (NULL);
	}


	/*
	 * Patch up the necessary information to identify which program this one
	 * comes from.
	 */
	memcpy(newpgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	newpgp->dp_dofversion = pgp->dp_dofversion;
	return (newpgp);
}
