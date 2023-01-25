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
 * Copyright (c) 2021, Domagoj Stolfa. All rights reserved.
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
 */

#include <assert.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#ifdef illumos
#include <alloca.h>
#endif

#include <dt_hashmap.h>
#include <dt_impl.h>
#include <dt_linker_subr.h>
#include <dt_printf.h>
#include <dt_program.h>
#include <dt_provider.h>

#if defined(__amd64__) || defined(__i386__)
#include <amd64/include/vmm.h>
#endif

#define VERICTX_DEFAULT_VECSIZE 256 /* We expect around 256 DIFOs by default. */

typedef struct dt_verictx {
	dtrace_hdl_t *dtp;

	/*
	 * Vector
	 */
	dtrace_difo_t **difovec;
	size_t num_difos;
	size_t difovec_size;
} dt_verictx_t;

void dt_prog_generate_ident(dtrace_prog_t *);

dtrace_prog_t *
dt_program_create(dtrace_hdl_t *dtp)
{
	char buf[DT_PROG_IDENTLEN] = { 0 };
	dtrace_prog_t *pgp = dt_zalloc(dtp, sizeof (dtrace_prog_t));

	if (pgp != NULL) {
		dt_list_append(&dtp->dt_programs, pgp);
	} else {
		(void) dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	/*
	 * Generate our random identifier
	 */
	dt_prog_generate_ident(pgp);


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
	pgp->dp_vmname = dt_zalloc(dtp, VM_MAX_NAMELEN);
	if (pgp->dp_vmname == NULL) {
		dt_list_delete(&dtp->dt_programs, pgp);
		free(pgp);
		dt_set_errno(dtp, EDT_NOMEM);
		return (NULL);
	}

	/*
	 * We don't want to set this by default.
	 */
	pgp->dp_pid = 0;

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

	if (pgp->dp_vmname)
		dt_free(dtp, pgp->dp_vmname);

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
		fprintf(
		    stderr, "DTRACEIOC_VPROBE_CREATE: %s\n", strerror(errno));
		return (n);
	}

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

void
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

	if ((new = dt_zalloc(dtp, sizeof (dtrace_actdesc_t))) == NULL)
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
dt_prog_verify_difo(void *_ctx, dtrace_difo_t *dbase, dtrace_difo_t *dnew,
    char *base_target, char *new_target)
{
	size_t i, j;
	dif_instr_t ibase, inew, inext;
	uint8_t opbase, opnew, opnext;
	dt_verictx_t *ctx = _ctx;
	dtrace_hdl_t *dtp;
	dtrace_difv_t *difv, *curdifo_var;
	dtrace_difo_t *difo = NULL;
	dtrace_diftype_t *rtype;
	dtrace_optval_t strsize = 0;

	i = 0;
	ibase = 0;
	inew = 0;
	opbase = 0;
	opnew = 0;
	dtp = ctx->dtp;
	rtype = &dnew->dtdo_rtype;

	for (i = 0; i < ctx->num_difos; i++) {
		difo = ctx->difovec[i];
		assert(difo != NULL);

		for (j = 0; j < dnew->dtdo_varlen; j++) {
			difv = &dnew->dtdo_vartab[j];

			curdifo_var = dt_get_variable(difo, difv->dtdv_id,
			    difv->dtdv_scope, difv->dtdv_kind);
			if (curdifo_var == NULL)
				continue;

			/*
			 * FIXME(dstolfa, important): Do some type-checking to
			 * make sure that this is sensible.
			 *
			 * Maybe also change the DIFO rtype if needed?
			 */
			if (difv->dtdv_type.dtdt_size >
			    curdifo_var->dtdv_type.dtdt_size)
				curdifo_var->dtdv_type = difv->dtdv_type;
			else
				difv->dtdv_type = curdifo_var->dtdv_type;
		}
	}

	(void) dtrace_getopt(dtp, "strsize", &strsize);
	if (rtype->dtdt_kind == DIF_TYPE_STRING)
		rtype->dtdt_size = strsize;

	/*
	 * Go through all of the base instructions and compare it to the new
	 * instructions. If we encounter a relocation, we check that it has
	 * been applied correctly and adjust the counter accordingly.
	 */
	for (i = 0; i < dbase->dtdo_len; i++) {
		ibase = dbase->dtdo_buf[i];
		inew = dnew->dtdo_buf[i];

		opbase = DIF_INSTR_OP(ibase);
		switch (opbase) {
		case DIF_OP_USETX:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_SETX) {
				fprintf(stderr,
				    "usetx was not set to setx (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_ULOAD:
			opnew = DIF_INSTR_OP(inew);
			if (i + 1 < dbase->dtdo_len)
				inext = dbase->dtdo_buf[i + 1];

			opnext = DIF_INSTR_OP(inext);
			if (opnew != DIF_OP_LDSB && opnew != DIF_OP_LDSH &&
			    opnew != DIF_OP_LDSW && opnew != DIF_OP_LDX  &&
			    opnew != DIF_OP_LDUB && opnew != DIF_OP_LDUH &&
			    opnew != DIF_OP_LDUW) {
				if (opnext == DIF_OP_RET && opnew == DIF_OP_NOP)
					break;

				fprintf(stderr,
				    "uload was not set to a ld* "
				    "instruction (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_UULOAD:
			opnew = DIF_INSTR_OP(inew);
			if (i + 1 < dbase->dtdo_len)
				inext = dbase->dtdo_buf[i + 1];

			opnext = DIF_INSTR_OP(inext);
			if (opnew != DIF_OP_ULDSB && opnew != DIF_OP_ULDSH &&
			    opnew != DIF_OP_ULDSW && opnew != DIF_OP_ULDX  &&
			    opnew != DIF_OP_ULDUB && opnew != DIF_OP_ULDUH &&
			    opnew != DIF_OP_ULDUW) {
				if (opnext == DIF_OP_RET && opnew == DIF_OP_NOP)
					break;

				fprintf(stderr,
				    "uuload was not set to a uld* "
				    "instruction (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_TYPECAST:
			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_NOP) {
				fprintf(stderr,
				    "typecast was not set to nop (!= %u)\n",
				    opnew);
				return (1);
			}

			break;

		case DIF_OP_PUSHTV: {
			uint8_t ors, orv, otype, nrs, nrv, ntype;

			opnew = DIF_INSTR_OP(inew);
			if (opnew != DIF_OP_PUSHTV) {
				fprintf(stderr, "pushtv was changed (!= %u)\n",
				    opnew);
				return (1);
			}

			ors = DIF_INSTR_RS(ibase);
			orv = DIF_INSTR_R2(ibase);
			otype = DIF_INSTR_TYPE(ibase);

			nrs = DIF_INSTR_RS(inew);
			nrv = DIF_INSTR_R2(inew);
			ntype = DIF_INSTR_TYPE(inew);

			if (ors != nrs || orv != nrv || ntype != DIF_TYPE_CTF) {
				fprintf(stderr,
				    "pushtv %u, %u, %u not allowed "
				    "from pushtv %u, %u, %u\n",
				    otype, orv, ors, ntype, nrv, nrs);
				return (1);
			}

			break;
		}

		case DIF_OP_SLL:
		case DIF_OP_SRA:
		case DIF_OP_SETX:
			/*
			 * These might come from a sign extension based on a
			 * typecast. Currently, we just check if they'd perhaps
			 * been turned into nops.
			 *
			 * FIXME(dstolfa, security): We should really make sure
			 * that this is only turned into a nop when it makes
			 * sense for it to be turned into a nop, which means
			 * that the verifier needs to be a whole lot more
			 * complex than it is right now -- or unnecessarily
			 * limiting.
			 */
			opnew = DIF_INSTR_OP(inew);
			if (opnew == DIF_OP_NOP)
				break;

			/*
			 * If we didn't turn it into a nop instruction, simply
			 * fall through to the default case.
			 */
		default:
			if (ibase != inew) {
				opnew = DIF_INSTR_OP(inew);
				fprintf(stderr, "Base program:\n");
				fprintf(stderr, "%s ==>\n", base_target);
				dt_dis(dbase, stderr);
				fprintf(stderr, "\nNew program:\n");
				fprintf(stderr, "%s ==>\n", new_target);
				dt_dis(dnew, stderr);
				fprintf(stderr, "\n");
				fprintf(stderr,
				    "ibase and inew aren't "
				    "the same at %zu (%x != %x)\n"
				    "  opbase = %u\n"
				    "  opnew = %u\n",
				    i, ibase, inew, opbase, opnew);
				return (1);
			}

			break;
		}
	}

	return (0);
}

static dt_verictx_t *
dt_verictx_alloc(dtrace_hdl_t *dtp)
{
	dt_verictx_t *ctx;

	ctx = dt_alloc(dtp, sizeof(dt_verictx_t));
	if (ctx == NULL)
		return (NULL);

	/*
	 * Set the handle that we are working on.
	 */
	ctx->dtp = dtp;

	/*
	 * Allocate the vector of DIFOs we need to check.
	 */
	ctx->difovec = dt_alloc(dtp,
	    sizeof(dtrace_difo_t *) * VERICTX_DEFAULT_VECSIZE);
	memset(
	    ctx->difovec, 0, sizeof(dtrace_difo_t *) * VERICTX_DEFAULT_VECSIZE);
	ctx->num_difos = 0;
	ctx->difovec_size = VERICTX_DEFAULT_VECSIZE;
	return (ctx);
}

void
dt_verictx_teardown(void *_ctx)
{
	dt_verictx_t *ctx = _ctx;

	dt_free(ctx->dtp, ctx->difovec);
	dt_free(ctx->dtp, ctx);
}

void *
dt_verictx_init(dtrace_hdl_t *dtp)
{

	return (dt_verictx_alloc(dtp));
}

static void
dt_verictx_add(dt_verictx_t *ctx, dtrace_difo_t *difo)
{

	assert(ctx->difovec != NULL);
	assert(ctx->num_difos <= ctx->difovec_size);
	if (ctx->num_difos == ctx->difovec_size) {
		size_t osize;
		dtrace_difo_t **new;

		osize = ctx->difovec_size;
		ctx->difovec_size <<= 1;
		new = dt_alloc(ctx->dtp,
		    ctx->difovec_size * sizeof(dtrace_difo_t *));
		if (new == NULL)
			errx(EXIT_FAILURE,
			    "dt_verictx_add(%p, %p): malloc failed: %s\n", ctx,
			    difo, strerror(errno));

		memcpy(new, ctx->difovec, osize * sizeof(dtrace_difo_t *));
		dt_free(ctx->dtp, ctx->difovec);
		ctx->difovec = new;
	}

	ctx->difovec[ctx->num_difos++] = difo;
}

int
dt_prog_verify(void *_ctx, dtrace_prog_t *pbase, dtrace_prog_t *pnew)
{
	dt_stmt_t *sbase, *snew;
	dtrace_stmtdesc_t *sdbase, *sdnew;
	dtrace_actdesc_t *adbase, *adnew;
	dtrace_ecbdesc_t *enew, *edp_new, *edp_base;
	dtrace_probedesc_t *pdnew, *descp_new, *descp_base;
	static const char testbuf[DT_PROG_IDENTLEN];
	char target_base[DTRACE_FULLNAMELEN] = { 0 };
	char target_new[DTRACE_FULLNAMELEN] = { 0 };
	dt_verictx_t *ctx = _ctx;
	dtrace_hdl_t *dtp;
	int self_ref;

	sbase = NULL;
	snew = NULL;
	sdbase = NULL;
	sdnew = NULL;
	adbase = NULL;
	adnew = NULL;
	enew = NULL;
	pdnew = NULL;

	if (ctx == NULL) {
		fprintf(stderr, "dt_prog_verify(%p): context is NULL\n", ctx);
		return (1);
	}

	dtp = ctx->dtp;
	if (dtp == NULL) {
		fprintf(stderr, "dt_prog_verify(): dtp == NULL\n");
		return (1);

	}

	if (pbase == NULL) {
		fprintf(stderr, "dt_prog_verify(): pbase == NULL\n");
		return (1);
	}

	if (pnew == NULL) {
		fprintf(stderr, "dt_prog_verify(): pnew == NULL\n");
		return (1);
	}

	self_ref = 0;
	if (pbase == pnew)
		self_ref = 1;

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
	    sbase && snew; sbase = dt_list_next(sbase)) {
		sdbase = sbase->ds_desc;
		sdnew = snew->ds_desc;

		if (sdbase == NULL || sdnew == NULL) {
			fprintf(stderr, "sdbase = %p, sdnew = %p (NULL err)\n",
			    sdbase, sdnew);
			return (1);
		}

		edp_base = sdbase->dtsd_ecbdesc;
		edp_new = sdnew->dtsd_ecbdesc;
		descp_base = &edp_base->dted_probe;
		descp_new = &edp_new->dted_probe;

		sprintf(target_base, "%s:%s:%s:%s:%s", descp_base->dtpd_target,
		    descp_base->dtpd_provider, descp_base->dtpd_mod,
		    descp_base->dtpd_func, descp_base->dtpd_name);

		sprintf(target_new, "%s:%s:%s:%s:%s", descp_new->dtpd_target,
		    descp_new->dtpd_provider, descp_new->dtpd_mod,
		    descp_new->dtpd_func, descp_new->dtpd_name);

		if (strcmp(target_base, target_new) != 0)
			continue;

		if (sdnew->dtsd_action == NULL && sdnew->dtsd_action_last != NULL) {
			fprintf(stderr,
			    "sdnew (%p) first action is NULL but last is %p\n",
			    sdnew, sdnew->dtsd_action_last);
			return (1);
		}

		if (sdnew->dtsd_action != NULL && sdnew->dtsd_action_last == NULL) {
			fprintf(stderr,
			    "sdnew (%p) first action is %p but last action is NULL\n",
			    sdnew, sdnew->dtsd_action);
			return (1);
		}

		if (sdbase->dtsd_action == NULL && sdbase->dtsd_action_last != NULL) {
			fprintf(stderr,
			    "sdbase (%p) first action is NULL but last is %p\n",
			    sdbase, sdbase->dtsd_action_last);
			return (1);
		}

		if (sdbase->dtsd_action != NULL && sdbase->dtsd_action_last == NULL) {
			fprintf(stderr,
			    "sdbase (%p) first action is %p but last action is NULL\n",
			    sdbase, sdbase->dtsd_action);
			return (1);
		}

		if ((sdbase->dtsd_action == NULL &&
		    sdnew->dtsd_action != NULL)           ||
		    (sdbase->dtsd_action_last == NULL &&
		    sdnew->dtsd_action_last != NULL)      ||
		    (sdbase->dtsd_action != NULL &&
		    sdnew->dtsd_action == NULL)           ||
		    (sdbase->dtsd_action_last != NULL &&
		    sdnew->dtsd_action_last == NULL)) {
			fprintf(stderr,
			    "statements inconsistent: "
			    "base = [%p, %p], new = [%p, %p]\n",
			    sdbase->dtsd_action, sdbase->dtsd_action_last,
			    sdnew->dtsd_action, sdnew->dtsd_action_last);
			return (1);
		}

		/*
		 * TODO(dstolfa): Some deduplication would be nice here.
		 */
		if (sdnew->dtsd_action == sdnew->dtsd_action_last &&
		    sdbase->dtsd_action == sdbase->dtsd_action_last) {
			adbase = sdbase->dtsd_action;
			adnew = sdnew->dtsd_action;

			if (adbase && adnew && adbase->dtad_difo &&
			    adnew->dtad_difo) {
				if (dt_prog_verify_difo(ctx, adbase->dtad_difo,
				    adnew->dtad_difo, target_base,
				    target_new))
					return (1);

				dt_verictx_add(ctx, adnew->dtad_difo);
			}
		}

		for (adbase = sdbase->dtsd_action, adnew = sdnew->dtsd_action;
		     sdbase->dtsd_action_last && sdnew->dtsd_action_last &&
		     adbase != sdbase->dtsd_action_last->dtad_next &&
		     adnew != sdnew->dtsd_action_last->dtad_next;
		     adbase = adbase->dtad_next, adnew = adnew->dtad_next) {
			if (adbase && adnew && adbase->dtad_difo &&
			    adnew->dtad_difo) {
				if (dt_prog_verify_difo(ctx, adbase->dtad_difo,
				    adnew->dtad_difo, target_base,
				    target_new))
					return (1);

				dt_verictx_add(ctx, adnew->dtad_difo);
			}
		}

		enew = sdnew->dtsd_ecbdesc;
		pdnew = &enew->dted_probe;

		pdnew->dtpd_vmid = pnew->dp_vmid;

		/*
		 * Copy over the old fmtdata so that we get the printf strings
		 * right. We don't ever need to actually pass to the guest.
		 */
		if (self_ref == 0)
			sdnew->dtsd_fmtdata = dt_printf_dup(
			    sdbase->dtsd_fmtdata);
		assert(sdnew != NULL);
		snew = dt_list_next(snew);
	}

	return (0);
}

void
dt_prog_generate_ident(dtrace_prog_t *pgp)
{

	arc4random_buf(pgp->dp_ident, DT_PROG_IDENTLEN);
}

static void
fill_instructions(dtrace_difo_t *difo, dif_instr_t *loads, size_t num_loads)
{
	uint_t i;

	i = num_loads;

	memcpy(difo->dtdo_buf, loads, sizeof(dif_instr_t) * num_loads);
	difo->dtdo_buf[i++] = DIF_INSTR_FMT(DIF_OP_HYPERCALL, 0, 0, 0);
	difo->dtdo_buf[i++] = DIF_INSTR_RET(0);
}

typedef struct {
	dt_list_t list;
	dtrace_probedesc_t *pdesc;
} dt_ppd_t;

static dt_stmt_t *
dt_vprog_get_memorized(dt_hashmap_t *hm, dtrace_probedesc_t *pdp)
{
	dt_stmt_t *stp;

	/* +1 for the NULL terminator just in case */
	char fullname[DTRACE_FULLNAMELEN + 1] = { 0 };

	sprintf(fullname, "%s:%s:%s:%s:%s", pdp->dtpd_target,
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	/*
	 * Get the original statement description for this probe description.
	 */
	stp = dt_hashmap_lookup(hm, fullname, DTRACE_FULLNAMELEN + 1);
	if (stp == NULL)
		return (NULL);

	return (stp);
}

static int
dt_vprog_memorize(dtrace_hdl_t *dtp, dt_hashmap_t *hm, dt_stmt_t *stp,
    dtrace_probedesc_t *pdp)
{
	int rval;

	/* +1 for the NULL terminator just in case */
	char fullname[DTRACE_FULLNAMELEN + 1] = { 0 };

	if (hm == NULL || stp == NULL)
		return (-1);

	sprintf(fullname, "%s:%s:%s:%s:%s", pdp->dtpd_target,
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	rval = dt_hashmap_insert(hm, fullname, DTRACE_FULLNAMELEN + 1, stp,
	    DTH_MANAGED);
	if (rval)
		return (dt_set_errno(dtp, EDT_NOMEM));

	return (rval);
}

static dt_stmt_t *
dt_vprog_reorganize(dtrace_hdl_t *dtp, dt_hashmap_t *hm, dtrace_prog_t *pgp,
    dt_stmt_t *ostp, dt_stmt_t *stp)
{
	dtrace_stmtdesc_t *sdp, *osdp, *nsdp;
	dtrace_probedesc_t *pdp;
	dtrace_actdesc_t *ap, *nap, *next;
	dtrace_ecbdesc_t *nedp;
	dt_stmt_t *nstp, *r;
	int alloc_fail;

	if (dtp == NULL || pgp == NULL || ostp == NULL || stp == NULL)
		return (NULL);

	if (ostp == stp)
		return (stp);

	sdp = stp->ds_desc;
	osdp = ostp->ds_desc;
	nsdp = NULL;
	nedp = NULL;

	if (osdp->dtsd_ecbdesc == NULL)
		abort();

	pdp = &osdp->dtsd_ecbdesc->dted_probe;
	nedp = dt_ecbdesc_create(dtp, pdp);
	if (nedp == NULL)
		return (NULL);

	nsdp = dtrace_stmt_create(dtp, nedp);
	if (nsdp == NULL) {
		dt_ecbdesc_release(dtp, nedp);
		dt_free(dtp, nedp);
		return (NULL);
	}

	for (ap = sdp->dtsd_action; ap != sdp->dtsd_action_last->dtad_next;
	     ap = next) {
		next = ap->dtad_next;
		/*
		 * Assert that we have the expected actions.
		 */
		assert(ap->dtad_kind == DTRACEACT_DIFEXPR ||
		    ap->dtad_kind == DTRACEACT_IMMSTACK);

		/*
		 * The only relevant bits to us are the DIFO, as it can contain
		 * a hypercall or some additional helpers, the arg as it gives
		 * us a number of frames, kind as it specifies our action kind
		 * and whether or not it's an action that returns.
		 */
		nap = dtrace_stmt_action(dtp, nsdp);
		if (nap == NULL) {
			for (ap = nsdp->dtsd_action; ap; ap = next) {
				next = ap->dtad_next;
				dt_free(dtp, ap);
			}
			dt_free(dtp, nsdp);
			dt_ecbdesc_release(dtp, nedp);
			dt_free(dtp, nedp);
			return (NULL);
		}

		nap->dtad_kind = ap->dtad_kind;
		nap->dtad_return = ap->dtad_return;
		nap->dtad_difo = dt_difo_dup(dtp, ap->dtad_difo, &alloc_fail);

		/*
		 * TODO: FIXME: Proper cleanup.
		 */
		if (alloc_fail != 0 && nap->dtad_difo == NULL) {
			fprintf(stderr, "%s(%u): allocation failed: %s\n",
			    __func__, __LINE__, strerror(errno));
			abort();
		}
		nap->dtad_arg = ap->dtad_arg;
	}

	/*
	 * Destroy the current statement, we don't need it.
	 */
	dtrace_stmt_destroy(dtp, sdp);
	nstp = dt_zalloc(dtp, sizeof(dt_stmt_t));
	if (nstp == NULL)
		abort();

	r = dt_list_next(stp);

	dt_list_delete(&pgp->dp_stmts, stp);
	dt_list_insert(&pgp->dp_stmts, ostp, nstp);

	nstp->ds_desc = nsdp;
	dt_free(dtp, stp);

	return (r);
}

static int
dt_vprog_squash(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp, *ostp;
	dtrace_probedesc_t *pdp;
	dtrace_ecbdesc_t *edp;
	dtrace_stmtdesc_t *sdp;
	dt_hashmap_t *hm;
	int rval;

	hm = dt_hashmap_create(DT_HASHSIZE_DEFAULT);
	if (hm == NULL)
		return (0);

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		sdp = stp->ds_desc;
		edp = sdp->dtsd_ecbdesc;
		pdp = &edp->dted_probe;
		ostp = dt_vprog_get_memorized(hm, pdp);
		if (ostp != NULL) {
			stp = dt_vprog_reorganize(dtp, hm, pgp, ostp, stp);
			assert(stp != NULL);
		} else {
			rval = dt_vprog_memorize(dtp, hm, stp, pdp);
			if (rval)
				return (rval);
		}

		if (stp == NULL)
			break;
	}

	dt_hashmap_free(hm, 1);
	return (0);
}

static int
dtrace_ldga_argno(dtrace_difo_t *difo, ssize_t idx)
{
	dif_instr_t instr;
	uint8_t opcode;
	uint8_t ri, rd;
	int argno = -1;

	assert(idx < difo->dtdo_len && idx >= 0);
	instr = difo->dtdo_buf[idx];

	opcode = DIF_INSTR_OP(instr);
	assert(opcode == DIF_OP_LDGA);

	ri = DIF_INSTR_R1(instr);

	/*
	 * Since D (and therefore DTrace) expects only constants in %ri, we
	 * expect it to be set with a 'setx' instruction, as 'const int x' will
	 * be compiled as 'int' rather than 'integer constant'. Moreover, we
	 * *assume* that the very first setx instruction we encounter going
	 * backwards from our ldga instruction will indeed be the one which
	 * tells us the argument number and there isn't any kind of DIF that
	 * moves the value around. This is for simplicity reasons rather than
	 * anything else and is obviously wrong -- but we don't really want to
	 * actually compute this right now.
	 */
	while (idx-- >= 0) {
		instr = difo->dtdo_buf[idx];
		opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_SETX)
			continue;

		rd = DIF_INSTR_RD(instr);
		if (rd == ri)
			break;
	}

	if (idx < 0)
		return (-1);

	argno = DIF_INSTR_INTEGER(instr);
	return (argno);
}

static dif_instr_t *
dt_loads_get(dtrace_hdl_t *dtp, dt_hashmap_t *load_hm, char *target,
    size_t **num_loads)
{
	int rval;

	struct he {
		size_t *num_loads;
		dif_instr_t *loads;
	} *he;

	he = dt_hashmap_lookup(load_hm, target, DTRACE_FULLNAMELEN + 1);
	if (he != NULL) {
		*num_loads = he->num_loads;
		return (he->loads);
	}

	he = malloc(sizeof(struct he));
	if (he == NULL)
		return (NULL);

	he->loads = malloc(sizeof(dif_instr_t) * HYPERTRACE_ARGS_MAX);
	if (he->loads == NULL) {
		free(he);
		return (NULL);
	}

	he->num_loads = malloc(sizeof(size_t));
	if (he->num_loads == NULL) {
		free(he->loads);
		free(he);
		return (NULL);
	}

	*he->num_loads = 0;

	rval = dt_hashmap_insert(load_hm, target, DTRACE_FULLNAMELEN + 1, he,
	    DTH_MANAGED);
	if (rval < 0) {
		free(he->loads);
		free(he);
		return (NULL);
	}

	*num_loads = he->num_loads;
	return (he->loads);
}

static size_t
dtrace_vprog_genargloads(dtrace_difo_t *difo, dif_instr_t *loads,
    size_t num_loads)
{
	size_t n, i, j;
	uint16_t var;
	ssize_t argno;
	dif_instr_t instr, new_instr;
	uint8_t opcode;

	n = num_loads;

	for (i = 0; i < difo->dtdo_len; i++) {
		instr = difo->dtdo_buf[i];
		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_LDGS:
			var = DIF_INSTR_VAR(instr);
			argno = var - DIF_VAR_ARG0;
			break;
		case DIF_OP_LDGA:
			var = DIF_INSTR_VAR(instr);
			if (var == DIF_VAR_ARGS)
				argno = dtrace_ldga_argno(difo, i);
			/*
			 * Compute the LDGS-version of ldga args, ri.
			 */
			var = DIF_VAR_ARG0 + argno;
			break;
		}

		if (argno < 5 || argno > 9)
			continue;

		/*
		 * We know we have a load of argno that's between 5 and 9.
		 */
		new_instr = DIF_INSTR_LDV(DIF_OP_LDGS, var, 1);
		for (j = 0; j < n; j++) {
			if (new_instr == loads[j])
				break;
		}

		/*
		 * Store our new instruction if we didn't actually find it.
		 */
		if (j == n)
			loads[n++] = new_instr;
		assert(n <= HYPERTRACE_ARGS_MAX);
	}

	return (n);
}

int
dt_free_loads(void *key __unused, size_t ks __unused, void *data,
    void *arg __unused)
{
	free(data);
	return (0);
}

static dtrace_prog_t *
dt_vprog_hcalls(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dtrace_prog_t *newpgp;
	dt_hashmap_t *load_hm;
	dt_stmt_t *newstmt, *stmt;
	dtrace_stmtdesc_t *newstmtdesc, *curstmtdesc;
	dtrace_ecbdesc_t *newecb, *curecb;
	dtrace_actdesc_t *newact, *curact;
	dtrace_difo_t *difo;
	dtrace_probedesc_t newpdesc = { 0 }, *pdp;
	dt_list_t ppds = { 0 };
	dt_ppd_t *ppd;
	size_t *num_loads;
	dif_instr_t *loads;
	int process;
	char target[DTRACE_FULLNAMELEN + 1] = { 0 };

	newpgp = dt_program_create(dtp);
	if (newpgp == NULL)
		return (NULL);

	load_hm = dt_hashmap_create(DT_HASHSIZE_DEFAULT);
	if (load_hm == NULL) {
		dt_program_destroy(dtp, newpgp);
		return (NULL);
	}

	for (stmt = dt_list_next(&pgp->dp_stmts);
	     stmt; stmt = dt_list_next(stmt)) {
		curstmtdesc = stmt->ds_desc;
		assert(curstmtdesc != NULL);
		curecb = curstmtdesc->dtsd_ecbdesc;
		pdp = &curecb->dted_probe;

		newpdesc = *pdp;
		newpdesc.dtpd_vmid = 0;

		/*
		 * Correct the ERROR probe's target forcefully.
		 */
		if (strcmp(pdp->dtpd_provider, "dtrace") == 0 &&
		    strcmp(pdp->dtpd_name, "ERROR") == 0) {
			if (pgp->dp_vmname == NULL) {
				dt_program_destroy(dtp, newpgp);
				return (NULL);
			}

			strcpy(pdp->dtpd_target, pgp->dp_vmname);
		}

		sprintf(target, "%s:%s:%s:%s:%s", pdp->dtpd_target,
		    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func,
		    pdp->dtpd_name);

		loads = dt_loads_get(dtp, load_hm, target, &num_loads);
		if (loads == NULL)
			abort();

		newecb = dt_ecbdesc_create(dtp, &newpdesc);
		if (newecb == NULL)
			abort();

		newstmtdesc = dtrace_stmt_create(dtp, newecb);
		if (newstmtdesc == NULL)
			abort();

		for (curact = curstmtdesc->dtsd_action; curact != NULL &&
		     curact != curstmtdesc->dtsd_action_last->dtad_next;
		     curact = curact->dtad_next) {
			if (curact->dtad_kind == DTRACEACT_IMMSTACK) {
				newact = dtrace_stmt_action(dtp, newstmtdesc);
				if (newact == NULL)
					abort();

				curact->dtad_kind = DTRACEACT_PRINTIMMSTACK;
				newact->dtad_kind = DTRACEACT_IMMSTACK;
				/*
				 * Ensure we have the number of frames.
				 */
				newact->dtad_arg = curact->dtad_arg;
				newact->dtad_return = 0;
			}

			if (curact->dtad_kind == DTRACEACT_DIFEXPR ||
			    curact->dtad_kind == DTRACEACT_PRINTF) {
				/*
				 * Look for any LDGA or LDGS of arg(s).
				 */
				*num_loads = dtrace_vprog_genargloads(
				    curact->dtad_difo, loads, *num_loads);
				assert(*num_loads <= HYPERTRACE_ARGS_MAX);
			}
		}

		newact = dtrace_stmt_action(dtp, newstmtdesc);
		if (newact == NULL) {
			fprintf(stderr, "%s(%u): allocation failed: %s\n",
			    __func__, __LINE__, strerror(errno));
			abort();
		}

		newact->dtad_difo = malloc(sizeof(dtrace_difo_t));
		difo = newact->dtad_difo;
		if (difo == NULL) {
			fprintf(stderr, "%s(%u): allocation failed: %s\n",
			    __func__, __LINE__, strerror(errno));
			abort();
		}

		memset(difo, 0, sizeof(dtrace_difo_t));

		/* n + 2 instructions: hcall; ret %r0 + all the args[] loads */
		difo->dtdo_buf = malloc(sizeof(dif_instr_t) * (2 + *num_loads));
		if (difo->dtdo_buf == NULL)
			errx(EXIT_FAILURE, "failed to allocate dtdo_buf: %s\n",
			    strerror(errno));

		fill_instructions(difo, loads, *num_loads);
		difo->dtdo_len = 2 + *num_loads;
		newact->dtad_kind = DTRACEACT_DIFEXPR;

		if (dtrace_stmt_add(dtp, newpgp, newstmtdesc))
			errx(EXIT_FAILURE,
			    "failed to add a new dtrace_stmtdesc_t: %s\n",
			    strerror(errno));

	}

	newpgp->dp_rflags = pgp->dp_rflags;
	dt_hashmap_iter(load_hm, dt_free_loads, NULL);
	dt_hashmap_free(load_hm, 1);

	if (dt_vprog_squash(dtp, newpgp)) {
		dt_free(dtp, newpgp);
		return (NULL);
	}

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
	newpgp->dp_vmid = pgp->dp_vmid;

	return (newpgp);
}
