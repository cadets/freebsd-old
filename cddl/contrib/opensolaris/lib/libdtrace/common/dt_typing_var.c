/*-
 * Copyright (c) 2021 Domagoj Stolfa
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

#include <dt_typing.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.h>
#include <dt_basic_block.h>
#include <dt_ifgnode.h>
#include <dt_typefile.h>
#include <dt_typing.h>
#include <dt_typing_helpers.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_var.h>

/*
 * dt_builtin_type() takes a node and a builtin variable, returning
 * the expected type of said builtin variable.
 */
void
dt_builtin_type(dt_ifg_node_t *n, uint16_t var, uint8_t idx)
{
	argcheck_cookie_t cookie;
	dtrace_probedesc_t *pdesc;
	dt_ifg_list_t *c_node;
	dt_ifg_node_t *child;
	int check_types;

	memset(&cookie, 0, sizeof(cookie));

	switch (var) {
	/*
	 * struct thread *
	 */
	case DIF_VAR_CURTHREAD:
	case DIF_VAR_HCURTHREAD:
		n->din_tf = dt_typefile_kernel();
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, t_thread);
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type %s: %s", t_thread,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint64_t
	 */
	case DIF_VAR_HUCALLER:
	case DIF_VAR_UCALLER:
	case DIF_VAR_TIMESTAMP:
	case DIF_VAR_VTIMESTAMP:
	case DIF_VAR_HTIMESTAMP:
	case DIF_VAR_HVTIMESTAMP:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uint64_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint_t
	 */
	case DIF_VAR_IPL:
	case DIF_VAR_HIPL:
	case DIF_VAR_HEPID:
	case DIF_VAR_EPID:
	case DIF_VAR_ID:
	case DIF_VAR_HPRID:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uint_t: %s (%s)",
			    dt_typefile_error(n->din_tf),
			    dt_typefile_stringof(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_VAR_ARGS:
		pdesc = &n->din_edp->dted_probe;
		if (strcmp(pdesc->dtpd_name, "ERROR") == 0) {
			/*
			 * arg0 -> nothing
			 * arg1 -> epid
			 * arg2 -> index of the action
			 * arg3 -> DIF offset into the action or -1
			 * arg4 -> fault type
			 * arg5 -> value dependent on the fault type
			 */
			char *arg_type[] = {
				[0] = "",
				[1] = "uint32_t",
				[2] = "uint32_t",
				[3] = "int",
				[4] = "uint32_t",
				[5] = "uintptr_t"
			};

			if (idx == 0 || idx > 5)
				dt_set_progerr(g_dtp, g_pgp,
				    "accessing arg%d in the ERROR probe is "
				    "not supported", idx);

			n->din_tf = dt_typefile_kernel();
			assert(n->din_tf != NULL);

			n->din_ctfid = dt_typefile_ctfid(n->din_tf,
			    arg_type[idx]);
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp,
				    "failed to get type %s: %s",
				    arg_type[idx],
				    dt_typefile_error(n->din_tf));

			n->din_type = DIF_TYPE_CTF;
		} else if (strcmp(pdesc->dtpd_provider, "dtrace") == 0) {
			idx = idx;

			dt_set_progerr(g_dtp, g_pgp,
			    "accessing arg%d in %s probe is not supported",
			    idx, pdesc->dtpd_name);
		} else {
			uint8_t child_op;
			cookie.node = n;
			cookie.varcode = var;
			cookie.idx = idx;

			check_types = 0;
			for (c_node = dt_list_next(&n->din_r1children); c_node;
			     c_node = dt_list_next(c_node)) {
				child = c_node->dil_ifgnode;
				assert(child->din_difo == n->din_difo);

				child_op = DIF_INSTR_OP(
				    child->din_buf[child->din_uidx]);

				if (child_op != DIF_OP_RET &&
				    child_op != DIF_OP_TYPECAST)
					check_types = 1;
			}

			for (c_node = dt_list_next(&n->din_r2children); c_node;
			     c_node = dt_list_next(c_node)) {
				child = c_node->dil_ifgnode;
				assert(child->din_difo == n->din_difo);

				child_op = DIF_INSTR_OP(
				    child->din_buf[child->din_uidx]);

				if (child_op != DIF_OP_RET &&
				    child_op != DIF_OP_TYPECAST)
					check_types = 1;
			}

			if (check_types == 1)
				dtrace_probe_iter(g_dtp, &n->din_edp->dted_probe,
				    dt_infer_type_arg, &cookie);
			else {
				n->din_type = DIF_TYPE_CTF;
				n->din_tf = dt_typefile_kernel();
				n->din_ctfid = dt_typefile_ctfid(n->din_tf,
				    "uint64_t");
			}
		}
		break;

	case DIF_VAR_ARG0:
	case DIF_VAR_ARG1:
	case DIF_VAR_ARG2:
	case DIF_VAR_ARG3:
	case DIF_VAR_ARG4:
	case DIF_VAR_ARG5:
	case DIF_VAR_ARG6:
	case DIF_VAR_ARG7:
	case DIF_VAR_ARG8:
	case DIF_VAR_ARG9:
	case DIF_VAR_HARG0:
	case DIF_VAR_HARG1:
	case DIF_VAR_HARG2:
	case DIF_VAR_HARG3:
	case DIF_VAR_HARG4:
	case DIF_VAR_HARG5:
	case DIF_VAR_HARG6:
	case DIF_VAR_HARG7:
	case DIF_VAR_HARG8:
	case DIF_VAR_HARG9:
	case DIF_VAR_UREGS:
	case DIF_VAR_REGS:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uintptr_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uintptr_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_VAR_WALLTIMESTAMP:
	case DIF_VAR_HWALLTIMESTAMP:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type int64_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint32_t
	 */
	case DIF_VAR_STACKDEPTH:
	case DIF_VAR_USTACKDEPTH:
	case DIF_VAR_HSTACKDEPTH:
	case DIF_VAR_HUSTACKDEPTH:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uint32_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uintptr_t
	 */
	case DIF_VAR_CALLER:
	case DIF_VAR_HCALLER:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uintptr_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uintptr_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * string
	 */
	case DIF_VAR_PROBEPROV:
	case DIF_VAR_PROBEMOD:
	case DIF_VAR_PROBEFUNC:
	case DIF_VAR_PROBENAME:
	case DIF_VAR_HPROBEPROV:
	case DIF_VAR_HPROBEMOD:
	case DIF_VAR_HPROBEFUNC:
	case DIF_VAR_HPROBENAME:
	case DIF_VAR_EXECNAME:
	case DIF_VAR_ZONENAME:
	case DIF_VAR_HEXECNAME:
	case DIF_VAR_HZONENAME:
	case DIF_VAR_JAILNAME:
	case DIF_VAR_HJAILNAME:
	case DIF_VAR_VMNAME:
	case DIF_VAR_HVMNAME:
	case DIF_VAR_EXECARGS:
	case DIF_VAR_HEXECARGS:
		n->din_type = DIF_TYPE_STRING;
		break;

	/*
	 * pid_t
	 */
	case DIF_VAR_HPID:
	case DIF_VAR_PID:
	case DIF_VAR_PPID:
	case DIF_VAR_HPPID:
		n->din_tf = dt_typefile_kernel();
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "pid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type pid_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * id_t
	 */
	case DIF_VAR_HTID:
	case DIF_VAR_TID:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "id_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type id_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uid_t
	 */
	case DIF_VAR_UID:
	case DIF_VAR_HUID:
		n->din_tf = dt_typefile_kernel();
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uid_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * gid_t
	 */
	case DIF_VAR_GID:
	case DIF_VAR_HGID:
		n->din_tf = dt_typefile_kernel();
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "gid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type gid_t: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * int
	 */
	case DIF_VAR_HCPU:
	case DIF_VAR_CPU:
	case DIF_VAR_HERRNO:
	case DIF_VAR_ERRNO:
	case DIF_VAR_HJID:
	case DIF_VAR_JID:
		n->din_tf = dt_typefile_mod("D");
		assert(n->din_tf != NULL);
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type int: %s",
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_VAR_HHOSTID:
	case DIF_VAR_HOSTID:
		n->din_tf = dt_typefile_kernel();
		assert(n->din_tf != NULL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "hostid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed te got type hostid_t: %s",
			    dt_typefile_error(n->din_tf));
		n->din_type = DIF_TYPE_CTF;
		break;

	default:
		dt_set_progerr(g_dtp, g_pgp, "variable %x does not exist", var);
	}
}

int
dt_infer_type_arg(
    dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp, void *_cookie)
{
	argcheck_cookie_t *cookie = (argcheck_cookie_t *)_cookie;
	uint16_t var;
	dt_ifg_node_t *n;
	dtrace_argdesc_t ad;
	char resolved_type[DTRACE_ARGTYPELEN];
	char *mod;
	dt_typefile_t *tf;
	ctf_id_t ctfid;
	int type, which;
	int is_profile_probe;
	uint8_t idx;

	memset(resolved_type, 0, DTRACE_ARGTYPELEN);
	assert(cookie != NULL);
	n = cookie->node;
	var = cookie->varcode;
	idx = cookie->idx;

	if (__predict_false(var != DIF_VAR_ARGS))
		return (1);

	assert(n != NULL);
	mod = (char *)pdp->dtpd_mod;

	memset(&ad, 0, sizeof(ad));
	ad.dtargd_ndx = idx;
	assert(ad.dtargd_ndx <= 9);

	ad.dtargd_id = pdp->dtpd_id;
	assert(ad.dtargd_id != DTRACE_IDNONE);

	is_profile_probe = 0;
	if (strstr(pdp->dtpd_name, "tick") != NULL)
		is_profile_probe = 1;

	if (!is_profile_probe && dt_ioctl(dtp, DTRACEIOC_PROBEARG, &ad) != 0) {
		(void) dt_set_errno(dtp, errno);
		return (1);
	}

	if (is_profile_probe == 0)
		memcpy(resolved_type, ad.dtargd_native, DTRACE_ARGTYPELEN);
	else
		strcpy(resolved_type, "uint64_t");

	/*
	 * Try by module first.
	 */
	if (strcmp(mod, "freebsd") == 0)
		tf = dt_typefile_kernel();
	else
		tf = dt_typefile_mod(mod);

	if (tf != NULL)
		ctfid = dt_typefile_ctfid(tf, resolved_type);
	if (tf == NULL || ctfid == CTF_ERR) {
		/*
		 * If we can't find it in the module, try in the kernel
		 * itself.
		 */
		tf = dt_typefile_kernel();
		assert(tf != NULL);
		ctfid = dt_typefile_ctfid(tf, resolved_type);
		if (ctfid == CTF_ERR) {
			fprintf(stderr, "could not find type %s in %s\n",
			    resolved_type, dt_typefile_stringof(tf));
			return (1);
		}
	}

	type = DIF_TYPE_CTF;

	/*
	 * This can't currently happen, but the assertion is here for
	 * completeness.
	 */
	assert(type != DIF_TYPE_NONE);

	if (n->din_type == DIF_TYPE_BOTTOM || n->din_type == DIF_TYPE_NONE ||
	    n->din_type == -1) {
		n->din_type = type;
		n->din_tf = tf;
		n->din_ctfid = ctfid;
		return (0);
	}

	/*
	 * This can't currently happen, but the rule is here for completness.
	 */
	if (type == DIF_TYPE_BOTTOM)
		return (0);

	if (n->din_type == DIF_TYPE_STRING && type == DIF_TYPE_STRING)
		return (0);

	if (n->din_type == DIF_TYPE_CTF) {
		if (type != DIF_TYPE_CTF) {
			fprintf(stderr,
			    "node currently has CTF type, but type is %d\n",
			    type);
			return (1);
		}

		assert(n->din_type == type);

		if (n->din_tf == tf &&
		    ctfid == n->din_ctfid)
			return (0);

		if (dt_type_subtype(
		    n->din_tf, n->din_ctfid, tf, ctfid, &which) == 0) {
			if (which == SUBTYPE_NONE)
				return (1);

			if (which & SUBTYPE_SND) {
				n->din_tf = tf;
				n->din_ctfid = ctfid;
				n->din_type = type;
			} else if ((which & SUBTYPE_ANY) == SUBTYPE_ANY) {
				fprintf(stderr,
				    "dt_infer_type_arg(): impossible "
				    "subtyping relation\n");
				return (1);
			}

			return (0);
		}
	}

	fprintf(stderr, "failed to infer type for type = %s\n", resolved_type);
	/*
	 * If we don't have a matching case before this, we can't type-check it.
	 */
	return (1);
}

/*
 * dt_infer_type_var() figures out the type of a variable in the varlist and
 * typechecks it against dr.
 */
int
dt_infer_type_var(dtrace_hdl_t *dtp, dtrace_difo_t *difo, dt_ifg_node_t *dr,
    dtrace_difv_t *dif_var)
{
	char buf[4096] = {0}, var_type[4096] = {0};
	dtrace_difv_t *difovar;
	int rv, which;
	ctf_id_t stripped_kind, stripped_id, orig_id;

	difovar = NULL;

	if (dr == NULL && dif_var == NULL) {
		fprintf(stderr,
		    "dt_infer_type_var(): both dr and dif_var are NULL\n");
		return (-1);
	}

	if (dr == NULL)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var == NULL) {
		fprintf(stderr,
		    "dt_infer_type_var(): dif_var is NULL, this makes "
		    "no sense\n");
		return (-1);
	}

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM) {
		dif_var->dtdv_tf = dr->din_tf;
		dif_var->dtdv_ctfid = dr->din_ctfid;
		dif_var->dtdv_sym = dr->din_sym;
		dif_var->dtdv_type.dtdt_kind = dr->din_type;
		if (dr->din_type == DIF_TYPE_CTF)
			dif_var->dtdv_type.dtdt_size =
			    dt_typefile_typesize(dr->din_tf, dr->din_ctfid);
		dif_var->dtdv_type.dtdt_ckind = dr->din_ctfid;

		return (dr->din_type);
	}

	if (dr->din_type == DIF_TYPE_BOTTOM)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING && dr->din_isnull)
		return (DIF_TYPE_STRING);

	if (dt_typecheck_stringiv(dtp, dr, dif_var)) {
		dif_var->dtdv_type.dtdt_kind = DIF_TYPE_STRING;
		return (DIF_TYPE_STRING);
	}

	if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_NONE &&
	    dif_var->dtdv_type.dtdt_kind != dr->din_type) {
		char b1[32] = "", b2[32] = "";
		if (dr->din_type == DIF_TYPE_CTF) {
			if (dt_typefile_typename(dr->din_tf, dr->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type_var(): failed at getting "
				    "type name %ld: %s\n",
				    dr->din_ctfid,
				    dt_typefile_error(dr->din_tf));
			sprintf(b2, "@%ld", dr->din_ctfid);
		} else if (dr->din_type == DIF_TYPE_STRING)
			strcpy(buf, "D string");
		else if (dr->din_type == DIF_TYPE_NONE)
			strcpy(buf, "none");
		else if (dr->din_type == DIF_TYPE_BOTTOM)
			strcpy(buf, "bottom");
		else
			strcpy(buf, "unknown");

		if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_CTF) {
			if (dt_typefile_typename(dif_var->dtdv_tf,
			    dif_var->dtdv_ctfid, var_type,
			    sizeof(var_type)) != ((char *)var_type))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type_var(): failed at getting "
				    "type name %ld: %s\n",
				    dif_var->dtdv_ctfid,
				    dt_typefile_error(dif_var->dtdv_tf));
			sprintf(b1, "@%ld", dif_var->dtdv_ctfid);
		} else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
			strcpy(var_type, "D string");
		else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_NONE)
			strcpy(var_type, "none");
		else if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM)
			strcpy(var_type, "bottom");
		else
			strcpy(var_type, "unknown");

		fprintf(stderr,
		    "dt_infer_type_var(): dif_var and dr have different "
		    "types: %s (%d%s) != %s (%d%s)\n",
		    var_type, dif_var->dtdv_type.dtdt_kind, b1, buf,
		    dr->din_type, b2);

		return (-1);
	}

	if (dr->din_type == DIF_TYPE_NONE || dr->din_type == DIF_TYPE_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp,
		    "dt_infer_type_var(): unexpected type %d\n", dr->din_type);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
		return (DIF_TYPE_STRING);

	if (dif_var->dtdv_ctfid != CTF_ERR) {
		if (dt_typefile_typename(dif_var->dtdv_tf, dif_var->dtdv_ctfid,
		    var_type, sizeof(var_type)) != ((char *)var_type))
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type_var(): failed at getting "
			    "type name %ld: %s\n",
			    dif_var->dtdv_ctfid,
			    dt_typefile_error(dif_var->dtdv_tf));

		if (dt_typefile_typename(dr->din_tf, dr->din_ctfid, buf,
		    sizeof(buf)) != ((char *)buf))
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type_var(): failed at getting "
			    "type name %ld: %s\n",
			    dr->din_ctfid, dt_typefile_error(dr->din_tf));

		rv = dt_type_subtype(dif_var->dtdv_tf, dif_var->dtdv_ctfid,
		    dr->din_tf, dr->din_ctfid, &which);

		if (rv != 0) {
			fprintf(stderr,
			    "dt_infer_type_var(): type mismatch "
			    "in variable store: %s != %s\n",
			    var_type, buf);

			return (-1);
		}

		if (which & SUBTYPE_FST) {
			dif_var->dtdv_tf = dr->din_tf;
			dif_var->dtdv_ctfid = dr->din_ctfid;
			dif_var->dtdv_sym = dr->din_sym;
			dif_var->dtdv_type.dtdt_kind = dr->din_type;
			dif_var->dtdv_type.dtdt_size =
			    dt_typefile_typesize(dr->din_tf, dr->din_ctfid);
			dif_var->dtdv_type.dtdt_ckind = dr->din_ctfid;
		}

		if (dif_var->dtdv_sym != NULL) {
			if (dr->din_sym && strcmp(
			    dif_var->dtdv_sym, dr->din_sym) != 0) {
				fprintf(stderr,
				    "dt_infer_type_var(): symbol name "
				    "mismatch: %s != %s\n",
				    dif_var->dtdv_sym, dr->din_sym);

				return (-1);
			} else if (dr->din_sym == NULL) {
				fprintf(stderr,
				    "dt_infer_type_var(): din_sym is NULL\n");
				return (-1);
			}
		}
	} else {
		dif_var->dtdv_tf = dr->din_tf;
		dif_var->dtdv_ctfid = dr->din_ctfid;
		dif_var->dtdv_sym = dr->din_sym;
		dif_var->dtdv_type.dtdt_kind = dr->din_type;
		dif_var->dtdv_type.dtdt_size =
		    dt_typefile_typesize(dr->din_tf, dr->din_ctfid);
		dif_var->dtdv_type.dtdt_ckind = dr->din_ctfid;
	}

	return (DIF_TYPE_CTF);
}

/*
 * dt_typecheck_vardefs() ensures that all existing variable definitions are
 * are consistent in their types inside the DIFO (defs list) and across DIFOs
 * which is done using the var_list.
 */
dt_ifg_node_t *
dt_typecheck_vardefs(dtrace_difo_t *difo, dt_list_t *defs, int *empty)
{
	dt_ifg_list_t *ifgl;
	dt_ifg_node_t *node, *onode;
	char buf1[4096] = {0}, buf2[4096] = {0};
	int type, otype;
	int class1, class2;
	dtrace_difv_t *var;
	uint16_t varid;
	int scope, kind;
	dif_instr_t instr;

	ifgl = NULL;
	type = otype = DIF_TYPE_NONE;
	class1 = class2 = -1;
	node = onode = NULL;
	var = NULL;
	varid = 0;
	scope = kind = 0;
	instr = 0;
	*empty = 1;

	/*
	 * We iterate over all the variable definitions for a particular
	 * node that is created through a variable load instruction.
	 * We make sure that:
	 *  (1) All definitions agree on the type of the variable
	 *  (2) All definitions conform to the previously inferred variable
	 *      type from a different DIFO (if it exists).
	 */
	for (ifgl = dt_list_next(defs); ifgl; ifgl = dt_list_next(ifgl)) {
		*empty = 0;
		onode = node;
		node = ifgl->dil_ifgnode;

		/*
		 * For r0node, we don't actually have check anything because
		 * by definition, the register r0 is always of type bottom,
		 * allowing us to construct any type we find convenient.
		 */
		otype = type;
		type = dt_infer_type(node);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1) {
			fprintf(stderr, "failed to infer type\n");
			return (NULL);
		}

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (onode && otype != type) {
			fprintf(stderr, "otype and type mismatch (%d, %d)\n",
			    otype, type);
			return (NULL);
		}

		instr = node->din_buf[node->din_uidx];
		dt_get_varinfo(instr, &varid, &scope, &kind);
		if (varid == 0 && scope == -1 && kind == -1)
			dt_set_progerr(
			    g_dtp, g_pgp, "failed to get variable information");

		/*
		 * We get the variable from the variable list.
		 *
		 * N.B.: This is not the variable table that is in the DIFO,
		 *       it is rather a separate variable table that we use
		 *       to keep track of types for each variable _across_
		 *       DIFOs.
		 */
		var = dt_get_var_from_varlist(varid, scope, kind);
		if (var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "could not find variable (%u, %d, %d) in varlist",
			    varid, scope, kind);


		/* If the type we are comparing to is bottom, skip. */
		if (type == DIF_TYPE_BOTTOM)
			continue;

		/*
		 * The previously inferred variable type must match the
		 * current type we inferred.
		 */
		if (var->dtdv_type.dtdt_kind != type) {
			char t1[DT_TYPE_NAMELEN] = { 0 };
			char t2[DT_TYPE_NAMELEN] = { 0 };

			if (type == DIF_TYPE_CTF) {
				if (dt_typefile_typename(node->din_tf,
					node->din_ctfid, t1,
					sizeof(t1)) != ((char *)t1))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type_var(): failed at getting "
					    "type name %ld: %s\n",
					    node->din_ctfid,
					    dt_typefile_error(node->din_tf));
				sprintf(t1, "@%ld", node->din_ctfid);
			} else if (type == DIF_TYPE_STRING)
				strcpy(t1, "D string");
			else if (type == DIF_TYPE_NONE)
				strcpy(t1, "none");
			else if (type == DIF_TYPE_BOTTOM)
				strcpy(t1, "bottom");
			else
				strcpy(t1, "unknown");

			if (var->dtdv_type.dtdt_kind == DIF_TYPE_CTF) {
				if (dt_typefile_typename(var->dtdv_tf,
					var->dtdv_ctfid, t2,
					sizeof(t2)) != ((char *)t2))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type_var(): failed at getting "
					    "type name %ld: %s\n",
					    var->dtdv_ctfid,
					    dt_typefile_error(var->dtdv_tf));
				sprintf(t2, "@%ld", var->dtdv_ctfid);
			} else if (var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
				strcpy(t2, "D string");
			else if (var->dtdv_type.dtdt_kind == DIF_TYPE_NONE)
				strcpy(t2, "none");
			else if (var->dtdv_type.dtdt_kind == DIF_TYPE_BOTTOM)
				strcpy(t2, "bottom");
			else
				strcpy(t2, "unknown");

			fprintf(stderr, "%s(): %s != %s\n", __func__, t1, t2);
			return (NULL);
		}

		if (type == DIF_TYPE_CTF) {
			/*
			 * We only allow for comparison within the typefile.
			 */
			if (node->din_tf != var->dtdv_tf) {
				fprintf(stderr,
				    "comparing node with typefile "
				    "%s to variable with typefile %s",
				    dt_typefile_stringof(node->din_tf),
				    dt_typefile_stringof(var->dtdv_tf));
				return (NULL);
			}
			/*
			 * We get the type name for reporting purposes.
			 */
			if (dt_typefile_typename(node->din_tf, node->din_ctfid,
			    buf1, sizeof(buf1)) != ((char *)buf1))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_typecheck_vardefs(): failed at getting "
				    "type name %ld: %s",
				    node->din_ctfid,
				    dt_typefile_error(node->din_tf));

			/*
			 * If the variable already has a type assigned to it,
			 * but it is not the same type that we just inferred
			 * it to be, we get the type name of the variable and
			 * report an error.
			 */
			if (var->dtdv_ctfid != -1 &&
			    node->din_ctfid != var->dtdv_ctfid) {
				if (var->dtdv_name >= difo->dtdo_strlen)
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_vardefs(): variable "
					    "name outside strtab (%zu, %zu)",
					    var->dtdv_name, difo->dtdo_strlen);

				if (dt_typefile_typename(var->dtdv_tf,
				    var->dtdv_ctfid, buf2,
				    sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_vardefs(): failed at "
					    "getting type name %ld: %s",
					    var->dtdv_ctfid,
					    dt_typefile_error(var->dtdv_tf));

				fprintf(stderr, "variable (%s) type and "
				    "inferred type mismatch: %s, %s",
				    difo->dtdo_strtab + var->dtdv_name,
				    buf1, buf2);
				return (NULL);
			}

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == NULL)
				continue;

			/*
			 * Get the previous' node's inferred type for
			 * error reporting.
			 */
			if (dt_typefile_typename(onode->din_tf,
			    onode->din_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_typecheck_vardefs(): failed at getting "
				    "type name %ld: %s",
				    onode->din_ctfid,
				    dt_typefile_error(onode->din_tf));

			/*
			 * Only compare within the typefile
			 */
			if (node->din_tf != onode->din_tf) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): node has typefile "
				    "%s but typefile %s is expected\n",
				    dt_typefile_stringof(node->din_tf),
				    dt_typefile_stringof(onode->din_tf));
				return (NULL);
			}

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (node->din_ctfid != onode->din_ctfid) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): types %s and "
				    "%s do not match\n",
				    buf1, buf2);
				return (NULL);
			}

			if ((node->din_sym == NULL && onode->din_sym != NULL) ||
			    (node->din_sym != NULL && onode->din_sym == NULL)) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): node or onode "
				    "is missing a symbol\n");
				return (NULL);
			}

			if ((node->din_sym == NULL && var->dtdv_sym != NULL) ||
			    (node->din_sym != NULL && var->dtdv_sym == NULL)) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): node or dif_var "
				    "is missing a symbol\n");
				return (NULL);
			}

			/*
			 * We don't have to check anything except for
			 * node->din_sym being not NULL
			 */
			if (node->din_sym &&
			    strcmp(node->din_sym, onode->din_sym) != 0) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): nodes have "
				    "different symbols: %s != %s\n",
				    node->din_sym, onode->din_sym);
				return (NULL);
			}

			if (node->din_sym &&
			    strcmp(node->din_sym, var->dtdv_sym) != 0) {
				fprintf(stderr,
				    "dt_typecheck_vardefs(): node and var "
				    "have different symbols: %s != %s\n",
				    node->din_sym, onode->din_sym);
				return (NULL);
			}

		}
	}

	return (node);
}
