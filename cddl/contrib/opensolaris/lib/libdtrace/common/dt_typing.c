/*-
 * Copyright (c) 2020 Domagoj Stolfa
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

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <assert.h>

static int dt_infer_type(dt_ifg_node_t *);

static dtrace_hdl_t *g_dtp;
static dtrace_prog_t *g_pgp;

/*
 * dt_get_class() takes in a buffer containing the type name and returns
 * the internal DTrace class it belongs to (DTC_INT, DTC_BOTTOM, DTC_STRUCT).
 */
static int
dt_get_class(char *buf)
{
	size_t len;
	ctf_id_t t, ot;
	int k;

	t = 0;
	ot = -1;
	k = 0;
	len = strlen(buf);

	/*
	 * XXX: This is a quick and dirty way to check if something is
	 *      a struct pointer. The "right" way to do this would be to
	 *      look at the current kind, and then get the reference kind
	 *      and make sure they are a (Pointer, Struct) tuple.
	 */
	if (len > strlen("struct") &&
	    strncmp(buf, "struct", strlen("struct")) == 0 &&
	    buf[len - 1] == '*')
		return (DTC_STRUCT);

	t = ctf_lookup_by_name(ctf_file, buf);
	if (t == CTF_ERR)
		dt_set_progerr(g_dtp, g_pgp,
		    "failed getting type (%s) by name: %s\n",
		    buf, ctf_errmsg(ctf_errno(ctf_file)));

	do  {

		if ((k = ctf_type_kind(ctf_file, t)) == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed getting type (%s) kind: %s",
			    buf, ctf_errmsg(ctf_errno(ctf_file)));

		if (t == ot)
			break;

		ot = t;
	} while (((t = ctf_type_reference(ctf_file, t)) != CTF_ERR));

	if (k == CTF_K_INTEGER)
		return (DTC_INT);

	return (DTC_BOTTOM);
}

/*
 * dt_type_compare() takes in two IFG nodes and "compares" their types.
 * Specifically, BOTTOM is the smallest element and no matter what it is
 * compared to, it is smaller than it (reflexivity applies). By convention,
 * we check dr1 for a BOTTOM type first and return dn2 if dr1 is BOTTOM
 * regardless of what dn2 is (could be BOTTOM). Both STRUCT and STRING are
 * considered to be greater than INT (because in DIF when we are adding an
 * integer onto a struct pointer or a string, we still expect to use it as
 * a string or a structure, rather than as a number).
 */
static int
dt_type_compare(dt_ifg_node_t *dr1, dt_ifg_node_t *dn2)
{
	char buf1[4096] = {0};
	char buf2[4096] = {0};
	int class1, class2;

	class1 = 0;
	class2 = 0;

	if (dr1->din_type == DIF_TYPE_BOTTOM && dn2->din_type == DIF_TYPE_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "both types are bottom");

	if (dr1->din_type == DIF_TYPE_BOTTOM)
		return (2);

	if (dn2->din_type == DIF_TYPE_BOTTOM)
		return (1);

	if (dr1->din_type == DIF_TYPE_CTF) {
		if (ctf_type_name(ctf_file, dr1->din_ctfid, buf1,
		    sizeof(buf1)) != ((char *)buf1))
			dt_set_progerr(g_dtp, g_pgp,
			    "failed at getting type name %ld: %s",
			    dr1->din_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));
	}

	if (dn2->din_type == DIF_TYPE_CTF) {
		if (ctf_type_name(ctf_file, dn2->din_ctfid, buf2,
		    sizeof(buf2)) != ((char *)buf2))
			dt_set_progerr(g_dtp, g_pgp,
			    "failed at getting type name %ld: %s",
			    dn2->din_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));
	}

	class1 = dr1->din_type == DIF_TYPE_CTF ? dt_get_class(buf1) : DTC_STRING;
	class2 = dn2->din_type == DIF_TYPE_CTF ? dt_get_class(buf2) : DTC_STRING;

	if (class1 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "class1 is bottom because of %s", buf1);

	if (class2 == DTC_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "class2 is bottom because of %s", buf2);

	if (class1 == DTC_STRING && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_STRUCT && class2 == DTC_INT)
		return (1);

	if (class1 == DTC_INT && (class2 == DTC_STRUCT || class2 == DTC_STRING))
		return (2);

	/*
	 * If the types are of the same class, we return the the first type
	 * by convention.
	 */
	if (class1 == DTC_INT && class2 == DTC_INT)
		return (1);

	return (-1);
}

/*
 * dt_builtin_type() takes a node and a builtin variable, returning
 * the expected type of said builtin variable.
 */
static void
dt_builtin_type(dt_ifg_node_t *n, uint16_t var)
{
	switch (var) {
	/*
	 * struct thread *
	 */
	case DIF_VAR_CURTHREAD:
	case DIF_VAR_HCURTHREAD:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, thread_str);
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type %s: %s",
			    thread_str, ctf_errmsg(ctf_errno(ctf_file)));

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
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uint64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

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
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uint_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * int64_t
	 */
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
	case DIF_VAR_WALLTIMESTAMP:
	case DIF_VAR_HWALLTIMESTAMP:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "int64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type int64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint32_t
	 */
	case DIF_VAR_STACKDEPTH:
	case DIF_VAR_USTACKDEPTH:
	case DIF_VAR_HSTACKDEPTH:
	case DIF_VAR_HUSTACKDEPTH:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uint32_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uintptr_t
	 */
	case DIF_VAR_CALLER:
	case DIF_VAR_HCALLER:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uintptr_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uintptr_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

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
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "pid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type pid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * id_t
	 */
	case DIF_VAR_HTID:
	case DIF_VAR_TID:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "id_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type id_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * uid_t
	 */
	case DIF_VAR_UID:
	case DIF_VAR_HUID:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;

	/*
	 * gid_t
	 */
	case DIF_VAR_GID:
	case DIF_VAR_HGID:
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "gid_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type gid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

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
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		break;
	default:
		dt_set_progerr(g_dtp, g_pgp, "variable %x does not exist", var);
	}
}

/*
 * dt_typecheck_regdefs() takes in a list of nodes that define
 * the current node we are looking at and ensures that their types
 * are consistent.
 */
static dt_ifg_node_t *
dt_typecheck_regdefs(dt_list_t *defs, int *empty)
{
	dt_ifg_list_t *ifgl;
	dt_ifg_node_t *node, *onode;
	char buf1[4096] = {0}, buf2[4096] = {0};
	int type, otype;
	int class1, class2;
	int first_iter;

	ifgl = NULL;
	type = otype = DIF_TYPE_NONE;
	class1 = class2 = -1;
	node = onode = NULL;
	*empty = 1;
	first_iter = 1;

	/*
	 * If we only have a r0node in our list of definitions,
	 * we will return the r0node and have the type as BOTTOM.
	 */
	if ((ifgl = dt_list_next(defs)) != NULL) {
		node = ifgl->dil_ifgnode;
		*empty = 0;
		if (node == r0node && dt_list_next(ifgl) == NULL)
			return (r0node);
	}

	/*
	 * We iterate over all the register definitions for a particular
	 * node. We make sure that each of the definitions agrees
	 * on the type of the register.
	 *
	 * Moreover, at this point we will have eliminated the case where
	 * we only have 1 node (r0node) present in the list.
	 */
	for (ifgl = dt_list_next(defs); ifgl; ifgl = dt_list_next(ifgl)) {
		onode = node;
		node = ifgl->dil_ifgnode;

		otype = type;

		/*
		 * If we have bottom, we just take the old node's value.
		 * onode is _the first_ node in the list, and could be
		 * bottom as well. The only two states we will pass this check
		 * in are:
		 *  (i)  onode is also bottom and we move on until we find the
		 *       first node that is not bottom, which we then
		 *       infer the type of and bail out when we find onode to be
		 *       bottom;
		 *  (ii) onode is a node that is _not_ bottom, but the
		 *       current node is bottom. We decide that we'll just
		 *       set node's value to the last node we saw and
		 *       inferred the type of which is not bottom. Two things
		 *       can happen in the next run. We either realise that we
		 *       have reached the end of the loop and bail out with the
		 *       last node that was not bottom, or we reach the
		 *       case where this check will fail and we can continue on
		 *       typechecking our last seen node that was not
		 *       bottom and the current node which is not bottom,
		 *       giving us the desired type-checking behaviour, making
		 *       sure that all branches have consistent register defns.
		 */
		if (node->din_type == DIF_TYPE_BOTTOM) {
			type = otype;
			node = onode;
			continue;
		}

		type = dt_infer_type(node);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1) {
			fprintf(stderr, "failed to infer type (-1)\n");
			return (NULL);
		}

		if (onode == r0node)
			continue;

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (first_iter == 0 && otype != type) {
			fprintf(stderr, "otype = %d, type = %d\n", otype, type);
			return (NULL);
		}

		if (type == DIF_TYPE_CTF) {
			/*
			 * We get the type name for reporting purposes.
			 */
			if (ctf_type_name(ctf_file, node->din_ctfid, buf1,
			    sizeof(buf1)) != ((char *)buf1))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name node %ld: %s",
				    node->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == NULL)
				continue;

			if (onode->din_type == DIF_TYPE_BOTTOM)
				continue;

 			/*
			 * Get the previous' node's inferred type for
			 * error reporting.
			 */
			if (ctf_type_name(ctf_file, onode->din_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type onode name %ld: %s",
				    onode->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (node->din_ctfid != onode->din_ctfid) {
				printf("looking at %zu and %zu\n", node->din_uidx, onode->din_uidx);
				fprintf(stderr, "types %s and %s do not match\n",
				    buf1, buf2);
				return (NULL);
			}

			if ((node->din_sym == NULL && onode->din_sym != NULL) ||
			    (node->din_sym != NULL && onode->din_sym == NULL)) {
				fprintf(stderr,
				    "symbol is missing in a node\n");
				return (NULL);
			}

			/*
			 * We don't need to check both
			 * because of the above check.
			 */
			if (node->din_sym &&
			    strcmp(node->din_sym, onode->din_sym) != 0) {
				fprintf(stderr, "nodes have different "
				    "symbols: %s != %s\n", node->din_sym,
				    onode->din_sym);
				return (NULL);
			}
		}

		first_iter = 0;
	}

	return (node);
}

/*
 * dt_typecheck_vardefs() ensures that all existing variable definitions are
 * are consistent in their types inside the DIFO (defs list) and across DIFOs
 * which is done using the var_list.
 */
static dt_ifg_node_t *
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
			dt_set_progerr(g_dtp, g_pgp, "failed to get variable information");

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

		/*
		 * The previously inferred variable type must match the
		 * current type we inferred.
		 */
		if (var->dtdv_type.dtdt_kind != type)
			return (NULL);

		if (type == DIF_TYPE_CTF) {
			/*
			 * We get the type name for reporting purposes.
			 */
			if (ctf_type_name(ctf_file, node->din_ctfid, buf1,
			    sizeof(buf1)) != ((char *)buf1))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name %ld: %s",
				    node->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

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
					    "variable name outside strtab "
					    "(%zu, %zu)", var->dtdv_name,
					    difo->dtdo_strlen);

				if (ctf_type_name(ctf_file, var->dtdv_ctfid, buf2,
					sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    var->dtdv_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

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
			if (ctf_type_name(ctf_file, onode->din_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name %ld: %s",
				    onode->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (node->din_ctfid != onode->din_ctfid) {
				fprintf(stderr, "types %s and %s do not match\n",
				    buf1, buf2);
				return (NULL);
			}

			if ((node->din_sym == NULL && onode->din_sym != NULL) ||
			    (node->din_sym != NULL && onode->din_sym == NULL)) {
				fprintf(stderr,
				    "node or onode is missing a symbol\n");
				return (NULL);
			}

			if ((node->din_sym == NULL && var->dtdv_sym != NULL) ||
			    (node->din_sym != NULL && var->dtdv_sym == NULL)) {
				fprintf(stderr,
				    "node or dif_var is missing a symbol\n");
				return (NULL);
			}

			/*
			 * We don't have to check anything except for
			 * node->din_sym being not NULL 
			 */
			if (node->din_sym &&
			    strcmp(node->din_sym, onode->din_sym) != 0) {
				fprintf(stderr, "nodes have different "
				    "symbols: %s != %s\n", node->din_sym,
				    onode->din_sym);
				return (NULL);
			}

			if (node->din_sym &&
			    strcmp(node->din_sym, var->dtdv_sym) != 0) {
				fprintf(stderr, "node and var "
				    "have different symbols: %s != %s\n",
				    node->din_sym, onode->din_sym);
				return (NULL);
			}

		}
	}

	return (node);
}

/*
 * dt_infer_type_var() figures out the type of a variable in the varlist and
 * typechecks it against dr.
 */
static int
dt_infer_type_var(dtrace_difo_t *difo, dt_ifg_node_t *dr, dtrace_difv_t *dif_var)
{
	char buf[4096] = {0}, var_type[4096] = {0};
	dtrace_difv_t *difovar;

	difovar = NULL;

	if (dr == NULL && dif_var == NULL) {
		fprintf(stderr, "both dr and dif_var are NULL\n");
		return (-1);
	}

	if (dr == NULL)
		return (dif_var->dtdv_type.dtdt_kind);

	if (dif_var == NULL) {
		fprintf(stderr, "dif_var is NULL, this makes no sense\n");
		return (-1);
	}

	if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_NONE &&
	    dif_var->dtdv_type.dtdt_kind != dr->din_type) {
		fprintf(stderr, "dif_var and dr have different types: %d != %d",
		    dif_var->dtdv_type.dtdt_kind, dr->din_type);

		return (-1);
	}

	if (dr->din_type == DIF_TYPE_NONE || dr->din_type == DIF_TYPE_BOTTOM)
		dt_set_progerr(g_dtp, g_pgp, "unexpected type %d", dr->din_type);

	if (dif_var->dtdv_type.dtdt_kind == DIF_TYPE_STRING)
		return (DIF_TYPE_STRING);

	if (dif_var->dtdv_ctfid != CTF_ERR) {
		if (dif_var->dtdv_ctfid != dr->din_ctfid) {
			if (ctf_type_name(
			    ctf_file, dif_var->dtdv_ctfid, var_type,
			    sizeof(var_type)) != ((char *)var_type))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name %ld: %s",
				    dif_var->dtdv_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (ctf_type_name(
			    ctf_file, dr->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name %ld: %s",
				    dr->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			fprintf(stderr, "type mismatch in STTS: %s != %s\n",
			    var_type, buf);

			return (-1);
		}

		if (dif_var->dtdv_sym != NULL) {
			if (dr->din_sym && strcmp(
				dif_var->dtdv_sym, dr->din_sym) != 0) {
				fprintf(stderr,
				    "symbol name mismatch: %s != %s\n",
				    dif_var->dtdv_sym, dr->din_sym);

				return (-1);
			} else if (dr->din_sym == NULL) {
				fprintf(stderr, "din_sym is NULL\n");
				return (-1);
			}
		}
	} else {
		dif_var->dtdv_ctfid = dr->din_ctfid;
		dif_var->dtdv_sym = dr->din_sym;
		dif_var->dtdv_type.dtdt_kind = dr->din_type;
		dif_var->dtdv_type.dtdt_size = ctf_type_size(
		    ctf_file, dr->din_ctfid);
		dif_var->dtdv_type.dtdt_ckind = dr->din_ctfid;
	}

	return (DIF_TYPE_CTF);
}
/*
 * dt_var_stack_typecheck() ensures that all the stacks at variable use
 * and definition site across all branches are consistent in their types.
 * Moreover, ensure that if we already have a variable in our varlist that
 * corresponds to the variable we are currently inferring/checking the type
 * of, ensure that the types there are consistent as well.
 */
static int
dt_var_stack_typecheck(dt_ifg_node_t *n, dt_ifg_node_t *dr1, dtrace_difv_t *dif_var)
{
	dt_stacklist_t *sl;
	dt_stack_t *se1, *se2;
	dt_ifg_node_t *var_stacknode, *node;
	char buf[4096] = {0}, var_type[4096] = {0};

	sl = NULL;
	se1 = se2 = NULL;
	var_stacknode = node = NULL;

	if (dr1 == NULL && dif_var == NULL) {
		fprintf(stderr, "both dr1 and dif_var are NULL");
		return (-1);
	}

	/*
	 * If there was nothing to typecheck above, then we simply create a new
	 * stack for the variable using the data from what we were comparing it
	 * to and move on.
	 */
	if (dif_var->dtdv_stack == NULL) {
		dif_var->dtdv_stack = malloc(sizeof(dt_list_t));
		if (dif_var->dtdv_stack == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to malloc dtdv_stack");

		memset(dif_var->dtdv_stack, 0, sizeof(dt_list_t));

		sl = dt_list_next(&n->din_stacklist);
		if (sl == NULL)
			dt_set_progerr(g_dtp, g_pgp, "sl is NULL, nonsense.");

		for (se1 = dt_list_next(&sl->dsl_stack);
		     se1; se1 = dt_list_next(se1)) {
			se2 = malloc(sizeof(dt_stack_t));
			if (se2 == NULL)
				dt_set_progerr(g_dtp, g_pgp, "failed to malloc se2");

			memset(se2, 0, sizeof(dt_stack_t));

			se2->ds_ifgnode = se1->ds_ifgnode;
			dt_list_append(dif_var->dtdv_stack, se2);
		}

		return (0);
	} else if (dr1 == NULL)
		return (0);

	/*
	 * In the case that we _do_ have a variable in our varlist, we
	 * check that the types of the inside DIFO definition and the varlist
	 * definition are consistent.
	 */
	for (sl = dt_list_next(&n->din_stacklist); sl != NULL;
	     sl = dt_list_next(sl)) {
		for (se1 = dt_list_next(&sl->dsl_stack),
		     se2 = dt_list_next(dif_var->dtdv_stack);
		     se1 && se2;
		     se1 = dt_list_next(se1), se2 = dt_list_next(se2)) {
			node = se1->ds_ifgnode;
			var_stacknode = se2->ds_ifgnode;

			if (node->din_type != var_stacknode->din_type) {
				fprintf(stderr, "type mismatch in variable\n");
				return (-1);
			}

			if (node->din_type == DIF_TYPE_CTF) {
				if (ctf_type_name(ctf_file, node->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    dr1->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				if (ctf_type_name(ctf_file,
				    var_stacknode->din_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    var_stacknode->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				if (var_stacknode->din_ctfid !=
				    node->din_ctfid) {
					fprintf(stderr, "type mismatch "
					    "in stgaa: %s != %s\n",
					    buf, var_type);

					return (-1);
				}
			}
		}
	}

	return (0);
}

/*
 * dt_typecheck_stack() ensures that everything on the stack across all branches
 * is consistent with its types.
 */
static dt_list_t *
dt_typecheck_stack(dt_list_t *stacklist, int *empty)
{
	dt_stacklist_t *sl;
	dt_list_t *stack, *ostack;
	dt_stack_t *se, *ose;
	dt_ifg_node_t *n, *on;
	char buf1[4096] = {0}, buf2[4096] = {0};

	se = ose = NULL;
	stack = ostack = NULL;
	sl = NULL;
	n = on = NULL;
	*empty = 1;

	for (sl = dt_list_next(stacklist); sl; sl = dt_list_next(sl)) {
		*empty = 0;
		ostack = stack;
		stack = &sl->dsl_stack;

		assert(stack != NULL);

		/*
		 * Infer types on the stack.
		 */
		for (se = dt_list_next(stack); se; se = dt_list_next(se)) {
			n = se->ds_ifgnode;
			if (dt_infer_type(n) == -1)
				dt_set_progerr(g_dtp, g_pgp, "failed to infer type for"
				    "opcode %d at %zu\n",
				    n->din_buf[n->din_uidx], n->din_uidx);
		}

		if (ostack == NULL)
			continue;

		for (se = dt_list_next(stack), ose = dt_list_next(ostack);
		     se && ose; se = dt_list_next(se), ose = dt_list_next(ose)) {
			n = se->ds_ifgnode;
			on = ose->ds_ifgnode;

			if (n->din_type != on->din_type) {
				fprintf(stderr,
				    "stack type mismatch: %d != %d\n",
				    n->din_type, on->din_type);

				return (NULL);
			}

			if (n->din_ctfid != on->din_ctfid) {
				if (ctf_type_name(ctf_file, n->din_ctfid, buf1,
				    sizeof(buf1)) != ((char *)buf1))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    n->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				if (ctf_type_name(ctf_file, on->din_ctfid, buf2,
				    sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting type name %ld: %s",
					    on->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				fprintf(stderr,
				    "stack ctf type mismatch: %s != %s\n",
				    buf1, buf2);

				return (NULL);
			}

			if (n->din_sym || on->din_sym) {
				fprintf(stderr, "symbol found on stack\n");
				return (NULL);
			}
		}
	}

	return (stack);
}

/*
 * This is the main part of the type inference algorithm.
 */
static int
dt_infer_type(dt_ifg_node_t *n)
{
	dt_ifg_node_t *dn1, *dn2, *dnv, *tc_n,
	    *symnode, *other, *var_stacknode, *node,
	    *data_dn1, *data_dn2;
	int type1, type2, res, i, t;
	char buf[4096] = {0}, symname[4096] = {0}, var_type[4096] = {0};
	ctf_membinfo_t *mip;
	size_t l;
	uint16_t var;
	dtrace_difo_t *difo;
	dif_instr_t instr, dn1_instr;
	uint8_t opcode, dn1_op;
	uint16_t sym, subr;
	dt_stacklist_t *sl;
	dt_ifg_node_t *arg0, *arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *arg7, *arg8;
	ctf_file_t *octfp = NULL;
	ctf_id_t type = 0;
	dtrace_difv_t *dif_var;
	dt_pathlist_t *il;
	dt_stack_t *se;
	dt_list_t *stack;
	int empty;

	empty = 1;
        se = NULL;
	il = NULL;
	dn1 = dn2 = dnv = var_stacknode = node = NULL;
	type1 = -1;
	type2 = -1;
	mip = NULL;
	sl = NULL;
	l = 0;
	difo = n->din_difo;
	instr = dn1_instr = 0;
	opcode = dn1_op = 0;
	sym = 0;
	res = 0;
	tc_n = NULL;
	symnode = NULL;
	other = NULL;
	var = 0;
	i = 0;
	subr = 0;
	arg0 = arg1 = arg2 = arg3 = arg4 = arg5 = arg6 = arg7 = arg8 = NULL;
	t = 0;
	dif_var = NULL;
	stack = NULL;

	/*
	 * If we already have the type, we just return it.
	 */
	if (n->din_type != -1)
		return (n->din_type);

	instr = n->din_buf[n->din_uidx];
	opcode = DIF_INSTR_OP(instr);

        dn1 = dt_typecheck_regdefs(&n->din_r1defs, &empty);
	if (dn1 == NULL && empty == 0) {
		fprintf(stderr, "inferring types for r1defs failed\n");
		return (-1);
	}

        dn2 = dt_typecheck_regdefs(&n->din_r2defs, &empty);
	if (dn2 == NULL && empty == 0) {
		fprintf(stderr, "inferring types for r2defs failed\n");
		return (-1);
	}

	data_dn1 = dt_typecheck_regdefs(&n->din_r1datadefs, &empty);
	if (data_dn1 == NULL && empty == 0) {
		fprintf(stderr, "inferring types for r1datadefs failed\n");
		return (-1);
	}

        data_dn2 = dt_typecheck_regdefs(&n->din_r2datadefs, &empty);
	if (data_dn2 == NULL && empty == 0) {
		fprintf(stderr, "inferring types for r2datadefs failed\n");
		return (-1);
	}

	dnv = dt_typecheck_vardefs(difo, &n->din_vardefs, &empty);
	if (dnv == NULL && empty == 0) {
		fprintf(stderr, "inferring types for vardefs failed\n");
		return (-1);
	}

	stack = dt_typecheck_stack(&n->din_stacklist, &empty);
	if (stack == NULL && empty == 0) {
		fprintf(stderr, "inferring types for stack failed\n");
		return (-1);
	}

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		/*
		 *  %r1 : t1 | sym    sym in range(symtab)
		 *        symtab(sym) = symname
		 *       t2 = type_at(t1, symname)
		 * ----------------------------------------
		 *      opcode [%r1], %r2 => %r2 : t2
		 */

		/*
		 * We only need one type here (the first one).
		 */
		if (dn1 == NULL) {
			fprintf(stderr, "uload/uuload dn1 is NULL\n");
			return (-1);
		}

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dn1->din_sym == NULL) {
			fprintf(stderr, "uload/uuload dn1 symbol is empty\n");
			return (-1);
		}

		/*
		 * sym in range(symtab)
		 */
		if ((uintptr_t)dn1->din_sym >= ((uintptr_t)difo->dtdo_symtab) + difo->dtdo_symlen)
			dt_set_progerr(g_dtp, g_pgp, "sym (%p) is out of range: %p",
			    dn1->din_sym,
			    (void *)(((uintptr_t)difo->dtdo_symtab) +
			    difo->dtdo_symlen));

		/*
		 * Get the original type name of dn1->din_ctfid for
		 * error reporting.
		 */
		if (ctf_type_name(ctf_file, dn1->din_ctfid, buf,
		    sizeof(buf)) != ((char *)buf))
			dt_set_progerr(g_dtp, g_pgp,
			    "failed at getting type name %ld: %s",
			    dn1->din_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));


		if (dt_get_class(buf) != DTC_STRUCT)
			return (-1);

		/*
		 * Figure out t2 = type_at(t1, symname)
		 */
		mip = malloc(sizeof(ctf_membinfo_t));
		if (mip == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to malloc mip");

		memset(mip, 0, sizeof(ctf_membinfo_t));

		/*
		 * Get the non-pointer type. This should NEVER fail.
		 */
		type = ctf_type_reference(ctf_file, dn1->din_ctfid);

		if (dt_lib_membinfo(
		    octfp = ctf_file, type, dn1->din_sym, mip) == 0)
			dt_set_progerr(g_dtp, g_pgp, "failed to get member info"
			    " for %s(%s): %s",
			    buf, dn1->din_sym,
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_mip = mip;
		n->din_ctfid = mip->ctm_type;
		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);


	case DIF_OP_USETX:
		/*
		 *  symtab(idx) = sym    idx in range(symtab)
		 * ------------------------------------------
		 *   usetx idx, %r1 => %r1 : uint64_t | sym
		 */

		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr, "usetx: sym (%u) >= symlen (%zu)\n",
			    sym, difo->dtdo_symlen);
			return (-1);
		}

		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type uint64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_sym = difo->dtdo_symtab + sym;
		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_TYPECAST:
		/*  symtab(idx) = t   idx in range(symtab)    t in ctf_file
		 * ---------------------------------------------------------
		 *                typecast idx, %r1 => %r1 : t
		 */

		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr, "typecast: sym (%u) >= symlen (%zu)\n",
			    sym, difo->dtdo_symlen);
			return (-1);
		}

		l = strlcpy(symname, difo->dtdo_symtab + sym, sizeof(symname));
		if (l >= sizeof(symname))
			dt_set_progerr(g_dtp, g_pgp,
			    "l (%zu) >= %zu when copying type name",
			    l, sizeof(symname));

		n->din_ctfid = ctf_lookup_by_name(ctf_file, symname);
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp, "failed to get type %s: %s",
			    symname, ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);
	/*
	 * Potential information necessary to apply relocations
	 */
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SRA:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
		/*
		 * In this rule, we allow %r1 and %r2 to be swapped.
		 * For the sake of conciseness, we just write out 1 rule.
		 *
		 *  %r1 : t1    %r2 : t2    t2 <: t1
		 * ----------------------------------
		 *  opcode %r1, %r2, %r3 => %r3 : t1
		 *
		 * The second rule has to do with symbol resolution and should
		 * only get applied when one of the two registers contains a
		 * type annotated with a symbol (indicating that the type)
		 * originates from symbol resolution, rather than a poset
		 * relation.
		 *
		 *  %r1 : t1    %r2 : uint64_t | sym    uint64_t <: t1
		 * ----------------------------------------------------
		 *        opcode %r1, %r2, %r3 => %r3 : t1 | sym
		 *
		 * N.B.: We allow this rule to work with a whole bunch of
		 *       arithmetic operations, not only add. This is simply
		 *       because we can't possibly infer all ways that one could
		 *       arrive at a given struct member, so we simply assume
		 *       that the calculation is correct. For example, we could
		 *       have something that looks like:
		 *
		 *  usetx %r1, sym
		 *  sll %r1, %r2, %r1
		 *  srl %r1, %r2, %r1
		 *
		 * where the first %r1 would be of type uint64_t | sym.
		 * Following that, sll %r1, %r2, %r1 => %r1 : uint64_t | sym
		 * and srl %r1, %r2, %r1 => %r1 : uint64_t | sym, still knowing
		 * that this type originates from a symbol.
		 */

		/*
		 * Nonsense. We need both types.
		 */
		if (dn1 == NULL) {
			fprintf(stderr, "r1r2: dn1 is NULL\n");
			return (-1);
		}

		if (dn2 == NULL) {
			fprintf(stderr, "r1r2: dn2 is NULL\n");
			return (-1);
		}

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dn1->din_sym == NULL && dn2->din_sym == NULL) {
			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(dn1, dn2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1)
				tc_n = dn1;
			else if (res == 2)
				tc_n = dn2;
			else {
				fprintf(stderr,
				    "r1r2 nosym: types can not be compared\n");
				return (-1);
			}

			/*
			 * We don't have to sanity check these because we do it
			 * in every base case of the recursive call.
			 */
			n->din_type = tc_n->din_type;
			n->din_ctfid = tc_n->din_ctfid;
		} else {
			symnode = dn1->din_sym != NULL ? dn1 : dn2;
			other = dn1->din_sym != NULL ? dn2 : dn1;

			if (other->din_type == DIF_TYPE_BOTTOM ||
			    symnode->din_type == DIF_TYPE_BOTTOM)
				dt_set_progerr(g_dtp, g_pgp, "unexpected bottom type");

			/*
			 * Get the type name
			 */
			if (ctf_type_name(
			    ctf_file, symnode->din_ctfid,
			    buf, sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", symnode->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (strcmp(buf, "uint64_t") != 0)
				dt_set_progerr(g_dtp, g_pgp, "symbol may not exist if not"
				    " paired with a uint64_t: %s", buf);

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(symnode, other);
			assert(res == 1 || res == 2 || res == -1);

			if (res == -1) {
				fprintf(stderr,
				    "r1r2 sym: types can not be compared\n");
				return (-1);
			}

			/*
			 * Get the type name of the other node
			 */
			if (ctf_type_name(ctf_file, other->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "failed at getting type name %ld: %s",
				    other->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (res == 1) {
				if (strcmp(buf, "uint64_t") != 0)
					dt_set_progerr(g_dtp, g_pgp, "the type of the"
					    " other node must be unit64_t"
					    " if symnode->din_ctfid <: "
					    " other->din_ctfid, but it is: %s",
					    buf);
			}

			/*
			 * At this point, we have ensured that the types are:
			 *  (1) Related (<: exists between t1 and t2)
			 *  (2) Well-ordered: if
			 *
			 *            symnode->din_ctfid <: other->din_ctfid,
			 *
			 *      then other->din_ctfid is also
			 *      uint64_t (reflexivity).
			 *  (3) One of the uint64_ts originates from a symbol.
			 */

			n->din_sym = symnode->din_sym;
			n->din_ctfid = other->din_ctfid;
			n->din_type = DIF_TYPE_CTF;
		}

		return (n->din_type);

	case DIF_OP_MOV:
	case DIF_OP_NOT:
		/*
		 *           %r1 : t
		 * ---------------------------
		 * opcode %r1, %r2 => %r2 : t
		 */

		/*
		 * Nonsense.
		 *
		 * N.B.: We don't need to check that type1 is sane, because
		 *       if dn1 is not NULL, then we'll have checked it already.
		 */
		if (dn1 == NULL) {
			fprintf(stderr, "mov/not: dn1 is NULL\n");
			return (-1);
		}

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		n->din_ctfid = dn1->din_ctfid;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_LDSB:
	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
		/*
		 *          %r1 :: Pointer
		 * -----------------------------------
		 *  opcode [%r1], %r2 => %r2 : int8_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "int8_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type int8_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDSH:
	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int16_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "int16_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type int16_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDSW:
	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int32_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "int32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			     "failed to get type unsigned char: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUB:
	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint8_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint8_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to get type uint8_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUH:
	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint16_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint16_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			     "failed to get type uint16_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUW:
	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint32_t
		 */
		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			     "failed to get type uint32_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_ULDX:
	case DIF_OP_RLDX:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
		/*
		 * ---------------------------------
		 *  setx idx, %r1 => %r1 : uint64_t
		 */

		n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint64_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_SETS:
		/*
		 * --------------------------------
		 *  sets idx, %r1 => %r1: D string
		 */

		n->din_type = DIF_TYPE_STRING;
		return (n->din_type);

	case DIF_OP_LDGA:
		break;

	case DIF_OP_LDLS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldls var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dnv == NULL) {
			if (dif_var == NULL) {
				fprintf(stderr, "variable and dnv don't exist\n");
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;

				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dnv->din_type) {
				fprintf(stderr, "type mismatch %d != %d\n",
				    dif_var->dtdv_type.dtdt_kind, dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dnv->din_ctfid) {
				if (ctf_type_name(ctf_file, dnv->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					errx(EXIT_FAILURE,
					    "failed at getting type name %ld: %s",
					    dnv->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				if (ctf_type_name(ctf_file, dif_var->dtdv_ctfid,
				    var_type,
				    sizeof(var_type)) != ((char *)var_type))
					errx(EXIT_FAILURE,
					    "failed at getting type name %ld: %s",
					    dif_var->dtdv_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				fprintf(stderr,
				    "variable ctf type mismatch %s != %s\n",
				    buf, var_type);
				return (-1);
			}

			if (dnv->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr, "symbol mismatch %s != NULL\n",
					dnv->din_sym);
				return (-1);
			}

			if (dnv->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr, "symbol mismatch NULL != %s\n",
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dnv->din_sym) != 0) {
				fprintf(stderr, "symbol mismatch %s != %s\n",
				    dnv->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dnv->din_ctfid;
		n->din_type = dnv->din_type;
		n->din_mip = dnv->din_mip;
		n->din_sym = dnv->din_sym;

		return (n->din_type);

	case DIF_OP_LDGS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldgs var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dn1 == NULL) {
			if (dt_var_is_builtin(var)) {
				dt_builtin_type(n, var);
				return (n->din_type);
			} else if (dif_var == NULL) {
				fprintf(stderr,
				    "variable %d and dn1 don't exist\n", var);
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;
				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->din_type) {
				fprintf(stderr, "type mismatch %d != %d\n",
				    dif_var->dtdv_type.dtdt_kind, dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->din_ctfid) {
				fprintf(stderr,
				    "variable ctf type mismatch %s != %s\n",
				    buf, var_type);
				return (-1);
			}

			if (dn1->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr, "symbol mismatch %s != NULL\n",
					dn1->din_sym);
				return (-1);
			}

			if (dn1->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr, "symbol mismatch NULL != %s\n",
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->din_sym) != 0) {
				fprintf(stderr, "symbol mismatch %s != %s\n",
				    dn1->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dn1->din_ctfid;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_LDTS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldts var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dn1 == NULL) {
			if (dif_var == NULL) {
				fprintf(stderr, "variable and dn1 don't exist\n");
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;

				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->din_type) {
				fprintf(stderr, "type mismatch %d != %d\n",
				    dif_var->dtdv_type.dtdt_kind, dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->din_ctfid) {
				fprintf(stderr,
				    "variable ctf type mismatch %s != %s\n",
				    buf, var_type);
				return (-1);
			}

			if (dn1->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr, "symbol mismatch %s != NULL\n",
					dn1->din_sym);
				return (-1);
			}

			if (dn1->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr, "symbol mismatch NULL != %s\n",
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->din_sym) != 0) {
				fprintf(stderr, "symbol mismatch %s != %s\n",
				    dn1->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dn1->din_ctfid;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_STGS:
		/*
		 *  %r1 : t       var notin builtins
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stgs %r1, var => var : t
		 *
		 *  %r1 : t       var notin builtins
		 *         var notin var_list
		 * ----------------------------------
		 *     stgs %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		/*
		 * If we are doing a STGS, and the variable is a builtin
		 * variable, we fail to type-check the instruction.
		 */
		if (dt_var_is_builtin(var)) {
			fprintf(stderr,
			    "trying to store to a builtin variable\n");
			return (-1);
		}

		if (dn2 == NULL) {
			fprintf(stderr, "dn2 is NULL in stgs.\n");
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_STTS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stts %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stts %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == NULL) {
			fprintf(stderr, "dn2 is NULL in stts.\n");
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_STLS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stls %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stls %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == NULL) {
			fprintf(stderr, "dn2 is NULL in stls.\n");
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_LDTA:
		break;
	case DIF_OP_CALL:
		/*
		 *     subr : t1 -> t2 ... -> tn -> t
		 *  stack[0] : t1    stack[1] : t2     ...
		 *  stack[n] : tm        m = stacklen - 1
		 *                m >= n
		 * ----------------------------------------
		 *       call subr, %r1 => %r1 : t
		 */

		subr = DIF_INSTR_SUBR(instr);

		/*
		 * We don't care if there are more things on the stack than
		 * the arguments we need, because they will simply not be used.
		 *
		 * Therefore, the transformation where we have
		 *
		 *     foo(a, b);
		 *     bar(a, b, c);
		 *
		 * which results in
		 *
		 *     push a
		 *     push b
		 *     push c
		 *     call foo
		 *     call bar
		 *
		 * is perfectly valid, so we shouldn't fail to type check this.
		 */
		switch (subr) {
		case DIF_SUBR_RAND:
			n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MUTEX_OWNED:
		case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		case DIF_SUBR_MUTEX_TYPE_SPIN:
			/*
			 * We expect a "struct mtx *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "mutex_owned/type() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, mtx_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, mtx_str);
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MUTEX_OWNER:
			/*
			 * We expect a "struct mtx *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "mutex_owner() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, mtx_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, mtx_str);
				return (-1);
			}

#ifdef __FreeBSD__
			n->din_ctfid = ctf_lookup_by_name(ctf_file, thread_str);
#elif defined(illumos)
			/*
			 * illumos not quite supported yet.
			 */
			return (-1);
#endif
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get thread type: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_READ_HELD:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "rw_read_held() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				     ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_WRITE_HELD:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "rw_write_held() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				     ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_ISWRITER:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "rw_iswriter() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYIN:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyin() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			/*
			 * We expect a "size_t" as the second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyin() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYINSTR:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyinstr() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			/*
			 * Check if the second (optional) argument is present
			 */
			se = dt_list_next(se);
			if (sl != NULL) {
				if (se->ds_ifgnode == NULL)
					errx(EXIT_FAILURE,
					    "copyinstr() ds_ifgnode is NULL");

				arg1 = se->ds_ifgnode;

				if (ctf_type_name(ctf_file,
				    arg1->din_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "size_t") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "size_t");
					return (-1);
				}
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_SPECULATION:
			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_PROGENYOF:
			/*
			 * We expect a "pid_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "progenyof() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "pid_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "pid_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_STRLEN:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "strlen() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "size_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type size_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYOUT:
			/*
			 * We expect a "void *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyout() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "uintptr_t" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyout() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a third argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyout() third argument is NULL");

			arg2 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg2->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg2->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			/*
			 * copyout returns void, so there is no point in setting
			 * the type to anything.
			 */
			break;

		case DIF_SUBR_COPYOUTSTR:
			/*
			 * We expect a "char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "char *");
				return (-1);
			}

			/*
			 * We expect a "uintptr_t" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a third argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() third argument is NULL");

			arg2 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg2->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg2->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			/*
			 * copyout returns void, so there is no point in setting
			 * the type to anything.
			 */

			break;

		case DIF_SUBR_ALLOCA:
			/*
			 * We expect a "size_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "alloca() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_BCOPY:
			/*
			 * We expect a "void *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "void *" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a third argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() third argument is NULL");

			arg2 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg2->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg2->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			break;

		case DIF_SUBR_COPYINTO:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			/*
			 * We expect a "void *" as a third argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() third argument is NULL");

			arg2 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg2->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg2->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}


			break;

		case DIF_SUBR_MSGDSIZE:
		case DIF_SUBR_MSGSIZE:
			/*
			 * We expect a "mblk_t *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "msg(d)size() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "mblk_t *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "mblk_t *");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "size_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type size_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_GETMAJOR:
			break;
		case DIF_SUBR_GETMINOR:
			break;

		case DIF_SUBR_DDI_PATHNAME:
			/*
			 * We expect a "void *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "int64_t" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int64_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int64_t");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_LLTOSTR:
			/*
			 * We expect a "int64_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "lltostr() second argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int64_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int64_t");
				return (-1);
			}

			/*
			 * Check if the second (optional) argument is present
			 */
			se = dt_list_next(se);
			if (sl != NULL) {
				if (se->ds_ifgnode == NULL)
					errx(EXIT_FAILURE,
					    "lltostr() ds_ifgnode is NULL");

				arg1 = se->ds_ifgnode;

				if (ctf_type_name(ctf_file,
				    arg1->din_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "int") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "int");
					return (-1);
				}
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_CLEANPATH:
		case DIF_SUBR_DIRNAME:
		case DIF_SUBR_BASENAME:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "basename/dirname/cleanpath() "
				    "first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_STRRCHR:
		case DIF_SUBR_STRCHR:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "strchr() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}
			/*
			 * We expect a "char" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "strchr() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "char") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "char");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_SUBSTR:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "substr() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}
			/*
			 * We expect a "int" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "substr() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int");
				return (-1);
			}

			/*
			 * Check if the third (optional) argument is present
			 */
			if (sl != NULL) {
				if (se->ds_ifgnode == NULL)
					errx(EXIT_FAILURE,
					    "substr() ds_ifgnode is NULL");

				arg2 = se->ds_ifgnode;

				if (ctf_type_name(ctf_file,
				    arg2->din_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg2->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "int") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "int");
					return (-1);
				}
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_RINDEX:
		case DIF_SUBR_INDEX:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "(r)index() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			/*
			 * We expect a "const char *" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "(r)index() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			/*
			 * Check if the third (optional) argument is present
			 */
			if (sl != NULL) {
				if (se->ds_ifgnode == NULL)
					errx(EXIT_FAILURE,
					    "(r)index() ds_ifgnode is NULL");

				arg2 = se->ds_ifgnode;

				if (ctf_type_name(ctf_file,
				    arg2->din_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg2->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "int") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "int");
					return (-1);
				}
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHS:
		case DIF_SUBR_HTONS:
			/*
			 * We expect a "uint16_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ntohs/htons() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint16_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint16_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint16_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint16_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHL:
		case DIF_SUBR_HTONL:
			/*
			 * We expect a "uint32_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ntohl/htonl() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint32_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint32_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint32_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHLL:
		case DIF_SUBR_HTONLL:
			/*
			 * We expect a "uint64_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ntohll/htonll() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint64_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint64_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_INET_NTOP:
			/*
			 * We expect a "int" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntop() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int");
				return (-1);
			}

			/*
			 * We expect a "void *" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA:
			/*
			 * We expect a "in_addr_t *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntoa() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "in_addr_t *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "in_addr_t *");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA6:
			/*
			 * We expect a "struct in6_addr *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntoa6() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "struct in6_addr *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "struct in6_addr *");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_TOLOWER:
		case DIF_SUBR_TOUPPER:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "toupper/tolower() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_MEMREF:
			/*
			 * We expect a "void *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "memref() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "memref() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(
			    ctf_file, "uintptr_t *");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uintptr_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_SX_SHARED_HELD:
		case DIF_SUBR_SX_EXCLUSIVE_HELD:
		case DIF_SUBR_SX_ISEXCLUSIVE:
			/*
			 * We expect a sx_str as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "sx_*() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, sx_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, sx_str);
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (n->din_ctfid == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MEMSTR:
			/*
			 * We expect a "void *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "memstr() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			/*
			 * We expect a "char" as a second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "memstr() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg1->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "char") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "char");
				return (-1);
			}

			/*
			 * We expect a "size_t" as a third argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "memstr() second argument is NULL");

			arg2 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg2->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg2->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}


			n->din_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_GETF:
			/*
			 * We expect a "int" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "getf() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "file_t *");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type file_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_STRTOLL:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "strtoll() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			/*
			 * Check if the second (optional) argument is present
			 */
			se = dt_list_next(se);
			if (sl != NULL) {
				if (se->ds_ifgnode == NULL)
					errx(EXIT_FAILURE,
					    "strtoll() ds_ifgnode is NULL");

				arg1 = se->ds_ifgnode;

				if (ctf_type_name(ctf_file,
				    arg1->din_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "int") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "int");
					return (-1);
				}
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "int64_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type int64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RANDOM:
			n->din_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_PTINFO:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "ptinfo() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (ctf_type_name(ctf_file,
			    arg0->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", arg0->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			n->din_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (n->din_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_STRTOK:
		case DIF_SUBR_STRSTR:
		case DIF_SUBR_STRJOIN:
		case DIF_SUBR_STRJOIN_HH:
		case DIF_SUBR_STRJOIN_HG:
		case DIF_SUBR_STRJOIN_GH:
		case DIF_SUBR_STRJOIN_GG:
		case DIF_SUBR_JSON:
			/*
			 * We expect a "const char *" as an argument.
			 */
			se = dt_list_next(stack);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "str/json() first argument is NULL");

			arg0 = se->ds_ifgnode;

			if (arg0->din_type == DIF_TYPE_CTF) {
				if (ctf_type_name(ctf_file,
				    arg0->din_ctfid, buf,
				    sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg0->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "const char *") != 0 &&
				    strcmp(buf, "char *") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "const char */char *");
					return (-1);
				}
			} else if (arg0->din_type == DIF_TYPE_NONE) {
				fprintf(stderr, "str/json arg0 type is NONE\n");
				return (-1);
			}

			/*
			 * We expect a "const char *" as the second argument.
			 */
			se = dt_list_next(se);
			if (se == NULL || se->ds_ifgnode == NULL)
				errx(EXIT_FAILURE,
				    "str/json() second argument is NULL");

			arg1 = se->ds_ifgnode;

			if (arg1->din_type == DIF_TYPE_CTF) {
				if (ctf_type_name(ctf_file,
				    arg1->din_ctfid, buf,
				    sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->din_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				/*
				 * If the argument type is wrong, fail to type check.
				 */
				if (strcmp(buf, "const char *") != 0 &&
				    strcmp(buf, "char *") != 0) {
					fprintf(stderr, "%s and %s are not the same",
					    buf, "const char *");
					return (-1);
				}
			} else if (arg0->din_type == DIF_TYPE_NONE) {
				fprintf(stderr, "str/json arg0 type is NONE\n");
				return (-1);
			}

			n->din_type = DIF_TYPE_STRING;
			break;
		default:
			return (-1);
		}

		return (n->din_type);

	case DIF_OP_LDGAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (dt_list_next(&n->din_stacklist) == NULL) {
			fprintf(stderr, "stack list is empty in ldgaa\n");
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (dt_var_stack_typecheck(n, dnv, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(n->din_difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->din_ctfid = dnv->din_ctfid;
			n->din_type = dnv->din_type;
			n->din_mip = dnv->din_mip;
			n->din_sym = dnv->din_sym;
		} else {
			n->din_ctfid = dif_var->dtdv_ctfid;
			n->din_type = dif_var->dtdv_type.dtdt_kind;
			n->din_sym = dif_var->dtdv_sym;
		}

		return (n->din_type);

	case DIF_OP_LDTAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (dt_list_next(&n->din_stacklist) == NULL) {
			fprintf(stderr, "stack list is empty in ldgaa\n");
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (dt_var_stack_typecheck(n, dnv, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(n->din_difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->din_ctfid = dnv->din_ctfid;
			n->din_type = dnv->din_type;
			n->din_mip = dnv->din_mip;
			n->din_sym = dnv->din_sym;
		} else {
			n->din_ctfid = dif_var->dtdv_ctfid;
			n->din_type = dif_var->dtdv_type.dtdt_kind;
			n->din_sym = dif_var->dtdv_sym;
		}

		return (n->din_type);

	case DIF_OP_STGAA:
		if (dn2 == NULL) {
			fprintf(stderr, "dn2 is NULL in stgaa.\n");
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  x[curthread] = 1;
		 *  x[tid] = 2;
		 */

		if (dt_var_stack_typecheck(n, dn2, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_STTAA:
		if (dn2 == NULL) {
			fprintf(stderr, "dn2 is NULL in sttaa.\n");
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp, "failed to find variable (%u, %d, %d)",
			    var, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  self->x[curthread] = 1;
		 *  self->x[tid] = 2;
		 */
		if (dt_var_stack_typecheck(n, dn2, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_ALLOCS:
		n->din_ctfid = 0;
		n->din_type = DIF_TYPE_CTF;
		n->din_mip = NULL;
		n->din_sym = NULL;

		return (n->din_type);

	case DIF_OP_COPYS:
		n->din_ctfid = dn1->din_ctfid;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_RET:
		if (dn1 == NULL) {
			fprintf(stderr, "ret dn1 is NULL\n");
			return (-1);
		}

		if (dn1->din_sym != NULL) {
			/*
			 * We only need one type here (the first one).
			 */

			/*
			 * sym in range(symtab)
			 */
			if ((uintptr_t)dn1->din_sym >=
			    ((uintptr_t)difo->dtdo_symtab) + difo->dtdo_symlen)
				dt_set_progerr(g_dtp, g_pgp, "sym (%p) is out of range: %p",
				    dn1->din_sym,
				    (void *)(((uintptr_t)difo->dtdo_symtab) +
				    difo->dtdo_symlen));

			/*
			 * Get the original type name of dn1->din_ctfid for
			 * error reporting.
			 */
			if (ctf_type_name(ctf_file, dn1->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    dn1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));


			if (dt_get_class(buf) != DTC_STRUCT)
				return (-1);

			/*
			 * Figure out t2 = type_at(t1, symname)
			 */
			mip = malloc(sizeof(ctf_membinfo_t));
			if (mip == NULL)
				dt_set_progerr(g_dtp, g_pgp, "failed to malloc mip");

			memset(mip, 0, sizeof(ctf_membinfo_t));

			/*
			 * Get the non-pointer type. This should NEVER fail.
			 */
			type = ctf_type_reference(ctf_file, dn1->din_ctfid);

			if (dt_lib_membinfo(
				octfp = ctf_file, type, dn1->din_sym, mip) == 0)
				dt_set_progerr(g_dtp, g_pgp, "failed to get member info"
				    " for %s(%s): %s",
				    buf, dn1->din_sym,
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_mip = mip;
			n->din_ctfid = mip->ctm_type;
			n->din_type = DIF_TYPE_CTF;
		} else {
			n->din_ctfid = dn1->din_ctfid;
			n->din_type = dn1->din_type;
		}

		return (n->din_type);

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTR_G:
	case DIF_OP_PUSHTR_H:
		if (dn1 == NULL) {
			fprintf(stderr, "pushtr dn1 is NULL\n");
			return (-1);
		}

		if (data_dn1->din_sym != NULL) {
			/*
			 * We only need one type here (the first one).
			 */

			/*
			 * sym in range(symtab)
			 */
			if ((uintptr_t)data_dn1->din_sym >=
			    ((uintptr_t)difo->dtdo_symtab) + difo->dtdo_symlen)
				dt_set_progerr(g_dtp, g_pgp, "sym (%p) is out of range: %p",
				    data_dn1->din_sym,
				    (void *)(((uintptr_t)difo->dtdo_symtab) +
					difo->dtdo_symlen));

			/*
			 * Get the original type name of dn1->din_ctfid for
			 * error reporting.
			 */
			if (ctf_type_name(ctf_file, data_dn1->din_ctfid, buf,
				sizeof(buf)) != ((char *)buf))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    data_dn1->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (dt_get_class(buf) != DTC_STRUCT)
				return (-1);

			/*
			 * Figure out t2 = type_at(t1, symname)
			 */
			mip = malloc(sizeof(ctf_membinfo_t));
			if (mip == NULL)
				dt_set_progerr(g_dtp, g_pgp, "failed to malloc mip");

			memset(mip, 0, sizeof(ctf_membinfo_t));

			/*
			 * Get the non-pointer type. This should NEVER fail.
			 */
			type = ctf_type_reference(ctf_file, data_dn1->din_ctfid);

			if (dt_lib_membinfo(
			    octfp = ctf_file, type, data_dn1->din_sym, mip) == 0)
				dt_set_progerr(g_dtp, g_pgp, "failed to get member info"
				    " for %s(%s): %s",
				    buf, data_dn1->din_sym,
				    ctf_errmsg(ctf_errno(ctf_file)));

			n->din_mip = mip;
			/*
			 * This should only happen with a typecast.
			 */
			if (dn1 != data_dn1) {
				dn1_instr = dn1->din_buf[dn1->din_uidx];
				dn1_op = DIF_INSTR_OP(dn1_instr);

				assert(dn1_op == DIF_OP_TYPECAST);

				n->din_ctfid = dn1->din_ctfid;
				n->din_type = dn1->din_type;
			} else {
				n->din_ctfid = mip->ctm_type;
				n->din_type = DIF_TYPE_CTF;
			}
		} else if (dn1->din_type == DIF_TYPE_CTF) {
			n->din_ctfid = dn1->din_ctfid;
			n->din_type = dn1->din_type;
		} else
			n->din_type = dn1->din_type;

		return (DIF_TYPE_NONE);

	case DIF_OP_PUSHTV:
		n->din_ctfid = dn1->din_ctfid;
		n->din_type = dn1->din_type;
		return (DIF_TYPE_NONE);

	case DIF_OP_FLUSHTS:
	case DIF_OP_POPTS:
	case DIF_OP_CMP:
	case DIF_OP_SCMP:
	case DIF_OP_SCMP_HH:
	case DIF_OP_SCMP_GG:
	case DIF_OP_SCMP_GH:
	case DIF_OP_SCMP_HG:
	case DIF_OP_HYPERCALL:
	case DIF_OP_TST:
	case DIF_OP_BA:
	case DIF_OP_BE:
	case DIF_OP_BNE:
	case DIF_OP_BG:
	case DIF_OP_BGU:
	case DIF_OP_BGE:
	case DIF_OP_BGEU:
	case DIF_OP_BL:
	case DIF_OP_BLU:
	case DIF_OP_BLE:
	case DIF_OP_BLEU:
	case DIF_OP_NOP:
		return (DIF_TYPE_NONE);

	default:
		dt_set_progerr(g_dtp, g_pgp, "unhandled instruction: %u", opcode);
	}

	return (-1);
}

int
dt_prog_infer_types(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_ifg_node_t *node = NULL;
	dt_ifg_list_t *ifgl = NULL;
	dif_instr_t instr = 0;
	uint_t opcode = 0;
	uint_t rd = 0;
	int type = -1;
	char buf[4096] = {0};


	/*
	 * A DIFO without instructions makes no sense.
	 */
	if (difo->dtdo_buf == NULL)
		return (EDT_DIFINVAL);

	/*
	 * If we don't have a table, length MUST be 0.
	 */
	if (difo->dtdo_inttab == NULL && difo->dtdo_intlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_strtab == NULL && difo->dtdo_strlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_vartab == NULL && difo->dtdo_varlen != 0)
		return (EDT_DIFINVAL);
	if (difo->dtdo_symtab == NULL && difo->dtdo_symlen != 0)
		return (EDT_DIFINVAL);

	/*
	 * If the symbol length is 0 and the symbol table is 0, we don't
	 * have any relocations to apply. In this case, we just return that
	 * no error occurred and leave the DIFO as it is.
	 */
	if (difo->dtdo_symtab == NULL)
		return (0);

	if (pgp == NULL)
		return (EDT_COMPILER);

	if (dtp == NULL)
		return (EDT_COMPILER);

	g_dtp = dtp;
	g_pgp = pgp;

	difo->dtdo_types = malloc(sizeof(char *) * difo->dtdo_len);
	if (difo->dtdo_types == NULL)
		dt_set_progerr(g_dtp, g_pgp, "failed to malloc dtdo_types");

	i = difo->dtdo_len - 1;

	for (ifgl = dt_list_next(&node_list);
	    ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		node = ifgl->dil_ifgnode;

		if (node->din_buf == NULL)
			continue;

		if (node->din_buf != difo->dtdo_buf)
			continue;

		instr = node->din_buf[node->din_uidx];
		opcode = DIF_INSTR_OP(instr);

		type = dt_infer_type(node);
		assert(type == -1 ||
		    type == DIF_TYPE_CTF || type == DIF_TYPE_STRING ||
		    type == DIF_TYPE_NONE || type == DIF_TYPE_BOTTOM);

		if (type == -1)
			dt_set_progerr(g_dtp, g_pgp, "failed to infer a type");

		if (type == DIF_TYPE_CTF) {
			if (ctf_type_name(ctf_file,
			    node->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp, "failed at getting type name"
				    " %ld: %s", node->din_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));
			difo->dtdo_types[node->din_uidx] = strdup(buf);
		} else if (type == DIF_TYPE_STRING)
			difo->dtdo_types[node->din_uidx] = strdup("string");
		else if (type == DIF_TYPE_NONE)
			difo->dtdo_types[node->din_uidx] = strdup("none");
		else if (type == DIF_TYPE_BOTTOM)
			difo->dtdo_types[node->din_uidx] = strdup("bottom");
		else
			difo->dtdo_types[node->din_uidx] = strdup("ERROR");

	}

	g_pgp = NULL;
	g_dtp = NULL;
	
	return (0);
}
