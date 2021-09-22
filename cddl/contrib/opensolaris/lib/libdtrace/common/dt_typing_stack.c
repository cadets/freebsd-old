/*-
 * Copyright (c) 2020, 2021 Domagoj Stolfa
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
#include <dt_typing_helpers.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_stack.h>

/*
 * dt_var_stack_typecheck() ensures that all the stacks at variable use
 * and definition site across all branches are consistent in their types.
 * Moreover, ensure that if we already have a variable in our varlist that
 * corresponds to the variable we are currently inferring/checking the type
 * of, ensure that the types there are consistent as well.
 */
int
dt_var_stack_typecheck(dt_ifg_node_t *n, dt_ifg_node_t *dr1,
    dtrace_difv_t *dif_var)
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

			if (node->din_tf != var_stacknode->din_tf) {
				fprintf(stderr, "typefile mismatch: %s != %s\n",
				    dt_typefile_stringof(node->din_tf),
				    dt_typefile_stringof(
					var_stacknode->din_tf));
				return (-1);
			}

			if (node->din_type == DIF_TYPE_CTF) {
				if (dt_typefile_typename(node->din_tf,
				    node->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting "
					    "type name %ld: %s",
					    dr1->din_ctfid,
					    dt_typefile_error(node->din_tf));

				if (dt_typefile_typename(var_stacknode->din_tf,
				    var_stacknode->din_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(g_dtp, g_pgp,
					    "failed at getting "
					    "type name %ld: %s",
					    var_stacknode->din_ctfid,
					    dt_typefile_error(
						var_stacknode->din_tf));

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
dt_list_t *
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
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_typecheck_stack(): failed to infer "
				    "type for opcode %d at %zu (%p)\n",
				    n->din_buf[n->din_uidx], n->din_uidx,
				    n->din_difo);
		}

		if (ostack == NULL)
			continue;

		for (se = dt_list_next(stack), ose = dt_list_next(ostack);
		     se && ose;
		     se = dt_list_next(se), ose = dt_list_next(ose)) {
			n = se->ds_ifgnode;
			on = ose->ds_ifgnode;

			if (n->din_type != on->din_type) {
				fprintf(stderr,
				    "dt_typecheck_stack(): stack type "
				    "mismatch at %zu and %zu (%p): %d != %d\n",
				    n->din_uidx, on->din_uidx, n->din_difo,
				    n->din_type, on->din_type);

				return (NULL);
			}

			/*
			 * TODO(dstolfa, important): We don't really want to
			 * compare by ctfid anymore because when we compare
			 * types across modules, we will have differing ctfids.
			 * We instead need to compare this via strings or some
			 * other mechanism...
			 */
			if (n->din_ctfid != on->din_ctfid) {
				if (dt_typefile_typename(n->din_tf,
				    n->din_ctfid, buf1,
				    sizeof(buf1)) != ((char *)buf1))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_stack(): failed at "
					    "getting type name %ld: %s",
					    n->din_ctfid,
					    dt_typefile_error(n->din_tf));

				if (dt_typefile_typename(on->din_tf,
				    on->din_ctfid, buf2,
				    sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_stack(): failed at"
					    "getting type name %ld: %s",
					    on->din_ctfid,
					    dt_typefile_error(on->din_tf));

				fprintf(stderr,
				    "dt_typecheck_stack(): stack ctf type "
				    "mismatch at %zu and %zu (%p): %s != %s\n",
				    n->din_uidx, on->din_uidx, n->din_difo,
				    buf1, buf2);

				return (NULL);
			}

			if (n->din_sym || on->din_sym) {
				fprintf(stderr,
				    "dt_typecheck_stack(): symbol found "
				    "on stack at %zu (%p)\n",
				    n->din_sym ? n->din_uidx : on->din_uidx,
				    n->din_difo);
				return (NULL);
			}
		}
	}

	return (stack);
}
