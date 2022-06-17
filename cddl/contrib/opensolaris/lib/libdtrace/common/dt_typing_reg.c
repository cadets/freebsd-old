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

#include <dt_typing_reg.h>

/*
 * dt_typecheck_regdefs() takes in a list of nodes that define
 * the current node we are looking at and ensures that their types
 * are consistent.
 */
dt_ifg_node_t *
dt_typecheck_regdefs(dt_list_t *defs, int *empty)
{
	dt_ifg_list_t *ifgl;
	dt_ifg_node_t *node, *onode;
	char buf1[4096] = {0}, buf2[4096] = {0};
	int type, otype;
	int class1, class2;
	int first_iter;
	int which;

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

		if (type == DIF_TYPE_STRING || otype == DIF_TYPE_STRING) {
			dt_ifg_node_t *str_node, *other_node;
			int string_type, other_type;

			str_node = type == DIF_TYPE_STRING ? node : onode;
			other_node = type == DIF_TYPE_STRING ? onode : node;

			string_type = str_node->din_type;
			other_type = other_node->din_type;

			if (other_type == DIF_TYPE_BOTTOM)
				continue;

			if (other_type ==  DIF_TYPE_STRING) {
				first_iter = 0;
				continue;
			}

			if (other_type == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				if (dt_typefile_typename(other_node->din_tf,
				    other_node->din_ctfid, buf2,
				    sizeof(buf2)) != ((char *)buf2))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_regdefs(): failed at "
					    "getting type name node %ld: %s",
					    other_node->din_ctfid,
					    dt_typefile_error(other_node->din_tf));

				if (strcmp(buf2, "const char *") == 0 ||
				    strcmp(buf2, "char *") == 0 ||
				    strcmp(buf2, "string") == 0) {
					first_iter = 0;
					continue;
				}
			}
		}

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (first_iter == 0 && otype != type) {
			char otype_str[256] = { 0 };
			char ctype_str[256] = { 0 };

			if (otype == DIF_TYPE_STRING) {
				strcpy(otype_str, "D string");
			} else if (otype == DIF_TYPE_BOTTOM) {
				strcpy(otype_str, "D bottom type");
			} else if (otype == DIF_TYPE_NONE) {
				strcpy(otype_str, "none");
			} else if (otype == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				if (dt_typefile_typename(onode->din_tf,
				    onode->din_ctfid, otype_str,
				    sizeof(otype_str)) != ((char *)otype_str))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_regdefs(): failed at "
					    "getting type name node %ld: %s",
					    onode->din_ctfid,
					    dt_typefile_error(onode->din_tf));
			} else {
				strcpy(otype_str, "unknown (ERROR)");
			}

			if (type == DIF_TYPE_STRING) {
				strcpy(ctype_str, "D string");
			} else if (type == DIF_TYPE_BOTTOM) {
				strcpy(ctype_str, "D bottom type");
			} else if (type == DIF_TYPE_NONE) {
				strcpy(ctype_str, "none");
			} else if (type == DIF_TYPE_CTF) {
				/*
				 * Get the CTF type name
				 */
				if (dt_typefile_typename(node->din_tf,
				    node->din_ctfid, ctype_str,
				    sizeof(ctype_str)) != ((char *)ctype_str))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_typecheck_regdefs(): failed at "
					    "getting type name node %ld: %s",
					    node->din_ctfid,
					    dt_typefile_error(node->din_tf));
			} else {
				strcpy(ctype_str, "unknown (ERROR)");
			}

			fprintf(stderr,
			    "failed to typecheck conditional: "
			    "(branch 1: %s (%zu) != branch 2: %s (%zu))\n",
			    otype_str, onode->din_uidx, ctype_str,
			    node->din_uidx);
			return (NULL);
		}

		if (type == DIF_TYPE_CTF) {
			assert(node->din_tf != NULL);

			/*
			 * We get the type name for reporting purposes.
			 */
			if (dt_typefile_typename(node->din_tf, node->din_ctfid,
			    buf1, sizeof(buf1)) != ((char *)buf1))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_typecheck_regdefs(): failed at "
				    "getting type name node %ld: %s",
				    node->din_ctfid,
				    dt_typefile_error(node->din_tf));

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (onode == NULL)
				continue;

			if (onode->din_type == DIF_TYPE_BOTTOM)
				continue;

			assert(onode->din_tf != NULL);
 			/*
			 * Get the previous' node's inferred type for
			 * error reporting.
			 */
			if (dt_typefile_typename(onode->din_tf,
			    onode->din_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_typecheck_regdefs(): failed at "
				    "getting type onode name %ld: %s",
				    onode->din_ctfid,
				    dt_typefile_error(onode->din_tf));

			/*
			 * Fail to typecheck if the types don't match 100%.
			 * We only do this if both types are non-NULL/0 as we
			 * might be doing some weird zeroing thing where we
			 * can't infer the correct type in either of the nodes.
			 * However, we know that any base CTF type can be
			 * reliably zeroed (non-struct, non-union).
			 */
			if ((node->din_isnull == 0 && onode->din_isnull == 0) &&
			    dt_type_subtype(node->din_tf, node->din_ctfid,
			    onode->din_tf, onode->din_ctfid, &which)) {
				fprintf(stderr,
				    "dt_typecheck_regdefs(): types %s (%zu) "
				    "and %s (%zu) do not match\n",
				    buf1, node->din_uidx, buf2,
				    onode->din_uidx);
				return (NULL);
			}

			if ((node->din_sym == NULL && onode->din_sym != NULL) ||
			    (node->din_sym != NULL && onode->din_sym == NULL)) {
				fprintf(stderr,
				    "dt_typecheck_regdefs(): symbol is "
				    "missing in a node\n");
				return (NULL);
			}

			/*
			 * We don't need to check both
			 * because of the above check.
			 */
			if (node->din_sym &&
			    strcmp(node->din_sym, onode->din_sym) != 0) {
				fprintf(stderr,
				    "dt_typecheck_regdefs(): nodes have "
				    "different symbols: %s != %s\n",
				    node->din_sym, onode->din_sym);
				return (NULL);
			}
		}

		first_iter = 0;
	}

	return (node);
}

