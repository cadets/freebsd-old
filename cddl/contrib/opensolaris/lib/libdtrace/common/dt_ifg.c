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

#include <dt_ifg.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_ifgnode.h>
#include <dt_basic_block.h>
#include <dt_linker_subr.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_cfg.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stddef.h>
#include <assert.h>

static int
dt_usite_uses_stack(dt_ifg_node_t *n)
{
	dif_instr_t instr;
	uint8_t op;

	instr = n->din_buf[n->din_uidx];
	op = DIF_INSTR_OP(instr);

	switch (op) {
	case DIF_OP_CALL:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_STTS:
	case DIF_OP_LDTS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
		return (1);

	default: break;
	}

	return (0);
}

static int
dt_usite_contains_var(dt_ifg_node_t *n, dt_node_kind_t *nkind, int *v)
{
	dif_instr_t instr;
	uint16_t _v, var;
	uint8_t opcode, varkind, scope;

	instr = n->din_buf[n->din_uidx];
	*v = 0;
	_v = 0;
	opcode = DIF_INSTR_OP(instr);

	var = nkind->dtnk_var;
	scope = nkind->dtnk_scope;
	varkind = nkind->dtnk_varkind;

	switch (opcode) {
	case DIF_OP_LDGA:
		_v = DIF_INSTR_R1(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		if (varkind != DIFV_KIND_ARRAY)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDTA:
		_v = DIF_INSTR_R1(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		if (varkind != DIFV_KIND_ARRAY)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDGS:
		_v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		if (varkind != DIFV_KIND_SCALAR)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDGAA:
		_v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		if (varkind != DIFV_KIND_ARRAY)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDTAA:
		_v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		if (varkind != DIFV_KIND_ARRAY)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDTS:
		_v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		if (varkind != DIFV_KIND_SCALAR)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	case DIF_OP_LDLS:
		_v = DIF_INSTR_VAR(instr);

		if (scope != DIFV_SCOPE_LOCAL)
			return (0);

		if (varkind != DIFV_KIND_SCALAR)
			return (0);

		if (_v == var)
			*v = 1;
		break;

	default:
		break;
	}

	return (*v);
}


static int
dt_usite_contains_reg(dt_ifg_node_t *n, uint8_t rd, int *r1, int *r2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, _rd = 0, _r1 = 0, _r2 = 0, opcode = 0;

	instr = n->din_buf[n->din_uidx];
	*r1 = 0;
	*r2 = 0;
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_ULDSB:
	case DIF_OP_ULDSH:
	case DIF_OP_ULDSW:
	case DIF_OP_ULDUB:
	case DIF_OP_ULDUH:
	case DIF_OP_ULDUW:
	case DIF_OP_ULDX:
	case DIF_OP_RLDSB:
	case DIF_OP_RLDSH:
	case DIF_OP_RLDSW:
	case DIF_OP_RLDUB:
	case DIF_OP_RLDUH:
	case DIF_OP_RLDUW:
	case DIF_OP_RLDX:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTR_H:
	case DIF_OP_PUSHTR_G:
	case DIF_OP_PUSHTV:
		rs = DIF_INSTR_RS(instr);
		if (rd == rs)
			*r1 = 1;
		break;

	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_ADD:
	case DIF_OP_SUB:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_UREM:
	case DIF_OP_SRA:
 	case DIF_OP_COPYS:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_R2(instr);

		if (_r1 == rd)
			*r1 = 1;
		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_NOT:
	case DIF_OP_MOV:
		_r1 = DIF_INSTR_R1(instr);

		if (_r1 == rd)
			*r1 = 1;
		break;

	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
	case DIF_OP_ALLOCS:
		_r2 = DIF_INSTR_R2(instr);

		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		_r2 = DIF_INSTR_RS(instr);

		if (_r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_RET:
		_rd = DIF_INSTR_RD(instr);

		if (_rd == rd)
			*r1 = 1;
		break;

	default:
		break;
	}

	return (*r1 != 0 || *r2 != 0);
}

static int
dt_update_nodes_bb_var(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_node_kind_t *nkind, dt_ifg_node_t *curnode)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	dt_ifg_list_t *ifgl;
	int r1, r2;
	uint_t idx;
	dif_instr_t instr;
	dt_ifg_list_t *curnode_e;
	int v;
	uint8_t scope, varkind;

	idx = 0;
	r1 = 0;
	r2 = 0;
	ifgl = NULL;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curnode_e = NULL;
	v = 0;
	scope = varkind = 0;

	assert(curnode != NULL);
	idx = curnode->din_uidx;

	_difo = bb->dtbb_difo;

	for (ifgl = dt_list_next(&node_list);
	    ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		n = ifgl->dil_ifgnode;
		instr = n->din_buf[n->din_uidx];

		if (n->din_difo != _difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (curnode->din_uidx >= n->din_uidx)
			continue;

		if (n->din_uidx < bb->dtbb_start ||
		    n->din_uidx > bb->dtbb_end)
			continue;

		if (n == curnode)
			continue;

		if (dt_usite_contains_var(n, nkind, &v)) {
			assert(v == 1);
			curnode_e = dt_ifgl_alloc(curnode);
			if (dt_in_list(&n->din_vardefs,
			    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
				dt_list_append(&n->din_vardefs, curnode_e);
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (dt_clobbers_var(instr, nkind))
			return (1);

	}
	return (0);
}

static int
dt_update_nodes_bb_stack(dt_list_t *bb_path, dtrace_difo_t *difo,
    dt_basic_block_t *bb, dt_ifg_node_t *curnode)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	dt_ifg_list_t *ifgl;
	int r1, r2;
	uint_t idx;
	uint8_t op;
	dif_instr_t instr;
	dt_ifg_list_t *curnode_e;
        int n_pushes;
	dt_stack_t *s_entry;
	dt_stacklist_t *curstack;

	idx = 0;
	r1 = 0;
	r2 = 0;
	ifgl = NULL;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curnode_e = NULL;
	op = 0;
	curstack = NULL;
	s_entry = NULL;
	n_pushes = 1;

	assert(curnode != NULL);
	idx = curnode->din_uidx;

	_difo = bb->dtbb_difo;

	for (ifgl = dt_list_next(&node_list);
	    ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		n = ifgl->dil_ifgnode;
		instr = n->din_buf[n->din_uidx];
		op = DIF_INSTR_OP(instr);

		if (n == curnode)
			continue;

		if (n->din_difo != _difo)
			continue;

		if (n_pushes < 1)
			errx(EXIT_FAILURE, "n_pushes is %d", n_pushes);

		if (n->din_uidx <= curnode->din_uidx)
			continue;

		if (n->din_uidx < bb->dtbb_start ||
		    n->din_uidx > bb->dtbb_end)
			continue;

		if (op == DIF_OP_FLUSHTS)
			return (1);

		if (n_pushes == 1 && op == DIF_OP_POPTS)
			return (1);

		if (n_pushes > 1 && op == DIF_OP_POPTS) {
			n_pushes--;
			continue;
		}

		if (op == DIF_OP_PUSHTV || op == DIF_OP_PUSHTR) {
			n_pushes++;
			continue;
		}

		if (dt_usite_uses_stack(n)) {
			s_entry = malloc(sizeof(dt_stack_t));
			if (s_entry == NULL)
				errx(EXIT_FAILURE, "failed to malloc s_entry");

			memset(s_entry, 0, sizeof(dt_stack_t));

			s_entry->ds_ifgnode = curnode;

			curstack = dt_get_stack(bb_path, n);
			if (curstack == NULL)
				errx(EXIT_FAILURE, "curstack should not be NULL");

			if (dt_in_list(&curstack->dsl_stack,
			    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
				dt_list_append(&curstack->dsl_stack, s_entry);
		}
	}

	return (0);
}

static int
dt_update_nodes_bb_reg(dtrace_difo_t *difo, dt_basic_block_t *bb,
    uint8_t rd, dt_ifg_node_t *curnode)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	dt_ifg_list_t *ifgl;
	int r1, r2;
	dif_instr_t instr, curinstr;
	uint8_t opcode, curop;
	dt_ifg_list_t *curnode_e;
	int seen_typecast;

	r1 = 0;
	r2 = 0;
	ifgl = NULL;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curinstr = 0;
	opcode = 0;
	curop = 0;
	curnode_e = NULL;
	seen_typecast = 0;

	assert(curnode != NULL);

	_difo = bb->dtbb_difo;
/*
	if (_difo != difo)
		return (0);
*/

	curinstr = curnode->din_buf[curnode->din_uidx];
	curop = DIF_INSTR_OP(curinstr);

	if (dt_usite_contains_reg(curnode, 0, &r1, &r2)) {
		assert(r1 == 1 || r2 == 1);
		if (r1 == 1) {
			curnode_e = dt_ifgl_alloc(r0node);
			if (dt_in_list(&curnode->din_r1defs,
			    (void *)&r0node, sizeof(dt_ifg_node_t *)) == NULL)
				dt_list_append(&curnode->din_r1defs, curnode_e);
		}

		if (r2 == 1) {
			curnode_e = dt_ifgl_alloc(r0node);
			if (dt_in_list(&curnode->din_r2defs,
			    (void *)&r0node, sizeof(dt_ifg_node_t *)) == NULL)
				dt_list_append(&curnode->din_r2defs, curnode_e);
		}
	}

	curnode_e = NULL;
	r1 = r2 = 0;


	for (ifgl = dt_list_next(&node_list);
	    ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		n = ifgl->dil_ifgnode;
		instr = n->din_buf[n->din_uidx];
		opcode = DIF_INSTR_OP(instr);

		if (n->din_difo != _difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (curnode->din_uidx >= n->din_uidx)
			continue;

		if (n->din_uidx < bb->dtbb_start ||
		    n->din_uidx > bb->dtbb_end)
			continue;

		if (n == curnode)
			continue;

		if (dt_usite_contains_reg(n, rd, &r1, &r2)) {
			assert(r1 == 1 || r2 == 1);
			if (r1 == 1 && seen_typecast == 0) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r1defs,
				    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r1defs, curnode_e);


			}

			if (r2 == 1 && seen_typecast == 0) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r2defs,
				    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r2defs, curnode_e);
			}

			if (r1 == 1 && curop != DIF_OP_TYPECAST) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r1datadefs,
				    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r1datadefs,
					    curnode_e);
			}

			if (r2 == 1 && curop != DIF_OP_TYPECAST) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r2datadefs,
				    (void *)&curnode, sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r2datadefs,
					    curnode_e);
			}
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (dt_clobbers_reg(instr, rd) &&
		    opcode != DIF_OP_TYPECAST)
			return (1);

		if (opcode == DIF_OP_TYPECAST)
			seen_typecast = 1;
	}

	return (0);
}

static void
dt_update_nodes(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_node_kind_t *nkind, dt_ifg_node_t *curnode)
{
	dt_bb_entry_t *chld;
	dt_basic_block_t *chld_bb;
	int redefined;
	uint8_t rd;
	uint16_t var;
	static dt_list_t bb_path = {0};
	dt_pathlist_t *bb_path_entry;

	chld = NULL;
	chld_bb = NULL;
	redefined = 0;
	bb_path_entry = NULL;

	bb_path_entry = malloc(sizeof(dt_pathlist_t));
	if (bb_path_entry == NULL)
		errx(EXIT_FAILURE, "failed to malloc bb_path_entry");

	memset(bb_path_entry, 0, sizeof(dt_pathlist_t));
	bb_path_entry->dtpl_bb = bb;
	dt_list_append(&bb_path, bb_path_entry);

	if (nkind->dtnk_kind == DT_NKIND_REG)
		redefined = dt_update_nodes_bb_reg(difo, bb, nkind->dtnk_rd, curnode);
	else if (nkind->dtnk_kind == DT_NKIND_VAR)
		redefined = dt_update_nodes_bb_var(difo, bb, nkind, curnode);
	else if (nkind->dtnk_kind == DT_NKIND_STACK)
		redefined = dt_update_nodes_bb_stack(&bb_path, difo, bb, curnode);
	else
	        goto end;

	if (redefined)
		goto end;

	for (chld = dt_list_next(&bb->dtbb_children);
	     chld; chld = dt_list_next(chld)) {
		chld_bb = chld->dtbe_bb;
		if (chld_bb->dtbb_idx >= DT_BB_MAX)
			errx(EXIT_FAILURE, "too many basic blocks.");
		dt_update_nodes(difo, chld_bb, nkind, curnode);
	}

end:
	dt_list_delete(&bb_path, bb_path_entry);
	free(bb_path_entry);
}

static void
dt_update_ifg(dtrace_difo_t *difo,
    dt_node_kind_t *nkind, dt_ifg_node_t *curnode)
{
	uint8_t rd;
	uint16_t var;
	dt_ifg_node_t *n, *n1;
	dt_ifg_list_t *ifgl, *r1l;
	dt_stacklist_t *sl;
	dt_pathlist_t *il;
	dt_list_t *stack;
	dt_stack_t *se;
	dt_node_kind_t *__nkind;
	dtrace_difo_t *_difo;

	n = n1 = NULL;
	ifgl = r1l = NULL;
	sl = NULL;
	stack = NULL;
	se = NULL;
	il = NULL;
	__nkind = NULL;

	rd = 0;
	var = 0;

	dt_update_nodes(_difo, difo->dtdo_bb, nkind, curnode);

	printf("----------------------------------------------\n");
	for (ifgl = dt_list_next(&node_list);
	     ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		n = ifgl->dil_ifgnode;

		for (r1l = dt_list_next(&n->din_r1defs); r1l; r1l = dt_list_next(r1l)) {
			n1 = r1l->dil_ifgnode;
			printf("DEFN: %zu ==> %zu\n", n->din_uidx, n1->din_uidx);
		}

		for (r1l = dt_list_next(&n->din_r2defs); r1l; r1l = dt_list_next(r1l)) {
			n1 = r1l->dil_ifgnode;
			printf("DEFN: %zu ==> %zu\n", n->din_uidx, n1->din_uidx);
		}

		for (r1l = dt_list_next(&n->din_vardefs); r1l; r1l = dt_list_next(r1l)) {
			n1 = r1l->dil_ifgnode;
			__nkind = &n1->din_kind;
			if (__nkind->dtnk_kind != DT_NKIND_VAR)
				errx(EXIT_FAILURE, "nkind of n1 is wrong: %d",
				    __nkind->dtnk_kind);

			printf("VAR: (%s, %s)\n",
			    __nkind->dtnk_scope == DIFV_SCOPE_GLOBAL ?
			    "global" : __nkind->dtnk_scope == DIFV_SCOPE_THREAD
			    ? "thread" : "local",
			    __nkind->dtnk_varkind == DIFV_KIND_SCALAR ? "scalar" : "array");
			printf("\tDEFN: %zu ==> %zu\n", n->din_uidx, n1->din_uidx);
		}

		for (sl = dt_list_next(&n->din_stacklist); sl; sl = dt_list_next(sl)) {
			stack = &sl->dsl_stack;
			printf("Stack identified by: ");
			for (il = dt_list_next(&sl->dsl_identifier); il; il = dt_list_next(il)) {
				if (dt_list_next(il) != NULL)
					printf("%zu--", il->dtpl_bb->dtbb_idx);
				else
					printf("%zu\n", il->dtpl_bb->dtbb_idx);
			}

			for (se = dt_list_next(stack); se; se = dt_list_next(se)) {
				n1 = se->ds_ifgnode;
				printf("\tDEFN: %zu ==> %zu\n", n->din_uidx, n1->din_uidx);
			}
		}

	}
	printf("----------------------------------------------\n");
}

/*
 * We assume that both dtp and difo are not NULL.
 */
int
dt_prog_infer_defns(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_ifg_node_t *n = NULL;
	dt_ifg_list_t *ifgl = NULL;
	dt_node_kind_t nkind;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	uint8_t rd = 0;
	uint16_t var = 0;

	memset(&nkind, 0, sizeof(dt_node_kind_t));
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

	/*
	 * Compute the basic blocks
	 */
	dt_compute_bb(difo);

	/*
	 * Compute control flow
	 */
	dt_compute_cfg(difo);

	/*
	 * Go over all the instructions, starting from the last one. For
	 * simplicity sake, we calculate the index inside the loop instead
	 * of writing the loop condition which either relies on UB or uses
	 * a signed integer.
	 */
	for (i = 0; i < difo->dtdo_len; i++) {
		idx = difo->dtdo_len - 1 - i;
		instr = difo->dtdo_buf[idx];

		n = dt_ifg_node_alloc(difo, idx);
		ifgl = malloc(sizeof(dt_ifg_list_t));
		if (ifgl == NULL)
			errx(EXIT_FAILURE, "failed to malloc ifgl");

		memset(ifgl, 0, sizeof(dt_ifg_list_t));

		ifgl->dil_ifgnode = n;
		if (node_last == NULL)
			node_last = ifgl;
		dt_list_prepend(&node_list, ifgl);
		dt_get_nkind(instr, &nkind);
		memcpy(&n->din_kind, &nkind, sizeof(dt_node_kind_t));
		dt_update_ifg(difo, &nkind, n);
	}

	return (0);
}

dt_ifg_node_t *
dt_find_node_in_ifg(dt_ifg_node_t *curnode, dt_ifg_node_t *find)
{
	dt_ifg_node_t *n;
	dt_ifg_list_t *ifgl;

	n = NULL;
	ifgl = NULL;

	if (curnode == find)
		return (find);

	for (ifgl = dt_list_next(&curnode->din_r1datadefs);
	     ifgl; ifgl = dt_list_next(ifgl)) {
		if ((n = dt_find_node_in_ifg(ifgl->dil_ifgnode, find)) == find)
			return (n);
	}

	for (ifgl = dt_list_next(&curnode->din_r2datadefs);
	     ifgl; ifgl = dt_list_next(ifgl)) {
		if ((n = dt_find_node_in_ifg(ifgl->dil_ifgnode, find)) == find)
			return (n);
	}

	return (NULL);
}
