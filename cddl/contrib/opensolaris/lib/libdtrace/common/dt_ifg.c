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
#include <errno.h>

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
dt_usite_contains_reg(dt_ifg_node_t *n, dt_ifg_node_t *curnode, uint8_t rd,
    int *r1, int *r2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, _rd = 0, _r1 = 0, _r2 = 0, opcode = 0;
	dif_instr_t curinstr;
	uint8_t curop;
	int check;

	curinstr = curnode->din_buf[curnode->din_uidx];
	instr = n->din_buf[n->din_uidx];

	*r1 = 0;
	*r2 = 0;

	opcode = DIF_INSTR_OP(instr);
	curop = DIF_INSTR_OP(curinstr);

	if (curop == DIF_OP_CALL)
		check = dt_subr_clobbers(DIF_INSTR_SUBR(curinstr));
	else
		check = 1;

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
	case DIF_OP_PUSHTV:
	case DIF_OP_TYPECAST:
		rs = DIF_INSTR_RS(instr);
		if (check && rd == rs)
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

		if (check && _r1 == rd)
			*r1 = 1;
		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
		_r1 = DIF_INSTR_R1(instr);
		_r2 = DIF_INSTR_RD(instr);

		if (check && _r1 == rd)
			*r1 = 1;
		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
	case DIF_OP_ALLOCS:
		_r2 = DIF_INSTR_R2(instr);

		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		_r2 = DIF_INSTR_RS(instr);

		if (check && _r2 == rd)
			*r2 = 1;
		break;

	case DIF_OP_RET:
		_rd = DIF_INSTR_RD(instr);

		if (check && _rd == rd)
			*r1 = 1;
		break;

	default:
		break;
	}

	return (*r1 != 0 || *r2 != 0);
}

static int
dt_update_nodes_bb_var(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_node_kind_t *nkind, dt_ifg_list_t *ifgl)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	int r1, r2;
	uint_t idx;
	dif_instr_t instr;
	dt_ifg_list_t *curnode_e;
	int v;
	uint8_t scope, varkind;
	dt_ifg_node_t *curnode;

	idx = 0;
	r1 = 0;
	r2 = 0;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curnode_e = NULL;
	v = 0;
	scope = varkind = 0;
	curnode = ifgl->dil_ifgnode;

	assert(ifgl != NULL);
	idx = curnode->din_uidx;

	_difo = bb->dtbb_difo;

	for (; ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		assert(ifgl != NULL);
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
dt_update_nodes_bb_stack(dt_basic_block_t **bb_path, ssize_t bb_path_len,
    dtrace_difo_t *difo, dt_basic_block_t *bb, dt_ifg_list_t *ifgl)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	int r1, r2;
	uint_t idx;
	uint8_t op;
	dif_instr_t instr;
	dt_ifg_list_t *curnode_e;
	int n_pushes;
	dt_stack_t *s_entry;
	dt_stacklist_t *curstack;
	dt_ifg_node_t *curnode;

	idx = 0;
	r1 = 0;
	r2 = 0;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curnode_e = NULL;
	op = 0;
	curstack = NULL;
	s_entry = NULL;
	n_pushes = 1;
	curnode = ifgl->dil_ifgnode;

	assert(ifgl != NULL);
	idx = curnode->din_uidx;

	_difo = bb->dtbb_difo;

	for (; ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		assert(ifgl != NULL);
		n = ifgl->dil_ifgnode;
		instr = n->din_buf[n->din_uidx];
		op = DIF_INSTR_OP(instr);

		if (n == curnode)
			continue;

		if (n->din_difo != _difo)
			continue;

		if (n_pushes < 1)
			errx(EXIT_FAILURE,
			    "dt_update_nodes_bb_stack(): n_pushes (%d) < 0 on "
			    "DIFO %p (node %zu)",
			    n_pushes, n->din_difo, n->din_uidx);

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

			curstack = dt_get_stack(bb_path, bb_path_len, n);
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
    uint8_t rd, dt_ifg_list_t *ifgl, int *seen_typecast)
{
	dtrace_difo_t *_difo;
	dt_ifg_node_t *n;
	int r1, r2;
	dif_instr_t instr, curinstr;
	uint8_t opcode, curop;
	dt_ifg_node_t *curnode;
	dt_ifg_list_t *curnode_e, *n_e;
	int clobbers;

	r1 = 0;
	r2 = 0;
	n = NULL;
	_difo = NULL;
	instr = 0;
	curinstr = 0;
	opcode = 0;
	curop = 0;
	curnode_e = NULL;

	assert(ifgl != NULL);

	curnode = ifgl->dil_ifgnode;

	_difo = bb->dtbb_difo;

	if (_difo != difo)
		return (0);

	curinstr = curnode->din_buf[curnode->din_uidx];
	curop = DIF_INSTR_OP(curinstr);

	if (dt_usite_contains_reg(curnode, curnode, 0, &r1, &r2)) {
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

	for (; ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		assert(ifgl != NULL);
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

		if (dt_usite_contains_reg(n, curnode, rd, &r1, &r2)) {
			assert(r1 == 1 || r2 == 1);
			if (r1 == 1 && *seen_typecast == 0) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r1defs, (void *)&curnode,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r1defs,
					    curnode_e);
				else
					free(curnode_e);

				n_e = dt_ifgl_alloc(n);
				if (dt_in_list(&curnode->din_r1children,
				    (void *)&n,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&curnode->din_r1children,
					    n_e);
				else
					free(n_e);
			}

			if (r2 == 1 && *seen_typecast == 0) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r2defs, (void *)&curnode,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r2defs,
					    curnode_e);
				else
					free(curnode_e);

				n_e = dt_ifgl_alloc(n);
				if (dt_in_list(&curnode->din_r2children,
				    (void *)&n,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&curnode->din_r2children,
					    n_e);
				else
					free(n_e);
			}

			if (r1 == 1 && curop != DIF_OP_TYPECAST) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r1datadefs,
				    (void *)&curnode,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r1datadefs,
					    curnode_e);
				else
					free(curnode_e);
			}

			if (r2 == 1 && curop != DIF_OP_TYPECAST) {
				curnode_e = dt_ifgl_alloc(curnode);
				if (dt_in_list(&n->din_r2datadefs,
				    (void *)&curnode,
				    sizeof(dt_ifg_node_t *)) == NULL)
					dt_list_append(&n->din_r2datadefs,
					    curnode_e);
				else
					free(curnode_e);
			}
		}

		clobbers = dt_clobbers_reg(instr, rd);

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (clobbers && opcode != DIF_OP_TYPECAST)
			return (1);

		if (clobbers && opcode == DIF_OP_TYPECAST)
			*seen_typecast = 1;
	}

	return (0);
}

static void
dt_compute_active_varregs(uint8_t *active_varregs, size_t n_varregs,
    dt_ifg_node_t *n)
{
	dif_instr_t instr, varsrc_instr;
	uint8_t opcode;
	uint8_t r1, r2, rd;
	size_t i;

	instr = n->din_buf[n->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	/*
	 * Based on the opcode, we will now compute the new set of active
	 * registers in the current run of the inference for varsources.
	 */
	switch (opcode) {
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SUB:
	case DIF_OP_ADD:
	case DIF_OP_MUL:
	case DIF_OP_SRA:
		/*
		 * If either of r1 and r2 is active, we will activate rd too, as
		 * this is probably some computation of an offset within a
		 * variable. However, if both are inactive, then we deactivate
		 * rd as well.
		 */
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);
		rd = DIF_INSTR_RD(instr);

		assert(rd < DIF_DIR_NREGS + 2);
		assert(r1 < DIF_DIR_NREGS + 2);
		assert(r2 < DIF_DIR_NREGS + 2);


		if (active_varregs[r1] == 0 && active_varregs[r2] == 0)
			active_varregs[rd] = 0;

		if (active_varregs[rd] == 0 && active_varregs[r1] == 1)
			active_varregs[rd] = 1;

		if (active_varregs[rd] == 0 && active_varregs[r2] == 1)
			active_varregs[rd] = 1;
		break;

	case DIF_OP_MOV:
		/*
		 * For any one of these instructions, we will compute if
		 * r1 is already an active register. If so, we simply activate
		 * rd as well.
		 */
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);
		assert(rd < DIF_DIR_NREGS + 2);
		assert(r1 < DIF_DIR_NREGS + 2);

		active_varregs[rd] = active_varregs[r1];
		break;

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
	case DIF_OP_CMP:
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
	case DIF_OP_SCMP:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
	case DIF_OP_POPTS:
		break;

	case DIF_OP_RET:
		/*
		 * On a ret instruction, all of the active registers are
		 * cleared. We are not longer actively looking to figure out
		 * which registers could be defining a variable, and therefore
		 * we don't want to keep track of them.
		 */
		for (i = 0; i < n_varregs; i++)
			active_varregs[i] = 0;

	default:
		rd = DIF_INSTR_RD(instr);
		assert(rd < DIF_DIR_NREGS + 2);

		active_varregs[rd] = 0;
	}
}

static void
update_active_varregs(uint8_t active_varregs[DIF_DIR_NREGS],
    dtrace_difo_t *_difo, dt_basic_block_t *bb, dt_ifg_list_t *ifgl)
{
	dt_ifg_node_t *curnode, *n;
	dif_instr_t instr;
	uint8_t opcode;
	uint16_t varid;
	int scope, kind;
	dt_var_entry_t *ve;
	dtrace_difv_t *difv;
	uint8_t curnode_rd, rd, r1;
	size_t i;
	int keep_going;

	if (_difo == NULL || bb == NULL || ifgl == NULL)
		errx(EXIT_FAILURE,
		    "update_active_varregs(): all three arguments "
		    "must be non-null (%p, %p, %p)\n",
		    _difo, bb, ifgl);

	curnode = ifgl->dil_ifgnode;
	instr = curnode->din_buf[curnode->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	/*
	 * This is only really relevant for load instructions -- nothing else
	 * in DIF can define a register as "containing a variable" that we can
	 * infer statically -- so we don't allow it.
	 */
	if (opcode != DIF_OP_LDGS && opcode != DIF_OP_LDGA &&
	    opcode != DIF_OP_LDTS && opcode != DIF_OP_LDTA &&
	    opcode != DIF_OP_LDLS)
		return;

	varid = DIF_INSTR_VAR(instr);

	/*
	 * Annoying boilerplate to compute the kind and scope of the variable.
	 */
	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDTS ||
	    opcode == DIF_OP_LDLS)
		kind = DIFV_KIND_SCALAR;
	else
		kind = DIFV_KIND_ARRAY;

	if (opcode == DIF_OP_LDGS || opcode == DIF_OP_LDGA)
		scope = DIFV_SCOPE_GLOBAL;
	else if (opcode == DIF_OP_LDTS || opcode == DIF_OP_LDTA)
		scope = DIFV_SCOPE_THREAD;
	else
		scope = DIFV_SCOPE_LOCAL;

	curnode_rd = DIF_INSTR_RD(instr);
	assert(curnode_rd < DIF_DIR_NREGS + 2);

	/*
	 * Activate the current node's destination register.
	 */
	active_varregs[curnode_rd] = 1;

	/*
	 * Go through all of the nodes in the current basic block
	 */
	for (; ifgl; ifgl = dt_list_next(ifgl)) {
		assert(ifgl != NULL);
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

		/*
		 * Compute which registers are being activated or deactivated
		 * with this node.
		 */
		dt_compute_active_varregs(active_varregs, DIF_DIR_NREGS, n);

		keep_going = 0;
		for (i = 0; i < DIF_DIR_NREGS + 2; i++)
			if (active_varregs[i] == 1)
				keep_going = 1;

		/*
		 * If there's no reason to keep going, that is to say that all
		 * the active registers have been clobbered, we simply return
		 * from the subroutine.
		 */
		if (keep_going == 0)
			return;

		if (opcode != DIF_OP_STB && opcode != DIF_OP_STH &&
		    opcode != DIF_OP_STW && opcode != DIF_OP_STX)
			continue;

		/*
		 * If we have STB/STH/STW/STX, we will get its r1 register and
		 * check if it's active. If so, we will add our varsource to the
		 * list.
		 */
		rd = DIF_INSTR_RD(instr);
		assert(rd < DIF_DIR_NREGS + 2);

		if (active_varregs[rd] == 0)
			continue;

		assert(scope == DIFV_SCOPE_GLOBAL ||
		    scope == DIFV_SCOPE_THREAD || scope == DIFV_SCOPE_LOCAL);
		assert(kind == DIFV_KIND_ARRAY || kind == DIFV_KIND_SCALAR);

		difv = dt_get_var_from_varlist(varid, scope, kind);
		if (difv == NULL)
			errx(EXIT_FAILURE,
			    "dt_update_varsources(): failed to get DIF "
			    "variable from the list (%u, %d, %d)\n",
			    varid, scope, kind);

		ve = malloc(sizeof(dt_var_entry_t));
		if (ve == NULL)
			errx(EXIT_FAILURE,
			    "dt_update_varsources(): malloc failed with: %s\n",
			    strerror(errno));

		memset(ve, 0, sizeof(dt_var_entry_t));
		ve->dtve_var = difv;

		dt_list_append(&n->din_varsources, ve);
	}
}

static void
remove_basic_blocks(dt_basic_block_t *bb, dt_basic_block_t **bb_path,
    ssize_t *bb_last, int *bb_in_path)
{
	dt_bb_entry_t *parent, *child;
	dt_basic_block_t *parent_bb, *child_bb;
	int iterated, remove;

	/*
	 * Start by removing the current basic block from the path. Since
	 * this will always be the last element in bb_path, we just need to
	 * decrement bb_last and we can consider it to be out of bb_path.
	 */
	bb_in_path[bb->dtbb_idx] = 0;
	*bb_last--;

	/*
	 * Find the parent that's in the path.
	 */
	iterated = 0;
	parent_bb = NULL;
	for (parent = dt_list_next(&bb->dtbb_parents); parent;
	     parent = dt_list_next(parent)) {
		iterated = 1;
		parent_bb = parent->dtbe_bb;

		if (bb_in_path[parent_bb->dtbb_idx])
			break;
	}

	/*
	 * There's only one case when we won't have a parent. That case is when
	 * we are in the root node. In that case, we will simply assert a few
	 * things and break out of the function.
	 */
	assert((iterated == 0 && parent_bb == NULL) ||
	    (iterated == 1 && parent_bb != NULL));

	if (parent_bb == NULL) {
		assert(bb->dtbb_start == 0);
		return;
	}

	remove = 1;
	for (child = dt_list_next(&parent_bb->dtbb_children); child;
	     child = dt_list_next(child)) {
		child_bb = child->dtbe_bb;

		if (child->dtbe_tovisit == 1) {
			remove = 0;
			break;
		}
	}
	/*
	 * Given that this is tail-recursive, the compiler should be able to
	 * optimize it away, and we don't need to unroll anything.
	 */
	if (remove)
		remove_basic_blocks(parent_bb, bb_path, bb_last, bb_in_path);
}

static void
dt_update_nodes(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_node_kind_t *nkind, dt_ifg_list_t *ifgl)
{
	dt_bb_entry_t *chld;
	dt_basic_block_t *chld_bb, *curbb;
	int redefined, var_redefined;
	uint8_t rd;
	uint16_t var;
	dt_basic_block_t *bb_path[DT_BB_MAX];
	ssize_t bb_last;
	int bb_in_path[DT_BB_MAX]; /* Quick lookup */
	dt_basic_block_t *bb_stack[DT_BB_MAX];
	ssize_t top;
	size_t i;
	uint8_t active_varregs[DIF_DIR_NREGS + 2];
	int seen_typecast = 0;

	if (ifgl == NULL || difo == NULL || bb == NULL || nkind == NULL)
		return;

	memset(active_varregs, 0, sizeof(active_varregs));
	memset(bb_stack, 0, sizeof(bb_stack));
	memset(bb_path, 0, sizeof(bb_path));
	memset(bb_in_path, 0, sizeof(bb_in_path));

	bb_last = -1;

	top = -1;
	bb_stack[++top] = bb;

	while (top > -1) {
		bb = bb_stack[top--];
		assert(bb != NULL);

		chld = NULL;
		chld_bb = NULL;
		redefined = 0;
		var_redefined = 0;

		bb_path[++bb_last] = bb;
		bb_in_path[bb->dtbb_idx] = 1;

		if (nkind->dtnk_kind == DT_NKIND_REG) {
			if (redefined == 0)
				redefined = dt_update_nodes_bb_reg(difo, bb,
				    nkind->dtnk_rd, ifgl, &seen_typecast);
			if (var_redefined == 0) {
				update_active_varregs(active_varregs, difo, bb,
				    ifgl);
				var_redefined = 1;
				for (i = 0; i < DIF_DIR_NREGS + 2; i++)
					if (active_varregs[i] == 1)
						var_redefined = 0;
			}
		} else if (nkind->dtnk_kind == DT_NKIND_VAR)
			redefined = dt_update_nodes_bb_var(difo, bb, nkind,
			    ifgl);
		else if (nkind->dtnk_kind == DT_NKIND_STACK)
			redefined = dt_update_nodes_bb_stack(bb_path,
			    bb_last + 1, difo, bb, ifgl);
		else
			return;

		if (redefined || dt_list_next(&bb->dtbb_children) == NULL)
			remove_basic_blocks(bb, bb_path, &bb_last, bb_in_path);

		if ((nkind->dtnk_kind == DT_NKIND_REG && var_redefined == 0) ||
		    redefined == 0) {
			for (chld = dt_list_next(&bb->dtbb_children); chld;
			     chld = dt_list_next(chld)) {
				bb = chld->dtbe_bb;
				assert(bb != NULL);
				if (bb->dtbb_idx >= DT_BB_MAX)
					errx(EXIT_FAILURE,
					    "dt_update_nodes(): too many basic "
					    "blocks.");

				bb_stack[++top] = bb;
				/*
				 * This is a little more subtle than it looks.
				 * dtbe_tovisit here is not per basic-block.
				 * It is in fact per individual child of each
				 * basic block -- which differs for different
				 * basic blocks. This ensures that we have a
				 * way to say "have we visited the children
				 * of *this particular basic block*" rather than
				 * "have we visited this basic block".
				 */
				chld->dtbe_tovisit = 0;
			}
		}
	}
}

static void
dt_update_ifg(dtrace_difo_t *difo,
    dt_node_kind_t *nkind, dt_ifg_list_t *ifgl)
{
	uint8_t rd;
	uint16_t var;
	dt_ifg_node_t *n, *n1;
	dt_ifg_list_t *r1l;
	dt_stacklist_t *sl;
	dt_pathlist_t *il;
	dt_list_t *stack;
	dt_stack_t *se;
	dt_node_kind_t *__nkind;
	dtrace_difo_t *_difo;
	dt_ifg_node_t *curnode;

	n = n1 = NULL;
	r1l = NULL;
	sl = NULL;
	stack = NULL;
	se = NULL;
	il = NULL;
	__nkind = NULL;

	rd = 0;
	var = 0;
	curnode = ifgl->dil_ifgnode;

	dt_update_nodes(difo, curnode->din_bb, nkind, ifgl);
}

static dt_basic_block_t *
dt_node_find_bb(dt_basic_block_t *root, uint_t ins_idx)
{
	dt_bb_entry_t *chld;
	dt_basic_block_t *bb;
	dt_basic_block_t *bb_stack[DT_BB_MAX];
	int visited[DT_BB_MAX];
	ssize_t top;

	/*
	 * Apparently DTrace uses sufficiently large conditionals sometimes.
	 * This is bad news, as doing this recursively will quickly become
	 * unreasonably slow. Since C compilers are great, they aren't able
	 * to properly optimize something that is not quite tail recursion,
	 * but is essentially a fold on a tail recursion.
	 */

	if (root == NULL)
		return (NULL);

	memset(visited, 0, sizeof(visited));
	memset(bb_stack, 0, sizeof(bb_stack));

	top = -1;

	bb_stack[++top] = root;

	while (top > -1) {
		bb = bb_stack[top--];
		assert(bb != NULL);

		if (visited[bb->dtbb_idx] == 0) {
			visited[bb->dtbb_idx] = 1;
			if (bb->dtbb_start <= ins_idx &&
			    bb->dtbb_end >= ins_idx)
				return (bb);
		}

		for (chld = dt_list_next(&bb->dtbb_children); chld;
		    chld = dt_list_next(chld)) {
			bb = chld->dtbe_bb;
			assert(bb != NULL);

			if (visited[bb->dtbb_idx] == 0)
				bb_stack[++top] = bb;
		}
	}

	return (NULL);
}

/*
 * We assume that both dtp and difo are not NULL.
 */
int
dt_prog_infer_defns(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_ecbdesc_t *edp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_ifg_node_t *n = NULL;
	dt_ifg_list_t *ifgl = NULL, *fst;
	dt_node_kind_t nkind;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	uint8_t rd = 0;
	uint16_t var = 0;
	dt_basic_block_t *nodebb;

	memset(&nkind, 0, sizeof(dt_node_kind_t));

	/*
	 * Passing a NULL difo makes no sense.
	 */
	if (difo == NULL)
		return (EDT_DIFINVAL);

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

	fst = NULL;
	/*
	 * First pass over the instructions. We build up all of the IFG nodes
	 * that we are going to need.
	 */
	for (i = 0; i < difo->dtdo_len; i++) {
		nodebb = dt_node_find_bb(difo->dtdo_bb, i);
		assert(nodebb != NULL);

		n = dt_ifg_node_alloc(pgp, edp, difo, nodebb, i);
		ifgl = dt_ifgl_alloc(n);
		if (ifgl == NULL)
			errx(EXIT_FAILURE, "failed to malloc ifgl");

		if (i == 0) {
			assert(fst == NULL);
			fst = ifgl;
		}

		if (i == difo->dtdo_len - 1)
			node_last = ifgl;

		dt_list_append(&node_list, ifgl);
	}

	/*
	 * Second pass over all the instructions, but this time we actually
	 * compute the IFG.
	 */
	for (ifgl = fst; ifgl; ifgl = dt_list_next(ifgl)) {
		n = ifgl->dil_ifgnode;
		idx = n->din_uidx;
		instr = difo->dtdo_buf[idx];

		dt_get_nkind(instr, &nkind);
		memcpy(&n->din_kind, &nkind, sizeof(dt_node_kind_t));
		dt_update_ifg(difo, &nkind, ifgl);
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
