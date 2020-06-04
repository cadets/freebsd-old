/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020 Domagoj Stolfa.
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
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
#include <dt_relo.h>
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
dt_usite_uses_stack(dt_relo_t *relo)
{
	dif_instr_t instr;
	uint8_t op;

	instr = relo->dr_buf[relo->dr_uidx];
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
dt_usite_contains_var(dt_relo_t *relo, dt_rkind_t *rkind, int *v)
{
	dif_instr_t instr;
	uint16_t _v, var;
	uint8_t opcode, varkind, scope;

	instr = relo->dr_buf[relo->dr_uidx];
	*v = 0;
	_v = 0;
	opcode = DIF_INSTR_OP(instr);

	var = rkind->r_var;
	scope = rkind->r_scope;
	varkind = rkind->r_varkind;

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
dt_usite_contains_reg(dt_relo_t *relo, uint8_t rd, int *r1, int *r2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, _rd = 0, _r1 = 0, _r2 = 0, opcode = 0;

	instr = relo->dr_buf[relo->dr_uidx];
	*r1 = 0;
	*r2 = 0;
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	/*
	 * Actual relocations
	 */
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	/* Loads */
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
dt_update_rel_bb_var(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_rkind_t *rkind, dt_relo_t *currelo)
{
	dtrace_difo_t *_difo;
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int r1, r2;
	uint_t idx;
	dif_instr_t instr;
	dt_rl_entry_t *currelo_e;
	int v;
	uint8_t scope, varkind;

	idx = 0;
	r1 = 0;
	r2 = 0;
	rl = NULL;
	relo = NULL;
	_difo = NULL;
	instr = 0;
	currelo_e = NULL;
	v = 0;
	scope = varkind = 0;

	assert(currelo != NULL);
	idx = currelo->dr_uidx;

	_difo = bb->dtbb_difo;
/*
	if (_difo != difo)
		return (0);
*/
	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;
		instr = relo->dr_buf[relo->dr_uidx];

		if (relo->dr_difo != _difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (currelo->dr_uidx >= relo->dr_uidx)
			continue;

		if (relo->dr_uidx < bb->dtbb_start ||
		    relo->dr_uidx > bb->dtbb_end)
			continue;

		if (relo == currelo)
			continue;

		/*
		 * Get the information about which registers in the current
		 * relocation match rd.
		 */
		if (dt_usite_contains_var(relo, rkind, &v)) {
			assert(v == 1);
			currelo_e = dt_rle_alloc(currelo);
			if (dt_in_list(&relo->dr_vardefs,
			    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
				dt_list_append(&relo->dr_vardefs, currelo_e);
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (dt_clobbers_var(instr, rkind))
			return (1);

	}
	return (0);
}

static int
dt_update_rel_bb_stack(dt_list_t *bb_path, dtrace_difo_t *difo,
    dt_basic_block_t *bb, dt_relo_t *currelo)
{
	dtrace_difo_t *_difo;
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int r1, r2;
	uint_t idx;
	uint8_t op;
	dif_instr_t instr;
	dt_rl_entry_t *currelo_e;
        int n_pushes;
	dt_stack_t *s_entry;
	dt_stacklist_t *curstack;

	idx = 0;
	r1 = 0;
	r2 = 0;
	rl = NULL;
	relo = NULL;
	_difo = NULL;
	instr = 0;
	currelo_e = NULL;
	op = 0;
	curstack = NULL;
	s_entry = NULL;
	n_pushes = 1;

	assert(currelo != NULL);
	idx = currelo->dr_uidx;

	_difo = bb->dtbb_difo;

	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;
		instr = relo->dr_buf[relo->dr_uidx];
		op = DIF_INSTR_OP(instr);

		if (relo == currelo)
			continue;

		if (relo->dr_difo != _difo)
			continue;

		if (n_pushes < 1)
			errx(EXIT_FAILURE, "n_pushes is %d", n_pushes);

		if (relo->dr_uidx <= currelo->dr_uidx)
			continue;

		if (relo->dr_uidx < bb->dtbb_start ||
		    relo->dr_uidx > bb->dtbb_end)
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

		/*
		 * Get the information about which registers in the current
		 * relocation match rd.
		 */
		if (dt_usite_uses_stack(relo)) {
			s_entry = malloc(sizeof(dt_stack_t));
			if (s_entry == NULL)
				errx(EXIT_FAILURE, "failed to malloc s_entry");

			memset(s_entry, 0, sizeof(dt_stack_t));

			s_entry->ds_rel = currelo;

			curstack = dt_get_stack(bb_path, relo);
			if (curstack == NULL)
				errx(EXIT_FAILURE, "curstack should not be NULL");

			if (dt_in_list(&curstack->dsl_stack,
			    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
				dt_list_append(&curstack->dsl_stack, s_entry);
		}
	}

	return (0);
}

static int
dt_update_rel_bb_reg(dtrace_difo_t *difo, dt_basic_block_t *bb,
    uint8_t rd, dt_relo_t *currelo)
{
	dtrace_difo_t *_difo;
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int r1, r2;
	dif_instr_t instr, curinstr;
	uint8_t opcode, curop;
	dt_rl_entry_t *currelo_e;
	int seen_typecast;

	r1 = 0;
	r2 = 0;
	rl = NULL;
	relo = NULL;
	_difo = NULL;
	instr = 0;
	curinstr = 0;
	opcode = 0;
	curop = 0;
	currelo_e = NULL;
	seen_typecast = 0;

	assert(currelo != NULL);

	_difo = bb->dtbb_difo;
/*
	if (_difo != difo)
		return (0);
*/

	curinstr = currelo->dr_buf[currelo->dr_uidx];
	curop = DIF_INSTR_OP(curinstr);

	if (dt_usite_contains_reg(currelo, 0, &r1, &r2)) {
		assert(r1 == 1 || r2 == 1);
		if (r1 == 1) {
			currelo_e = dt_rle_alloc(r0relo);
			if (dt_in_list(&currelo->dr_r1defs,
			    (void *)&r0relo, sizeof(dt_relo_t *)) == 0)
				dt_list_append(&currelo->dr_r1defs, currelo_e);
		}

		if (r2 == 1) {
			currelo_e = dt_rle_alloc(r0relo);
			if (dt_in_list(&currelo->dr_r2defs,
			    (void *)&r0relo, sizeof(dt_relo_t *)) == 0)
				dt_list_append(&currelo->dr_r2defs, currelo_e);
		}
	}

	currelo_e = NULL;
	r1 = r2 = 0;


	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;
		instr = relo->dr_buf[relo->dr_uidx];
		opcode = DIF_INSTR_OP(instr);

		if (relo->dr_difo != _difo)
			continue;

		/*
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (currelo->dr_uidx >= relo->dr_uidx)
			continue;

		if (relo->dr_uidx < bb->dtbb_start ||
		    relo->dr_uidx > bb->dtbb_end)
			continue;

		if (relo == currelo)
			continue;

		/*
		 * Get the information about which registers in the current
		 * relocation match rd.
		 */
		if (dt_usite_contains_reg(relo, rd, &r1, &r2)) {
			assert(r1 == 1 || r2 == 1);
			if (r1 == 1 && seen_typecast == 0) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r1defs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r1defs, currelo_e);


			}

			if (r2 == 1 && seen_typecast == 0) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r2defs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r2defs, currelo_e);
			}

			if (r1 == 1 && curop != DIF_OP_TYPECAST) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r1datadefs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r1datadefs,
					    currelo_e);
			}

			if (r2 == 1 && curop != DIF_OP_TYPECAST) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r2datadefs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r2datadefs,
					    currelo_e);
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
dt_update_rel(dtrace_difo_t *difo, dt_basic_block_t *bb,
    dt_rkind_t *rkind, dt_relo_t *currelo)
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

	if (rkind->r_kind == DT_RKIND_REG)
		redefined = dt_update_rel_bb_reg(difo, bb, rkind->r_rd, currelo);
	else if (rkind->r_kind == DT_RKIND_VAR)
		redefined = dt_update_rel_bb_var(difo, bb, rkind, currelo);
	else if (rkind->r_kind == DT_RKIND_STACK)
		redefined = dt_update_rel_bb_stack(&bb_path, difo, bb, currelo);
	else
	        goto end;

	if (redefined)
		goto end;

	for (chld = dt_list_next(&bb->dtbb_children);
	     chld; chld = dt_list_next(chld)) {
		chld_bb = chld->dtbe_bb;
		if (chld_bb->dtbb_idx >= DT_BB_MAX)
			errx(EXIT_FAILURE, "too many basic blocks.");
		dt_update_rel(difo, chld_bb, rkind, currelo);
	}

end:
	dt_list_delete(&bb_path, bb_path_entry);
	free(bb_path_entry);
}

static void
dt_update_relocations(dtrace_difo_t *difo,
    dt_rkind_t *rkind, dt_relo_t *currelo)
{
	uint8_t rd;
	uint16_t var;
	dt_relo_t *relo, *relo1;
	dt_rl_entry_t *rl, *r1l;
	dt_stacklist_t *sl;
	dt_pathlist_t *il;
	dt_list_t *stack;
	dt_stack_t *se;
	dt_rkind_t *__rkind;
	dtrace_difo_t *_difo;

	relo = relo1 = NULL;
	rl = r1l = NULL;
	sl = NULL;
	stack = NULL;
	se = NULL;
	il = NULL;
	__rkind = NULL;

	rd = 0;
	var = 0;

	dt_update_rel(_difo, difo->dtdo_bb, rkind, currelo);

	printf("----------------------------------------------\n");
	for (rl = dt_list_next(&relo_list);
	     rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;

		for (r1l = dt_list_next(&relo->dr_r1defs); r1l; r1l = dt_list_next(r1l)) {
			relo1 = r1l->drl_rel;
			printf("DEFN: %zu ==> %zu\n", relo->dr_uidx, relo1->dr_uidx);
		}

		for (r1l = dt_list_next(&relo->dr_r2defs); r1l; r1l = dt_list_next(r1l)) {
			relo1 = r1l->drl_rel;
			printf("DEFN: %zu ==> %zu\n", relo->dr_uidx, relo1->dr_uidx);
		}

		for (r1l = dt_list_next(&relo->dr_vardefs); r1l; r1l = dt_list_next(r1l)) {
			relo1 = r1l->drl_rel;
			__rkind = &relo1->dr_rkind;
			if (__rkind->r_kind != DT_RKIND_VAR)
				errx(EXIT_FAILURE, "rkind of relo1 is wrong: %d",
				    __rkind->r_kind);

			printf("VAR: (%s, %s)\n",
			    __rkind->r_scope == DIFV_SCOPE_GLOBAL ?
			    "global" : __rkind->r_scope == DIFV_SCOPE_THREAD
			    ? "thread" : "local",
			    __rkind->r_varkind == DIFV_KIND_SCALAR ? "scalar" : "array");
			printf("\tDEFN: %zu ==> %zu\n", relo->dr_uidx, relo1->dr_uidx);
		}

		for (sl = dt_list_next(&relo->dr_stacklist); sl; sl = dt_list_next(sl)) {
			stack = &sl->dsl_stack;
			printf("Stack identified by: ");
			for (il = dt_list_next(&sl->dsl_identifier); il; il = dt_list_next(il)) {
				if (dt_list_next(il) != NULL)
					printf("%zu--", il->dtpl_bb->dtbb_idx);
				else
					printf("%zu\n", il->dtpl_bb->dtbb_idx);
			}

			for (se = dt_list_next(stack); se; se = dt_list_next(se)) {
				relo1 = se->ds_rel;
				printf("\tDEFN: %zu ==> %zu\n", relo->dr_uidx, relo1->dr_uidx);
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
	dt_relo_t *relo = NULL;
	dt_rl_entry_t *rl = NULL;
	dt_rkind_t rkind;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	uint8_t rd = 0;
	uint16_t var = 0;

	memset(&rkind, 0, sizeof(dt_rkind_t));
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

		relo = dt_relo_alloc(difo, idx);
		rl = malloc(sizeof(dt_rl_entry_t));
		if (rl == NULL)
			errx(EXIT_FAILURE, "failed to malloc rl");

		memset(rl, 0, sizeof(dt_rl_entry_t));

		rl->drl_rel = relo;
		if (relo_last == NULL)
			relo_last = rl;
		dt_list_prepend(&relo_list, rl);
		dt_get_rkind(instr, &rkind);
		memcpy(&relo->dr_rkind, &rkind, sizeof(dt_rkind_t));
		dt_update_relocations(difo, &rkind, relo);
	}

	return (0);
}

dt_relo_t *
dt_find_relo_in_ifg(dt_relo_t *currelo, dt_relo_t *find)
{
	dt_relo_t *relo;
	dt_rl_entry_t *rl;

	relo = NULL;
	rl = NULL;

	if (currelo == find)
		return (find);

	for (rl = dt_list_next(&currelo->dr_r1datadefs);
	     rl; rl = dt_list_next(rl)) {
		if ((relo = dt_find_relo_in_ifg(rl->drl_rel, find)) == find)
			return (relo);
	}

	for (rl = dt_list_next(&currelo->dr_r2datadefs);
	     rl; rl = dt_list_next(rl)) {
		if ((relo = dt_find_relo_in_ifg(rl->drl_rel, find)) == find)
			return (relo);
	}

	return (NULL);
}
