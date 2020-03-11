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

#include <sys/dtrace.h>

#include <dt_prog_link.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dtrace.h>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

static dt_list_t relo_list;

static dt_relo_t *
dt_relo_alloc(dif_instr_t *buf, uint_t idx)
{
	dt_relo_t *relo;

	relo = malloc(sizeof(dt_relo_t));
	memset(relo, 0, sizeof(dt_relo_t));

	relo->dr_buf = buf;
	relo->dr_uidx = idx;

	return (relo);
}

static int
dt_usite_contains_reg(dt_relo_t *relo, u_int rd, int *id1, int *id2)
{
	dif_instr_t instr = 0;
	uint_t rs = 0, r1 = 0, r2 = 0, opcode = 0;

	instr = relo->dr_buf[relo->dr_uidx];
	*id1 = -1;
	*id2 = -1;
	opcode = DIF_INSTR_OP(instr);

	switch (instr) {
	/*
	 * Actual relocations
	 */
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
		rs = DIF_INSTR_RS(instr);
		if (rd == rs)
			*id1 = 0;
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
		r1 = DIF_INSTR_R1(instr);
		r2 = DIF_INSTR_R2(instr);

		if (r1 == rd)
			*id1 = 0;
		if (r2 == rd)
			*id2 = 1;
		break;

	case DIF_OP_NOT:
	case DIF_OP_MOV:
		r1 = DIF_INSTR_R1(instr);

		if (r1 == rd)
			*id1 = 0;
		break;

	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
	case DIF_OP_ALLOCS:
		r1 = DIF_INSTR_R1(instr);

		if (r1 == rd)
			*id1 = 0;
		break;

	default:
		break;
	}

	return (*id1 != -1 || *id2 != -1);
}

static void
dt_update_relocations(dtrace_difo_t *difo, uint_t rd, uint_t idx)
{
	dt_relo_t *relo = NULL;
	dt_rl_entry_t *rl = NULL;
	int id1 = 0, id2 = 0;

	/*
	 * Every time we find a relocation whose use site contains
	 * a register we are currently defining, we will in the relocation
	 * with the definition index. Any changes to the instruction that
	 * are necessary as a result will be applied later on.
	 */
	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;

		if (relo->dr_buf != difo->dtdo_buf)
			continue;

		/*
		 * We've already found a definition, skip it.
		 */
		if (relo->dr_didx[0] != 0 && relo->dr_didx[1] != 0)
			continue;

		/*
		 * Get the information about which registers in the current
		 * relocation match rd.
		 */
		if (dt_usite_contains_reg(relo, rd, &id1, &id2)) {
			assert(id1 == 0 || id1 == 1 || id2 == 0 || id2 == 1);

			/*
			 * If the first register in the instruction is in fact
			 * rd, and there is no prior definition of said register
			 * we set the definition to this instruction. In the
			 * case where there already exists an instruction
			 * defining rd for the current instruction, we simply do
			 * nothing, as this is the case of:
			 * mov %r1, %r2  <- the case described above
			 * mov %r1, %r3  <- first (real) definition %r1
			 * tst %r1       <- use of %r1
			 */
			if (id1 != -1 && relo->dr_didx[id1] == 0)
				relo->dr_didx[id1] = idx;

			if (id2 != -1 && relo->dr_didx[id2] == 0)
				relo->dr_didx[id2] = idx;
		}
	}
}

static int
dt_prog_infer_types(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_relo_t *relo = NULL;
	dt_rl_entry_t *rl = NULL;
	dif_instr_t instr = 0;
	uint_t opcode = 0;
	uint_t rd = 0;

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

	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;

		if (relo->dr_buf == NULL)
			continue;

		instr = relo->dr_buf[relo->dr_uidx];
		opcode = DIF_INSTR_OP(instr);
		/*
		 * Perhaps get the used registers based on the instruction
		 * (in this case I think we only care about relocations),
		 * and then go through the definitions, putting the instructions
		 * whose type needs to be inferred on the stack. Once we reach
		 * and instruction whose type we can infer on the spot, we pop
		 * instruction by instruction off the stack and fill in the type
		 * until there are no more instructions. After we are done with
		 * that one pass, we keep going through the rest of the instructions
		 * and inferring the type whenever necessary.
		 */
	}

	return (0);
}

/*
 * We assume that both dtp and difo are not NULL.
 */
static int
dt_prog_infer_defns(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_relo_t *relo = NULL;
	dt_rl_entry_t *rl = NULL;
	dif_instr_t instr = 0;
	uint_t opcode = 0;
	uint_t rd = 0;

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
	 * Go over all the instructions, starting from the last one. For
	 * simplicity sake, we calculate the index inside the loop instead
	 * of writing the loop condition which either relies on UB or uses
	 * a signed integer.
	 */
	for (i = 0; i < difo->dtdo_len; i++) {
		idx = difo->dtdo_len - 1 - i;
		instr = difo->dtdo_buf[idx];

		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		/*
		 * Actual relocations
		 */
		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
		case DIF_OP_USETX:
		case DIF_OP_TYPECAST:
		/*
		 * Potential information necessary to apply relocations
		 */
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
		case DIF_OP_NOT:
		case DIF_OP_MOV:
		case DIF_OP_LDSB:
		case DIF_OP_LDSH:
		case DIF_OP_LDSW:
		case DIF_OP_LDUB:
		case DIF_OP_LDUH:
		case DIF_OP_LDUW:
		case DIF_OP_LDX:
		case DIF_OP_SETX:
		case DIF_OP_SETS:
		case DIF_OP_LDGA:
		case DIF_OP_LDGS:
		case DIF_OP_LDTA:
		case DIF_OP_LDTS:
		case DIF_OP_SRA:
		case DIF_OP_CALL:
		case DIF_OP_LDGAA:
		case DIF_OP_LDTAA:
		case DIF_OP_LDLS:
		case DIF_OP_ALLOCS:
		case DIF_OP_COPYS:
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
			relo = dt_relo_alloc(difo->dtdo_buf, idx);
			rl = malloc(sizeof(dt_rl_entry_t));
			memset(rl, 0, sizeof(dt_rl_entry_t));

			rl->drl_rel = relo;
			dt_list_append(&relo_list, rl);

			rd = DIF_INSTR_RD(instr);
			dt_update_relocations(difo, rd, idx);
			break;

		/* Everything else */
		default:
			break;
		}
	}

	return (0);
}

int
dt_prog_apply_rel(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp = NULL;
	dtrace_stmtdesc_t *sdp = NULL;
	dtrace_actdesc_t *ad = NULL;
	int rval = 0;

	/*
	 * Go over all the statements in a D program
	 */
	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == NULL)
			return (dt_set_errno(dtp, EDT_NOSTMT));

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == NULL)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == NULL)
			return (dt_set_errno(dtp, EDT_ACTLAST));

		/*
		 * We go over each action and apply the relocations in each
		 * DIFO (if it exists).
		 */
		for (ad = sdp->dtsd_action;
		    ad != sdp->dtsd_action_last; ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			rval = dt_prog_infer_defns(dtp, ad->dtad_difo);
			if (rval != 0)
				return (dt_set_errno(dtp, rval));

			rval = dt_prog_infer_types(dtp, ad->dtad_difo);
			if (rval != -0)
				return (dt_set_errno(dtp, rval));
		}
	}
	return (0);
}
