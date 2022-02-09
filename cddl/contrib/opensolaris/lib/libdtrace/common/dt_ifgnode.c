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

#include <dt_ifgnode.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_list.h>
#include <dt_linker_subr.h>

#include <stdio.h>
#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdlib.h>

dt_ifg_list_t *
dt_ifgl_alloc(dt_ifg_node_t *node)
{
	dt_ifg_list_t *ifgl;

	ifgl = malloc(sizeof(dt_ifg_list_t));
	if (ifgl == NULL)
		errx(EXIT_FAILURE, "failed to malloc node entry");

	memset(ifgl, 0, sizeof(dt_ifg_list_t));
	ifgl->dil_ifgnode = node;

	return (ifgl);
}

dt_ifg_node_t *
dt_ifg_node_alloc(dtrace_prog_t *pgp, dtrace_ecbdesc_t *edp,
    dtrace_difo_t *difo, dt_basic_block_t *bb, uint_t idx)
{
	dt_ifg_node_t *node;

	node = malloc(sizeof(dt_ifg_node_t));
	if (node == NULL)
		errx(EXIT_FAILURE, "failed to malloc node");

	memset(node, 0, sizeof(dt_ifg_node_t));

	node->din_pgp = pgp;
	node->din_difo = difo;
	node->din_bb = bb;
	node->din_uidx = idx;
	node->din_edp = edp;

	/*
	 * Initialise the D type to -1 as 0 is defined as a CTF type.
	 */
	node->din_type = -1;
	node->din_sym = NULL;
	node->din_ctfid = CTF_ERR;

	return (node);
}

void
dt_get_nkind(dif_instr_t instr, dt_node_kind_t *nkind)
{
	uint8_t opcode;

	opcode = 0;
	memset(nkind, 0, sizeof(dt_node_kind_t));

	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
	case DIF_OP_USETX:
	case DIF_OP_TYPECAST:
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
		nkind->dtnk_kind = DT_NKIND_REG;
		nkind->dtnk_rd = DIF_INSTR_RD(instr);
		break;

	case DIF_OP_STGS:
		nkind->dtnk_kind = DT_NKIND_VAR;
		nkind->dtnk_var = DIF_INSTR_VAR(instr);
		nkind->dtnk_scope = DIFV_SCOPE_GLOBAL;
		nkind->dtnk_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		nkind->dtnk_kind = DT_NKIND_VAR;
		nkind->dtnk_var = DIF_INSTR_VAR(instr);
		nkind->dtnk_scope = DIFV_SCOPE_GLOBAL;
		nkind->dtnk_varkind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		nkind->dtnk_kind = DT_NKIND_VAR;
		nkind->dtnk_var = DIF_INSTR_VAR(instr);
		nkind->dtnk_scope = DIFV_SCOPE_THREAD;
		nkind->dtnk_varkind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTS:
		nkind->dtnk_kind = DT_NKIND_VAR;
		nkind->dtnk_var = DIF_INSTR_VAR(instr);
		nkind->dtnk_scope = DIFV_SCOPE_THREAD;
		nkind->dtnk_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		nkind->dtnk_kind = DT_NKIND_VAR;
		nkind->dtnk_var = DIF_INSTR_VAR(instr);
		nkind->dtnk_scope = DIFV_SCOPE_LOCAL;
		nkind->dtnk_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTV:
		nkind->dtnk_kind = DT_NKIND_STACK;

	default:
		break;
	}
}

/*
 * This subroutine assumes it's being called with a node `n` that is an
 * instruction with a destination register.
 */
uint8_t
dt_get_rd_from_node(dt_ifg_node_t *n)
{

	assert(n != NULL);
	return (DIF_INSTR_RD(n->din_difo->dtdo_buf[n->din_uidx]));
}
