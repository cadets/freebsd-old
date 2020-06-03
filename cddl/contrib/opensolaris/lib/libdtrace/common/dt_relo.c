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

#include <dt_relo.h>

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

dt_rl_entry_t *
dt_rle_alloc(dt_relo_t *relo)
{
	dt_rl_entry_t *rl;

	rl = malloc(sizeof(dt_rl_entry_t));
	if (rl == NULL)
		errx(EXIT_FAILURE, "failed to malloc relo entry");

	memset(rl, 0, sizeof(dt_rl_entry_t));
	rl->drl_rel = relo;

	return (rl);
}

dt_relo_t *
dt_relo_alloc(dtrace_difo_t *difo, uint_t idx)
{
	dt_relo_t *relo;

	relo = malloc(sizeof(dt_relo_t));
	if (relo == NULL)
		errx(EXIT_FAILURE, "failed to malloc relo");

	memset(relo, 0, sizeof(dt_relo_t));

	relo->dr_difo = difo;
	relo->dr_uidx = idx;

	/*
	 * Initialise the D type to -1 as 0 is defined as a CTF type.
	 */
	relo->dr_type = -1;
	relo->dr_sym = NULL;
	relo->dr_ctfid = CTF_ERR;

	return (relo);
	;}

void
dt_get_rkind(dif_instr_t instr, dt_rkind_t *rkind)
{
	uint8_t opcode;

	opcode = 0;
	memset(rkind, 0, sizeof(dt_rkind_t));

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
		rkind->r_kind = DT_RKIND_REG;
		rkind->r_rd = DIF_INSTR_RD(instr);
		break;

	case DIF_OP_STGS:
		rkind->r_kind = DT_RKIND_VAR;
		rkind->r_var = DIF_INSTR_VAR(instr);
		rkind->r_scope = DIFV_SCOPE_GLOBAL;
		rkind->r_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		rkind->r_kind = DT_RKIND_VAR;
		rkind->r_var = DIF_INSTR_VAR(instr);
		rkind->r_scope = DIFV_SCOPE_GLOBAL;
		rkind->r_varkind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		rkind->r_kind = DT_RKIND_VAR;
		rkind->r_var = DIF_INSTR_VAR(instr);
		rkind->r_scope = DIFV_SCOPE_THREAD;
		rkind->r_varkind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTS:
		rkind->r_kind = DT_RKIND_VAR;
		rkind->r_var = DIF_INSTR_VAR(instr);
		rkind->r_scope = DIFV_SCOPE_THREAD;
		rkind->r_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		rkind->r_kind = DT_RKIND_VAR;
		rkind->r_var = DIF_INSTR_VAR(instr);
		rkind->r_scope = DIFV_SCOPE_LOCAL;
		rkind->r_varkind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTR_G:
	case DIF_OP_PUSHTR_H:
	case DIF_OP_PUSHTV:
		rkind->r_kind = DT_RKIND_STACK;

	default:
		break;
	}
}

