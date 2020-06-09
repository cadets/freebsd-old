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

#include <dt_linker_subr.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_relo.h>
#include <dt_basic_block.h>

#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <assert.h>
#include <stddef.h>

int
dt_clobbers_reg(dif_instr_t instr, uint8_t r)
{
	uint8_t opcode;
	uint8_t rd;

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
		rd = DIF_INSTR_RD(instr);
		return (r == rd);
	}

	return (0);
}

int
dt_var_is_builtin(uint16_t var)
{
	if (var == DIF_VAR_ARGS || var == DIF_VAR_REGS ||
	    var == DIF_VAR_UREGS)
		return (1);

	if (var >= DIF_VAR_CURTHREAD && var <= DIF_VAR_MAX)
		return (1);

	return (0);
}

int
dt_clobbers_var(dif_instr_t instr, dt_node_kind_t *nkind)
{
	uint8_t opcode;
	uint16_t v;
	uint8_t scope, varkind;

	scope = nkind->dtnk_scope;
	varkind = nkind->dtnk_varkind;

	if (varkind == DIFV_KIND_ARRAY)
		return (0);

	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_STGS:
		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (nkind->dtnk_var == v)
			return (1);
		break;

	case DIF_OP_STLS:
		if (scope != DIFV_SCOPE_LOCAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (nkind->dtnk_var == v)
			return (1);
		break;

	case DIF_OP_STTS:
		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (nkind->dtnk_var == v)
			return (1);
		break;
	}

	return (0);
}

dtrace_difv_t *
dt_get_variable(dtrace_difo_t *difo, uint16_t varid, int scope, int kind)
{
	dtrace_difv_t *var;
	size_t i;

	var = NULL;
	i = 0;

	for (i = 0; i < difo->dtdo_varlen; i++) {
		var = &difo->dtdo_vartab[i];

		if (var->dtdv_scope == scope && var->dtdv_kind == kind &&
		    var->dtdv_id == varid)
			return (var);

	}

	return (NULL);
}

dtrace_difv_t *
dt_get_var_from_varlist(uint16_t varid, int scope, int kind)
{
	dtrace_difv_t *var;
	dt_var_entry_t *ve;

	ve = NULL;
	var = NULL;

	for (ve = dt_list_next(&var_list); ve; ve = dt_list_next(ve)) {
		var = ve->dtve_var;

		if (var->dtdv_scope == scope && var->dtdv_kind == kind &&
		    var->dtdv_id == varid)
			return (var);
	}

	return (NULL);
}

void
dt_get_varinfo(dif_instr_t instr, uint16_t *varid, int *scope, int *kind)
{
	uint8_t opcode;

	opcode = DIF_INSTR_OP(instr);
	switch (opcode) {
	case DIF_OP_STGS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_GLOBAL;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STTS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_THREAD;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STLS:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_LOCAL;
		*kind = DIFV_KIND_SCALAR;
		break;

	case DIF_OP_STGAA:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_GLOBAL;
		*kind = DIFV_KIND_ARRAY;
		break;

	case DIF_OP_STTAA:
		*varid = DIF_INSTR_VAR(instr);
		*scope = DIFV_SCOPE_THREAD;
		*kind = DIFV_KIND_ARRAY;
		break;

	default:
		*varid = 0;
		*scope = -1;
		*kind = -1;
		break;
	}
}

void
dt_insert_var(dtrace_difo_t *difo, uint16_t varid, int scope, int kind)
{
	dt_var_entry_t *ve;
	dtrace_difv_t *var, *d_var;

	ve = NULL;
	var = d_var = NULL;

	/*
	 * Search through the existing variable list looking for
	 * the variable being currently defined. If we find it,
	 * we will simply break out of the loop and move onto
	 * the next instruction.
	 */
	for (ve = dt_list_next(&var_list); ve; ve = dt_list_next(ve)) {
		var = ve->dtve_var;
		if (var->dtdv_scope == scope &&
		    var->dtdv_kind == kind   &&
		    var->dtdv_id == varid)
			break;
	}

	if (ve != NULL)
		return;

	/*
	 * Get the variable we want from the DIFO table.
	 */
	d_var = dt_get_variable(difo, varid, scope, kind);
	if (d_var == NULL)
		errx(EXIT_FAILURE, "failed to find variable (%u, %d, %d)",
		    varid, scope, kind);

	/*
	 * Allocate a new variable to be put into our list and
	 * copy the contents of the variable in the DIFO table
	 * into the newly allocated region.
	 */
	var = malloc(sizeof(dtrace_difv_t));
	if (var == NULL)
		errx(EXIT_FAILURE, "failed to allocate a new variable");

	memcpy(var, d_var, sizeof(dtrace_difv_t));

	var->dtdv_ctfid = CTF_ERR;
	var->dtdv_sym = NULL;
	var->dtdv_type.dtdt_kind = DIF_TYPE_NONE;
	var->dtdv_type.dtdt_size = 0;
	var->dtdv_stack = NULL;

	ve = malloc(sizeof(dt_var_entry_t));
	if (ve == NULL)
		errx(EXIT_FAILURE,
		    "failed to allocate a new varlist entry");

	memset(ve, 0, sizeof(dt_var_entry_t));
	ve->dtve_var = var;

	dt_list_append(&var_list, ve);
}

void
dt_populate_varlist(dtrace_difo_t *difo)
{
	dt_var_entry_t *ve;
	dtrace_difv_t *var;
	size_t i;
	uint8_t opcode;
	dif_instr_t instr;
	uint16_t varid;

	ve = NULL;
	var = NULL;
	i = 0;
	opcode = 0;
	instr = 0;
	varid = 0;

	for (i = 0; i < difo->dtdo_len; i++) {
		instr = difo->dtdo_buf[i];
		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_STGS:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var(difo, varid, DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);
			break;

		case DIF_OP_STLS:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var(difo, varid, DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
			break;

		case DIF_OP_STTS:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var(difo, varid, DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
			break;

		case DIF_OP_STGAA:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var(difo, varid, DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
			break;

		case DIF_OP_STTAA:
			varid = DIF_INSTR_VAR(instr);
			dt_insert_var(difo, varid, DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
			break;
		}
	}
}


dt_stacklist_t *
dt_get_stack(dt_list_t *bb_path, dt_ifg_node_t *n)
{
	dt_stacklist_t *sl;

	sl = NULL;

	for (sl = dt_list_next(&n->din_stacklist); sl; sl = dt_list_next(sl)) {
		if (dt_list_equal(bb_path,
		    &sl->dsl_identifier, sizeof(dt_pathlist_t)))
			break;
	}

	if (sl == NULL) {
		sl = malloc(sizeof(dt_stacklist_t));
		if (sl == NULL)
			errx(EXIT_FAILURE, "failed to malloc sl");

		memset(sl, 0, sizeof(dt_stacklist_t));
		dt_list_copy((dt_list_t *)&sl->dsl_identifier,
		    bb_path, sizeof(dt_pathlist_t));

		dt_list_append(&n->din_stacklist, sl);
	}

	return (sl);
}
