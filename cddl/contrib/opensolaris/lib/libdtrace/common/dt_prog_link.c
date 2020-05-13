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
#include <err.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

static ctf_file_t *ctf_file;
static dt_list_t relo_list;
static dt_list_t bb_list;
static dt_rl_entry_t *relo_first = NULL;
static int discovered[DT_BB_MAX] = {0};

#define DTC_BOTTOM	-1
#define DTC_INT		 0
#define DTC_STRUCT	 1
#define DTC_STRING	 2

typedef struct dt_pathlist {
	dt_list_t dtpl_list;
	dt_basic_block_t *dtpl_bb;
} dt_pathlist_t;

static int
dt_in_list(dt_list_t *lst, void *find, size_t size)
{
	void *e;

	for (e = dt_list_next(lst); e; e = dt_list_next(e))
		if (memcmp((char *)e + sizeof(dt_list_t), find, size) == 0)
			return (1);

	return (0);
}


static int
dt_get_class(char *buf)
{
	size_t len;

	len = strlen(buf);

	if (len > strlen("struct") &&
	    strncmp(buf, "struct", strlen("struct")) == 0 &&
	    buf[len - 1] == '*')
		return (DTC_STRUCT);

	if (strcmp(buf, "char") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed char") == 0)
		return (DTC_INT);
	if (strcmp(buf, "unsigned char") == 0)
		return (DTC_INT);

	if (strcmp(buf, "short") == 0)
		return (DTC_INT);
	if (strcmp(buf, "short int") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed short") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed short int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "unsigned short") == 0)
		return (DTC_INT);
	if (strcmp(buf, "unsigned short int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "int") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "unsigned") == 0)
		return (DTC_INT);
	if (strcmp(buf, "unsigned int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "long int") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed long int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "unsigned long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "unsigned long int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "long long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "long long int") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed long long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "signed long long int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "unsigned long long") == 0)
		return (DTC_INT);
	if (strcmp(buf, "unsigned long long int") == 0)
		return (DTC_INT);

	if (strcmp(buf, "size_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "ssize_t") == 0)
		return (DTC_INT);

	if (strcmp(buf, "uint8_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "uint16_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "uint32_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "uint64_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "uintmax_t") == 0)
		return (DTC_INT);

	if (strcmp(buf, "int8_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "int16_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "int32_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "int64_t") == 0)
		return (DTC_INT);
	if (strcmp(buf, "intmax_t") == 0)
		return (DTC_INT);

	return (DTC_BOTTOM);
}

static int
dt_type_compare(dt_relo_t *dr1, dt_relo_t *dr2)
{
	char buf1[4096] = {0};
	char buf2[4096] = {0};
	int class1, class2;

	class1 = 0;
	class2 = 0;

	if (dr1->dr_type == DIF_TYPE_CTF)
		if (ctf_type_name(ctf_file, dr1->dr_ctfid, buf1,
		    sizeof(buf1)) != ((char *)buf1))
			errx(EXIT_FAILURE,
			    "failed at getting type name %ld: %s",
			    dr1->dr_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));

	if (dr2->dr_type == DIF_TYPE_CTF)
		if (ctf_type_name(ctf_file, dr2->dr_ctfid, buf2,
		    sizeof(buf2)) != ((char *)buf2))
			errx(EXIT_FAILURE,
			    "failed at getting type name %ld: %s",
			    dr2->dr_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));

	class1 = dr1->dr_type == DIF_TYPE_CTF ? dt_get_class(buf1) : DTC_STRING;
	class2 = dr2->dr_type == DIF_TYPE_CTF ? dt_get_class(buf2) : DTC_STRING;

	if (class1 == DTC_BOTTOM)
		errx(EXIT_FAILURE, "class1 is bottom because of %s", buf1);

	if (class2 == DTC_BOTTOM)
		errx(EXIT_FAILURE, "class2 is bottom because of %s", buf2);

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

static dt_rl_entry_t *
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

static dt_relo_t *
dt_relo_alloc(dtrace_difo_t *difo, uint_t idx)
{
	dt_relo_t *relo;

	relo = malloc(sizeof(dt_relo_t));
	memset(relo, 0, sizeof(dt_relo_t));

	relo->dr_difo = difo;
	relo->dr_uidx = idx;

	/*
	 * Initialise the D type to -1 as 0 is defined as a CTF type.
	 */
	relo->dr_type = -1;
	relo->dr_sym = 0;
	relo->dr_ctfid = -1;
	relo->dr_drel[0] = NULL;
	relo->dr_drel[1] = NULL;
	relo->dr_didx[0] = 0;
	relo->dr_didx[1] = 0;

	return (relo);
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
	uint8_t rs = 0, _r1 = 0, _r2 = 0, opcode = 0;

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

	default:
		break;
	}

	return (*r1 != 0 || *r2 != 0);
}

static int
dt_clobbers_var(dif_instr_t instr, dt_rkind_t *rkind)
{
	uint8_t opcode;
	uint16_t v;
	uint8_t scope, varkind;

	scope = rkind->r_scope;
	varkind = rkind->r_varkind;

	if (varkind == DIFV_KIND_ARRAY)
		return (0);

	opcode = DIF_INSTR_OP(instr);

	switch(opcode) {
	case DIF_OP_STGS:
		if (scope != DIFV_SCOPE_GLOBAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (rkind->r_var == v)
			return (1);
		break;

	case DIF_OP_STLS:
		if (scope != DIFV_SCOPE_LOCAL)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (rkind->r_var == v)
			return (1);
		break;

	case DIF_OP_STTS:
		if (scope != DIFV_SCOPE_THREAD)
			return (0);

		v = DIF_INSTR_VAR(instr);
		if (rkind->r_var == v)
			return (1);
		break;
	}

	return (0);
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

static void
dt_copy_list(dt_list_t *dst, dt_list_t *src, size_t entry_size)
{
	void *e, *new;

	e = new = NULL;

	for (e = dt_list_next(src); e; e = dt_list_next(e)) {
		new = malloc(entry_size);
		memset(new, 0, sizeof(dt_list_t));
		/*
		 * We ensure all pointers are set to NULL, and then we copy
		 * the actual data at the right offset.
		 */
		memcpy(((char *)new) + sizeof(dt_list_t),
		    ((char *)e) + sizeof(dt_list_t),
		    entry_size - sizeof(dt_list_t));

		dt_list_append(dst, new);
	}
}

static int
dt_list_equal(dt_list_t *fst, dt_list_t *snd, size_t entry_size)
{
	int empty;
	void *e1, *e2;

	empty = 1;
	e1 = e2 = NULL;

	for (e1 = dt_list_next(fst), e2 = dt_list_next(snd);
	     e1 && e2; e1 = dt_list_next(e1), e2 = dt_list_next(e2)) {
		if (memcmp((char *)e1 + sizeof(dt_list_t),
			(char *)e2 + sizeof(dt_list_t),
			entry_size - sizeof(dt_list_t)) != 0)
			return (0);

		empty = 0;
	}

	return (!empty);
}

static dt_stacklist_t *
dt_get_stack(dt_list_t *bb_path, dt_relo_t *r)
{
	dt_stacklist_t *sl;

	sl = NULL;

	for (sl = dt_list_next(&r->dr_stacklist); sl; sl = dt_list_next(sl)) {
		if (dt_list_equal(bb_path,
		    &sl->dsl_identifier, sizeof(dt_pathlist_t)))
			break;
	}

	if (sl == NULL) {
		sl = malloc(sizeof(dt_stacklist_t));
		memset(sl, 0, sizeof(dt_stacklist_t));
		dt_copy_list((dt_list_t *)&sl->dsl_identifier,
		    bb_path, sizeof(dt_pathlist_t));

		dt_list_append(&r->dr_stacklist, sl);
	}

	return (sl);
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
/*
	if (_difo != difo)
		return (0);
*/
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
		 * If the current instruction comes after the one we are looking
		 * at, we don't even need to look at it because DIF by defn
		 * has no loops.
		 */
		if (currelo->dr_uidx >= relo->dr_uidx)
			continue;

		if (relo->dr_uidx < bb->dtbb_start ||
		    relo->dr_uidx > bb->dtbb_end)
			continue;

		/*
		 * Get the information about which registers in the current
		 * relocation match rd.
		 */
		if (dt_usite_uses_stack(relo)) {
			s_entry = malloc(sizeof(dt_stack_t));
			memset(s_entry, 0, sizeof(dt_stack_t));

			s_entry->ds_rel = currelo;

			curstack = dt_get_stack(bb_path, relo);
			if (curstack == NULL)
				errx(EXIT_FAILURE, "curstack should not be NULL");

			if (dt_in_list(&curstack->dsl_stack,
			    (void *)&currelo, sizeof(dt_relo_t *)) == 0) {
				dt_list_append(&curstack->dsl_stack, s_entry);
			}
		}
	}

	return (0);
}

static int
dt_clobbers_reg(dif_instr_t instr, uint8_t r)
{
	uint8_t opcode;
	uint8_t rd;

	opcode = DIF_INSTR_OP(instr);

	switch(opcode) {
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

static int
dt_update_rel_bb_reg(dtrace_difo_t *difo, dt_basic_block_t *bb,
    uint8_t rd, dt_relo_t *currelo)
{
	dtrace_difo_t *_difo;
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int r1, r2;
	uint_t idx;
	dif_instr_t instr;
	dt_rl_entry_t *currelo_e;

	idx = 0;
	r1 = 0;
	r2 = 0;
	rl = NULL;
	relo = NULL;
	_difo = NULL;
	instr = 0;
	currelo_e = NULL;

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
		if (dt_usite_contains_reg(relo, rd, &r1, &r2)) {
			assert(r1 == 1 || r2 == 1);
			if (r1 == 1) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r1defs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r1defs, currelo_e);
			}

			if (r2 == 1) {
				currelo_e = dt_rle_alloc(currelo);
				if (dt_in_list(&relo->dr_r2defs,
				    (void *)&currelo, sizeof(dt_relo_t *)) == 0)
					dt_list_append(&relo->dr_r2defs, currelo_e);
			}
		}

		/*
		 * If we run into a redefinition of the current register,
		 * we simply break out of the loop, there is nothing left
		 * to fill in inside this basic block.
		 */
		if (dt_clobbers_reg(instr, rd))
			return (1);

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
		if (discovered[chld_bb->dtbb_idx] == 0)
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

	memset(discovered, 0, sizeof(int) * DT_BB_MAX);
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

static void
dt_builtin_type(dt_relo_t *r, uint16_t var)
{
	switch(var) {
	/*
	 * struct thread *
	 */
	case DIF_VAR_CURTHREAD:
	case DIF_VAR_GCURTHREAD:
	case DIF_VAR_HCURTHREAD:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, thread_str);
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type %s: %s",
			    thread_str, ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint64_t
	 */
	case DIF_VAR_HUCALLER:
	case DIF_VAR_GUCALLER:
	case DIF_VAR_UCALLER:
	case DIF_VAR_TIMESTAMP:
	case DIF_VAR_VTIMESTAMP:
	case DIF_VAR_GTIMESTAMP:
	case DIF_VAR_GVTIMESTAMP:
	case DIF_VAR_HTIMESTAMP:
	case DIF_VAR_HVTIMESTAMP:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint_t
	 */
	case DIF_VAR_IPL:
	case DIF_VAR_GIPL:
	case DIF_VAR_HIPL:
	case DIF_VAR_GEPID:
	case DIF_VAR_HEPID:
	case DIF_VAR_EPID:
	case DIF_VAR_ID:
	case DIF_VAR_HPRID:
	case DIF_VAR_GPRID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
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
	case DIF_VAR_GARG0:
	case DIF_VAR_GARG1:
	case DIF_VAR_GARG2:
	case DIF_VAR_GARG3:
	case DIF_VAR_GARG4:
	case DIF_VAR_GARG5:
	case DIF_VAR_GARG6:
	case DIF_VAR_GARG7:
	case DIF_VAR_GARG8:
	case DIF_VAR_GARG9:
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
	case DIF_VAR_GWALLTIMESTAMP:
	case DIF_VAR_WALLTIMESTAMP:
	case DIF_VAR_HWALLTIMESTAMP:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int64_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type int64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * uint32_t
	 */
	case DIF_VAR_STACKDEPTH:
	case DIF_VAR_USTACKDEPTH:
	case DIF_VAR_GSTACKDEPTH:
	case DIF_VAR_GUSTACKDEPTH:
	case DIF_VAR_HSTACKDEPTH:
	case DIF_VAR_HUSTACKDEPTH:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint32_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));
x
		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * uintptr_t
	 */
	case DIF_VAR_GCALLER:
	case DIF_VAR_CALLER:
	case DIF_VAR_HCALLER:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uintptr_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uintptr_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * string
	 */
	case DIF_VAR_PROBEPROV:
	case DIF_VAR_PROBEMOD:
	case DIF_VAR_PROBEFUNC:
	case DIF_VAR_PROBENAME:
	case DIF_VAR_GPROBEPROV:
	case DIF_VAR_GPROBEMOD:
	case DIF_VAR_GPROBEFUNC:
	case DIF_VAR_GPROBENAME:
	case DIF_VAR_HPROBEPROV:
	case DIF_VAR_HPROBEMOD:
	case DIF_VAR_HPROBEFUNC:
	case DIF_VAR_HPROBENAME:
	case DIF_VAR_EXECNAME:
	case DIF_VAR_ZONENAME:
	case DIF_VAR_HEXECNAME:
	case DIF_VAR_HZONENAME:
	case DIF_VAR_GEXECNAME:
	case DIF_VAR_GZONENAME:
	case DIF_VAR_GJAILNAME:
	case DIF_VAR_JAILNAME:
	case DIF_VAR_HJAILNAME:
	case DIF_VAR_VMNAME:
	case DIF_VAR_GVMNAME:
	case DIF_VAR_HVMNAME:
	case DIF_VAR_EXECARGS:
	case DIF_VAR_GEXECARGS:
	case DIF_VAR_HEXECARGS:
		r->dr_type = DIF_TYPE_STRING;
		break;

	/*
	 * pid_t
	 */
	case DIF_VAR_GPID:
	case DIF_VAR_HPID:
	case DIF_VAR_PID:
	case DIF_VAR_PPID:
	case DIF_VAR_GPPID:
	case DIF_VAR_HPPID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "pid_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type pid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * id_t
	 */
	case DIF_VAR_GTID:
	case DIF_VAR_HTID:
	case DIF_VAR_TID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "id_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type id_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * uid_t
	 */
	case DIF_VAR_UID:
	case DIF_VAR_GUID:
	case DIF_VAR_HUID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uid_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * gid_t
	 */
	case DIF_VAR_GID:
	case DIF_VAR_GGID:
	case DIF_VAR_HGID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "gid_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type gid_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;

	/*
	 * int
	 */
	case DIF_VAR_GCPU:
	case DIF_VAR_HCPU:
	case DIF_VAR_CPU:
	case DIF_VAR_HERRNO:
	case DIF_VAR_GERRNO:
	case DIF_VAR_ERRNO:
	case DIF_VAR_GJID:
	case DIF_VAR_HJID:
	case DIF_VAR_JID:
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type int: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		break;
	default:
		errx(EXIT_FAILURE, "variable %x does not exist", var);
	}
}

static int
dt_typecheck_regdefs(dt_list_t *defs)
{
	dt_rl_entry_t *rl;
	dt_relo_t *relo, *orelo;
	char buf1[4096] = {0}, buf2[4096] = {0};
	int type, otype;
	int class1, class2;

	rl = NULL;
	type = otype = -1;
	class1 = class2 = -1;
	relo = orelo = NULL;

	/*
	 * We iterate over all the register definitions for a particular
	 * relocation. We make sure that each of the definitions agrees
	 * on the type of the register.
	 */
	for (rl = dt_list_next(defs); rl; rl = dt_list_next(rl)) {
		orelo = relo;
		relo = rl->drl_rel;

		otype = type;
		type = dt_infer_type(relo);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1)
			return (-1);

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (orelo && otype != type) {
			fprintf(stderr, "otype = %d, type = %d\n", otype, type);
			return (-1);
		}

		if (type == DIF_TYPE_CTF) {
			/*
			 * We get the type name for reporting purposes.
			 */
			if (ctf_type_name(ctf_file, relo->dr_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    relo->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (orelo == NULL)
				continue;

 			/*
			 * Get the previous' relocation's inferred type for
			 * error reporting.
			 */
			if (ctf_type_name(ctf_file, orelo->dr_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    orelo->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (relo->dr_ctfid != orelo->dr_ctfid) {
				fprintf(stderr, "types %s and %s do not match\n",
				    buf1, buf2);
				return (-1);
			}
		}
	}

	return (type);
}


static int
dt_typecheck_vardefs(dt_list_t *defs)
{
	dt_rl_entry_t *rl;
	dt_relo_t *relo, *orelo;
	char buf1[4096] = {0}, buf2[4096] = {0};
	int type, otype;
	int class1, class2;

	rl = NULL;
	type = otype = -1;
	class1 = class2 = -1;
	relo = orelo = NULL;

	/*
	 * We iterate over all the variable definitions for a particular
	 * relocation that is created through a variable load instruction.
	 * We make sure that:
	 *  (1) All definitions agree on the type of the variable
	 *  (2) All definitions conform to the previously inferred variable
	 *      type from a different DIFO (if it exists).
	 */
	for (rl = dt_list_next(defs); rl; rl = dt_list_next(rl)) {
		orelo = relo;
		relo = rl->drl_rel;

		otype = type;
		type = dt_infer_type(relo);

		/*
		 * We failed to infer the type to begin with, bail out.
		 */
		if (type == -1) {
			fprintf(stderr, "failed to infer type\n");
			return (-1);
		}

		/*
		 * The type at the previous definition does not match the type
		 * inferred in the current one, which is nonsense.
		 */
		if (orelo && otype != type) {
			fprintf(stderr, "otype and type mismatch (%d, %d)\n",
			    otype, type);
			return (-1);
		}

		/*
		 * We get the variable from the variable table.
		 *
		 * N.B.: This is not the variable table that is in the DIFO,
		 *       it is rather a separate variable table that we use
		 *       to keep track of types for each variable _across_
		 *       DIFOs.
		 *
		 * TODO: Actually implement this.
		 */
		var = dt_get_variable(difo, varid, kind, scope);

		/*
		 * The previously inferred variable type must match the
		 * current type we inferred.
		 */
		if (var->dtdv_type != type)
			return (-1);

		if (type == DIF_TYPE_CTF) {
			/*
			 * We get the type name for reporting purposes.
			 */
			if (ctf_type_name(ctf_file, relo->dr_ctfid, buf1,
			    sizeof(buf1)) != ((char *)buf1))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    relo->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the variable already has a type assigned to it,
			 * but it is not the same type that we just inferred
			 * it to be, we get the type name of the variable and
			 * report an error.
			 */
			if (var->dtdv_ctfid != -1 &&
			    relo->dr_ctfid != var->dtdv_ctfid) {
				if (var->dtdv_name >= difo->dtdo_strlen)
					errx(EXIT_FAILURE,
					    "variable name outside strtab "
					    "(%zu, %zu)", var->dtdv_name,
					    difo->dtdo_strlen);

				if (ctf_type_name(ctf_file, var->dtdv_ctfid, buf2,
					sizeof(buf2)) != ((char *)buf2))
					errx(EXIT_FAILURE,
					    "failed at getting type name %ld: %s",
					    var->dtdv_ctfid,
					    ctf_errmsg(ctf_errno(ctf_file)));

				fprintf(stderr, "variable (%s) type and "
				    "inferred type mismatch: %s, %s",
				    difo->dtdo_strtab + var->dtdv_name,
				    buf1, buf2);
				return (-1);
			}

			/*
			 * If we are at the first definition, or only have one
			 * definition, we don't need to check the types.
			 */
			if (orelo == NULL)
				continue;

 			/*
			 * Get the previous' relocation's inferred type for
			 * error reporting.
			 */
			if (ctf_type_name(ctf_file, orelo->dr_ctfid, buf2,
			    sizeof(buf2)) != ((char *)buf2))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    other->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * Fail to typecheck if the types don't match 100%.
			 */
			if (relo->dr_ctfid != orelo->dr_ctfid) {
				fprintf(stderr, "types %s and %s do not match\n",
				    buf1, buf2);
				return (-1);
			}
		}
	}

	return (type);
}

static int
dt_infer_type(dt_relo_t *r)
{
	dt_relo_t *dr1, *dr2, *tc_r, *symrelo, *other;
	int type1, type2, res, i, t;
	char buf[4096] = {0}, symname[4096] = {0};
	ctf_membinfo_t *mip;
	size_t l;
	uint16_t var;
	dtrace_difo_t *difo;
	dif_instr_t instr;
	uint8_t opcode;
	uint16_t sym, subr;
	dt_stacklist_t *sl;
	dt_relo_t *arg0, *arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *arg7, *arg8;
	ctf_file_t *octfp = NULL;
	ctf_id_t type = 0;

	dr1 = r->dr_drel[0];
	dr2 = r->dr_drel[1];
	type1 = -1;
	type2 = -1;
	mip = NULL;
	sl = NULL;
	l = 0;
	difo = r->dr_difo;
	instr = 0;
	opcode = 0;
	sym = 0;
	res = 0;
	tc_r = NULL;
	symrelo = NULL;
	other = NULL;
	var = 0;
	i = 0;
	subr = 0;
	arg0 = arg1 = arg2 = arg3 = arg4 = arg5 = arg6 = arg7 = arg8 = NULL;
	t = 0;

	/*
	 * If we already have the type, we just return it.
	 */
	if (r->dr_type != -1)
		return (r->dr_type);

	instr = r->dr_buf[r->dr_uidx];
	opcode = DIF_INSTR_OP(instr);

	type = dt_typecheck_regdefs(&r->dr_r1defs);
	if (type == -1)
		return (-1);

	type = dt_typecheck_regdefs(&r->dr_r2defs);
	if (type == -1)
		return (-1);

	type = dt_typecheck_vardefs(&r->dr_vardefs);
	if (type == -1)
		return (-1);

	for (rl = dt_list_next(&r->dr_vardefs); rl; rl = dt_list_next(rl)) {
	}

	for (sl = dt_list_next(&r->dr_stacklist); sl; sl = dt_list_next(sl)) {
	}

	if (dr1 != NULL) {
		type1 = dt_infer_type(dr1);
		if (type1 != DIF_TYPE_CTF && type1 != DIF_TYPE_STRING) {
			fprintf(stderr, "type1 could not be inferred\n");
			return (-1);
		}
	}

	if (dr2 != NULL) {
		type2 = dt_infer_type(dr2);
		if (type2 != DIF_TYPE_CTF && type2 != DIF_TYPE_STRING) {
			fprintf(stderr, "type2 could not be inferred\n");
			return (-1);
		}
	}

	/*
	 * It seems like we might need a poset of types, knowing what to cast to
	 * when we have something like add %r1, %r1, %r2
	 * where %r1 : struct foo * @ 0
	 *       %r2 : uint64_t
	 * We'd want to know that the resulting type of %r1 after the add is
	 *       %r1 : struct foo * @ r2 (UNRESOLVED)
	 * which can then be resolved to either
	 *       %r1 : struct foo * @ n (constant compile-time)
	 * or
	 *       %r1 : struct foo @ r2 (runtime)
	 *
	 * There are a number of assumptions we make here:
	 *  (1) the runtime values will always be sensible, otherwise we
	 *      can't say anything about the resulting type. We must assume
	 *      that after adding %r2 to %r1, we will still land in struct foo.
	 *  (2) structs take priority over integers. That is to say, if we add
	 *      an integer to a struct, we require that the class of integers,
	 *      call it Integer is <: than the class of Struct. That is:
	 *
	 *                   -----------------
	 *                   Integer <: Struct
	 *
	 * Another point of interest is instructions like ldx.
	 * The resulting type will depend on the previously inferred information.
	 *
	 * While it may be reasonable to think that ldx should be an uint64_t,
	 * you can imagine a case of curthread->td_proc->p_pid. Here, the first
	 * ldx (one getting td_proc) is actually resulting of struct proc *, not
	 * an uint64_t. Thus, we need to actually infer that:
	 *  (1) in an uload [%r1], %r1. We need to know that %r1 we are trying
	 *      to load from is in fact %r1 : struct thread * @ n (constant)
	 *      and that the resulting type, namely struct thread + n gives us
	 *      a type of struct proc *, which we need to load using ldx.
	 *  (2) the offset (usetx) already needs to be resolved
	 *
	 * For the CTF API, we need to also know the symbol name, so we might
	 * as well keep the information in what symbol was resolved in order to
	 * reach the offset, e.g. struct foo * @ n (constant, sym_name).
	 */
	switch(opcode) {
	/*
	 * Actual relocations
	 */
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
		if (dr1 == NULL) {
			fprintf(stderr, "uload/uuload dr1 is NULL\n");
			return (-1);
		}

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dr1->dr_sym == 0) {
			fprintf(stderr, "uload/uuload dr1 symbol is empty\n");
			return (-1);
		}

		/*
		 * sym in range(symtab)
		 */
		if (dr1->dr_sym >= difo->dtdo_symlen)
			errx(EXIT_FAILURE, "sym (%zu) is out of range: %zu",
			    dr1->dr_sym, difo->dtdo_symlen);

		/*
		 * symtab(sym) = symname
		 */
		l = strlcpy(symname, difo->dtdo_symtab +
		    dr1->dr_sym, sizeof(symname));
		if (l >= sizeof(symname))
			errx(EXIT_FAILURE,
			    "l (%zu) >= %zu when copying symbol name",
			    l, sizeof(symname));

		/*
		 * Get the original type name of dr1->dr_ctfid for
		 * error reporting.
		 */
		if (ctf_type_name(ctf_file, dr1->dr_ctfid, buf,
		    sizeof(buf)) != ((char *)buf))
			errx(EXIT_FAILURE,
			    "failed at getting type name %ld: %s",
			    dr1->dr_ctfid,
			    ctf_errmsg(ctf_errno(ctf_file)));


		if (dt_get_class(buf) != DTC_STRUCT)
			return (-1);

		/*
		 * Figure out t2 = type_at(t1, symname)
		 */
		mip = malloc(sizeof(ctf_membinfo_t));
		memset(mip, 0, sizeof(ctf_membinfo_t));

		/*
		 * Get the non-pointer type. This should NEVER fail.
		 */
		type = ctf_type_reference(ctf_file, dr1->dr_ctfid);

		if (dt_lib_membinfo(
		    octfp = ctf_file, type, symname, mip) == 0)
			errx(EXIT_FAILURE, "failed to get member info"
			    " for %s(%s): %s",
			    buf, symname,
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_mip = mip;
		r->dr_ctfid = mip->ctm_type;
		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);


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

		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint64_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_sym = sym;
		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

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
			errx(EXIT_FAILURE,
			    "l (%zu) >= %zu when copying type name",
			    l, sizeof(symname));

		r->dr_ctfid = ctf_lookup_by_name(ctf_file, symname);
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type %s: %s",
			    symname, ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);
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
		if (dr1 == NULL) {
			fprintf(stderr, "r1r2: dr1 is NULL\n");
			return (-1);
		}

		if (dr2 == NULL) {
			fprintf(stderr, "r1r2: dr2 is NULL\n");
			return (-1);
		}

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dr1->dr_sym == 0 && dr2->dr_sym == 0) {
			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(dr1, dr2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1)
				tc_r = dr1;
			else if (res == 2)
				tc_r = dr2;
			else {
				fprintf(stderr,
				    "r1r2 nosym: types can not be compared\n");
				return (-1);
			}

			/*
			 * We don't have to sanity check these because we do it
			 * in every base case of the recursive call.
			 */
			r->dr_type = tc_r->dr_type;
			r->dr_ctfid = tc_r->dr_ctfid;
		} else {
			symrelo = dr1->dr_sym != 0 ? dr1 : dr2;
			other = dr1->dr_sym != 0 ? dr2 : dr1;

			/*
			 * Get the type name
			 */
			if (ctf_type_name(
			    ctf_file, symrelo->dr_ctfid,
			    buf, sizeof(buf)) != ((char *)buf))
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", symrelo->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (strcmp(buf, "uint64_t") != 0)
				errx(EXIT_FAILURE, "symbol may not exist if not"
				    " paired with a uint64_t: %s", buf);

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(symrelo, other);
			assert(res == 1 || res == 2 || res == -1);

			if (res == -1) {
				fprintf(stderr,
				    "r1r2 sym: types can not be compared\n");
				return (-1);
			}

			/*
			 * Get the type name of the other relocation
			 */
			if (ctf_type_name(ctf_file, other->dr_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				errx(EXIT_FAILURE,
				    "failed at getting type name %ld: %s",
				    other->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			if (res == 1) {
				if (strcmp(buf, "uint64_t") != 0)
					errx(EXIT_FAILURE, "the type of the"
					    " other relocation must be unit64_t"
					    " if symrelo->dr_ctfid <: "
					    " other->dr_ctfid, but it is: %s",
					    buf);
			}

			/*
			 * At this point, we have ensured that the types are:
			 *  (1) Related (<: exists between t1 and t2)
			 *  (2) Well-ordered: if
			 *
			 *            symrelo->dr_ctfid <: other->dr_ctfid,
			 *
			 *      then other->dr_ctfid is also
			 *      uint64_t (reflexivity).
			 *  (3) One of the uint64_ts originates from a symbol.
			 */

			r->dr_sym = symrelo->dr_sym;
			r->dr_ctfid = other->dr_ctfid;
			r->dr_type = DIF_TYPE_CTF;
		}

		return (r->dr_type);

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
		 *       if dr1 is not NULL, then we'll have checked it already.
		 */
		if (dr1 == NULL) {
			fprintf(stderr, "mov/not: dr1 is NULL\n");
			return (-1);
		}

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->dr_sym;

		return (r->dr_type);

	case DIF_OP_LDSB:
	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
		/*
		 *          %r1 :: Pointer
		 * -----------------------------------
		 *  opcode [%r1], %r2 => %r2 : int8_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int8_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			    "failed to get type int8_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDSH:
	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int16_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int16_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			    "failed to get type int16_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDSW:
	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int32_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int32_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			     "failed to get type unsigned char: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDUB:
	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint8_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint8_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			    "failed to get type uint8_t: %s",
			    ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDUH:
	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint16_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint16_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			     "failed to get type uint16_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDUW:
	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint32_t
		 */
		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE,
			     "failed to get type uint32_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_LDX:
	case DIF_OP_SETX:
		/*
		 * ---------------------------------
		 *  setx idx, %r1 => %r1 : uint64_t
		 */

		r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
		if (r->dr_ctfid == CTF_ERR)
			errx(EXIT_FAILURE, "failed to get type uint64_t: %s",
			     ctf_errmsg(ctf_errno(ctf_file)));

		r->dr_type = DIF_TYPE_CTF;
		return (r->dr_type);

	case DIF_OP_SETS:
		/*
		 * --------------------------------
		 *  sets idx, %r1 => %r1: D string
		 */

		r->dr_type = DIF_TYPE_STRING;
		return (r->dr_type);

	case DIF_OP_LDGA:
		break;

	case DIF_OP_LDGS:
	case DIF_OP_LDTS:
	case DIF_OP_LDLS:
		/*
		 *           var : t
		 * ----------------------------
		 *  opcode var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dr1 == NULL) {
			if (opcode == DIF_OP_LDGS && var < DIF_VAR_MAX) {
				dt_builtin_type(r, var);
				return (r->dr_type);
			}

			fprintf(stderr, "ld*: dr1 is NULL\n");
			return (-1);
		}

		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->dr_sym;

		return (r->dr_type);

	case DIF_OP_STGS:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		/*
		 *  %r1 : t       var notin builtins
		 * ----------------------------------
		 *     opcode %r1, var => var : t
		 */

		/*
		 * This is redundant currently, but leave it here for error
		 * reporting in the future.
		 */
		if (dr1 == NULL) {
			/*
			 * If we are doing a STGS, and the variable is a builtin
			 * variable, we fail to type-check the instruction.
			 */
			fprintf(stderr, "st*: dr1 is NULL\n");
			if (opcode == DIF_OP_STGS)
				for (i = 0; i < DIF_VAR_MAX; i++)
					if (var == i)
						return (-1);

			return (-1);
		}

		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->dr_sym;

		return (r->dr_type);

	case DIF_OP_LDTA:
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
		 * TODO: Add type-checking for things on the stack.
		 *       getmajor/getminor?
		 */
		/*
		 * Infer each of the stack types. We should at this point have:
		 *  (1) the D type (CTF or string)
		 *  (2) the CTF id if it's a CTF type
		 *
		 * which we can use to compare the CTF type ID with the expected
		 * type for a subroutine, ensuring that proper arguments are
		 * being passed through to the subroutines.
		 */
		for (sl = dt_list_next(&r->dr_stacklist); sl != NULL;
		    sl = dt_list_next(sl))
			if ((t = dt_infer_type(sl->dsl_rel)) == -1) {
				fprintf(stderr,
				    "stack type could not be inferred\n");
				return (-1);
			}

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
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MUTEX_OWNED:
		case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
		case DIF_SUBR_MUTEX_TYPE_SPIN:
			/*
			 * We expect a "struct mtx *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "mutex_owned/type() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, mtx_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, mtx_str);
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MUTEX_OWNER:
			/*
			 * We expect a "struct mtx *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "mutex_owner() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, thread_str);
#elif defined(illumos)
			/*
			 * illumos not quite supported yet.
			 */
			return (-1);
#endif
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get thread type: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_READ_HELD:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "rw_read_held() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				     ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_WRITE_HELD:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "rw_write_held() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				     ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RW_ISWRITER:
			/*
			 * We expect a "struct rwlock *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "rw_iswriter() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, rw_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, rw_str);
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYIN:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyin() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyin() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYINSTR:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyinstr() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl != NULL) {
				if (sl->dsl_rel == NULL)
					errx(EXIT_FAILURE,
					    "copyinstr() dsl_rel is NULL");

				arg1 = sl->dsl_rel;

				if (ctf_type_name(ctf_file,
				    arg1->dr_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->dr_ctfid,
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

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_SPECULATION:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_PROGENYOF:
			/*
			 * We expect a "pid_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "progenyof() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "pid_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "pid_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_STRLEN:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "strlen() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "size_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type size_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_COPYOUT:
			/*
			 * We expect a "void *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyout() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyout() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyout() third argument is NULL");

			arg2 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg2->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg2->dr_ctfid,
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
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyoutstr() third argument is NULL");

			arg2 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg2->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg2->dr_ctfid,
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
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "alloca() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_BCOPY:
			/*
			 * We expect a "void *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "bcopy() third argument is NULL");

			arg2 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg2->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg2->dr_ctfid,
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
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "copyinto() third argument is NULL");

			arg2 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg2->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg2->dr_ctfid,
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
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "msg(d)size() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "mblk_t *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "mblk_t *");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "size_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type size_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_GETMAJOR:
			break;
		case DIF_SUBR_GETMINOR:
			break;

		case DIF_SUBR_DDI_PATHNAME:
			/*
			 * We expect a "void *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int64_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int64_t");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_LLTOSTR:
			/*
			 * We expect a "int64_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "lltostr() second argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl != NULL) {
				if (sl->dsl_rel == NULL)
					errx(EXIT_FAILURE,
					    "lltostr() dsl_rel is NULL");

				arg1 = sl->dsl_rel;

				if (ctf_type_name(ctf_file,
				    arg1->dr_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->dr_ctfid,
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

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_CLEANPATH:
		case DIF_SUBR_DIRNAME:
		case DIF_SUBR_BASENAME:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "basename/dirname/cleanpath() "
				    "first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_STRRCHR:
		case DIF_SUBR_STRCHR:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "strchr() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "strchr() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "char") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "char");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_SUBSTR:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "substr() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "substr() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
				if (sl->dsl_rel == NULL)
					errx(EXIT_FAILURE,
					    "substr() dsl_rel is NULL");

				arg2 = sl->dsl_rel;

				if (ctf_type_name(ctf_file,
				    arg2->dr_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg2->dr_ctfid,
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

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_RINDEX:
		case DIF_SUBR_INDEX:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "(r)index() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "(r)index() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
				if (sl->dsl_rel == NULL)
					errx(EXIT_FAILURE,
					    "(r)index() dsl_rel is NULL");

				arg2 = sl->dsl_rel;

				if (ctf_type_name(ctf_file,
				    arg2->dr_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg2->dr_ctfid,
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

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHS:
		case DIF_SUBR_HTONS:
			/*
			 * We expect a "uint16_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ntohs/htons() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint16_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint16_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint16_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint16_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHL:
		case DIF_SUBR_HTONL:
			/*
			 * We expect a "uint32_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ntohl/htonl() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint32_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint32_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint32_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint32_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_NTOHLL:
		case DIF_SUBR_HTONLL:
			/*
			 * We expect a "uint64_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ntohll/htonll() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uint64_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uint64_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_INET_NTOP:
			/*
			 * We expect a "int" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntop() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ddi_pathname() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "void *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "void *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA:
			/*
			 * We expect a "in_addr_t *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntoa() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "in_addr_t *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "in_addr_t *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA6:
			/*
			 * We expect a "struct in6_addr *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "inet_ntoa6() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "struct in6_addr *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "struct in6_addr *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_TOLOWER:
		case DIF_SUBR_TOUPPER:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "toupper/tolower() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_MEMREF:
			/*
			 * We expect a "void *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "memref() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "memref() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(
			    ctf_file, "uintptr_t *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uintptr_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_SX_SHARED_HELD:
		case DIF_SUBR_SX_EXCLUSIVE_HELD:
		case DIF_SUBR_SX_ISEXCLUSIVE:
			/*
			 * We expect a sx_str as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "sx_*() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, sx_str) != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, sx_str);
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MEMSTR:
			/*
			 * We expect a "void *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "memstr() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "memstr() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "memstr() second argument is NULL");

			arg2 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg2->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg2->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "size_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "size_t");
				return (-1);
			}


			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_GETF:
			/*
			 * We expect a "int" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "getf() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "int") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "int");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "file_t *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type file_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_STRTOLL:
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "strtoll() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			sl = dt_list_next(sl);
			if (sl != NULL) {
				if (sl->dsl_rel == NULL)
					errx(EXIT_FAILURE,
					    "strtoll() dsl_rel is NULL");

				arg1 = sl->dsl_rel;

				if (ctf_type_name(ctf_file,
				    arg1->dr_ctfid,
				    buf, sizeof(buf)) != (char *)buf)
					errx(EXIT_FAILURE,
					    "failed at getting type name"
					    " %ld: %s", arg1->dr_ctfid,
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

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int64_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type int64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_RANDOM:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "uint64_t");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uint64_t: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_PTINFO:
			/*
			 * We expect a "uintptr_t" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "ptinfo() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "uintptr_t") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "uintptr_t");
				return (-1);
			}

			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "void *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type void *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
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
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "str/json() first argument is NULL");

			arg0 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg0->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg0->dr_ctfid,
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
			 * We expect a "const char *" as the second argument.
			 */
			sl = dt_list_next(sl);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "str/json() second argument is NULL");

			arg1 = sl->dsl_rel;

			if (ctf_type_name(ctf_file,
			    arg1->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", arg1->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));

			/*
			 * If the argument type is wrong, fail to type check.
			 */
			if (strcmp(buf, "const char *") != 0) {
				fprintf(stderr, "%s and %s are not the same",
				    buf, "const char *");
				return (-1);
			}

			r->dr_type = DIF_TYPE_STRING;
			break;
		default:
			return (-1);
		}

		return (r->dr_type);

	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_ALLOCS:
	case DIF_OP_COPYS:
	case DIF_OP_ULDX:
	case DIF_OP_RLDX:
		break;
	}

	return (-1);
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

	difo->dtdo_types = malloc(sizeof(char *) * difo->dtdo_len);
	i = difo->dtdo_len - 1;

	for (rl = dt_list_next(&relo_list);
	    rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;

		if (relo->dr_buf == NULL)
			continue;

		if (relo->dr_buf != difo->dtdo_buf)
			continue;

		instr = relo->dr_buf[relo->dr_uidx];
		opcode = DIF_INSTR_OP(instr);

		type = dt_infer_type(relo);
		assert(type == -1 ||
		    type == DIF_TYPE_CTF || type == DIF_TYPE_STRING);

		if (type == -1)
			errx(EXIT_FAILURE, "failed to infer a type");

		if (type == DIF_TYPE_CTF) {
			if (ctf_type_name(ctf_file,
			    relo->dr_ctfid, buf, sizeof(buf)) != (char *)buf)
				errx(EXIT_FAILURE, "failed at getting type name"
				    " %ld: %s", relo->dr_ctfid,
				    ctf_errmsg(ctf_errno(ctf_file)));
			difo->dtdo_types[relo->dr_uidx] = strdup(buf);
		} else
			difo->dtdo_types[relo->dr_uidx] = strdup("string");
	}

	return (0);
}

static void
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

/*
 * Determine what instructions clobber relevant state in the DTrace
 * abstract machine. This includes registers, the stack or a variable.
 */
static int
dt_clobbers(dif_instr_t instr)
{
	uint8_t opcode;

	opcode = DIF_INSTR_OP(instr);
	switch(opcode) {
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
	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
	case DIF_OP_PUSHTR:
	case DIF_OP_PUSHTR_G:
	case DIF_OP_PUSHTR_H:
	case DIF_OP_PUSHTV:
		return (1);
	}

	return (0);
}

static int
dt_is_relo(dif_instr_t instr)
{

	uint8_t op = DIF_INSTR_OP(instr);
	return (dt_clobbers(instr) || (op >= DIF_OP_BA && op <= DIF_OP_BLEU));
}

static dt_basic_block_t *
dt_alloc_bb(dtrace_difo_t *difo)
{
	dt_basic_block_t *bb;
	static size_t i = 0;

	bb = malloc(sizeof(dt_basic_block_t));
	if (bb == NULL)
		return (NULL);

	memset(bb, 0, sizeof(dt_basic_block_t));
	bb->dtbb_difo = difo;
	bb->dtbb_idx = i++;

	return (bb);
}

static dt_bb_entry_t *
dt_alloc_bb_e(dtrace_difo_t *difo)
{
	dt_bb_entry_t *bb_e;

	bb_e = malloc(sizeof(dt_bb_entry_t));
	if (bb_e == NULL)
		errx(EXIT_FAILURE, "failed to allocate the BB list entry");

	memset(bb_e, 0, sizeof(dt_bb_entry_t));

	bb_e->dtbe_bb = dt_alloc_bb(difo);
	if (bb_e->dtbe_bb == NULL)
		errx(EXIT_FAILURE, "failed to allocate the basic block");

	return (bb_e);
}

static void
dt_compute_bb(dtrace_difo_t *difo)
{
	dt_basic_block_t *bb;
	dt_bb_entry_t *bb_e;
	int *leaders;
	uint16_t lbl;
	dif_instr_t instr;
	uint8_t opcode;
	int i;

	bb = NULL;
	bb_e = NULL;
	leaders = NULL;
	i = 0;
	lbl = 0;
	instr = 0;
	opcode = 0;

	leaders = malloc(sizeof(int) * difo->dtdo_len);
	memset(leaders, 0, sizeof(int) * difo->dtdo_len);

	/*
	 * First instruction is a leader.
	 */
	leaders[0] = 1;

	/*
	 * Compute the leaders.
	 */
	for (i = 0; i < difo->dtdo_len; i++) {
		instr = difo->dtdo_buf[i];
		opcode = DIF_INSTR_OP(instr);

		if (opcode >= DIF_OP_BA && opcode <= DIF_OP_BLEU) {
			lbl = DIF_INSTR_LABEL(instr);
			if (lbl >= difo->dtdo_len)
				errx(EXIT_FAILURE, "lbl (%hu) branching outside"
				    " of code length (%zu)",
				    lbl, difo->dtdo_len);

			/*
			 * We have a valid label. Any DIFO which does not end
			 * with a ret instruction is not valid, so we check if
			 * position i + 1 is a valid instruction.
			 */
			if (i + 1 >= difo->dtdo_len)
				errx(EXIT_FAILURE, "malformed DIFO");

			leaders[i + 1] = 1;
			leaders[lbl] = 1;
		}
	}

	/*
	 * For each leader we encounter, we compute the set of all instructions
	 * that fit into the current basic block.
	 */
	for (i = 0; i < difo->dtdo_len; i++) {
		if (leaders[i] == 1) {
			/*
			 * We've encountered a leader, we don't actually need
			 * to copy any instructions over, as we already have
			 * them in a DIFO (and we will be changing said
			 * instructions in the DIFO itself). Instead, we just
			 * observe that we will always have had a basic block
			 * allocated in our bb pointer and simply save the end
			 * instruction as the instruction before the leader and
			 * allocate a new basic block with the leader as the
			 * starting instruction.
			 */
			if (bb != NULL) {
				bb->dtbb_end = i - 1;
			}

			bb_e = dt_alloc_bb_e(difo);

			if (bb == NULL)
				difo->dtdo_bb = bb_e->dtbe_bb;
			bb = bb_e->dtbe_bb;

			bb->dtbb_start = i;
			dt_list_append(&bb_list, bb_e);
		}
	}

	/*
	 * We will always have allocated a new basic block without the end
	 * instruction, because in the case of no branches we will simply have
	 * the first basic block, whereas with branches we will have the case
	 * of a target near the end, with no branches in between there and the
	 * ret instruction.
	 */
	bb->dtbb_end = difo->dtdo_len - 1;
}

static void
dt_compute_cfg(dtrace_difo_t *difo)
{
	dt_basic_block_t *bb1, *bb2;
	dt_bb_entry_t *bb_e1, *bb_e2, *bb_new1, *bb_new2;
	int lbl;
	uint8_t opcode;
	dif_instr_t instr;

	bb1 = bb2 = NULL;
	bb_e1 = bb_e2 = bb_new1 = bb_new2 = NULL;
	lbl = -1;
	opcode = 0;
	instr = 0;

	for (bb_e1 = dt_list_next(&bb_list); bb_e1; bb_e1 = dt_list_next(bb_e1)) {
		bb1 = bb_e1->dtbe_bb;
		if (bb1 == NULL)
			errx(EXIT_FAILURE, "bb1 should not be NULL");

		if (bb1->dtbb_difo != difo)
			continue;

		instr = bb1->dtbb_buf[bb1->dtbb_end];
		opcode = DIF_INSTR_OP(instr);

		if (opcode >= DIF_OP_BA && opcode <= DIF_OP_BLEU)
			lbl = DIF_INSTR_LABEL(instr);

		for (bb_e2 = dt_list_next(&bb_list); bb_e2;
		    bb_e2 = dt_list_next(bb_e2)) {
			bb2 = bb_e2->dtbe_bb;
			if (bb2 == NULL)
				errx(EXIT_FAILURE, "bb2 should not be NULL");

			if (bb1 == bb2)
				continue;

			if (bb2->dtbb_difo != difo)
				continue;

			if (lbl != -1 && bb2->dtbb_start == lbl) {
				bb_new1 = malloc(sizeof(dt_bb_entry_t));
				memcpy(bb_new1, bb_e2, sizeof(dt_bb_entry_t));

				bb_new2 = malloc(sizeof(dt_bb_entry_t));
				memcpy(bb_new2, bb_e1, sizeof(dt_bb_entry_t));

				dt_list_append(&bb1->dtbb_children, bb_new1);
				dt_list_append(&bb2->dtbb_parents, bb_new2);
				printf("bb1 (%p) -> bb2 (%p):\n", bb1, bb2);
				printf("\t(%zu, %zu) ===> (%zu, %zu)\n",
				       bb1->dtbb_start, bb1->dtbb_end,
				       bb2->dtbb_start, bb2->dtbb_end);
			}

			if (bb1->dtbb_end + 1 == bb2->dtbb_start) {
				bb_new1 = malloc(sizeof(dt_bb_entry_t));
				memcpy(bb_new1, bb_e2, sizeof(dt_bb_entry_t));

				bb_new2 = malloc(sizeof(dt_bb_entry_t));
				memcpy(bb_new2, bb_e1, sizeof(dt_bb_entry_t));

				dt_list_append(&bb1->dtbb_children, bb_new1);
				dt_list_append(&bb2->dtbb_parents, bb_new2);
				printf("bb1 (%p) -> bb2 (%p):\n", bb1, bb2);
				printf("\t(%zu, %zu) ===> (%zu, %zu)\n",
				       bb1->dtbb_start, bb1->dtbb_end,
				       bb2->dtbb_start, bb2->dtbb_end);
			}
		}
	}
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
	dt_rkind_t rkind;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	uint8_t rd = 0;
	uint16_t var = 0;
	int *leaders = NULL;

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

	leaders = malloc(sizeof(int) * difo->dtdo_len);
	memset(leaders, 0, sizeof(int) * difo->dtdo_len);

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
		memset(rl, 0, sizeof(dt_rl_entry_t));

		rl->drl_rel = relo;
		dt_list_prepend(&relo_list, rl);
		relo_first = rl;
		dt_get_rkind(instr, &rkind);
		memcpy(&relo->dr_rkind, &rkind, sizeof(dt_rkind_t));
		dt_update_relocations(difo, &rkind, relo);
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
	char bootfile[MAXPATHLEN] = {0};
	size_t len = sizeof(bootfile);
	int err = 0;

	/*
	 * Get the boot file location (default /boot/kernel/kernel)
	 */
	if (sysctlbyname("kern.bootfile", bootfile, &len, NULL, 0) != 0)
		strlcpy(bootfile, "kernel", sizeof(bootfile));

	/*
	 * Open the boot file and read in the CTF information.
	 */
	ctf_file = ctf_open(bootfile, &err);
	if (err != 0)
		errx(EXIT_FAILURE, "failed opening bootfile(%s): %s",
		    bootfile, ctf_errmsg(ctf_errno(ctf_file)));

	/*
	 * Zero out the relo list and basic block list.
	 */
	memset(&relo_list, 0, sizeof(dt_list_t));
	memset(&bb_list, 0, sizeof(dt_list_t));

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
		    ad != sdp->dtsd_action_last->dtad_next; ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			rval = dt_prog_infer_defns(dtp, ad->dtad_difo);
			if (rval != 0)
				return (dt_set_errno(dtp, rval));

//			rval = dt_prog_infer_types(dtp, ad->dtad_difo);
//			if (rval != -0)
//				return (dt_set_errno(dtp, rval));
		}
	}

	free(ctf_file);
	return (0);
}
