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

static ctf_file_t *ctf_file;
static dt_list_t relo_list;
static dt_rl_entry_t *relo_last = NULL;

typedef struct dt_rkind {
	int			r_kind;
#define DT_RKIND_REG	1
#define DT_RKIND_VAR	2
#define DT_RKIND_STACK	3
	union {
		uint8_t		rd;
		uint16_t	var;
	} u;
#define r_rd	u.rd
#define r_var	u.var
} dt_rkind_t;

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
dt_usite_contains_var(dt_relo_t *relo, uint16_t var, int *id)
{
	dif_instr_t instr = 0;
	uint16_t v = 0;
	uint8_t opcode = 0;

	instr = relo->dr_buf[relo->dr_uidx];
	*id = -1;
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_LDGA:
	case DIF_OP_LDTA:
		v = DIF_INSTR_R1(instr);

		if (v == var)
			*id = 0;
		break;

	case DIF_OP_LDGS:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_LDTS:
	case DIF_OP_LDLS:
		v = DIF_INSTR_VAR(instr);

		if (v == var)
			*id = 0;
		break;

	default:
		break;
	}

	return (*id != -1);
}


static int
dt_usite_contains_reg(dt_relo_t *relo, uint8_t rd, int *id1, int *id2)
{
	dif_instr_t instr = 0;
	uint8_t rs = 0, r1 = 0, r2 = 0, opcode = 0;

	instr = relo->dr_buf[relo->dr_uidx];
	*id1 = -1;
	*id2 = -1;
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
		r2 = DIF_INSTR_R2(instr);

		if (r2 == rd)
			*id2 = 0;
		break;

	case DIF_OP_STGS:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		r2 = DIF_INSTR_RS(instr);

		if (r2 == rd)
			*id2 = 0;
		break;

	default:
		break;
	}

	return (*id1 != -1 || *id2 != -1);
}


static void
dt_update_relocations_var(dtrace_difo_t *difo, uint16_t var, dt_relo_t *currelo)
{
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int id;
	uint_t idx;

	idx = 0;
	id = -1;
	rl = NULL;
	relo = NULL;

	assert(currelo != NULL);
	idx = currelo->dr_uidx;

	/*
	 * Every time we find a relocation whose use site contains
	 * a variable we are currently defining, we fill in the relocation
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
		 * Find out if the current relocation uses var anywhere.
		 */
		if (dt_usite_contains_var(relo, var, &id)) {
			assert(id == 0);

			/*
			 * Check if var is used
			 */
			if (id != -1 && relo->dr_didx[id] == 0) {
				assert(relo->dr_drel[id] == NULL);

				relo->dr_didx[id] = idx;
				relo->dr_drel[id] = currelo;
			}
		}
	}

}

static void
dt_update_relocations_reg(dtrace_difo_t *difo, uint8_t rd, dt_relo_t *currelo)
{
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int id1, id2;
	uint_t idx;

	idx = 0;
	id1 = 0;
	id2 = 0;
	rl = NULL;
	relo = NULL;

	assert(currelo != NULL);
	idx = currelo->dr_uidx;

	/*
	 * Every time we find a relocation whose use site contains
	 * a register we are currently defining, we fill in the relocation
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
			assert(id1 == 0 || id2 == 1);

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
			if (id1 != -1 && relo->dr_didx[id1] == 0) {
				assert(relo->dr_drel[id1] == NULL);

				relo->dr_didx[id1] = idx;
				relo->dr_drel[id1] = currelo;
			}

			if (id2 != -1 && relo->dr_didx[id2] == 0) {
				assert(relo->dr_drel[id2] == NULL);

				relo->dr_didx[id2] = idx;
				relo->dr_drel[id2] = currelo;
			}
		}
	}
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
dt_update_relocations_stack(dtrace_difo_t *difo, dt_relo_t *currelo)
{
	dt_relo_t *relo;
	dt_rl_entry_t *rl;
	int id1, id2, n_pushes;
	uint_t idx;
	dt_stacklist_t *sl;

	idx = 0;
	rl = NULL;
	relo = NULL;
	sl = NULL;
	n_pushes = 1;

	assert(currelo != NULL);
	idx = currelo->dr_uidx;

	/*
	 * Every time we find a relocation that uses the stack and is after
	 * the current instruction (a push instruction), but is not preceded
	 * by a popts or a flushts, we will add this relocation onto the list
	 * of pushes in the instruction that uses the stack.
	 *
	 * N.B.: We are actually starting from the _first_ instruction here
	 *       because our list is built up from bottom-up, rather than
	 *       top-down because most passes are done bottom-up except for
	 *       this one.
	 */
	for (rl = relo_last; rl != NULL; rl = dt_list_prev(rl)) {
		relo = rl->drl_rel;

		if (relo->dr_buf != difo->dtdo_buf)
			continue;

		if (n_pushes < 1)
			errx(EXIT_FAILURE, "n_pushes is %d", n_pushes);

		op = DIF_INSTR_OP(relo->dr_buf[relo->dr_uidx]);

		/*
		 * If we popts or flushts after the first push, we don't want
		 * to go through the rest of the relocations because this push
		 * becomes meaningless.
		 */

		if (op == DIF_OP_FLUSHTS)
			break;

		if (n_pushes == 1 && op == DIF_OP_POPTS)
			break;

		/*
		 * If we have more pushes and we encounter a popts, we
		 * just decrement the number of pushes and keep going.
		 */
		if (n_pushes > 1 && op == DIF_OP_POPTS) {
			n_pushes--;
			continue;
		}

		/*
		 * If the current instruction is a push, we just increment the
		 * number of pushes and keep going.
		 */
		if (op == DIF_OP_PUSHTV || op == DIF_OP_PUSHTR) {
			n_pushes++;
			continue;
		}

		/*
		 * Does the current relocation use the stack?
		 */
		if (dt_usite_uses_stack(relo)) {
			sl = malloc(sizeof(dt_stacklist_t));
			memset(sl, 0, sizeof(dt_stacklist_t));

			/*
			 * N.B.: This list is built up to be an argument list
			 *       so that arg0 is the first one in the list and
			 *       argn the last one.
			 */
			sl->dsl_rel = currelo;
			dt_list_append(relo->dr_stacklist, sl);
		}
	}
}

static void
dt_update_relocations(dtrace_difo_t *difo, dt_rkind_t *rkind, dt_relo_t *currelo)
{
	uint8_t rd;
	uint16_t var;

	rd = 0;
	var = 0;

	if (rkind->r_kind == DT_RKIND_REG) {
		rd = rkind->r_rd;
		dt_update_relocations_reg(difo, rd, currelo);
	} else if (rkind->r_kind == DT_RKIND_VAR) {
		var = rkind->r_var;
		dt_update_relocations_var(difo, var, currelo);
	} else if (rkind->r_kind == DT_RKIND_STACK)
		dt_update_relocations_stack(difo, currelo);
	else
		errx(EXIT_FAILURE, "r_kind is unknown (%d)", rkind->r_kind);
}

static int
dt_infer_type(dt_relo_t *r)
{
	dt_relo_t *dr1, *dr2, *tc_r, *symrelo, *other;
	int type1, type2, res;
	char buf[4096] = {0}, symname[4096] = {0};
	ctf_membinfo_t *mip;
	size_t l;
	dtrace_difo_t *difo;
	dif_instr_t instr;
	uint8_t opcode;
	uint16_t sym;

	dr1 = r->dr_drel[0];
	dr2 = r->dr_drel[1];
	type1 = -1;
	type2 = -1;
	mip = NULL;
	l = 0;
	difo = r->dr_difo;
	instr = 0;
	opcode = 0;
	sym = 0;
	res = 0;
	tc_r = NULL;
	symrelo = NULL;
	other = NULL;

	/*
	 * If we already have the type, we just return it.
	 */
	if (r->dr_type != 0)
		return (r->dr_type);

	if (dr1 != NULL) {
		type1 = dt_infer_type(dr1);
		if (type1 != DIF_TYPE_CTF && type1 != DIF_TYPE_STRING)
			return (-1);
	}

	if (dr2 != NULL) {
		type2 = dt_infer_type(dr2);
		if (type2 != DIF_TYPE_CTF && type2 != DIF_TYPE_STRING)
			return (-1);
	}

	instr = r->dr_buf[r->dr_uidx];
	opcode = DIF_INSTR_OP(instr);

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
		if (dr1 == NULL)
			return (-1);

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dr1->dr_sym == 0)
			return (-1);

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


		/*
		 * Figure out t2 = type_at(t1, symname)
		 */
		mip = malloc(sizeof(ctf_membinfo_t));
		memset(mip, 0, sizeof(ctf_membinfo_t));

		if (ctf_member_info(
		    ctf_file, dr1->dr_ctfid, symname, mip) != 0)
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
		if (sym >= difo->dtdo_symlen)
			return (-1);

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
		if (sym >= difo->dtdo_symlen)
			return (-1);

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
		if (dr1 == NULL)
			return (-1);
		if (dr2 == NULL)
			return (-1);

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dr1->dr_sym != 0 || dr2->dr_sym != 0) {
			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(dr1, dr2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1)
				tc_r = dr1;
			else if (res == 2)
				tc_r = dr2;
			else
				return (-1);

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

			if (res == -1)
				return (-1);

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
		if (dr1 == NULL)
			return (-1);

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->sym;

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

		if (dr1 == NULL)
			return (-1);

		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->sym;

		return (r->dr_type);

	case DIF_OP_STGS:
	case DIF_OP_STTS:
	case DIF_OP_STLS:
		/*
		 *           %r1 : t
		 * ----------------------------
		 *  opcode %r1, var => var : t
		 */

		if (dr1 == NULL)
			return (-1);

		r->dr_ctfid = dr1->dr_ctfid;
		r->dr_type = dr1->dr_type;
		r->dr_mip = dr1->dr_mip;
		r->dr_sym = dr1->sym;

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
			if ((t = dt_infer_type(sl->dsl_rel)) == -1)
				return (-1);

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

			r->dr_type = DIF_TYPE_STRING
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
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_INET_NTOA6:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_TOUPPER:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_TOLOWER:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_MEMREF:
			r->dr_ctfid = ctf_lookup_by_name(
			    ctf_file, "uintptr_t *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type uintptr_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_SX_SHARED_HELD:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_SX_EXCLUSIVE_HELD:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_SX_ISEXCLUSIVE:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "int");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE, "failed to get type int: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_MEMSTR:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_GETF:
			r->dr_ctfid = ctf_lookup_by_name(ctf_file, "file_t *");
			if (r->dr_ctfid == CTF_ERR)
				errx(EXIT_FAILURE,
				    "failed to get type file_t *: %s",
				    ctf_errmsg(ctf_errno(ctf_file)));

			r->dr_type = DIF_TYPE_CTF;
			break;

		case DIF_SUBR_JSON:
			r->dr_type = DIF_TYPE_STRING;
			break;

		case DIF_SUBR_STRTOLL:
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
			/*
			 * We expect a "const char *" as an argument.
			 */
			sl = dt_list_next(&r->dr_stacklist);
			if (sl == NULL || sl->dsl_rel == NULL)
				errx(EXIT_FAILURE,
				    "strjoin/tok/str() first argument is NULL");

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
				    "strjoin/tok/str() second argument is NULL");

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

		return (r->d_type);

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
		switch (opcode) {
		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
			type = dt_infer_type(relo);
		        assert(type == DIF_TYPE_CTF || type == DIF_TYPE_STRING);

		}
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
	dt_rkind_t rkind;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	uint8_t rd = 0;

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
			relo = dt_relo_alloc(difo, idx);
			rl = malloc(sizeof(dt_rl_entry_t));
			memset(rl, 0, sizeof(dt_rl_entry_t));

			rl->drl_rel = relo;
			dt_list_append(&relo_list, rl);
			relo_last = rl;

			rd = DIF_INSTR_RD(instr);

		        rkind.r_kind = DT_RKIND_REG;
		        rkind.r_rd = rd;
			dt_update_relocations(difo, &rkind, relo);
			break;

		case DIF_OP_STGS:
		case DIF_OP_STGAA:
		case DIF_OP_STTAA:
		case DIF_OP_STTS:
		case DIF_OP_STLS:
			relo = dt_relo_alloc(difo, idx);
			rl = malloc(sizeof(dt_rl_entry_t));
			memset(rl, 0, sizeof(dt_rl_entry_t));

			rl->drl_rel = relo;
			dt_list_append(&relo_list, rl);
			relo_last = rl;

			var = DIF_INSTR_VAR(instr);

			rkind.r_kind = DT_RKIND_VAR;
			rkind.r_var = var;
			dt_update_relocations(difo, &rkind, relo);
			break;

		case DIF_OP_PUSHTR:
		case DIF_OP_PUSHTR_G:
		case DIF_OP_PUSHTR_H:
		case DIF_OP_PUSHTV:
			/*
			 * Here we need to do an update pass based on the stack.
			 *
			 * We want to find all instructions that use the stack
			 * and add a reference to this relocation, as it will
			 * help us later on when we need to type-check arrays
			 * and subroutines.
			 */
			relo = dt_relo_alloc(difo, idx);
			rl = malloc(sizeof(dt_rl_entry_t));
			memset(rl, 0, sizeof(dt_rl_entry_t));

			rl->drl_rel = relo;
			dt_list_append(&relo_list, rl);
			relo_last = rl;

			rkind.r_kind = DT_RKIND_STACK;
			dt_update_relocations(difo, &rkind, relo);

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
	 * Zero out the relo list.
	 */
	memset(&relo_list, 0, sizeof(dt_list_t));

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

	free(ctf_file);
	return (0);
}
