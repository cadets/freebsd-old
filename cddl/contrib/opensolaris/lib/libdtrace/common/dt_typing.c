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
#include <dt_typing_reg.h>
#include <dt_typing_stack.h>
#include <dt_typing_subr.h>
#include <dt_typing_var.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

dtrace_hdl_t *g_dtp;
dtrace_prog_t *g_pgp;

static int
dt_setx_value(dtrace_difo_t *difo, dif_instr_t instr)
{
	uint8_t opcode;
	uint16_t index;

	opcode = DIF_INSTR_OP(instr);
	assert(opcode == DIF_OP_SETX);
	assert(difo->dtdo_inttab != NULL);

	index = DIF_INSTR_INTEGER(instr);
	assert(index < difo->dtdo_intlen);

	return (difo->dtdo_inttab[index]);
}

/*
 * This is the main part of the type inference algorithm.
 */
int
dt_infer_type(dt_ifg_node_t *n)
{
	dt_ifg_node_t *dn1, *dn2, *dnv, *tc_n,
	    *symnode, *other, *var_stacknode, *node,
	    *data_dn1 = NULL, *data_dn2 = NULL;
	int type1, type2, res, i, t;
	char buf[4096] = { 0 }, symname[4096] = { 0 }, var_type[4096] = { 0 };
	ctf_membinfo_t *mip;
	size_t l;
	uint16_t var;
	dtrace_difo_t *difo;
	dif_instr_t instr, dn1_instr;
	uint8_t opcode, dn1_op, idx;
	uint16_t sym;
	ctf_id_t type = 0;
	dtrace_difv_t *dif_var;
	dt_pathlist_t *il;
	dt_list_t *stack;
	int empty;
	ctf_id_t varkind;
	size_t userland_len = strlen("userland ");
	int kind;
	int c;

	const char *insname[] = {
		[DIF_OP_OR]        = "or",
		[DIF_OP_XOR]       = "xor",
		[DIF_OP_AND]       = "and",
		[DIF_OP_SLL]       = "sll",
		[DIF_OP_SRL]       = "srl",
		[DIF_OP_SUB]       = "sub",
		[DIF_OP_ADD]       = "add",
		[DIF_OP_MUL]       = "mul",
		[DIF_OP_SDIV]      = "sdiv",
		[DIF_OP_UDIV]      = "udiv",
		[DIF_OP_SREM]      = "srem",
		[DIF_OP_UREM]      = "urem",
		[DIF_OP_NOT]       = "not",
		[DIF_OP_MOV]       = "mov",
		[DIF_OP_CMP]       = "cmp",
		[DIF_OP_TST]       = "tst",
		[DIF_OP_BA]        = "ba",
		[DIF_OP_BE]        = "be",
		[DIF_OP_BNE]       = "bne",
		[DIF_OP_BG]        = "bg",
		[DIF_OP_BGU]       = "bgu",
		[DIF_OP_BGE]       = "bge",
		[DIF_OP_BGEU]      = "bgeu",
		[DIF_OP_BL]        = "bl",
		[DIF_OP_BLU]       = "blu",
		[DIF_OP_BLE]       = "ble",
		[DIF_OP_BLEU]      = "bleu",
		[DIF_OP_LDSB]      = "ldsb",
		[DIF_OP_LDSH]      = "ldsh",
		[DIF_OP_LDSW]      = "ldsw",
		[DIF_OP_LDUB]      = "ldub",
		[DIF_OP_LDUH]      = "lduh",
		[DIF_OP_LDUW]      = "lduw",
		[DIF_OP_LDX]       = "ldx",
		[DIF_OP_RET]       = "ret",
		[DIF_OP_NOP]       = "nop",
		[DIF_OP_SETX]      = "setx",
		[DIF_OP_SETS]      = "sets",
		[DIF_OP_SCMP]      = "scmp",
		[DIF_OP_LDGA]      = "ldga",
		[DIF_OP_LDGS]      = "ldgs",
		[DIF_OP_STGS]      = "stgs",
		[DIF_OP_LDTA]      = "ldta",
		[DIF_OP_LDTS]      = "ldts",
		[DIF_OP_STTS]      = "stts",
		[DIF_OP_SRA]       = "sra",
		[DIF_OP_CALL]      = "call",
		[DIF_OP_PUSHTR]    = "pushtr",
		[DIF_OP_PUSHTV]    = "pushtv",
		[DIF_OP_POPTS]     = "popts",
		[DIF_OP_FLUSHTS]   = "flushts",
		[DIF_OP_LDGAA]     = "ldgaa",
		[DIF_OP_LDTAA]     = "ldtaa",
		[DIF_OP_STGAA]     = "stgaa",
		[DIF_OP_STTAA]     = "sttaa",
		[DIF_OP_LDLS]      = "ldls",
		[DIF_OP_STLS]      = "stls",
		[DIF_OP_ALLOCS]    = "allocs",
		[DIF_OP_COPYS]     = "copys",
		[DIF_OP_STB]       = "stb",
		[DIF_OP_STH]       = "sth",
		[DIF_OP_STW]       = "stw",
		[DIF_OP_STX]       = "stx",
		[DIF_OP_ULDSB]     = "uldsb",
		[DIF_OP_ULDSH]     = "uldsh",
		[DIF_OP_ULDSW]     = "uldsw",
		[DIF_OP_ULDUB]     = "uldub",
		[DIF_OP_ULDUH]     = "ulduh",
		[DIF_OP_ULDUW]     = "ulduw",
		[DIF_OP_ULDX]      = "uldx",
		[DIF_OP_RLDSB]     = "rldsb",
		[DIF_OP_RLDSH]     = "rldsh",
		[DIF_OP_RLDSW]     = "rldsw",
		[DIF_OP_RLDUB]     = "rldub",
		[DIF_OP_RLDUH]     = "rlduh",
		[DIF_OP_RLDUW]     = "rlduw",
		[DIF_OP_RLDX]      = "rldx",
		[DIF_OP_XLATE]     = "xlate",
		[DIF_OP_XLARG]     = "xlarg",
		[DIF_OP_HYPERCALL] = "hypercall",
		[DIF_OP_USETX]     = "usetx",
		[DIF_OP_ULOAD]     = "uload",
		[DIF_OP_UULOAD]    = "uuload",
		[DIF_OP_TYPECAST]  = "typecast",
	};

	empty = 1;
	il = NULL;
	dn1 = dn2 = dnv = var_stacknode = node = NULL;
	type1 = -1;
	type2 = -1;
	mip = NULL;
	l = 0;
	difo = n->din_difo;
	instr = dn1_instr = 0;
	opcode = dn1_op = 0;
	sym = 0;
	res = 0;
	tc_n = NULL;
	symnode = NULL;
	other = NULL;
	var = 0;
	i = 0;
	t = 0;
	dif_var = NULL;
	stack = NULL;

	/*
	 * If we already have the type, we just return it.
	 */
	if (n->din_type != -1)
		return (n->din_type);

	/*
	 * We do not tolerate NULL ECBs.
	 */
	assert(n->din_edp != NULL);
	instr = n->din_buf[n->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	dn1 = dt_typecheck_regdefs(&n->din_r1defs, &empty);
	if (dn1 == NULL && empty == 0) {
		fprintf(stderr,
		    "dt_infer_type(%s, %zu@%p): inferring types "
		    "for r1defs failed\n",
		    insname[opcode], n->din_uidx, n->din_difo);
		return (-1);
	}

	dn2 = dt_typecheck_regdefs(&n->din_r2defs, &empty);
	if (dn2 == NULL && empty == 0) {
		fprintf(stderr,
		    "dt_infer_type(%s, %zu@%p): inferring types "
		    "for r2defs failed\n",
		    insname[opcode], n->din_uidx, n->din_difo);
		return (-1);
	}

	dnv = dt_typecheck_vardefs(difo, &n->din_vardefs, &empty);
	if (dnv == NULL && empty == 0) {
		fprintf(stderr,
		    "dt_infer_type(%s, %zu@%p): inferring types "
		    "for vardefs failed\n",
		    insname[opcode], n->din_uidx, n->din_difo);
		return (-1);
	}

	stack = dt_typecheck_stack(&n->din_stacklist, &empty);
	if (stack == NULL && empty == 0) {
		fprintf(stderr,
		    "dt_infer_type(%s, %zu@%p): inferring types "
		    "for stack failed\n",
		    insname[opcode], n->din_uidx, n->din_difo);
		return (-1);
	}

	switch (opcode) {
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
		if (dn1 == NULL) {
			fprintf(stderr, "dt_infer_type(%s, %zu@%p): dn1 is NULL\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		/*
		 * If there is no symbol here, we can't do anything.
		 */
		if (dn1->din_sym == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn1 symbol is empty\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		mip = dt_mip_from_sym(dn1);
		if (mip == NULL) {
			dt_set_progerr(g_dtp, g_pgp,
			    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
			    __func__, insname[opcode], n->din_uidx, n->din_difo,
			    dn1->din_sym);
			return (-1);
		}

		n->din_mip = mip;
		n->din_ctfid = mip->ctm_type;
		n->din_type = DIF_TYPE_CTF;
		n->din_tf = dn1->din_tf;
		return (n->din_type);


	case DIF_OP_USETX:
		/*
		 *  symtab(idx) = sym    idx in range(symtab)
		 * ------------------------------------------
		 *   usetx idx, %r1 => %r1 : uint64_t | sym
		 */

		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): "
			    "sym (%u) >= symlen (%" PRIu64 ")\n",
			    insname[opcode], n->din_uidx, n->din_difo, sym,
			    difo->dtdo_symlen);
			return (-1);
		}

		n->din_tf = dt_typefile_D();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get "
			    "type uint64_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_sym = difo->dtdo_symtab + sym;
		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_TYPECAST:
		/*  symtab(idx) = t   idx in range(symtab)    t in ctf_file
		 * ---------------------------------------------------------
		 *                typecast idx, %r1 => %r1 : t
		 */

		if (dn1 == NULL)
			return (-1);

		mip = dt_mip_from_sym(dn1);
		sym = DIF_INSTR_SYMBOL(instr);
		if (sym >= difo->dtdo_symlen) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): "
			    "sym (%u) >= symlen (%" PRIu64 ")\n",
			    insname[opcode], n->din_uidx, n->din_difo, sym,
			    difo->dtdo_symlen);
			return (-1);
		}

		l = strlcpy(symname, difo->dtdo_symtab + sym, sizeof(symname));
		if (l >= sizeof(symname))
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): "
			    "length (%zu) >= %zu when copying type name",
			    insname[opcode], n->din_uidx, n->din_difo, l,
			    sizeof(symname));

		if (strncmp(symname, "userland ", userland_len) == 0) {
			char *tmpbuf;

			tmpbuf = malloc(sizeof(symname));
			if (tmpbuf == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): "
				    "malloc() failed: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    strerror(errno));

			memcpy(tmpbuf, symname + userland_len,
			    sizeof(symname) - userland_len);
			memcpy(symname, tmpbuf, sizeof(symname));
		}

		/*
		 * We kind of have to guess here. We start by getting the
		 * 'module' field of the probe description and try to find that
		 * module. If we can't, this might be a SDT probe that is
		 * "poorly" defined. We then look for the type in the kernel
		 * itself. If we can't find it there, we just bail out for now
		 * rather than causing runtime failures.
		 *
		 * TODO: Maybe we can tolerate some failures by looking at
		 * symbols too?
		 */
		if (strcmp(symname, "D string") == 0) {
			n->din_type = DIF_TYPE_STRING;
			n->din_mip = mip;
			return (n->din_type);
		}

		if (strcmp(symname, "bottom") == 0) {
			n->din_type = DIF_TYPE_BOTTOM;
			n->din_mip = mip;
			return (n->din_type);
		}

		if (strcmp(n->din_edp->dted_probe.dtpd_mod, "freebsd") == 0)
			n->din_tf = dt_typefile_kernel();
		else
			n->din_tf = dt_typefile_mod(n->din_edp->dted_probe.dtpd_mod);

		if (n->din_tf != NULL)
			n->din_ctfid = dt_typefile_ctfid(n->din_tf, symname);
		if (n->din_tf == NULL || n->din_ctfid == CTF_ERR) {
			/*
			 * XXX: Do we want to do this from the guest, or do we
			 * want the host data model here? Not 100% sure.
			 */
			n->din_tf = dt_typefile_mod("D");
			assert(n->din_tf != NULL);
			n->din_ctfid = dt_typefile_ctfid(n->din_tf, symname);

			if (n->din_ctfid == CTF_ERR) {
				n->din_tf = dt_typefile_kernel();
				assert(n->din_tf != NULL);
				n->din_ctfid = dt_typefile_ctfid(n->din_tf,
				    symname);
				if (n->din_ctfid == CTF_ERR)
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed to get "
					    "type %s: %s",
					    insname[opcode], n->din_uidx,
					    n->din_difo, symname,
					    dt_typefile_error(n->din_tf));
			}
		}

		n->din_mip = mip;
		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);
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
		if (dn1 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn1 is NULL\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		/*
		 * If we have no type with a symbol associated with it,
		 * we apply the first typing rule.
		 */
		if (dn1->din_sym == NULL && dn2->din_sym == NULL) {
			ctf_id_t k;

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(dn1, dn2);
			assert(res == 1 || res == 2 || res == -1);

			if (res == 1) {
				tc_n = dn1;
				other = dn2;
			} else if (res == 2) {
				tc_n = dn2;
				other = dn1;
			} else {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p) nosym: types can "
				    "not be compared\n",
				    insname[opcode], n->din_uidx, n->din_difo);
				return (-1);
			}

			k = dt_typefile_typekind(tc_n->din_tf, tc_n->din_ctfid);
			if (opcode == DIF_OP_ADD &&
			    (k == CTF_K_STRUCT || k == CTF_K_UNION) &&
			    other->din_hasint) {
				char typename[DT_TYPE_NAMELEN] = { 0 };
				(void)dt_typefile_typename(tc_n->din_tf,
				    tc_n->din_ctfid, typename,
				    sizeof(typename));
				mip = dt_mip_by_offset(g_dtp, tc_n->din_tf,
				    tc_n->din_ctfid, other->din_int);
				if (mip == NULL) {
					n->din_type = tc_n->din_type;
					n->din_ctfid = tc_n->din_ctfid;
					n->din_tf = tc_n->din_tf;
					n->din_int = other->din_int;
					return (n->din_type);
				}

				n->din_type = DIF_TYPE_CTF;
				n->din_ctfid = mip->ctm_type;
				n->din_tf = tc_n->din_tf;
				n->din_mip = NULL;
				n->din_sym = NULL;
			} else {
				/*
				 * We don't have to sanity check these because
				 * we do it in every base case of the recursive
				 * call.
				 */
				n->din_type = tc_n->din_type;
				n->din_ctfid = tc_n->din_ctfid;
				n->din_tf = tc_n->din_tf;
				n->din_int = other->din_int;
			}
		} else {
			if (dn1->din_sym == NULL) {
				assert(dn2->din_sym != NULL);
				symnode = dn2;
				other = dn1;
			} else if (dn2->din_sym == NULL) {
				assert(dn1->din_sym != NULL);
				symnode = dn1;
				other = dn2;
			} else {
				uint8_t op1, op2;
				assert(dn1->din_sym != NULL &&
				    dn2->din_sym != NULL);

				op1 = DIF_INSTR_OP(dn1->din_buf[dn1->din_uidx]);
				op2 = DIF_INSTR_OP(dn2->din_buf[dn2->din_uidx]);
				if (op1 == DIF_OP_USETX) {
					symnode = dn1;
					other = dn2;
				} else {
					assert(op2 == DIF_OP_USETX);
					symnode = dn2;
					other = dn1;
				}
			}

			if (other->din_type == DIF_TYPE_BOTTOM ||
			    symnode->din_type == DIF_TYPE_BOTTOM)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): unexpected bottom "
				    "type (binary arithmetic operation)",
				    insname[opcode], n->din_uidx, n->din_difo);

			/*
			 * Get the type name
			 */
			if (dt_typefile_typename(symnode->din_tf,
			    symnode->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed at getting "
				    "type name %ld for symnode: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    symnode->din_ctfid,
				    dt_typefile_error(symnode->din_tf));

			/*
			 * Check which type is "bigger".
			 */
			res = dt_type_compare(symnode, other);
			assert(res == 1 || res == 2 || res == -1);

			if (res == -1) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): types can not be "
				    "compared\n",
				    insname[opcode], n->din_uidx, n->din_difo);
				return (-1);
			}

			/*
			 * Get the type name of the other node
			 */
			if (dt_typefile_typename(other->din_tf,
			    other->din_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed at getting "
				    "type name %ld for other: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    other->din_ctfid,
				    dt_typefile_error(other->din_tf));

			if (res == 1) {
				if (strcmp(buf, "uint64_t") != 0)
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): the type "
					    "of the other node must be uint64_t"
					    " if symnode->din_ctfid (%zu@%p) <:"
					    " other->din_ctfid (%zu@%p), but it "
					    "is: %s",
					    insname[opcode], n->din_uidx,
					    n->din_difo, symnode->din_uidx,
					    symnode->din_difo, other->din_uidx,
					    other->din_difo, buf);
			}

			/*
			 * At this point, we have ensured that the types are:
			 *  (1) Related (<: exists between t1 and t2)
			 *  (2) Well-ordered: if
			 *
			 *            symnode->din_ctfid <: other->din_ctfid,
			 *
			 *      then other->din_ctfid is also
			 *      uint64_t (reflexivity).
			 *  (3) One of the uint64_ts originates from a symbol.
			 */

			if (other->din_sym == NULL) {
				n->din_sym = symnode->din_sym;
				n->din_ctfid = other->din_ctfid;
				n->din_tf = other->din_tf;
				n->din_type = DIF_TYPE_CTF;
				return (n->din_type);
			}

			c = dt_get_class(other->din_tf, other->din_ctfid, 1);
			if (c != DTC_STRUCT && c != DTC_UNION)
				return (-1);

			/*
			 * Figure out t2 = type_at(t1, symname)
			 */
			mip = malloc(sizeof(ctf_membinfo_t));
			if (mip == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed to "
				    "malloc mip",
				    insname[opcode], n->din_uidx, n->din_difo);

			memset(mip, 0, sizeof(ctf_membinfo_t));

			/*
			 * Get the non-pointer type. This should NEVER fail.
			 */
			type = dt_typefile_reference(
			    other->din_tf, other->din_ctfid);

			if (dt_typefile_membinfo(other->din_tf, type,
			    other->din_sym, mip) == 0)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed to get "
				    "member info for %s(%s): %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    buf, other->din_sym,
				    dt_typefile_error(other->din_tf));

			n->din_mip = mip;
			n->din_sym = symnode->din_sym;
			n->din_ctfid = mip->ctm_type;
			n->din_tf = other->din_tf;
			n->din_type = DIF_TYPE_CTF;
		}

		return (n->din_type);

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
		 *       if dn1 is not NULL, then we'll have checked it already.
		 */
		if (dn1 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn1 is NULL\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		/*
		 * We don't have to sanity check here because we do it in every
		 * base case of the recursive call.
		 */
		n->din_ctfid = dn1->din_ctfid;
		n->din_tf = dn1->din_tf;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		if (opcode == DIF_OP_MOV)
			n->din_isnull = dn1->din_isnull;

		return (n->din_type);

	case DIF_OP_LDSB:
	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
		/*
		 *          %r1 :: Pointer
		 * -----------------------------------
		 *  opcode [%r1], %r2 => %r2 : int8_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int8_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "int8_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDSH:
	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int16_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int16_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "int16_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDSW:
	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : int32_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get "
			    "type unsigned char: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUB:
	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
		/*
		 *          %r1 :: Pointer
		 * ------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint8_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint8_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "uint8_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUH:
	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint16_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint16_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "uint16_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_LDUW:
	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
		/*
		 *          %r1 :: Pointer
		 * -------------------------------------
		 *  opcode [%r1], %r2 => %r2 : uint32_t
		 */
		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "uint32_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		return (n->din_type);

	case DIF_OP_ULDX:
	case DIF_OP_RLDX:
	case DIF_OP_LDX:
	case DIF_OP_SETX:
		/*
		 * ---------------------------------
		 *  setx idx, %r1 => %r1 : uint64_t
		 */

		n->din_tf = dt_typefile_kernel();
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get type "
			    "uint64_t: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		if (opcode == DIF_OP_SETX) {
			n->din_int = dt_setx_value(difo, instr);
			n->din_isnull = n->din_int == 0;
			n->din_hasint = 1;
		}
		return (n->din_type);

	case DIF_OP_SETS:
		/*
		 * --------------------------------
		 *  sets idx, %r1 => %r1: D string
		 */

		n->din_type = DIF_TYPE_STRING;
		return (n->din_type);

	case DIF_OP_LDGA:
		/*
		 *   var : t          %r2 : int
		 * --------------------------------
		 *  ldga var, %r2,  %r1 => %r1 : t
		 */

		var = DIF_INSTR_R1(instr);
		idx = DIF_INSTR_R2(instr);

		if (!dt_var_is_builtin(var)) {
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): %u "
			    "is not a built-in variable",
			    insname[opcode], n->din_uidx, n->din_difo, var);
		}

		dt_builtin_type(n, var, idx);
		return (n->din_type);

	case DIF_OP_LDLS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldls var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dnv == NULL) {
			if (dif_var == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable and dnv "
				    "don't exist\n",
				    insname[opcode], n->din_uidx, n->din_difo);
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_tf = dif_var->dtdv_tf;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;

				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dnv->din_type) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_type.dtdt_kind,
				    dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dnv->din_ctfid) {
				if (dt_typefile_typename(dnv->din_tf,
				    dnv->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld for dnv: %s",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dnv->din_ctfid,
					    dt_typefile_error(dnv->din_tf));

				if (dt_typefile_typename(dif_var->dtdv_tf,
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld for dif_var: %s",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dif_var->dtdv_ctfid,
					    dt_typefile_error(
					        dif_var->dtdv_tf));

				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    buf, var_type);
				return (-1);
			}

			if (dnv->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != NULL\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dnv->din_sym);
				return (-1);
			}

			if (dnv->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch NULL != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dnv->din_sym) != 0) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dnv->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dnv->din_ctfid;
		n->din_tf = dnv->din_tf;
		n->din_type = dnv->din_type;
		n->din_mip = dnv->din_mip;
		n->din_sym = dnv->din_sym;

		return (n->din_type);

	case DIF_OP_LDGS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldgs var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dn1 == NULL) {
			if (dt_var_is_builtin(var)) {
				dt_builtin_type(n, var, 0);
				return (n->din_type);
			} else if (dif_var == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable %d and "
				    "dn1 don't exist\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    var);
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_tf = dif_var->dtdv_tf;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;
				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->din_type) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_type.dtdt_kind,
				    dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_tf != dn1->din_tf) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable typefile "
				    "is %s, but dn1 typefile is %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dt_typefile_stringof(dif_var->dtdv_tf),
				    dt_typefile_stringof(dn1->din_tf));
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->din_ctfid) {
				if (dt_typefile_typename(dn1->din_tf,
				    dn1->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dn1->din_ctfid,
					    dt_typefile_error(dn1->din_tf));

				if (dt_typefile_typename(dif_var->dtdv_tf,
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dn1->din_ctfid,
					    dt_typefile_error(
					        dif_var->dtdv_tf));

				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != NULL\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dn1->din_sym);
				return (-1);
			}

			if (dn1->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch NULL != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->din_sym) != 0) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dn1->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dn1->din_ctfid;
		n->din_tf = dn1->din_tf;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_LDTS:
		/*
		 *           var : t
		 * ----------------------------
		 *  ldts var, %r1 => %r1 : t
		 */

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find variable "
			    "(%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dn1 == NULL) {
			if (dif_var == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable "
				    "and dn1 don't exist\n",
				    insname[opcode], n->din_uidx, n->din_difo);
				return (-1);
			} else {
				n->din_ctfid = dif_var->dtdv_ctfid;
				n->din_tf = dif_var->dtdv_tf;
				n->din_type = dif_var->dtdv_type.dtdt_kind;
				n->din_sym = dif_var->dtdv_sym;

				return (n->din_type);
			}
		}

		if (dif_var != NULL) {
			if (dif_var->dtdv_type.dtdt_kind != dn1->din_type) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): type "
				    "mismatch %d != %d\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_type.dtdt_kind,
				    dn1->din_type);
				return (-1);
			}

			if (dif_var->dtdv_ctfid != dn1->din_ctfid) {
				if (dt_typefile_typename(dn1->din_tf,
				    dn1->din_ctfid, buf,
				    sizeof(buf)) != ((char *)buf))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dn1->din_ctfid,
					    dt_typefile_error(dn1->din_tf));

				if (dt_typefile_typename(dif_var->dtdv_tf,
				    dif_var->dtdv_ctfid, var_type,
				    sizeof(var_type)) != ((char *)var_type))
					dt_set_progerr(g_dtp, g_pgp,
					    "dt_infer_type(%s, %zu@%p): failed at "
					    "getting type name %ld: %s\n",
					    insname[opcode], n->din_uidx,
					    n->din_difo, dn1->din_ctfid,
					    dt_typefile_error(
					        dif_var->dtdv_tf));

				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): variable ctf type "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    buf, var_type);
				return (-1);
			}

			if (dn1->din_sym && dif_var->dtdv_sym == NULL) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != NULL\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dn1->din_sym);
				return (-1);
			}

			if (dn1->din_sym == NULL && dif_var->dtdv_sym) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch NULL != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_sym);
				return (-1);
			}

			if (strcmp(dif_var->dtdv_sym, dn1->din_sym) != 0) {
				fprintf(stderr,
				    "dt_infer_type(%s, %zu@%p): symbol "
				    "mismatch %s != %s\n",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dn1->din_sym, dif_var->dtdv_sym);
				return (-1);
			}

		}

		n->din_ctfid = dn1->din_ctfid;
		n->din_tf = dn1->din_tf;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_STGS:
		/*
		 *  %r1 : t       var notin builtins
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stgs %r1, var => var : t
		 *
		 *  %r1 : t       var notin builtins
		 *         var notin var_list
		 * ----------------------------------
		 *     stgs %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		/*
		 * If we are doing a STGS, and the variable is a builtin
		 * variable, we fail to type-check the instruction.
		 */
		if (dt_var_is_builtin(var)) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): trying to store to a "
			    "builtin variable\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL in stgs.\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(g_dtp, n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dif_var->dtdv_ctfid;
		n->din_tf = dif_var->dtdv_tf;
		n->din_type = dif_var->dtdv_type.dtdt_kind;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_STTS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stts %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stts %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL in stts.\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(g_dtp, n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dif_var->dtdv_ctfid;
		n->din_tf = dif_var->dtdv_tf;
		n->din_type = dif_var->dtdv_type.dtdt_kind;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_STLS:
		/*
		 *             %r1 : t
		 *         var in var_list
		 *         var_list @ var = t
		 * ----------------------------------
		 *     stls %r1, var => var : t
		 *
		 *              %r1 : t
		 *         var notin var_list
		 * ----------------------------------
		 *     stls %r1, var => var : t /\
		 *        update var_list var t
		 */

		var = DIF_INSTR_VAR(instr);

		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL in stls.\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_LOCAL, DIFV_KIND_SCALAR);

		if (dt_infer_type_var(g_dtp, n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_tf = dn2->din_tf;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_LDTA:
		break;
	case DIF_OP_CALL:
		/*
		 *     subr : t1 -> t2 ... -> tn -> t
		 *  stack[0] : t1    stack[1] : t2     ...
		 *  stack[n] : tm        m = stacklen - 1
		 *                m >= n
		 * ----------------------------------------
		 *       call subr, %r1 => %r1 : t
		 */
		return (dt_infer_type_subr(n, stack));

	case DIF_OP_LDGAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (dt_list_next(&n->din_stacklist) == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (dt_var_stack_typecheck(n, dnv, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(g_dtp, n->din_difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->din_ctfid = dnv->din_ctfid;
			n->din_tf = dnv->din_tf;
			n->din_type = dnv->din_type;
			n->din_mip = dnv->din_mip;
			n->din_sym = dnv->din_sym;
		} else {
			n->din_ctfid = dif_var->dtdv_ctfid;
			n->din_tf = dif_var->dtdv_tf;
			n->din_type = dif_var->dtdv_type.dtdt_kind;
			n->din_sym = dif_var->dtdv_sym;
		}

		return (n->din_type);

	case DIF_OP_LDTAA:
		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * If the stack is empty, this instruction makes no sense.
		 */
		if (dt_list_next(&n->din_stacklist) == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): stack list is "
			    "empty in ldgaa\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		/*
		 * Make sure the stack contains what we expect
		 */
		if (dt_var_stack_typecheck(n, dnv, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(g_dtp, n->din_difo, dnv, dif_var) == -1)
			return (-1);

		if (dnv) {
			n->din_ctfid = dnv->din_ctfid;
			n->din_tf = dnv->din_tf;
			n->din_type = dnv->din_type;
			n->din_mip = dnv->din_mip;
			n->din_sym = dnv->din_sym;
		} else {
			n->din_ctfid = dif_var->dtdv_ctfid;
			n->din_tf = dif_var->dtdv_tf;
			n->din_type = dif_var->dtdv_type.dtdt_kind;
			n->din_sym = dif_var->dtdv_sym;
		}

		return (n->din_type);

	/*
	 * FIXME(dstolfa): Handle STGAAs to struct types.
	 */
	case DIF_OP_STGAA:
		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL in "
			    "stgaa.\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): "
			    "failed to find variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_GLOBAL, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  x[curthread] = 1;
		 *  x[tid] = 2;
		 */

		if (dt_var_stack_typecheck(n, dn2, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(g_dtp, n->din_difo, dn2, dif_var) == -1)
			return (-1);

		if (dn2->din_type != DIF_TYPE_BOTTOM) {
			n->din_ctfid = dn2->din_ctfid;
			n->din_tf = dn2->din_tf;
			n->din_type = dn2->din_type;
			n->din_mip = dn2->din_mip;
			n->din_sym = dn2->din_sym;
		} else {
			n->din_ctfid = dif_var->dtdv_ctfid;
			n->din_tf = dif_var->dtdv_tf;
			n->din_type = dif_var->dtdv_type.dtdt_kind;
			n->din_mip = dn2->din_mip;
			n->din_sym = dn2->din_sym;
		}

		return (n->din_type);

	case DIF_OP_STTAA:
		if (dn2 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): dn2 is NULL in sttaa.\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		var = DIF_INSTR_VAR(instr);

		dif_var = dt_get_var_from_varlist(var,
		    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);
		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to find "
			    "variable (%u, %d, %d)",
			    insname[opcode], n->din_uidx, n->din_difo, var,
			    DIFV_SCOPE_THREAD, DIFV_KIND_ARRAY);

		/*
		 * We compare the first seen stack and the current possible
		 * stacks in order to make sure that we aren't doing something
		 * like:
		 *
		 *  self->x[curthread] = 1;
		 *  self->x[tid] = 2;
		 */
		if (dt_var_stack_typecheck(n, dn2, dif_var) == -1)
			return (-1);

		if (dt_infer_type_var(g_dtp, n->din_difo, dn2, dif_var) == -1)
			return (-1);

		n->din_ctfid = dn2->din_ctfid;
		n->din_tf = dn2->din_tf;
		n->din_type = dn2->din_type;
		n->din_mip = dn2->din_mip;
		n->din_sym = dn2->din_sym;

		return (n->din_type);

	case DIF_OP_ALLOCS:
		n->din_ctfid = CTF_ERR;
		n->din_tf = NULL;
		n->din_type = DIF_TYPE_BOTTOM;
		n->din_mip = NULL;
		n->din_sym = NULL;

		return (n->din_type);

	case DIF_OP_COPYS:
		n->din_ctfid = dn1->din_ctfid;
		n->din_tf = dn1->din_tf;
		n->din_type = dn1->din_type;
		n->din_mip = dn1->din_mip;
		n->din_sym = dn1->din_sym;

		return (n->din_type);

	case DIF_OP_RET:
		/* 
		 * Only do this if it's a CTF type. We might be coming from a
		 * typecast.
		 */
		if (dn1->din_sym != NULL) {
			dt_typefile_t *tf;
			ctf_id_t ctfid;
			int type;

			tf = dn1->din_tf;
			type = dn1->din_type;
			ctfid = dn1->din_ctfid;
			fprintf(stderr, "ret: in the != NULL\n");

			/*
			 * We only need one type here (the first one).
			 */

			mip = dt_mip_from_sym(dn1);
			if (mip == NULL) {
				dt_set_progerr(g_dtp, g_pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode], n->din_uidx,
				    n->din_difo, dn1->din_sym);
				return (-1);
			}

			n->din_mip = mip;
			n->din_tf = dn1->din_tf;
			n->din_ctfid =
			    dn1 == dn1 ? mip->ctm_type : dn1->din_ctfid;
			n->din_type =
			    dn1 == dn1 ? DIF_TYPE_CTF : dn1->din_type;
		} else {
			n->din_ctfid = dn1->din_ctfid;
			n->din_tf = dn1->din_tf;
			n->din_type = dn1->din_type;
		}

		return (n->din_type);

	case DIF_OP_PUSHTR:
		if (dn1 == NULL) {
			fprintf(stderr,
			    "dt_infer_type(%s, %zu@%p): pushtr dn1 is NULL\n",
			    insname[opcode], n->din_uidx, n->din_difo);
			return (-1);
		}

		if (dn1->din_sym != NULL) {
			/*
			 * We only need one type here (the first one).
			 */

			mip = dt_mip_from_sym(dn1);
			if (mip == NULL) {
				dt_set_progerr(g_dtp, g_pgp,
				    "%s(%s, %zu@%p): failed to get mip from symbol (%s)",
				    __func__, insname[opcode], n->din_uidx,
				    n->din_difo, dn1->din_sym);
				return (-1);
			}

			n->din_mip = mip;
			n->din_ctfid = mip->ctm_type;
			n->din_tf = dn1->din_tf;
			n->din_type = DIF_TYPE_CTF;
		} else if (dn1->din_type == DIF_TYPE_CTF) {
			n->din_ctfid = dn1->din_ctfid;
			n->din_tf = dn1->din_tf;
			n->din_type = dn1->din_type;
		} else
			/*
			 * XXX: Do we need to store the typefile here?
			 */
			n->din_type = dn1->din_type;

		return (DIF_TYPE_NONE);

	case DIF_OP_PUSHTV:
		n->din_ctfid = dn1->din_ctfid;
		n->din_tf = dn1->din_tf;
		n->din_type = dn1->din_type;
		return (DIF_TYPE_NONE);

	case DIF_OP_FLUSHTS:
	case DIF_OP_POPTS:
	case DIF_OP_CMP:
	case DIF_OP_SCMP:
	case DIF_OP_HYPERCALL:
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
		return (DIF_TYPE_NONE);

	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX: {
		dtrace_difv_t *ovar;
		dt_var_entry_t *ve;
		int insid;

		insid = opcode - DIF_OP_STB;
		assert(insid >= 0 && insid <= 3);

		assert(dn1 != NULL);
		assert(dn2 != NULL); /* the destination register source */

		/*
		 * If we reach a ST instruction, we need to make sure that we
		 * didn't do so by having a string or an uninitialized node.
		 */
		if (dn1->din_type == DIF_TYPE_STRING)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): can't store from a "
			    "string type (loc %zu)",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dn1->din_uidx);

		if (dn1->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): can't store "
			    "from type none (loc %zu)",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dn1->din_uidx);

		/*
		 * If there is no symbol associated with our stx, this might
		 * have come from a translator which was resolved before this
		 * step. We just skip this instruction, as nothing will actually
		 * have this as a source.
		 */
		if (dn1->din_sym == NULL) {
			n->din_type = dn2->din_type;
			n->din_ctfid = dn2->din_ctfid;
			n->din_tf = dn2->din_tf;
			return (n->din_type);
		}

		/*
		 * Make sure all of the variable definitions match up, pick one
		 * and check that it's a CTF type.
		 *
		 * FIXME(dstolfa): Doing something like foo[0].snd = foo->bar;
		 * can cause the "not within a variable" if a stx happens on
		 * something that had an `add` instruction later on, e.g. giving
		 * an offset into the variable. This needs to be fixed.
		 */
		dif_var = NULL;
		for (ve = dt_list_next(&n->din_varsources); ve;
		     ve = dt_list_next(ve)) {
			ovar = dif_var;
			dif_var = ve->dtve_var;

			if (ovar == NULL)
				continue;

			if (dif_var->dtdv_id != ovar->dtdv_id ||
			    dif_var->dtdv_scope != ovar->dtdv_scope ||
			    dif_var->dtdv_kind != ovar->dtdv_kind) {
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): node has a "
				    "mismatch in varsources: "
				    "(%u, %u, %u) != (%u, %u, %u)",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_id, dif_var->dtdv_scope,
				    dif_var->dtdv_kind, ovar->dtdv_id,
				    ovar->dtdv_scope, ovar->dtdv_kind);
			}

			if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_CTF)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): instruction only "
				    "makes sense on CTF variable types, got %d",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_type.dtdt_kind);

			if (dif_var->dtdv_type.dtdt_kind !=
			    ovar->dtdv_type.dtdt_kind)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): node has a "
				    "mismatch in variable types: %d != %d",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_type.dtdt_kind,
				    ovar->dtdv_type.dtdt_kind);

			if (dif_var->dtdv_tf != ovar->dtdv_tf)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): node has a "
				    "mismatch in variable typefiles: %s != %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dt_typefile_stringof(dif_var->dtdv_tf),
				    dt_typefile_stringof(ovar->dtdv_tf));

			if (dt_typefile_typename(dif_var->dtdv_tf,
			    dif_var->dtdv_ctfid, buf,
			    sizeof(buf)) != ((char *)buf))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed getting "
				    "type name %ld: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_ctfid,
				    dt_typefile_error(dif_var->dtdv_tf));

			if (dt_typefile_typename(ovar->dtdv_tf,
			    ovar->dtdv_ctfid, buf,
			    sizeof(var_type)) != ((char *)var_type))
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed getting "
				    "type name %ld: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    ovar->dtdv_ctfid,
				    dt_typefile_error(ovar->dtdv_tf));

			if (dif_var->dtdv_ctfid != ovar->dtdv_ctfid) {
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): node has a "
				    "mismatch in varsource types: %s != %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    buf, var_type);
			}
		}

		if (dif_var == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): register [%%r%d] "
			    "is not within a variable",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_get_rd_from_node(n));

		if (dif_var->dtdv_type.dtdt_kind != DIF_TYPE_CTF)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): variable %zu is not of "
			    "a CTF type",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dif_var->dtdv_id);

		varkind = dt_typefile_typekind(dif_var->dtdv_tf,
		    dif_var->dtdv_ctfid);

		/*
		 * Only accept structs for now -- but we might need to handle
		 * unions and arrays at some point too.
		 */
		if (varkind != CTF_K_STRUCT)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): expected a struct CTF "
			    "kind, got %d",
			    insname[opcode], n->din_uidx, n->din_difo, varkind);

		/*
		 * At this point, we should have a membinfo pointer to the field
		 * that we will be accessing.
		 */
		mip = malloc(sizeof(ctf_membinfo_t));
		if (mip == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): malloc failed on "
			    "mip: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    strerror(errno));

		memset(mip, 0, sizeof(ctf_membinfo_t));

		if (dt_typefile_membinfo(dif_var->dtdv_tf, dif_var->dtdv_ctfid,
		    dn1->din_sym, mip) == 0)
			dt_set_progerr(g_dtp, g_pgp,
			    "dt_infer_type(%s, %zu@%p): failed to get "
			    "member info: %s",
			    insname[opcode], n->din_uidx, n->din_difo,
			    dt_typefile_error(dif_var->dtdv_tf));

		/*
		 * If dn1 is a CTF type, we will actually type-check that
		 * we are storing a meaningful type to the destination. If
		 * instead it is a bottom type, we will simply accept whatever
		 * the type is and store it anyway.
		 */
		if (dn1->din_type == DIF_TYPE_CTF) {
			/*
			 * We will be checking all of the compatible types too,
			 * but we start with these.
			 */
			const char *dst_type[] = {
				[0] = "uint8_t",
				[1] = "uint16_t",
				[2] = "uint32_t",
				[3] = "uint64_t" };
			ctf_id_t dst_ctfid;

			if (dt_typefile_typename(dn1->din_tf, dn1->din_ctfid,
			    buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed getting "
				    "typename of %d: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dn1->din_ctfid,
				    dt_typefile_error(dn1->din_tf));

			if (dt_typefile_typename(dif_var->dtdv_tf,
			    dif_var->dtdv_ctfid, var_type,
			    sizeof(var_type)) != (char *)var_type)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed getting "
				    "typename of %d: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dif_var->dtdv_ctfid,
				    dt_typefile_error(dif_var->dtdv_tf));

			if ((dst_ctfid = dt_typefile_ctfid(dt_typefile_kernel(),
			    dst_type[insid])) == CTF_ERR)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): failed getting "
				    "ctfid from %s for %s: %s",
				    insname[opcode], n->din_uidx, n->din_difo,
				    dt_typefile_stringof(dt_typefile_kernel()),
				    dst_type[insid],
				    dt_typefile_error(dt_typefile_kernel()));

			if (dt_typefile_compat(dif_var->dtdv_tf, dst_ctfid,
			    dn1->din_tf, dn1->din_ctfid) == 0)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_infer_type(%s, %zu@%p): types %s "
				    "(variable field) and %s "
				    "(instruction %zu) are not compatible",
				    insname[opcode], n->din_uidx, n->din_difo,
				    var_type, buf, dn1->din_uidx);
		}

		n->din_type = dn2->din_type;
		n->din_ctfid = dn2->din_ctfid;
		n->din_tf = dn2->din_tf;
		return (n->din_type);
	} /* case DIF_OP_STX */
	default:
		dt_set_progerr(g_dtp, g_pgp, "unhandled instruction: %u",
		    opcode);
	}

	return (-1);
}

int
dt_prog_infer_types(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_difo_t *difo)
{
	uint_t i = 0, idx = 0;
	dt_ifg_node_t *node = NULL;
	dt_ifg_list_t *ifgl = NULL;
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

	if (pgp == NULL)
		return (EDT_COMPILER);

	if (dtp == NULL)
		return (EDT_COMPILER);

	g_dtp = dtp;
	g_pgp = pgp;

	difo->dtdo_types = malloc(sizeof(char *) * difo->dtdo_len);
	if (difo->dtdo_types == NULL)
		dt_set_progerr(g_dtp, g_pgp, "failed to malloc dtdo_types");

	i = difo->dtdo_len - 1;

	for (ifgl = dt_list_next(&node_list);
	    ifgl != NULL; ifgl = dt_list_next(ifgl)) {
		node = ifgl->dil_ifgnode;

		if (node->din_buf == NULL)
			continue;

		if (node->din_buf != difo->dtdo_buf)
			continue;

		instr = node->din_buf[node->din_uidx];
		opcode = DIF_INSTR_OP(instr);

		type = dt_infer_type(node);
		assert(type == -1 ||
		    type == DIF_TYPE_CTF || type == DIF_TYPE_STRING ||
		    type == DIF_TYPE_NONE || type == DIF_TYPE_BOTTOM);

		if (type == -1)
			dt_set_progerr(g_dtp, g_pgp,
			    "failed to infer a type for %zu@%p\n",
			    node->din_uidx, node->din_difo);

		if (type == DIF_TYPE_CTF) {
			if (node->din_tf == NULL)
				dt_set_progerr(dtp, pgp,
				    "%s(): typefile NULL at %zu@%p\n", __func__,
				    node->din_uidx, node->din_difo);

			if (dt_typefile_typename(node->din_tf,
			    node->din_ctfid, buf, sizeof(buf)) != (char *)buf)
				dt_set_progerr(g_dtp, g_pgp,
				    "dt_prog_infer_types(): failed at getting "
				    "type name %ld: %s (DIFO %p, node %zu)",
				    node->din_ctfid,
				    dt_typefile_error(node->din_tf),
				    node->din_difo, node->din_uidx);
			difo->dtdo_types[node->din_uidx] = strdup(buf);
		} else if (type == DIF_TYPE_STRING)
			difo->dtdo_types[node->din_uidx] = strdup("string");
		else if (type == DIF_TYPE_NONE)
			difo->dtdo_types[node->din_uidx] = strdup("none");
		else if (type == DIF_TYPE_BOTTOM)
			difo->dtdo_types[node->din_uidx] = strdup("bottom");
		else
			difo->dtdo_types[node->din_uidx] = strdup("ERROR");
	}

	g_pgp = NULL;
	g_dtp = NULL;

	return (0);
}
