/*-
 * Copyright (c) 2020 Domagoj Stolfa
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
 *
 * $FreeBSD$
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/dtrace.h>

#include <dt_prog_link.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dtrace.h>

#include <dt_ifgnode.h>
#include <dt_basic_block.h>
#include <dt_ifg.h>
#include <dt_cfg.h>
#include <dt_linker_subr.h>
#include <dt_typefile.h>
#include <dt_typing.h>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

dt_list_t node_list;
dt_list_t bb_list;
dt_ifg_list_t *node_last = NULL;
dt_list_t var_list;
dt_ifg_node_t *r0node = NULL;

typedef struct dtrace_ecbdesclist {
	dt_list_t next;
	dtrace_ecbdesc_t *ecbdesc;
} dtrace_ecbdesclist_t;

char t_mtx[MAXPATHLEN];
char t_rw[MAXPATHLEN];
char t_sx[MAXPATHLEN];
char t_thread[MAXPATHLEN];

static void
patch_usetxs(dtrace_hdl_t *dtp, dt_ifg_node_t *n)
{
	dt_ifg_list_t *usetx_ifgl;
	dt_ifg_node_t *usetx_node;
	uint8_t rd, opcode;
	dif_instr_t instr;
	dtrace_difo_t *difo;
	int index;
	uint16_t offset;

	if (n == NULL)
		return;

	if (n->din_difo == NULL)
		return;

	if (n->din_mip == NULL)
		return;

	difo = n->din_difo;
	offset = n->din_mip->ctm_offset / 8 /* bytes */;

	for (usetx_ifgl = dt_list_next(&n->din_usetxs); usetx_ifgl;
	     usetx_ifgl = dt_list_next(usetx_ifgl)) {
		usetx_node = usetx_ifgl->dil_ifgnode;
		if (usetx_node->din_relocated == 1)
			continue;

		instr = usetx_node->din_buf[usetx_node->din_uidx];
		opcode = DIF_INSTR_OP(instr);
		if (opcode != DIF_OP_USETX)
			errx(EXIT_FAILURE, "opcode (%d) is not usetx", opcode);

		rd = DIF_INSTR_RD(instr);

		if (difo->dtdo_inthash == NULL) {
			difo->dtdo_inthash = dt_inttab_create(dtp);

			if (difo->dtdo_inthash == NULL)
				errx(EXIT_FAILURE,
				    "failed "
				    "to allocate inttab");
		}

		if ((index = dt_inttab_insert(difo->dtdo_inthash, offset, 0)) ==
		    -1)
			errx(EXIT_FAILURE, "failed to insert %u into inttab",
			    offset);

		usetx_node->din_buf[usetx_node->din_uidx] = DIF_INSTR_SETX(
		    index, rd);
		usetx_node->din_relocated = 1;
	}
}

static void
dt_prepare_typestrings(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	char __kernel[] = "kernel`";
	size_t __kernel_len = strlen(__kernel);

	if (strncmp(mtx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "mtx_str does not start with \"kernel`\" (%s)", mtx_str);

	if (strncmp(rw_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "rw_str does not start with \"kernel`\" (%s)", rw_str);

	if (strncmp(sx_str, __kernel, __kernel_len) != 0)
		dt_set_progerr(dtp, pgp,
		    "sx_str does not start with \"kernel`\" (%s)", sx_str);

	memcpy(t_mtx, mtx_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_rw, rw_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_sx, sx_str + __kernel_len, MAXPATHLEN - __kernel_len);
	memcpy(t_thread, thread_str, MAXPATHLEN);
}

static void
relocate_uloadadd(dtrace_hdl_t *dtp, dt_ifg_node_t *node)
{
	size_t size, kind;
	ctf_id_t ctfid;
	uint8_t rd, r1;
	uint8_t opcode, new_op;
	ctf_encoding_t encoding;
	dif_instr_t instr, new_instr;

	instr = node->din_buf[node->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	if (opcode == DIF_OP_ADD)
		goto usetx_relo;

	ctfid = dt_typefile_resolve(node->din_tf, node->din_mip->ctm_type);
	size = dt_typefile_typesize(node->din_tf, ctfid);
	kind = dt_typefile_typekind(node->din_tf, ctfid);


	/*
	 * NOTE: We support loading of CTF_K_ARRAY due to it
	 * just being a pointer, really.
	 */
	if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER &&
	    kind != CTF_K_ARRAY)
		errx(EXIT_FAILURE, "a load of kind %zu is unsupported in DIF.",
		    kind);

	if (kind == CTF_K_POINTER || kind == CTF_K_ARRAY) {
		new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX : DIF_OP_ULDX;
		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	} else {
		if (dt_typefile_encoding(node->din_tf, ctfid, &encoding) != 0)
			errx(EXIT_FAILURE, "failed to get encoding for %ld",
			    ctfid);

		if (encoding.cte_format & CTF_INT_SIGNED) {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSB :
				    DIF_OP_ULDSB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSH :
				    DIF_OP_ULDSH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDSW :
				    DIF_OP_ULDSW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else
				errx(
				    EXIT_FAILURE, "unsupported size %zu", size);
		} else {
			if (size == 1)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUB :
				    DIF_OP_ULDUB;
			else if (size == 2)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUH :
				    DIF_OP_ULDUH;
			else if (size == 4)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDUW :
				    DIF_OP_ULDUW;
			else if (size == 8)
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX :
				    DIF_OP_ULDX;
			else
				errx(
				    EXIT_FAILURE, "unsupported size %zu", size);
		}

		rd = DIF_INSTR_RD(instr);
		r1 = DIF_INSTR_R1(instr);

		new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
	}

usetx_relo:
	if (node->din_mip == NULL) {
		node->din_relocated = 1;
		return;
	}

	patch_usetxs(dtp, node);

	if (opcode != DIF_OP_ADD)
		node->din_buf[node->din_uidx] = new_instr;
	node->din_relocated = 1;
}

static void
relocate_retpush(dtrace_hdl_t *dtp, dt_ifg_node_t *node,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad,
    dtrace_diftype_t *orig_rtype)
{

	/*
	 * If this instruction does not come from a usetx,
	 * we don't really have to do anything with it.
	 */
	if (node->din_mip == NULL)
		return;

	patch_usetxs(dtp, node);
}

static void
relocate_push(dtrace_hdl_t *dtp, dt_ifg_node_t *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{

	relocate_retpush(dtp, node, actkind, ad, orig_rtype);
}

static void
ret_cleanup(dt_ifg_node_t *node, dtrace_diftype_t *rtype)
{
	dt_ifg_list_t *r1l;
	dif_instr_t instr = 0;
	uint8_t opcode = 0;
	dt_ifg_node_t *n;

	/*
	 * We only need to clean up things if we return by reference
	 * currently.
	 */
	if ((rtype->dtdt_flags & DIF_TF_BYREF) == 0 &&
	    (rtype->dtdt_flags & DIF_TF_BYUREF) == 0)
		return;

	for (r1l = dt_list_next(&node->din_r1defs); r1l;
	    r1l = dt_list_next(r1l)) {
		n = r1l->dil_ifgnode;

		instr = n->din_buf[n->din_uidx];
		opcode = DIF_INSTR_OP(instr);

		switch (opcode) {
		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
			break;

		case DIF_OP_LDUB:
		case DIF_OP_LDSB:
		case DIF_OP_LDUH:
		case DIF_OP_LDSH:
		case DIF_OP_LDUW:
		case DIF_OP_LDSW:
		case DIF_OP_LDX:
			n->din_buf[n->din_uidx] = DIF_INSTR_NOP;
			break;
		}
	}
}

static void
relocate_ret(dtrace_hdl_t *dtp, dt_ifg_node_t *node, dtrace_actkind_t actkind,
    dtrace_actdesc_t *ad, dtrace_diftype_t *orig_rtype)
{
	dtrace_diftype_t *rtype;
	dtrace_difo_t *difo;
	dtrace_prog_t *pgp;
	int ctf_kind;

	/*
	 * In case of a RET, we first patch up the DIFO with the correct return
	 * type and size.
	 */
	difo = node->din_difo;
	rtype = &difo->dtdo_rtype;

	rtype->dtdt_kind = node->din_type;
	if (node->din_type == DIF_TYPE_CTF)
		rtype->dtdt_ckind = node->din_ctfid;
	else if (node->din_type == DIF_TYPE_STRING)
		rtype->dtdt_ckind = DT_STR_TYPE(dtp);
	else if (node->din_type == DIF_TYPE_BOTTOM)
		/*
		 * If we have a bottom type, we really
		 * don't care which CTF type the host
		 * wants here. It can be patched in
		 * later on demand.
		 */
		rtype->dtdt_ckind = CTF_BOTTOM_TYPE;
	else
		errx(EXIT_FAILURE,
		    "unexpected node->din_type (%x) at location %zu",
		    node->din_type, node->din_uidx);

	assert(actkind != DTRACEACT_NONE);
	if (actkind != DTRACEACT_DIFEXPR)
		assert(ad != NULL);

	switch (actkind) {
	case DTRACEACT_EXIT:
		*rtype = dt_int_rtype;
		rtype->dtdt_size = sizeof(int);
		break;

	case DTRACEACT_PRINTA:
	case DTRACEACT_PRINTM:
	case DTRACEACT_TRACEMEM:
	case DTRACEACT_TRACEMEM_DYNSIZE:
		break;

	case DTRACEAGG_QUANTIZE:
	case DTRACEAGG_LQUANTIZE:
	case DTRACEAGG_LLQUANTIZE:
		break;

	case DTRACEACT_PRINTF:
	case DTRACEACT_DIFEXPR:
		if (ad && ad->dtad_return == 0) {
			*rtype = dt_void_rtype;
			break;
		}

		/*
		 * Fall through to the default case.
		 */
	default:
		if (node->din_mip == NULL && rtype->dtdt_kind == DIF_TYPE_CTF) {
			ctf_kind = dt_typefile_typekind(
			    node->din_tf, node->din_ctfid);

			/*
			 * XXX(dstolfa, important): Is this a sensible thing to
			 * be doing for all guests? We claim to know on the host
			 * whether or not we need to dereference something --
			 * but is that actually true? Need to think about this a
			 * bit more. On the guest, we lack the information about
			 * what takes a dereferenced value in, but on the host
			 * we lack type information.
			 */
			rtype->dtdt_flags = orig_rtype->dtdt_flags;

			if (ctf_kind == CTF_K_ARRAY) {
				rtype->dtdt_flags |= DIF_TF_BYREF;
			}

			ret_cleanup(node, rtype);

			rtype->dtdt_size = dt_typefile_typesize(
			    node->din_tf, node->din_ctfid);
		} else if (rtype->dtdt_kind == DIF_TYPE_BOTTOM) {
			/*
			 * We don't care what the size is, we just need to set
			 * the correct flags.
			 */
			rtype->dtdt_flags = orig_rtype->dtdt_flags;
		} else {
			rtype->dtdt_flags |= DIF_TF_BYREF;
		}

		break;
	}
	/*
	 * Safety guard
	 */
	if (node->din_type == DIF_TYPE_STRING) {
		rtype->dtdt_flags |= DIF_TF_BYREF;
		rtype->dtdt_ckind = CTF_ERR;
	}

	relocate_retpush(dtp, node, actkind, ad, orig_rtype);
}

static void
patch_setxs(dt_list_t *setx_defs1, dt_list_t *setx_defs2)
{
	dt_ifg_list_t *sd1l, *sd2l;
	dt_ifg_node_t *sd1, *sd2;
	dif_instr_t instr1, instr2;
	uint8_t op1, op2;

	for (sd1l = dt_list_next(setx_defs1), sd2l = dt_list_next(setx_defs2);
	     sd1l && sd2l;
	     sd1l = dt_list_next(sd1l), sd2l = dt_list_next(sd2l)) {
		sd1 = sd1l->dil_ifgnode;
		sd2 = sd2l->dil_ifgnode;

		sd1->din_buf[sd1->din_uidx] = DIF_INSTR_NOP;
		sd2->din_buf[sd2->din_uidx] = DIF_INSTR_NOP;
	}
}

static int
check_setxs(dt_list_t *setx_defs1, dt_list_t *setx_defs2)
{
	dt_ifg_list_t *sd1l, *sd2l;
	dt_ifg_node_t *sd1, *sd2;
	dif_instr_t instr1, instr2;
	uint8_t op1, op2;

	for (sd1l = dt_list_next(setx_defs1), sd2l = dt_list_next(setx_defs2);
	     sd1l && sd2l;
	     sd1l = dt_list_next(sd1l), sd2l = dt_list_next(sd2l)) {
		sd1 = sd1l->dil_ifgnode;
		sd2 = sd2l->dil_ifgnode;

		instr1 = sd1->din_buf[sd1->din_uidx];
		instr2 = sd2->din_buf[sd2->din_uidx];

		op1 = DIF_INSTR_OP(instr1);
		op2 = DIF_INSTR_OP(instr2);

		/*
		 * This is really the only thing we need to check here.
		 */
		if (op1 != DIF_OP_SETX || instr1 != instr2)
			return (0);
	}

	return (1);
}

static void
relocate_ifg_entry(dt_ifg_list_t *ifgl, dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *orig_rtype)
{
	dt_ifg_node_t *node;
	dif_instr_t instr;
	uint8_t opcode;

	node = ifgl->dil_ifgnode;
	if (node->din_difo != difo)
		return;

	instr = node->din_buf[node->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_RET:
		relocate_ret(dtp, node, actkind, ad, orig_rtype);
		break;

	case DIF_OP_PUSHTR:
		relocate_push(dtp, node, actkind, ad, orig_rtype);
		break;

	case DIF_OP_PUSHTV: {
		/*
		 * Patch up the type we're pushing on the stack.
		 */
		dif_instr_t newinstr;
		uint8_t rs, rv;

		rs = DIF_INSTR_RS(instr);
		rv = DIF_INSTR_R2(instr);

		newinstr = DIF_INSTR_PUSHTS(DIF_OP_PUSHTV,
		    node->din_type, rv, rs);
		node->din_buf[node->din_uidx] = newinstr;
		break;
	}

	case DIF_OP_ADD:
	case DIF_OP_ULOAD:
	case DIF_OP_UULOAD:
		relocate_uloadadd(dtp, node);
		break;

	case DIF_OP_TYPECAST: {
		dif_instr_t idef1, idef2;
		uint8_t opdef1, opdef2;
		dt_ifg_node_t *ndef1, *ndef2;
		dt_ifg_list_t *rd1, *rd2;
		uint8_t r11, r12, r21, r22, currd, rd;
		dt_list_t *setx_defs1, *setx_defs2, *defs;
		char symname[4096] = { 0 };
		uint16_t sym;
		size_t l;

		/*
		 * For typecast, we simply turn it into a nop. We only
		 * ever use typecast for type inference and can't
		 * actually execute it as an instruction. We will
		 * collapse the nops later.
		 */
		node->din_buf[node->din_uidx] = DIF_INSTR_NOP;

		if (node->din_uidx < 2)
			goto end;

		patch_usetxs(dtp, node);
		sym = DIF_INSTR_SYMBOL(instr);
		currd = DIF_INSTR_RD(instr);

		if (sym >= difo->dtdo_symlen)
			dt_set_progerr(dtp, pgp,
			    "%s(): sym (%u) >= symlen (%zu)\n", __func__, sym,
			    difo->dtdo_symlen);

		l = strlcpy(symname, difo->dtdo_symtab + sym, sizeof(symname));
		if (l >= sizeof(symname))
			dt_set_progerr(dtp, pgp,
			    "%s(): length (%zu) >= %zu when copying type name",
			    __func__, l, sizeof(symname));

		if (strcmp(symname, "uintptr_t") != 0)
			goto end;

		/*
		 * Now we need to check if we have a sll followed by a sra as
		 * the previous two instructions. This can happen in the case
		 * sign extension is needed -- however we don't actually want to
		 * do this for an uintptr_t.
		 */
		for (rd1 = dt_list_next(&node->din_r1defs); rd1;
		     rd1 = dt_list_next(rd1)) {
			ndef1 = rd1->dil_ifgnode;
			idef1 = ndef1->din_buf[ndef1->din_uidx];
			opdef1 = DIF_INSTR_OP(idef1);

			if (opdef1 != DIF_OP_SRA)
				continue;

			r11 = DIF_INSTR_R1(idef1);
			r21 = DIF_INSTR_R2(idef1);

			/*
			 * Figure out which register we need to look up the
			 * definitions for.
			 */
			defs = NULL;
			setx_defs1 = NULL;

			if (r11 == currd) {
				defs = &ndef1->din_r1defs;
				setx_defs1 = &ndef1->din_r2defs;
			}

			if (r21 == currd) {
				/*
				 * Assert that we don't have a sra %r1, %r1, %r1
				 * as that would be extremely weird.
				 */
				assert(defs == NULL);
				assert(setx_defs1 == NULL);
				defs = &ndef1->din_r2defs;
				setx_defs1 = &ndef1->din_r1defs;
			}

			if (defs == NULL)
				continue;

			for (rd2 = dt_list_next(defs); rd2;
			     rd2 = dt_list_next(rd2)) {
				ndef2 = rd2->dil_ifgnode;
				idef2 = ndef2->din_buf[ndef2->din_uidx];
				opdef2 = DIF_INSTR_OP(idef2);

				if (opdef2 != DIF_OP_SLL)
					continue;

				r12 = DIF_INSTR_R1(idef2);
				r22 = DIF_INSTR_R2(idef2);

				rd = DIF_INSTR_RD(idef2);

				setx_defs2 = NULL;
				if (r12 == rd)
					setx_defs2 = &ndef2->din_r2defs;

				if (r22 == rd)
					setx_defs2 = &ndef2->din_r1defs;

				if (setx_defs2 == NULL)
					continue;

				if (!check_setxs(setx_defs1, setx_defs2))
					continue;

				ndef2->din_buf[ndef2->din_uidx] = DIF_INSTR_NOP;
				ndef1->din_buf[ndef1->din_uidx] = DIF_INSTR_NOP;

				patch_setxs(setx_defs1, setx_defs2);
			}
		}

end:
		node->din_relocated = 1;
		break;
	}

	default:
		break;
	}
}

static int
dt_prog_relocate(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_actkind_t actkind, dtrace_actdesc_t *ad, dtrace_difo_t *difo,
    dtrace_diftype_t *orig_rtype)
{
	dt_ifg_list_t *ifgl;
	int i, index;

	if (difo->dtdo_inttab != NULL) {
		assert(difo->dtdo_intlen != 0);
		assert(difo->dtdo_inthash == NULL);

		difo->dtdo_inthash = dt_inttab_create(dtp);
		if (difo->dtdo_inthash == NULL)
			errx(EXIT_FAILURE, "failed to allocate inthash");

		for (i = 0; i < difo->dtdo_intlen; i++) {
			if ((index = dt_inttab_insert(difo->dtdo_inthash,
			    difo->dtdo_inttab[i], 0)) != i)
				errx(EXIT_FAILURE,
				    "failed to insert %" PRIu64 ", got %d (!= %d)\n",
				    difo->dtdo_inttab[i], index, i);
		}
	}

	for (ifgl = dt_list_next(&node_list); ifgl != NULL;
	    ifgl = dt_list_next(ifgl)) {
		relocate_ifg_entry(ifgl, dtp, pgp, actkind, ad, difo, orig_rtype);
	}

	return (0);
}

static int
dt_update_usetx_bb(dtrace_difo_t *difo, dt_basic_block_t *bb, dt_ifg_node_t *n)
{
	dt_ifg_list_t *ifgl, *nifgl;
	dif_instr_t instr;
	dt_ifg_node_t *node, *usetx_node;
	uint8_t opcode;
	uint8_t rd, _rd, r1;

	ifgl = NULL;
	nifgl = NULL;
	node = usetx_node = NULL;
	instr = 0;
	opcode = 0;
	rd = _rd = r1 = 0;

	rd = DIF_INSTR_RD(n->din_buf[n->din_uidx]);

	if (n->din_sym == NULL)
		errx(EXIT_FAILURE, "usetx din_sym should not be NULL");

	for (ifgl = dt_list_next(&node_list); ifgl; ifgl = dt_list_next(ifgl)) {
		node = ifgl->dil_ifgnode;
		instr = node->din_buf[node->din_uidx];
		opcode = DIF_INSTR_OP(instr);

		if (node->din_difo != difo)
			continue;

		if (n->din_uidx >= node->din_uidx)
			continue;

		if (node->din_uidx < bb->dtbb_start ||
		    node->din_uidx > bb->dtbb_end)
			continue;

		if (node == n)
			continue;

		if (opcode == DIF_OP_ULOAD    ||
		    opcode == DIF_OP_UULOAD   ||
		    opcode == DIF_OP_RET      ||
		    opcode == DIF_OP_PUSHTR   ||
		    opcode == DIF_OP_ADD      ||
		    opcode == DIF_OP_TYPECAST) {
			usetx_node = dt_find_node_in_ifg(node, n);

			if (usetx_node != n)
				continue;

			nifgl = malloc(sizeof(dt_ifg_list_t));
			memset(nifgl, 0, sizeof(dt_ifg_list_t));

			nifgl->dil_ifgnode = n;
			if (dt_in_list(&node->din_usetxs,
			    (void *)&n, sizeof(dt_ifg_node_t *)) == NULL)
				dt_list_append(&node->din_usetxs, nifgl);
		}
	}

	return (0);
}

static void
_dt_update_usetxs(dtrace_difo_t *difo, dt_basic_block_t *bb, dt_ifg_node_t *n)
{
	dt_bb_entry_t *chld;
	dt_basic_block_t *chld_bb;
	int redefined;

	chld = NULL;
	chld_bb = NULL;
	redefined = 0;

	redefined = dt_update_usetx_bb(difo, bb, n);
	if (redefined)
		return;

	for (chld = dt_list_next(&bb->dtbb_children); chld;
	    chld = dt_list_next(chld)) {
		chld_bb = chld->dtbe_bb;
		if (chld_bb->dtbb_idx > DT_BB_MAX)
			errx(EXIT_FAILURE, "too many basic blocks.");
		_dt_update_usetxs(difo, chld_bb, n);
	}
}

static void
dt_update_usetxs(dtrace_difo_t *difo, dt_ifg_node_t *n)
{
	dif_instr_t instr;
	uint8_t opcode;

	instr = 0;
	opcode = 0;

	if (n == NULL)
		return;

	instr = n->din_buf[n->din_uidx];
	opcode = DIF_INSTR_OP(instr);

	if (opcode != DIF_OP_USETX)
		return;

	if (n->din_sym == NULL)
		errx(EXIT_FAILURE, "opcode is usetx but no symbol found");

	if (n->din_difo != difo)
		return;

	_dt_update_usetxs(difo, difo->dtdo_bb, n);
}

static void
dt_prog_infer_usetxs(dtrace_difo_t *difo)
{
	dt_ifg_list_t *ifgl;
	dt_ifg_node_t *n;

	ifgl = NULL;
	n = NULL;

	for (ifgl = node_last; ifgl; ifgl = dt_list_prev(ifgl)) {
		n = ifgl->dil_ifgnode;
		dt_update_usetxs(difo, n);
	}
}

static void
dt_prog_assemble(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_difo_t *difo,
    dtrace_diftype_t **biggest_type)
{
	size_t inthash_size;
	uint64_t *otab;
	size_t i;
	dtrace_difv_t *var, *vlvar;
	uint32_t id;
	uint8_t scope;

	var = vlvar = NULL;
	i = 0;
	otab = NULL;
	inthash_size = 0;

	if (difo->dtdo_inthash != NULL) {
		inthash_size = dt_inttab_size(difo->dtdo_inthash);
		if (inthash_size == 0) {
			fprintf(stderr, "inthash_size is 0\n");
			return;
		}

		otab = difo->dtdo_inttab;
		difo->dtdo_inttab = dt_alloc(dtp,
		    sizeof(uint64_t) * inthash_size);
		if (difo->dtdo_inttab == NULL)
			errx(EXIT_FAILURE, "failed to malloc inttab");

		memset(difo->dtdo_inttab, 0, sizeof(uint64_t) * inthash_size);
		free(otab);

		dt_inttab_write(difo->dtdo_inthash,
		    difo->dtdo_inttab);

		difo->dtdo_intlen = inthash_size;
	}

	/*
	 * By this time we should have any variable being used in this
	 * DIFO inside the varlist because the only _valid_ DIF currently
	 * is one where we store to a variable before loading it, so this
	 * information should already be available.
	 */
	for (i = 0; i < difo->dtdo_varlen; i++) {
		var = &difo->dtdo_vartab[i];

		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		vlvar = dt_get_var_from_varlist(var->dtdv_id,
		    var->dtdv_scope, var->dtdv_kind);
		assert(vlvar != NULL);

		var->dtdv_type = vlvar->dtdv_type;
		id = var->dtdv_id;
		scope = var->dtdv_scope;

		biggest_type[scope][id] = biggest_type[scope][id].dtdt_size >=
			var->dtdv_type.dtdt_size ?
			  biggest_type[scope][id] :
			  var->dtdv_type;
	}
}

static void
finalize_vartab(dtrace_difo_t *difo, dtrace_diftype_t **biggest_type)
{
	size_t i;
	dtrace_difv_t *var;

	/*
	 * Re-patch the variable table to ensure that we have uniform types
	 * across all of the references of the variable. Without this, the
	 * kernel verifier will fail.
	 */
	for (i = 0; i < difo->dtdo_varlen; i++) {
		var = &difo->dtdo_vartab[i];

		if (dt_var_is_builtin(var->dtdv_id))
			continue;

		var->dtdv_type = biggest_type[var->dtdv_scope][var->dtdv_id];
	}

}

static int
process_difo(dtrace_hdl_t *dtp, dtrace_prog_t *pgp, dtrace_actdesc_t *ad,
    dtrace_difo_t *difo, dtrace_ecbdesc_t *ecbdesc,
    dtrace_diftype_t **biggest_vartype)
{
	int rval;
	dtrace_actkind_t actkind;
	dtrace_diftype_t saved_rtype;

	rval = dt_prog_infer_defns(dtp, pgp, ecbdesc, difo);
	if (rval != 0)
		return (rval);

	saved_rtype = difo->dtdo_rtype;
	rval = dt_prog_infer_types(dtp, pgp, difo);
	if (rval != 0)
		return (rval);

	dt_prog_infer_usetxs(difo);

	actkind = ad == NULL ? DTRACEACT_DIFEXPR : ad->dtad_kind;
	rval = dt_prog_relocate(dtp, pgp, actkind, ad, difo, &saved_rtype);
	if (rval != 0)
		return (rval);

	dt_prog_assemble(dtp, pgp, difo, biggest_vartype);
	return (0);
}

int
dt_prog_apply_rel(dtrace_hdl_t *dtp, dtrace_prog_t *pgp)
{
	dt_stmt_t *stp = NULL;
	dtrace_stmtdesc_t *sdp = NULL;
	dtrace_actdesc_t *ad = NULL;
	dtrace_ecbdesc_t *ecbdesc;
	dtrace_preddesc_t *pred;
	dt_list_t processed_ecbdescs;
	dtrace_ecbdesclist_t *edl;
	int rval = 0;
	int err = 0;
	int i;
	dtrace_diftype_t *biggest_vartype[DIFV_NSCOPES];

	dt_typefile_openall(dtp);
	if (err)
		errx(EXIT_FAILURE, "failed to open CTF files: %s\n",
		    strerror(errno));

	dt_prepare_typestrings(dtp, pgp);

	/*
	 * Zero out the node list and basic block list.
	 */
	memset(&node_list, 0, sizeof(dt_list_t));
	memset(&bb_list, 0, sizeof(dt_list_t));
	memset(&processed_ecbdescs, 0, sizeof(dt_list_t));

	r0node = dt_ifg_node_alloc(pgp, NULL, NULL, NULL, UINT_MAX);
	r0node->din_type = DIF_TYPE_BOTTOM;

	/*
	 * Regenerate the identifier, since it's no longer the same program. Set
	 * the srcident to the original identifier.
	 */
	memcpy(pgp->dp_srcident, pgp->dp_ident, DT_PROG_IDENTLEN);
	dt_prog_generate_ident(pgp);

	for (i = 0; i < DIFV_NSCOPES; i++) {
		biggest_vartype[i] = malloc(
		    sizeof(dtrace_diftype_t) * DIF_VARIABLE_MAX);
		if (biggest_vartype[i] == NULL)
			dt_set_progerr(dtp, pgp,
			    "could not allocate biggest_vartype\n");

		memset(biggest_vartype[i], 0,
		    sizeof(dtrace_diftype_t) * DIF_VARIABLE_MAX);
	}

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		sdp = stp->ds_desc;

		if (sdp == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_NOSTMT));
		}

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_DIFINVAL));
		}

		pred = &ecbdesc->dted_pred;
		assert(pred != NULL);

		if (pred->dtpdd_difo != NULL)
			dt_populate_varlist(dtp, pred->dtpdd_difo);

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == NULL)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_ACTLAST));
		}

		/*
		 * We populate the variable list before we actually do a pass
		 * to infer definitions or type-checking. The reason for this
		 * is to do with the semantics of probes being concurrent, in
		 * the sense that they are in fact in parallel composition with
		 * each other, rather than having some sort of ordering. Even
		 * though for now we simply adopt the D style of type checking
		 * for variables (store before a load), we would also like for
		 * this to type-check:
		 *
		 * foo { y = x; } bar { x = 1; }
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			dt_populate_varlist(dtp, ad->dtad_difo);
		}
	}
	/*
	 * Go over all the statements in a D program
	 */
	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		sdp = stp->ds_desc;
		if (sdp == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_NOSTMT));
		}

		ecbdesc = sdp->dtsd_ecbdesc;
		if (ecbdesc == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_DIFINVAL));
		}

		pred = &ecbdesc->dted_pred;
		assert(pred != NULL);

		if (pred->dtpdd_difo != NULL) {
			for (edl = dt_list_next(&processed_ecbdescs); edl;
			     edl = dt_list_next(edl))
				if (edl->ecbdesc == ecbdesc)
					break;

			if (edl == NULL) {
				rval = process_difo(dtp, pgp, NULL,
				    pred->dtpdd_difo, ecbdesc, biggest_vartype);
				if (rval != 0) {
					for (i = 0; i < DIFV_NSCOPES; i++)
						free(biggest_vartype[i]);
					return (dt_set_errno(dtp, rval));
				}

				edl = dt_alloc(dtp, sizeof(dtrace_ecbdesclist_t));
				if (edl == NULL) {
					for (i = 0; i < DIFV_NSCOPES; i++)
						free(biggest_vartype[i]);
					return (dt_set_errno(dtp, EDT_NOMEM));
				}

				memset(edl, 0, sizeof(dtrace_ecbdesclist_t));

				edl->ecbdesc = ecbdesc;
				dt_list_append(&processed_ecbdescs, edl);
			}
		}
		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == NULL)
			continue;

		/*
		 * If we are in a state where we have the first action, but not
		 * a last action we bail out. This should not happen.
		 */
		if (sdp->dtsd_action_last == NULL) {
			for (i = 0; i < DIFV_NSCOPES; i++)
				free(biggest_vartype[i]);
			return (dt_set_errno(dtp, EDT_ACTLAST));
		}

		/*
		 * We go over each action and apply the relocations in each
		 * DIFO (if it exists).
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			rval = process_difo(dtp, pgp, ad, ad->dtad_difo,
			    ecbdesc, biggest_vartype);
			if (rval != 0) {
				for (i = 0; i < DIFV_NSCOPES; i++)
					free(biggest_vartype[i]);
				return (dt_set_errno(dtp, rval));
			}
		}
	}

	for (stp = dt_list_next(&pgp->dp_stmts); stp; stp = dt_list_next(stp)) {
		/*
		 * We don't need any checks here, because we just passed them
		 * above.
		 */
		sdp = stp->ds_desc;
		ecbdesc = sdp->dtsd_ecbdesc;
		pred = &ecbdesc->dted_pred;

		if (pred->dtpdd_difo != NULL)
			finalize_vartab(pred->dtpdd_difo, biggest_vartype);

		/*
		 * Nothing to do if the action is missing
		 */
		if (sdp->dtsd_action == NULL)
			continue;

		/*
		 * Finalize the variable table for each DIFO.
		 */
		for (ad = sdp->dtsd_action;
		     ad != sdp->dtsd_action_last->dtad_next;
		     ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			finalize_vartab(ad->dtad_difo, biggest_vartype);
		}

	}

	for (i = 0; i < DIFV_NSCOPES; i++)
		free(biggest_vartype[i]);
	while ((edl = dt_list_next(&processed_ecbdescs)) != NULL) {
		dt_list_delete(&processed_ecbdescs, edl);
		dt_free(dtp, edl);
	}

	return (0);
}
