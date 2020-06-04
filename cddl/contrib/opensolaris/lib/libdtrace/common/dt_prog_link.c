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

#include <dt_relo.h>
#include <dt_basic_block.h>
#include <dt_ifg.h>
#include <dt_cfg.h>
#include <dt_linker_subr.h>
#include <dt_typing.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <err.h>

#ifndef illumos
#include <sys/sysctl.h>
#endif

ctf_file_t *ctf_file = NULL;
dt_list_t relo_list;
dt_list_t bb_list;
dt_rl_entry_t *relo_last = NULL;
dt_list_t var_list;
dt_relo_t *r0relo = NULL;

static int
dt_prog_relocate(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	size_t idx;
	dt_rl_entry_t *rl, *usetx_rl;
	dt_relo_t *relo, *usetx_relo;
	dif_instr_t instr, new_instr;
	uint8_t opcode, new_op;
	size_t size, kind;
	ctf_id_t ctfid;
	uint8_t rd, r1;
	uint16_t offset;
        ctf_encoding_t ep;
	int index, i;

	rl = NULL;
	relo = NULL;
	idx = 0;
	instr = 0;
	opcode = 0;
	size = 0;
	kind = 0;
	ctfid = 0;
	new_instr = 0;
	new_op = 0;
	index = i = 0;
	memset(&ep, 0, sizeof(ctf_encoding_t));

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
				    "failed to insert %d, got %d (!= %d)\n",
				    difo->dtdo_inttab[i], index, i);
		}
	}

	for (rl = dt_list_next(&relo_list); rl != NULL; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;

		if (relo->dr_difo != difo)
			continue;

		instr = relo->dr_buf[relo->dr_uidx];
		opcode = DIF_INSTR_OP(instr);
		switch (opcode) {
		case DIF_OP_RET:
		case DIF_OP_PUSHTR:
		case DIF_OP_PUSHTR_H:
		case DIF_OP_PUSHTR_G:
			if (relo->dr_mip == NULL)
				continue;

			ctfid = ctf_type_resolve(ctf_file, relo->dr_mip->ctm_type);
		        size = ctf_type_size(ctf_file, ctfid);
			kind = ctf_type_kind(ctf_file, ctfid);
			offset = relo->dr_mip->ctm_offset / 8; /* bytes */

			for (usetx_rl = dt_list_next(&relo->dr_usetxs);
			     usetx_rl; usetx_rl = dt_list_next(usetx_rl)) {
				usetx_relo = usetx_rl->drl_rel;
				if (usetx_relo->dr_relocated == 1)
					continue;

				instr = usetx_relo->dr_buf[usetx_relo->dr_uidx];
				opcode = DIF_INSTR_OP(instr);
				if (opcode != DIF_OP_USETX)
					errx(EXIT_FAILURE,
					    "opcode (%d) is not usetx", opcode);

				rd = DIF_INSTR_RD(instr);

				if (difo->dtdo_inthash == NULL) {
					difo->dtdo_inthash =
					    dt_inttab_create(dtp);

					if (difo->dtdo_inthash == NULL)
						errx(EXIT_FAILURE, "failed "
						    "to allocate inttab");
				}

				if ((index = dt_inttab_insert(
				    difo->dtdo_inthash, offset, 0)) == -1)
					errx(EXIT_FAILURE,
					    "failed to insert %u into inttab",
					    offset);

				usetx_relo->dr_buf[usetx_relo->dr_uidx] =
				    DIF_INSTR_SETX(index, rd);
				usetx_relo->dr_relocated = 1;
			}
			break;

		case DIF_OP_ULOAD:
		case DIF_OP_UULOAD:
			ctfid = ctf_type_resolve(ctf_file, relo->dr_mip->ctm_type);
		        size = ctf_type_size(ctf_file, ctfid);
			kind = ctf_type_kind(ctf_file, ctfid);

			if (kind != CTF_K_INTEGER && kind != CTF_K_POINTER)
				errx(EXIT_FAILURE, "a load of kind %d is"
				    " unsupported in DIF.", kind);

			if (kind == CTF_K_POINTER) {
				new_op = opcode == DIF_OP_ULOAD ? DIF_OP_LDX : DIF_OP_ULDX;
				rd = DIF_INSTR_RD(instr);
				r1 = DIF_INSTR_R1(instr);

				new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
			} else {
			        if (ctf_type_encoding(ctf_file, ctfid, &ep) != 0)
					errx(EXIT_FAILURE,
					    "failed to get encoding for %d",
					    ctfid);

				if (ep.cte_format & CTF_INT_SIGNED) {
					if (size == 1)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDSB : DIF_OP_ULDSB;
					else if (size == 2)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDSH : DIF_OP_ULDSH;
					else if (size == 4)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDSW : DIF_OP_ULDSW;
					else if (size == 8)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDX : DIF_OP_ULDX;
					else
						errx(EXIT_FAILURE,
						    "unsupported size %zu",
						    size);
				} else {
					if (size == 1)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDUB : DIF_OP_ULDUB;
					else if (size == 2)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDUH : DIF_OP_ULDUH;
					else if (size == 4)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDUW : DIF_OP_ULDUW;
					else if (size == 8)
						new_op = opcode == DIF_OP_ULOAD ?
						    DIF_OP_LDX : DIF_OP_ULDX;
					else
						errx(EXIT_FAILURE,
						    "unsupported size %zu",
						    size);
				}

				rd = DIF_INSTR_RD(instr);
				r1 = DIF_INSTR_R1(instr);

				new_instr = DIF_INSTR_LOAD(new_op, r1, rd);
			}

			offset = relo->dr_mip->ctm_offset / 8; /* bytes */

			for (usetx_rl = dt_list_next(&relo->dr_usetxs);
			     usetx_rl; usetx_rl = dt_list_next(usetx_rl)) {
				usetx_relo = usetx_rl->drl_rel;
				if (usetx_relo->dr_relocated == 1)
					continue;

				instr = usetx_relo->dr_buf[usetx_relo->dr_uidx];
				opcode = DIF_INSTR_OP(instr);
				if (opcode != DIF_OP_USETX)
					errx(EXIT_FAILURE,
					    "opcode (%d) is not usetx", opcode);

				rd = DIF_INSTR_RD(instr);

				if (difo->dtdo_inthash == NULL) {
					difo->dtdo_inthash =
					    dt_inttab_create(dtp);

					if (difo->dtdo_inthash == NULL)
						errx(EXIT_FAILURE, "failed "
						    "to allocate inttab");
				}

				if ((index = dt_inttab_insert(
				    difo->dtdo_inthash, offset, 0)) == -1)
					errx(EXIT_FAILURE,
					    "failed to insert %u into inttab",
					    offset);

				usetx_relo->dr_buf[usetx_relo->dr_uidx] =
				    DIF_INSTR_SETX(index, rd);
				usetx_relo->dr_relocated = 1;
			}

			relo->dr_buf[relo->dr_uidx] = new_instr;
			relo->dr_relocated = 1;
			break;

		case DIF_OP_TYPECAST:
			/*
			 * For typecast, we simply turn it into a nop. We only
			 * ever use typecast for type inference and can't
			 * actually execute it as an instruction. We will
			 * collapse the nops later.
			 */
			relo->dr_buf[relo->dr_uidx] = DIF_INSTR_NOP;
			relo->dr_relocated = 1;
			break;
		}
	}

	return (0);
}

static int
dt_update_usetx_bb(dtrace_difo_t *difo, dt_basic_block_t *bb, dt_relo_t *r)
{
	dt_rl_entry_t *rl, *nrl;
	dif_instr_t instr;
	dt_relo_t *relo, *usetx_relo;
	uint8_t opcode;
	uint8_t rd, _rd, r1;

	rl = NULL;
	nrl = NULL;
	relo = usetx_relo = NULL;
	instr = 0;
	opcode = 0;
	rd = _rd = r1 = 0;

	rd = DIF_INSTR_RD(r->dr_buf[r->dr_uidx]);

	if (r->dr_sym == NULL)
		errx(EXIT_FAILURE, "usetx dr_sym should not be NULL");

	for (rl = dt_list_next(&relo_list); rl; rl = dt_list_next(rl)) {
		relo = rl->drl_rel;
		instr = relo->dr_buf[relo->dr_uidx];
		opcode = DIF_INSTR_OP(instr);

		if (relo->dr_difo != difo)
			continue;

		if (r->dr_uidx >= relo->dr_uidx)
			continue;

		if (relo->dr_uidx < bb->dtbb_start ||
		    relo->dr_uidx > bb->dtbb_end)
			continue;

		if (relo == r)
			continue;

		if (opcode == DIF_OP_ULOAD    ||
		    opcode == DIF_OP_UULOAD   ||
		    opcode == DIF_OP_RET      ||
		    opcode == DIF_OP_PUSHTR   ||
		    opcode == DIF_OP_PUSHTR_H ||
		    opcode == DIF_OP_PUSHTR_G) {
			usetx_relo = dt_find_relo_in_ifg(relo, r);

			if (usetx_relo != r)
				continue;

			nrl = malloc(sizeof(dt_rl_entry_t));
			memset(nrl, 0, sizeof(dt_rl_entry_t));

			nrl->drl_rel = r;
			if (dt_in_list(&relo->dr_usetxs,
			    (void *)&r, sizeof(dt_relo_t *)) == 0) {
				printf("usetx %zu ==> %zu\n", r->dr_uidx, relo->dr_uidx);
				dt_list_append(&relo->dr_usetxs, nrl);
			}
		}
	}

	return (0);
}

static void
_dt_update_usetxs(dtrace_difo_t *difo, dt_basic_block_t *bb, dt_relo_t *r)
{
	dt_bb_entry_t *chld;
	dt_basic_block_t *chld_bb;
	int redefined;

	chld = NULL;
	chld_bb = NULL;
	redefined = 0;

	redefined = dt_update_usetx_bb(difo, bb, r);
	if (redefined)
		return;

	for (chld = dt_list_next(&bb->dtbb_children);
	     chld; chld = dt_list_next(chld)) {
		chld_bb = chld->dtbe_bb;
		if (chld_bb->dtbb_idx > DT_BB_MAX)
			errx(EXIT_FAILURE, "too many basic blocks.");
		_dt_update_usetxs(difo, chld_bb, r);
	}
}

static void
dt_update_usetxs(dtrace_difo_t *difo, dt_relo_t *r)
{
	dif_instr_t instr;
	uint8_t opcode;

	instr = 0;
	opcode = 0;

	if (r == NULL)
		return;

	instr = r->dr_buf[r->dr_uidx];
	opcode = DIF_INSTR_OP(instr);

	if (opcode != DIF_OP_USETX)
		return;

	if (r->dr_sym == NULL)
		errx(EXIT_FAILURE, "opcode is usetx but no symbol found");

	if (r->dr_difo != difo)
		return;

	_dt_update_usetxs(difo, difo->dtdo_bb, r);

}

static void
dt_prog_infer_usetxs(dtrace_difo_t *difo)
{
	dt_rl_entry_t *rl;
	dt_relo_t *r;

	rl = NULL;
	r = NULL;

	for (rl = relo_last; rl; rl = dt_list_prev(rl)) {
		r = rl->drl_rel;
		dt_update_usetxs(difo, r);
	}
}

static void
dt_prog_assemble(dtrace_hdl_t *dtp, dtrace_difo_t *difo)
{
	size_t inthash_size;
	uint64_t *otab;
	size_t i;
	dtrace_difv_t *var, *vlvar;

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
		difo->dtdo_inttab = malloc(sizeof(uint64_t) * inthash_size);
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

		memcpy(&var->dtdv_type, &vlvar->dtdv_type,
		    sizeof(dtrace_diftype_t));
	}
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

	r0relo = dt_relo_alloc(NULL, UINT_MAX);
	r0relo->dr_type = DIF_TYPE_BOTTOM;

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
		     ad != sdp->dtsd_action_last->dtad_next; ad = ad->dtad_next) {
			if (ad->dtad_difo == NULL)
				continue;

			dt_populate_varlist(ad->dtad_difo);
		}

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

			rval = dt_prog_infer_types(dtp, ad->dtad_difo);
			if (rval != 0)
				return (dt_set_errno(dtp, rval));

		        dt_prog_infer_usetxs(ad->dtad_difo);

			rval = dt_prog_relocate(dtp, ad->dtad_difo);
			if (rval != 0)
				return (dt_set_errno(dtp, rval));

			dt_prog_assemble(dtp, ad->dtad_difo);
		}
	}

	free(ctf_file);
	return (0);
}
