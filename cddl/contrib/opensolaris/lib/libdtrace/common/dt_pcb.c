/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DTrace Parsing Control Block
 *
 * A DTrace Parsing Control Block (PCB) contains all of the state that is used
 * by a single pass of the D compiler, other than the global variables used by
 * lex and yacc.  The routines in this file are used to set up and tear down
 * PCBs, which are kept on a stack pointed to by the libdtrace global 'yypcb'.
 * The main engine of the compiler, dt_compile(), is located in dt_cc.c and is
 * responsible for calling these routines to begin and end a compilation pass.
 *
 * Sun's lex/yacc are not MT-safe or re-entrant, but we permit limited nested
 * use of dt_compile() once the entire parse tree has been constructed but has
 * not yet executed the "cooking" pass (see dt_cc.c for more information).  The
 * PCB design also makes it easier to debug (since all global state is kept in
 * one place) and could permit us to make the D compiler MT-safe or re-entrant
 * in the future by adding locks to libdtrace or switching to Flex and Bison.
 */

#include <strings.h>
#include <stdlib.h>
#include <assert.h>

#include <dt_impl.h>
#include <dt_program.h>
#include <dt_provider.h>
#include <dt_pcb.h>

/*
 * Initialize the specified PCB by zeroing it and filling in a few default
 * members, and then pushing it on to the top of the PCB stack and setting
 * yypcb to point to it.  Increment the current handle's generation count.
 */
void
dt_pcb_push(dtrace_hdl_t *dtp, dt_pcb_t *pcb)
{
	/*
	 * Since lex/yacc are not re-entrant and we don't implement state save,
	 * assert that if another PCB is active, it is from the same handle and
	 * has completed execution of yyparse().  If the first assertion fires,
	 * the caller is calling libdtrace without proper MT locking.  If the
	 * second assertion fires, dt_compile() is being called recursively
	 * from an illegal location in libdtrace, or a dt_pcb_pop() is missing.
	 */
	if (yypcb != NULL) {
		assert(yypcb->pcb_hdl == dtp);
		assert(yypcb->pcb_yystate == YYS_DONE);
	}

	bzero(pcb, sizeof (dt_pcb_t));

	dt_scope_create(&pcb->pcb_dstack);
	dt_idstack_push(&pcb->pcb_globals, dtp->dt_globals);
	dt_irlist_create(&pcb->pcb_ir);

	pcb->pcb_hdl = dtp;
	pcb->pcb_prev = dtp->dt_pcb;

	dtp->dt_pcb = pcb;
	dtp->dt_gen++;

	yyinit(pcb);
}

static int
dt_pcb_pop_ident(dt_idhash_t *dhp, dt_ident_t *idp, void *arg)
{
	dtrace_hdl_t *dtp = arg;

	if (idp->di_gen == dtp->dt_gen)
		dt_idhash_delete(dhp, idp);

	return (0);
}

/*
 * Pop the topmost PCB from the PCB stack and destroy any data structures that
 * are associated with it.  If 'err' is non-zero, destroy any intermediate
 * state that is left behind as part of a compilation that has failed.
 */
void
dt_pcb_pop(dtrace_hdl_t *dtp, int err)
{
	dt_pcb_t *pcb = yypcb;
	uint_t i;

	assert(pcb != NULL);
	assert(pcb == dtp->dt_pcb);

	while (pcb->pcb_dstack.ds_next != NULL)
		(void) dt_scope_pop();

	dt_scope_destroy(&pcb->pcb_dstack);
	dt_irlist_destroy(&pcb->pcb_ir);

	dt_node_link_free(&pcb->pcb_list);
	dt_node_link_free(&pcb->pcb_hold);

	if (err != 0) {
		dt_xlator_t *dxp, *nxp;
		dt_provider_t *pvp, *nvp;

		if (pcb->pcb_prog != NULL)
			dt_program_destroy(dtp, pcb->pcb_prog);
		if (pcb->pcb_stmt != NULL)
			dtrace_stmt_destroy(dtp, pcb->pcb_stmt);
		if (pcb->pcb_ecbdesc != NULL)
			dt_ecbdesc_release(dtp, pcb->pcb_ecbdesc);

		for (dxp = dt_list_next(&dtp->dt_xlators); dxp; dxp = nxp) {
			nxp = dt_list_next(dxp);
			if (dxp->dx_gen == dtp->dt_gen)
				dt_xlator_destroy(dtp, dxp);
		}

		for (pvp = dt_list_next(&dtp->dt_provlist); pvp; pvp = nvp) {
			nvp = dt_list_next(pvp);
			if (pvp->pv_gen == dtp->dt_gen)
				dt_provider_destroy(dtp, pvp);
		}

		(void) dt_idhash_iter(dtp->dt_aggs, dt_pcb_pop_ident, dtp);
		dt_idhash_update(dtp->dt_aggs);

		(void) dt_idhash_iter(dtp->dt_globals, dt_pcb_pop_ident, dtp);
		dt_idhash_update(dtp->dt_globals);

		(void) dt_idhash_iter(dtp->dt_tls, dt_pcb_pop_ident, dtp);
		dt_idhash_update(dtp->dt_tls);

		(void) ctf_discard(dtp->dt_cdefs->dm_ctfp);
		(void) ctf_discard(dtp->dt_ddefs->dm_ctfp);
	}

	if (pcb->pcb_pragmas != NULL)
		dt_idhash_destroy(pcb->pcb_pragmas);
	if (pcb->pcb_locals != NULL)
		dt_idhash_destroy(pcb->pcb_locals);
	if (pcb->pcb_idents != NULL)
		dt_idhash_destroy(pcb->pcb_idents);
	if (pcb->pcb_inttab != NULL)
		dt_inttab_destroy(pcb->pcb_inttab);
	if (pcb->pcb_strtab != NULL)
		dt_strtab_destroy(pcb->pcb_strtab);
	if (pcb->pcb_symtab != NULL)
		dt_strtab_destroy(pcb->pcb_symtab);
	if (pcb->pcb_regs != NULL)
		dt_regset_destroy(pcb->pcb_regs);

	for (i = 0; i < pcb->pcb_asxreflen; i++)
		dt_free(dtp, pcb->pcb_asxrefs[i]);

	dt_free(dtp, pcb->pcb_asxrefs);
	dt_difo_free(dtp, pcb->pcb_difo);

	free(pcb->pcb_filetag);
	free(pcb->pcb_sflagv);

	dtp->dt_pcb = pcb->pcb_prev;
	bzero(pcb, sizeof (dt_pcb_t));
	yyinit(dtp->dt_pcb);
}

static int
dt_pcb_dump_ident(dt_idhash_t *idh, dt_ident_t *idp, void *data)
{
	int fd = *((int *)data);
	char *indent = data + sizeof(int);

	assert(idp != NULL);

        dprintf(fd, "%s\tVAR:\n", indent);
	dprintf(fd, "%s\t\tdi_name = %s\n", indent, idp->di_name);
	dprintf(fd, "%s\t\tdi_kind = %u\n", indent, idp->di_kind);
	dprintf(fd, "%s\t\tdi_flags = %u\n", indent, idp->di_flags);
	dprintf(fd, "%s\t\tdi_id = %u\n", indent, idp->di_id);
	dprintf(fd, "%s\t\tdi_type = %ld\n", indent, idp->di_type);

	return (0);
}

static void
dt_pcb_dump_idhash(int fd, dt_idhash_t *idh, const char *indent)
{

	char *data = malloc(sizeof(int) + strlen(indent));

	*((int *)data) = fd;
	(void) strlcat(data + sizeof(int), indent, strlen(indent));
	(void) dt_idhash_iter(idh, dt_pcb_dump_ident, data);
	free(data);
}

static void
dt_pcb_dump_idstack(int fd, dt_idstack_t *ids, const char *indent)
{
	dt_idhash_t *dhp;

	for (dhp = dt_list_prev(&ids->dids_list);
	    dhp != NULL; dhp = dt_list_prev(dhp))
		dt_pcb_dump_idhash(fd, dhp, indent);
}

static void
dt_pcb_dump_inttab(int fd, dt_inttab_t *inttab, const char *indent)
{
	dt_inthash_t *ih;

	for (ih = inttab->int_head; ih != NULL; ih = ih->inh_next) {
		dprintf(fd, "%s\t[%u] = %lu (%s)\n", indent,
			ih->inh_index, ih->inh_value,
			ih->inh_flags ? "private" : "shared");
	}
}

static ssize_t
dt_pcb_dump_str_entry(const char *s, size_t n, size_t off, void *data)
{

	int fd = *((int *)data);
	char *indent = data + sizeof(int);
	dprintf(fd, "%s\t[%zu] = %s\n", indent, off, s);
	return (1);
}

static void
dt_pcb_dump_strtab(int fd, dt_strtab_t *strtab, const char *indent)
{

	char *data = malloc(sizeof(int) + strlen(indent));
	*((int *)data) = fd;
	(void) strlcpy(data + sizeof(int), indent, strlen(indent));

	(void) dt_strtab_write(strtab,
	    (dt_strtab_write_f *)dt_pcb_dump_str_entry, data);

	free(data);
}

#define OP2(opcode, instr, opstr)                        \
	case opcode: {		                         \
		int r1, r2, rd;                          \
		r1 = DIF_INSTR_R1(instr);                \
		r2 = DIF_INSTR_R2(instr);                \
		rd = DIF_INSTR_RD(instr);                \
		dprintf(fd, "%s %%r%d, %%r%d, %%r%d\n",  \
			opstr, r1, r2, rd);	         \
		break;                                   \
	}

#define OP1(opcode, instr, opstr)			\
	case opcode: {					\
		int r1, rd;				\
		r1 = DIF_INSTR_R1(instr);		\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s %%r%d, %%r%d\n",	\
			opstr, r1, rd);    		\
		break;					\
	}

#define OP0(opcode, instr, opstr)			\
	case opcode: {					\
		int rd;					\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s %%r%d\n", opstr, rd);   \
		break;					\
	}

#define BR(opcode, instr, opstr)			\
	case opcode: {					\
		int label;				\
		label = DIF_INSTR_LABEL(instr);		\
		dprintf(fd, "%s %d",               	\
			opstr, label);    		\
		break;					\
	}

#define LIT(opcode, opstr)			\
	case opcode: {				\
		dprintf(fd, "%s", opstr);	\
		break;				\
	}

#define LDSR(opcode, instr, opstr)			\
	case opcode: {					\
		int r1, rd;				\
		r1 = DIF_INSTR_R1(instr);		\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s [%%r%d], %%r%d\n",	\
			opstr, r1, rd);			\
		break;					\
	}

#define LDSVAR(opcode, instr, opstr)			\
	case opcode: {					\
		int var, rd;				\
		var = DIF_INSTR_VAR(instr);		\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s %d, %%r%d\n",		\
			opstr, var, rd);		\
		break;					\
	}

#define SET(opcode, instr, opstr)			\
	case opcode: {					\
		int idx, rd;				\
		idx = DIF_INSTR_INTEGER(instr);		\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s %d, %%r%d\n",		\
			opstr, idx, rd);    		\
		break;					\
	}

#define CALL(instr) LDSVAR(DIF_OP_CALL, instr, "call")

#define LDSARR(opcode, instr, opstr)			\
	case opcode: {					\
		int var, ri, rd;			\
		var = DIF_INSTR_VAR(instr);		\
		ri = DIF_INSTR_R1(instr);		\
		rd = DIF_INSTR_RD(instr);		\
		dprintf(fd, "%s %d, %%r%d, %%r%d\n",	\
			opstr, var, ri, rd);		\
		break;					\
	}

#define XL(opcode, instr, opstr) SET(opcode, instr, opstr)

#define PUSH(opcode, instr, opstr)			\
	case opcode: {					\
		int ty, rs, rp;				\
		ty = DIF_INSTR_TYPE(instr);		\
		rs = DIF_INSTR_RS(instr);		\
		rp = DIF_INSTR_R2(instr);		\
		dprintf(fd, "%s %d, %%r%d, %%r%d\n",	\
			opstr, ty, rs, rp);		\
		break;					\
	}

static void
dt_pcb_dump_instr(int fd, dif_instr_t instr)
{
	uint8_t opcode;

	opcode = DIF_INSTR_OP(instr);
	switch (opcode) {
		OP2(DIF_OP_OR, instr, "or"); OP2(DIF_OP_XOR, instr, "xor");
		OP2(DIF_OP_AND, instr, "and"); OP2(DIF_OP_SLL, instr, "sll");
		OP2(DIF_OP_SRL, instr, "srl"); OP2(DIF_OP_SUB, instr, "sub");
		OP2(DIF_OP_ADD, instr, "add"); OP2(DIF_OP_MUL, instr, "mul");
		OP2(DIF_OP_SDIV, instr, "sdiv"); OP2(DIF_OP_UDIV, instr, "udiv");
		OP2(DIF_OP_SREM, instr, "srem"); OP2(DIF_OP_UREM, instr, "urem");
		OP1(DIF_OP_NOT, instr, "not"); OP1(DIF_OP_MOV, instr, "mov");
		OP1(DIF_OP_CMP, instr, "cmp"); OP0(DIF_OP_TST, instr, "tst");
		BR(DIF_OP_BA, instr, "ba"); BR(DIF_OP_BE, instr, "be");
		BR(DIF_OP_BNE, instr, "bne"); BR(DIF_OP_BG, instr, "bg");
		BR(DIF_OP_BGU, instr, "bgu"); BR(DIF_OP_BGE, instr, "bge");
		BR(DIF_OP_BGEU, instr, "bgeu"); BR(DIF_OP_BL, instr, "bl");
		BR(DIF_OP_BLU, instr, "blu"); BR(DIF_OP_BLE, instr, "ble");
		BR(DIF_OP_BLEU, instr, "bleu"); LDSR(DIF_OP_LDSB, instr, "ldsb");
		LDSR(DIF_OP_LDSH, instr, "lsdh"); LDSR(DIF_OP_LDSW, instr, "ldsw");
		LDSR(DIF_OP_LDUB, instr, "ldub"); LDSR(DIF_OP_LDUH, instr, "lduh");
		LDSR(DIF_OP_LDUW, instr, "lduw"); LDSR(DIF_OP_LDX, instr, "ldx");
		OP0(DIF_OP_RET, instr, "ret"); LIT(DIF_OP_NOP, "nop"); SET(DIF_OP_SETX, instr, "setx");
		SET(DIF_OP_SETS, instr, "sets"); OP1(DIF_OP_SCMP, instr, "scmp");
		LDSR(DIF_OP_ULDSB, instr, "uldsb"); LDSR(DIF_OP_ULDSH, instr, "uldsh");
		LDSR(DIF_OP_ULDSW, instr, "uldsw"); LDSR(DIF_OP_ULDUB, instr, "uldub");
		LDSR(DIF_OP_ULDUH, instr, "ulduh"); LDSR(DIF_OP_ULDUW, instr, "ulduw");
		LDSR(DIF_OP_ULDX, instr, "uldx"); LDSR(DIF_OP_RLDSB, instr, "rldsb");
		LDSR(DIF_OP_RLDSH, instr, "rldsh"); LDSR(DIF_OP_RLDSW, instr, "rldsw");
		LDSR(DIF_OP_RLDUB, instr, "rldub"); LDSR(DIF_OP_RLDUH, instr, "rlduh");
		LDSR(DIF_OP_RLDUW, instr, "rlduw"); LDSR(DIF_OP_RLDX, instr, "rldx");
		LDSR(DIF_OP_STB, instr, "stb"); LDSR(DIF_OP_STH, instr, "sth");
		LDSR(DIF_OP_STW, instr, "stw"); LDSR(DIF_OP_STX, instr, "stx");
		OP2(DIF_OP_COPYS, instr, "copys"); OP1(DIF_OP_ALLOCS, instr, "allocs");
		LDSVAR(DIF_OP_STLS, instr, "stls"); LDSVAR(DIF_OP_LDLS, instr, "ldls");
		LDSVAR(DIF_OP_STTAA, instr, "sttaa"); LDSVAR(DIF_OP_STGAA, instr, "stgaa");
		LDSVAR(DIF_OP_LDTAA, instr, "ldtaa"); LDSVAR(DIF_OP_LDGAA, instr, "ldgaa");
		LIT(DIF_OP_FLUSHTS, "flushts"); LIT(DIF_OP_POPTS, "popts");
		CALL(instr); OP2(DIF_OP_SRA, instr, "sra");
		LDSVAR(DIF_OP_LDGS, instr, "ldgs"); LDSVAR(DIF_OP_STGS, instr, "stgs");
		LDSVAR(DIF_OP_LDTS, instr, "ldts"); LDSVAR(DIF_OP_STTS, instr, "stts");
		PUSH(DIF_OP_PUSHTR, instr, "pushtr"); PUSH(DIF_OP_PUSHTV, instr, "pushtv");
		LDSARR(DIF_OP_LDGA, instr, "ldga"); LDSARR(DIF_OP_LDTA, instr, "ldta");
		XL(DIF_OP_XLATE, instr, "xlate"); XL(DIF_OP_XLARG, instr, "xlarg");
		LIT(DIF_OP_HYPERCALL, "hypercall"); OP1(DIF_OP_SCMP_HH, instr, "scmp_hh");
		OP1(DIF_OP_SCMP_HG, instr, "scmp_hg"); OP1(DIF_OP_SCMP_GH, instr, "scmp_gh");
		OP1(DIF_OP_SCMP_GG, instr, "scmp_gg"); PUSH(DIF_OP_PUSHTR_G, instr, "pushtr_g");
		PUSH(DIF_OP_PUSHTR_H, instr, "pushtr_h"); SET(DIF_OP_USETX, instr, "usetx");
		LDSR(DIF_OP_ULOAD, instr, "uload"); LDSR(DIF_OP_UULOAD, instr, "uuload");
	default:
		dprintf(fd, "unknown opcode\n");
	}
}

static void
dt_pcb_dump_irlist(int fd, dt_irlist_t *irlist, const char *indent)
{
	dt_irnode_t *in;

	for (in = irlist->dl_list; in != NULL; in = in->di_next) {
		dprintf(fd, "%s\t%u: ", indent, in->di_label);
		dt_pcb_dump_instr(fd, in->di_instr);
	}
}

static void
dt_pcb_dump_attribute(int fd, dtrace_attribute_t *attr, const char *indent)
{

	dprintf(fd, "%s\tdtat_name = %u\n", indent, attr->dtat_name);
	dprintf(fd, "%s\tdtat_data = %u\n", indent, attr->dtat_data);
	dprintf(fd, "%s\tdtat_name = %u\n", indent, attr->dtat_class);
}

static void
dt_pcb_dump_typeinfo(int fd, dtrace_typeinfo_t *ti, const char *indent)
{

	dprintf(fd, "%s\tdtt_object = %s\n", indent, ti->dtt_object);
	dprintf(fd, "%s\tdtt_ctfp = %p\n", indent, ti->dtt_ctfp);
	dprintf(fd, "%s\tdtt_type = %ld\n", indent, ti->dtt_type);
	dprintf(fd, "%s\tdtt_flags = %u\n", indent, ti->dtt_flags);
}

static void
dt_pcb_dump_probeinfo(int fd, dtrace_probeinfo_t *pinfo, const char *indent)
{
	int i;
 	char *new_indent = malloc(strlen(indent) + 4);

	(void) strcpy(new_indent, indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 2);

	dprintf(fd, "%s\tdtp_attr:\n", indent);
	dt_pcb_dump_attribute(fd, &pinfo->dtp_attr, new_indent);

	dprintf(fd, "%s\tdtp_arga:\n", indent);
	dt_pcb_dump_attribute(fd, &pinfo->dtp_arga, new_indent);

	(void) strlcat(new_indent, "\t", strlen(indent) + 4);
	dprintf(fd, "%s\tdtp_argv:\n", indent);
	for (i = 0; i < pinfo->dtp_argc; i++) {
		dprintf(fd, "%s\t\tdtp_argv[%d]:\n", indent, i);
		dt_pcb_dump_typeinfo(fd,
		    (dtrace_typeinfo_t *)&pinfo->dtp_argv[i], new_indent);
	}

	free(new_indent);
}

static void
dt_pcb_dump_difo(int fd, dtrace_difo_t *difo, const char *indent)
{
	uint_t i;
	char *c;
	dtrace_difv_t *v;
	dtrace_diftype_t *t;
	dof_relodesc_t *r;

	if (difo == NULL) {
		dprintf(fd, "%s\t\tEMPTY\n", indent);
		return;
	}

	dprintf(fd, "%s\tdtdo_buf:\n", indent);
	for (i = 0; i < difo->dtdo_len; i++) {
		dprintf(fd, "%s\t\t", indent);
		dt_pcb_dump_instr(fd, difo->dtdo_buf[i]);
	}

	dprintf(fd, "%s\tdtdo_inttab:\n", indent);
	for (i = 0; i < difo->dtdo_intlen; i++)
		dprintf(fd, "%s\t\t[%i] = %lu\n", indent, i, difo->dtdo_inttab);

	dprintf(fd, "%s\tdtdo_strtab:\n%s\t\t", indent, indent);
	i = 0;
	for (c = difo->dtdo_strtab; i != difo->dtdo_strlen; c++) {
		if (c == 0 && i != difo->dtdo_strlen - 1) {
			dprintf(fd, "\n");
			i++;
			continue;
		} else
			dprintf(fd, "%c", *c);
		i++;
	}

	dprintf(fd, "\n%s\tdtdo_vartab:\n", indent);
	for (i = 0; i < difo->dtdo_varlen; i++) {
		v = &difo->dtdo_vartab[i];

		dprintf(fd, "%s\t\t[%d]:\n", indent, i);
		dprintf(fd, "%s\t\t\tdtdv_name = %u (%s)\n", indent,
		    v->dtdv_name, difo->dtdo_strtab + v->dtdv_name);
		dprintf(fd, "%s\t\t\tdtdv_id = %u\n", indent, v->dtdv_id);
		dprintf(fd, "%s\t\t\tdtdv_kind = %u\n", indent, v->dtdv_kind);
		dprintf(fd, "%s\t\t\tdtdv_scope = %u\n", indent, v->dtdv_scope);
		dprintf(fd, "%s\t\t\tdtdv_flags = %u\n", indent, v->dtdv_flags);

		t = &v->dtdv_type;
		dprintf(fd, "%s\t\t\tdtdv_type:\n", indent);
		dprintf(fd, "%s\t\t\t\tdtdt_kind = %u\n", indent, t->dtdt_kind);
		dprintf(fd, "%s\t\t\t\tdtdt_ckind = %u\n", indent, t->dtdt_ckind);
		dprintf(fd, "%s\t\t\t\tdtdt_flags = %u\n", indent, t->dtdt_flags);
		dprintf(fd, "%s\t\t\t\tdtdt_size = %u\n", indent, t->dtdt_size);
	}

	dprintf(fd, "%s\tdtdo_len = %u\n", indent, difo->dtdo_len);
	dprintf(fd, "%s\tdtdo_intlen = %u\n", indent, difo->dtdo_intlen);
	dprintf(fd, "%s\tdtdo_strlen = %u\n", indent, difo->dtdo_strlen);
	dprintf(fd, "%s\tdtdo_varlen = %u\n", indent, difo->dtdo_varlen);

	t = &difo->dtdo_rtype;
	dprintf(fd, "%s\tdtdo_rtype:\n", indent);
	dprintf(fd, "%s\t\tdtdt_kind = %u\n", indent, t->dtdt_kind);
	dprintf(fd, "%s\t\tdtdt_ckind = %u\n", indent, t->dtdt_ckind);
	dprintf(fd, "%s\t\tdtdt_flags = %u\n", indent, t->dtdt_flags);
	dprintf(fd, "%s\t\tdtdt_size = %u\n", indent, t->dtdt_size);

	dprintf(fd, "%s\tdtdo_refcnt = %u\n", indent, difo->dtdo_refcnt);
	dprintf(fd, "%s\tdtdo_destructive = %u\n", indent, difo->dtdo_destructive);

	dprintf(fd, "%s\tdtdo_kreltab:\n", indent);
	for (i = 0; i < difo->dtdo_krelen; i++) {
		r = &difo->dtdo_kreltab[i];
		dprintf(fd, "%s\t\tdofr_name = %u\n", indent, r->dofr_name);
		dprintf(fd, "%s\t\tdofr_type = %u\n", indent, r->dofr_type);
		dprintf(fd, "%s\t\tdofr_offset = %lu\n", indent, r->dofr_offset);
		dprintf(fd, "%s\t\tdofr_data = %lu\n", indent, r->dofr_data);
	}

	dprintf(fd, "%s\tdtdo_ureltab:\n", indent);
	for (i = 0; i < difo->dtdo_urelen; i++) {
		r = &difo->dtdo_ureltab[i];
		dprintf(fd, "%s\t\tdofr_name = %u\n", indent, r->dofr_name);
		dprintf(fd, "%s\t\tdofr_type = %u\n", indent, r->dofr_type);
		dprintf(fd, "%s\t\tdofr_offset = %lu\n", indent, r->dofr_offset);
		dprintf(fd, "%s\t\tdofr_data = %lu\n", indent, r->dofr_data);
	}

	dprintf(fd, "%s\tdtdo_krelen = %u\n", indent, difo->dtdo_krelen);
	dprintf(fd, "%s\tdtdo_urelen = %u\n", indent, difo->dtdo_urelen);

	/*
	 * TODO: Xlators.
	 */
}

static void
dt_pcb_dump_actdesc(int fd, dtrace_actdesc_t *ad, const char *indent)
{
	char *new_indent = malloc(strlen(indent) + 4);

	(void) strcpy(new_indent, indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 2);

	dprintf(fd, "%s\tdtad_difo:\n", indent);
	dt_pcb_dump_difo(fd, ad->dtad_difo, new_indent);

	dprintf(fd, "%s\tdtad_next = %p\n", indent, ad->dtad_next);
	dprintf(fd, "%s\tdtad_kind = %u\n", indent, ad->dtad_kind);
	dprintf(fd, "%s\tdtad_ntuple = %u\n", indent, ad->dtad_ntuple);
	dprintf(fd, "%s\tdtad_arg = %lu\n", indent, ad->dtad_arg);
	dprintf(fd, "%s\tdtad_uarg = %lu\n", indent, ad->dtad_uarg);
	dprintf(fd, "%s\tdtad_refcnt = %d\n", indent, ad->dtad_refcnt);

	free(new_indent);
}

static void
dt_pcb_dump_preddesc(int fd, dtrace_preddesc_t *pd, const char *indent)
{
	char *new_indent = malloc(strlen(indent) + 4);

	(void) strcpy(new_indent, indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 2);

	dprintf(fd, "%s\tdtpdd_difo:\n", indent);
	dt_pcb_dump_difo(fd, pd->dtpdd_difo, new_indent);

	dprintf(fd, "%s\tdtpdd_predicate = %p\n", indent, pd->dtpdd_predicate);

	free(new_indent);
}


static void
dt_pcb_dump_ecbdesc(int fd, dtrace_ecbdesc_t *ed, const char *indent)
{
	dtrace_actdesc_t *ad;
	char *new_indent = malloc(strlen(indent) + 4);

	(void) strcpy(new_indent, indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 2);

	dprintf(fd, "%s\tdted_action list:\n", indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 4);
	for (ad = ed->dted_action;
	     ad != NULL; ad = ad->dtad_next) {
		dprintf(fd, "%s\t\t[%p]:\n", indent, ad);
		dt_pcb_dump_actdesc(fd, ad, new_indent);
	}

	new_indent[strlen(new_indent) - 1] = '\0';

	dprintf(fd, "%s\tdted_pred:\n", indent);
	dt_pcb_dump_preddesc(fd, &ed->dted_pred, new_indent);

	dprintf(fd, "%s\tdted_probe = %s:%s:%s:%s:%s(%d)\n",
		indent,
		ed->dted_probe.dtpd_target,
	        ed->dted_probe.dtpd_provider,
		ed->dted_probe.dtpd_mod,
	        ed->dted_probe.dtpd_func,
	        ed->dted_probe.dtpd_name,
		ed->dted_probe.dtpd_id);

	dprintf(fd, "%s\tdted_uarg = %lu\n", indent, ed->dted_uarg);
	dprintf(fd, "%s\tdted_refcnt = %d\n", indent, ed->dted_refcnt);

	free(new_indent);
}

static void
dt_pcb_dump_stmt(int fd, dtrace_stmtdesc_t *stmt, const char *indent)
{
	dtrace_actdesc_t *ad;
	char *new_indent = malloc(strlen(indent) + 4);

	(void) strcpy(new_indent, indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 2);

	dprintf(fd, "%s\tdtsd_ecbdesc:\n", indent);
	dt_pcb_dump_ecbdesc(fd, stmt->dtsd_ecbdesc, new_indent);

	dprintf(fd, "%s\tdtsd_action list:\n", indent);
	(void) strlcat(new_indent, "\t", strlen(indent) + 4);
	for (ad = stmt->dtsd_action;
	    ad != stmt->dtsd_action_last->dtad_next; ad = ad->dtad_next) {
		dprintf(fd, "%s\t\t[%p]:\n", indent, ad);
		dt_pcb_dump_actdesc(fd, ad, new_indent);
	}

	new_indent[strlen(new_indent) - 1] = '\0';

	dprintf(fd, "%s\tdtsd_aggdata = %p\n", indent, stmt->dtsd_aggdata);
	dprintf(fd, "%s\tdtsd_fmtdata = %p\n", indent, stmt->dtsd_fmtdata);
	dprintf(fd, "%s\tdtsd_strdata = %p\n", indent, stmt->dtsd_strdata);
	dprintf(fd, "%s\tdtsd_data = %p\n", indent, stmt->dtsd_data);

	dprintf(fd, "%s\tdtsd_descattr:\n", indent);
	dt_pcb_dump_attribute(fd, &stmt->dtsd_descattr, new_indent);

	dprintf(fd, "%s\tdtsd_stmtattr:\n", indent);
	dt_pcb_dump_attribute(fd, &stmt->dtsd_descattr, new_indent);

	free(new_indent);
}

void
dt_pcb_dump(dt_pcb_t *pcb, int fd)
{
	int i;
	dt_idhash_t *dhp;
	dt_ident_t *idp;

	dprintf(fd, "pcb = %p\n", pcb);
	if (pcb == NULL)
	        return;

	dprintf(fd, "\tpcb_hdl = %p:\n", pcb->pcb_hdl);
	dprintf(fd, "\tpcb_sargc = %d\n", pcb->pcb_sargc);

	dprintf(fd, "\tpcb_sargv:\n");
	for (i = 0; i < pcb->pcb_sargc; i++) {
		assert(pcb->pcb_sargv[i] != NULL);
		dprintf(fd, "\t\t%s\n", pcb->pcb_sargv[i]);
	}

	dprintf(fd, "\tpcb_sflagv:\n");
	for (i = 0; i < pcb->pcb_sargc; i++)
		dprintf(fd, "\t\t%d\n", pcb->pcb_sflagv[i]);

	dprintf(fd, "\tpcb_dstack.ds_ident = %s\n", pcb->pcb_dstack.ds_ident);

	/*
	dprintf(fd, "\tpcb_globals:\n");
	dt_pcb_dump_idstack(fd, &pcb->pcb_globals, "\t");
	*/

	dprintf(fd, "\tpcb_locals:\n");
	if (pcb->pcb_locals == NULL)
		dprintf(fd, "\t\empty\n");
	else
		dt_pcb_dump_idhash(fd, pcb->pcb_locals, "\t");

	dprintf(fd, "\tpcb_idents:\n");
	if (pcb->pcb_idents == NULL)
		dprintf(fd, "\t\tEMPTY\n");
	else
		dt_pcb_dump_idhash(fd, pcb->pcb_idents, "\t");

	dprintf(fd, "\tpcb_pragmas:\n");
	if (pcb->pcb_pragmas == NULL)
		dprintf(fd, "\t\tEMPTY\n");
	else
		dt_pcb_dump_idhash(fd, pcb->pcb_pragmas, "\t");

	dprintf(fd, "\tpcb_inttab:\n");
	if (pcb->pcb_inttab)
		dt_pcb_dump_inttab(fd, pcb->pcb_inttab, "\t");
	else
		dprintf(fd, "\t\tEMPTY\n");

	dprintf(fd, "\tpcb_strtab:\n");
	if (pcb->pcb_strtab)
		dt_pcb_dump_strtab(fd, pcb->pcb_strtab, "\t");
	else
		dprintf(fd, "\t\tEMPTY\n");

	dprintf(fd, "\tpcb_ir:\n");
	dt_pcb_dump_irlist(fd, &pcb->pcb_ir, "\t");

	dprintf(fd, "\tpcb_asvidx = %d\n", pcb->pcb_asvidx);
	if (pcb->pcb_pdesc)
		dprintf(fd, "\tpcb_pdesc = %s:%s:%s:%s:%s(%d)\n",
			pcb->pcb_pdesc->dtpd_target,
			pcb->pcb_pdesc->dtpd_provider,
			pcb->pcb_pdesc->dtpd_mod,
			pcb->pcb_pdesc->dtpd_func,
			pcb->pcb_pdesc->dtpd_name,
			pcb->pcb_pdesc->dtpd_id);
	else
		dprintf(fd, "\tpcb_pdesc = EMPTY\n");

	dprintf(fd, "\tpcb_probe = %p\n", pcb->pcb_probe);

	dprintf(fd, "\tpcb_pinfo:\n");
	dt_pcb_dump_probeinfo(fd, &pcb->pcb_pinfo, "\t");

	dprintf(fd, "\tpcb_amin:\n");
	dt_pcb_dump_attribute(fd, &pcb->pcb_amin, "\t");

	dprintf(fd, "\tpcb_stmt:\n");
	if (pcb->pcb_stmt)
		dt_pcb_dump_stmt(fd, pcb->pcb_stmt, "\t");
	else
		dprintf(fd, "\t\tEMPTY\n");

	dprintf(fd, "\tpcb_ecbdesc:\n");
	if (pcb->pcb_ecbdesc)
		dt_pcb_dump_ecbdesc(fd, pcb->pcb_ecbdesc, "\t");
	else
		dprintf(fd, "\t\tEMPTY\n");

	dprintf(fd, "\tpcb_cflags = %u\n", pcb->pcb_cflags);
	dprintf(fd, "\tpcb_idepth = %u\n", pcb->pcb_idepth);
	dprintf(fd, "\tpcb_context = %u\n", pcb->pcb_context);
	dprintf(fd, "\tpcb_token = %u\n", pcb->pcb_token);
	dprintf(fd, "\tpcb_cstate = %u\n", pcb->pcb_cstate);
	dprintf(fd, "\tpcb_braces = %u\n", pcb->pcb_braces);
	dprintf(fd, "\tpcb_brackets = %u\n", pcb->pcb_brackets);
	dprintf(fd, "\tpcb_parens = %u\n", pcb->pcb_parens);
}
