#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <strings.h>

#include <dt_ctir.h>
#include <dt_program.h>

#include <dt_impl.h>

#define CT_PROC_DEFAULT_SIZE 128

/*
 * TODO: Implement the macros.
 */
#define CTIR_REG_FORMAT3(r1, r2, r3) ((r1) | (r2 << 8) | (r3 << 16))
#define CTIR_REG_FORMAT2(r1, imm) ((r1) | (imm << 8))
#define CTIR_R1(x) ((x) & 0xff)
#define CTIR_R2(x) (((x) >> 8) & 0xff)
#define CTIR_R3(x) (((x) >> 16) & 0xff)
#define CTIR_IMM(x) (((x) >> 8) & 0xffff)
#define CTIR_LABEL(x) ((x) & 0xffffff)

static uint64_t cur_proc_id = 1; /* Start from 1 */

ct_ctir_t *
ctir_alloc(void)
{

	ct_ctir_t *ctir;
	ctir = malloc(sizeof(ct_ctir_t));
	return (ctir);
}

static ct_proc_t *
ctir_acquire_proc(ct_proc_t *p, dtrace_probedesc_t *pd)
{
	char probename[DTRACE_FULLNAMELEN];
	char *cp;
	ct_proc_t *it;

	assert(pd != NULL);
	assert(p != NULL);

	/*
	 * Create a full probe name.
	 */
	cp = probename;
	cp = stpncpy(cp, pd->dtpd_provider,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_mod,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_func,
		     sizeof(probename) - (cp - probename) - 1);
	*cp++ = ':';
	cp = stpncpy(cp, pd->dtpd_name,
		     sizeof(probename) - (cp - probename) - 1);

	assert(*cp == 0);

	/*
	 * We go over all of the currently known processes and look for the
	 * one named by the probedesc.
	 */
	for (it = p; it; it = dt_list_next(it)) {
		assert(it->desc != NULL);
		if (strcmp(it->desc->name, probename) == 0)
			return (it);
	}

	/*
	 * If it is NULL, we simply didn't find that process yet. We then
	 * construct it and fill in the name of the process description.
	 * The instructions themselves and the type will be filled out at
	 * a later stage.
	 */
	it = malloc(sizeof(ct_proc_t));
	assert(it != NULL);

	it->desc = malloc(sizeof(ct_procdesc_t));
	assert(it->desc != NULL);

        strncpy(it->desc->name, probename, sizeof(probename));
	it->desc->name[DTRACE_FULLNAMELEN-1] = 0;

	/*
	 * Give it a numeric (unique) identifier for internal handling.
	 */
	assert(cur_proc_id + 1 > cur_proc_id); /* XXX: Bad */
	it->desc->id = cur_proc_id++;

	/*
	 * Append the process into the list, so we can find it in the next run.
	 */
	dt_list_append(&p->list, it);

	return (it);
}

static uint8_t
ctir_translate_op(dif_instr_t instr)
{
	dif_instr_t opcode = DIF_INSTR_OP(instr);

	switch (opcode) {
	case DIF_OP_OR:
		return (CT_OP_OR);

	case DIF_OP_XOR:
		return (CT_OP_XOR);

	case DIF_OP_AND:
		return (CT_OP_AND);

	case DIF_OP_SLL:
		return (CT_OP_SLL);

	case DIF_OP_SRL:
		return (CT_OP_SRL);

	case DIF_OP_SUB:
		return (CT_OP_SUB);

	case DIF_OP_ADD:
		return (CT_OP_ADD);

	case DIF_OP_MUL:
		return (CT_OP_MUL);

	case DIF_OP_SDIV:
		return (CT_OP_SDIV);

	case DIF_OP_UDIV:
		return (CT_OP_UDIV);

	case DIF_OP_SREM:
		return (CT_OP_SREM);

	case DIF_OP_UREM:
		return (CT_OP_UREM);

	case DIF_OP_NOT:
		return (CT_OP_NOT);

	case DIF_OP_MOV:
		return (CT_OP_MOV);

	case DIF_OP_CMP:
		return (CT_OP_CMP);

	case DIF_OP_TST:
		return (CT_OP_TST);

	case DIF_OP_BA:
		return (CT_OP_BA);

	case DIF_OP_BE:
		return (CT_OP_BE);

	case DIF_OP_BNE:
		return (CT_OP_BNE);

	case DIF_OP_BG:
		return (CT_OP_BG);

	case DIF_OP_BGU:
		return (CT_OP_BGU);

	case DIF_OP_BGE:
		return (CT_OP_BGE);

	case DIF_OP_BGEU:
		return (CT_OP_BGEU);

	case DIF_OP_BL:
		return (CT_OP_BL);

	case DIF_OP_BLU:
		return (CT_OP_BLU);

	case DIF_OP_BLE:
		return (CT_OP_BLE);

	case DIF_OP_BLEU:
		return (CT_OP_BLEU);

	case DIF_OP_RLDSB:
	case DIF_OP_ULDSB:
	case DIF_OP_LDSB:
		return (CT_OP_LS8);

	case DIF_OP_RLDSH:
	case DIF_OP_ULDSH:
	case DIF_OP_LDSH:
		return (CT_OP_LS16);

	case DIF_OP_RLDSW:
	case DIF_OP_ULDSW:
	case DIF_OP_LDSW:
		return (CT_OP_LS32);

	case DIF_OP_RLDUB:
	case DIF_OP_ULDUB:
	case DIF_OP_LDUB:
		return (CT_OP_LU8);

	case DIF_OP_RLDUH:
	case DIF_OP_ULDUH:
	case DIF_OP_LDUH:
		return (CT_OP_LU16);

	case DIF_OP_RLDUW:
	case DIF_OP_ULDUW:
	case DIF_OP_LDUW:
		return (CT_OP_LU32);

	case DIF_OP_RLDX:
	case DIF_OP_ULDX:
	case DIF_OP_LDX:
		return (CT_OP_L64);

	case DIF_OP_RET:
		return (CT_OP_EMIT);

	case DIF_OP_SETX:
		return (CT_OP_SETX);

	case DIF_OP_SETS:
		return (CT_OP_SETS);

	case DIF_OP_SCMP:
		return (CT_OP_SCMP);

	case DIF_OP_LDGA:
		return (CT_OP_GRECV);

	case DIF_OP_LDGS:
		return (CT_OP_GRECV);

	case DIF_OP_STGS:
		return (CT_OP_GSEND);

	case DIF_OP_LDTA:
		return (CT_OP_TRECV);

	case DIF_OP_LDTS:
		return (CT_OP_TRECV);

	case DIF_OP_STTS:
		return (CT_OP_TSEND);

	case DIF_OP_SRA:
		return (CT_OP_SRA);

	case DIF_OP_CALL:
		return (CT_OP_CALL);

	case DIF_OP_PUSHTR:
		return (CT_OP_PUSHTR);

	case DIF_OP_PUSHTV:
		return (CT_OP_PUSHTV);

	case DIF_OP_POPTS:
		return (CT_OP_POPTS);

	case DIF_OP_FLUSHTS:
		return (CT_OP_FLUSHTS);

	case DIF_OP_LDGAA:
		return (CT_OP_GRECV);

	case DIF_OP_LDTAA:
		return (CT_OP_TRECV);

	case DIF_OP_STGAA:
		return (CT_OP_GSEND);

	case DIF_OP_STTAA:
		return (CT_OP_TSEND);

	case DIF_OP_LDLS:
		return (0);

	case DIF_OP_STLS:
		return (0);

	case DIF_OP_ALLOCS:
		return (CT_OP_ALLOCS);

	case DIF_OP_COPYS:
		return (0);

	case DIF_OP_STB:
		return (CT_OP_ST8);

	case DIF_OP_STH:
		return (CT_OP_ST16);

	case DIF_OP_STW:
		return (CT_OP_ST32);

	case DIF_OP_STX:
		return (CT_OP_ST64);

	default:
		break;
	}

	return (0);
}

static uint8_t
ctir_determine_opkind(uint8_t op)
{
	switch (op) {
	case CT_OP_OR:
	case CT_OP_XOR:
	case CT_OP_AND:
	case CT_OP_SLL:
	case CT_OP_SRL:
	case CT_OP_SRA:
	case CT_OP_SUB:
	case CT_OP_ADD:
	case CT_OP_MUL:
	case CT_OP_SDIV:
	case CT_OP_UDIV:
	case CT_OP_SREM:
	case CT_OP_UREM:
	case CT_OP_PUSHTR:
		return (CT_INSDESC_RRR);

	case CT_OP_NOT:
	case CT_OP_MOV:
	case CT_OP_CMP:
	case CT_OP_LS8:
	case CT_OP_LS16:
	case CT_OP_LS32:
	case CT_OP_LU8:
	case CT_OP_LU16:
	case CT_OP_LU32:
	case CT_OP_L64:
	case CT_OP_ST8:
	case CT_OP_ST16:
	case CT_OP_ST32:
	case CT_OP_ST64:
	case CT_OP_ALLOCS:
		return (CT_INSDESC_RR);

	case CT_OP_TST:
	case CT_OP_EMIT:
	case CT_OP_PUSHTV:
		return (CT_INSDESC_R);

	case CT_OP_BA:
	case CT_OP_BE:
	case CT_OP_BNE:
	case CT_OP_BG:
	case CT_OP_BGU:
	case CT_OP_BGE:
	case CT_OP_BGEU:
	case CT_OP_BL:
	case CT_OP_BLU:
	case CT_OP_BLE:
	case CT_OP_BLEU:
		return (CT_INSDESC_B);

	case CT_OP_FLUSHTS:
	case CT_OP_POPTS:
		return (CT_INSDESC_STANDALONE);

	case CT_OP_SETX:
	case CT_OP_SETS:
	case CT_OP_CALL:
		return (CT_INSDESC_RI);

	case CT_OP_GRECV:
	case CT_OP_GSEND:
	case CT_OP_TRECV:
	case CT_OP_TSEND:
		return (CT_INSDESC_CHAN);
	}

	return (0);
}

static uint32_t
ctir_registers_from_dif(dif_instr_t instr)
{
	dif_instr_t opcode = DIF_INSTR_OP(instr);
	uint32_t regs = 0;

	switch (opcode) {
	case DIF_OP_OR:
	case DIF_OP_XOR:
	case DIF_OP_AND:
	case DIF_OP_SLL:
	case DIF_OP_SRL:
	case DIF_OP_SRA:
	case DIF_OP_SUB:
	case DIF_OP_ADD:
	case DIF_OP_MUL:
	case DIF_OP_SDIV:
	case DIF_OP_UDIV:
	case DIF_OP_SREM:
	case DIF_OP_COPYS:
	case DIF_OP_UREM: {
		uint8_t rs1 = DIF_INSTR_R1(instr);
		uint8_t rs2 = DIF_INSTR_R2(instr);
		uint8_t rd  = DIF_INSTR_RD(instr);
		regs = CTIR_REG_FORMAT3(rd, rs1, rs2);

		break;
	}
	case DIF_OP_NOT:
	case DIF_OP_MOV:
	case DIF_OP_LDSB:
	case DIF_OP_LDSH:
	case DIF_OP_LDSW:
	case DIF_OP_LDUB:
	case DIF_OP_LDUH:
	case DIF_OP_LDUW:
	case DIF_OP_LDX:
	case DIF_OP_STB:
	case DIF_OP_STH:
	case DIF_OP_STW:
	case DIF_OP_STX:
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
	case DIF_OP_ALLOCS:
	case DIF_OP_PUSHTR: {
		uint8_t rs = DIF_INSTR_R1(instr);
		uint8_t rd = DIF_INSTR_RD(instr);
		regs = CTIR_REG_FORMAT3(rd, rs, 0);

		break;
	}
	case DIF_OP_CMP:
	case DIF_OP_SCMP: {
		uint8_t rs1 = DIF_INSTR_R1(instr);
		uint8_t rs2 = DIF_INSTR_R2(instr);
		regs = CTIR_REG_FORMAT3(rs1, rs2, 0);

		break;
	}
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
		regs = DIF_INSTR_LABEL(instr);
		break;
	case DIF_OP_RET:
	case DIF_OP_PUSHTV: {
		uint8_t rd = DIF_INSTR_RD(instr);
		regs = CTIR_REG_FORMAT3(rd, 0, 0);

		break;
	}
	case DIF_OP_TST: {
		uint8_t rs = DIF_INSTR_R1(instr);
		regs = CTIR_REG_FORMAT3(rs, 0, 0);

		break;
	}
	case DIF_OP_LDGS:
	case DIF_OP_STGS:
	case DIF_OP_LDTS:
	case DIF_OP_STTS:
	case DIF_OP_LDGAA:
	case DIF_OP_LDTAA:
	case DIF_OP_STGAA:
	case DIF_OP_STTAA:
	case DIF_OP_LDLS:
	case DIF_OP_STLS:
	case DIF_OP_SETX:
	case DIF_OP_SETS:
	case DIF_OP_CALL: {
		uint8_t r1 = DIF_INSTR_RD(instr);
		uint16_t imm = DIF_INSTR_INTEGER(instr);
		regs = CTIR_REG_FORMAT2(r1, imm);
		break;
	}
	case DIF_OP_FLUSHTS:
	case DIF_OP_POPTS:
		regs = 0;
		break;
	default:
		assert(instr == 0); /* XXX: Bad */
	}

	return (regs);
}

static void
ctir_infer_ground_types(ct_ins_t *first_ins, ct_dynamic_chan_t *chan)
{
}

static char *
ctir_var_name(uint16_t var_id)
{
	return (NULL);
}

static uint8_t
ctir_chankind(uint16_t var_id)
{

	return (0);
}

/*
 * ctir_translate_difo translates a DIFO into a CTIR block. It works in a clean
 * register space. That is, it assumes that it can start using registers starting
 * with r0 up to whatever it needs. This must be fixed up in the caller.
 */
static ct_ins_t *
ctir_translate_difo(ct_ins_t *cti, dtrace_difo_t *dp)
{
	int i;
	ct_ins_t *first = cti; /* Save to return later */

	for (i = 0; i < dp->dtdo_len; i++) {
		dif_instr_t instr = dp->dtdo_buf[i];
		uint8_t op = 0;
		uint8_t kind = 0;
		ct_ins_t *current = NULL;
		ct_insdesc_t *desc;

		op = ctir_translate_op(instr);
		if (op == 0)
			continue;

		kind = ctir_determine_opkind(op);
		assert(kind != 0);

		current = malloc(sizeof(ct_ins_t));
		if (current == NULL)
			return (NULL);

		current->desc = malloc(sizeof(ct_ins_t));
		if (current->desc == NULL) {
			free(current);
			return (NULL);
		}

		desc = current->desc;
		desc->kind = kind;
		desc->instr = op;

		switch (kind) {
		case CT_INSDESC_RRR: {
			uint32_t regs = ctir_registers_from_dif(instr);

			desc->u.rrr.r1 = CTIR_R1(regs);
		        desc->u.rrr.r2 = CTIR_R2(regs);
			desc->u.rrr.r3 = CTIR_R3(regs);

			break;
		}
		case CT_INSDESC_RR: {
		        uint32_t regs = ctir_registers_from_dif(instr);

			desc->u.rr.r1 = CTIR_R1(regs);
			desc->u.rr.r2 = CTIR_R2(regs);

			break;
		}
		case CT_INSDESC_R: {
			uint32_t regs = ctir_registers_from_dif(instr);

			desc->u.r.r = CTIR_R1(regs);

			break;
		}
		case CT_INSDESC_RI: {
			uint32_t regs = ctir_registers_from_dif(instr);

			desc->u.ri.r = CTIR_R1(regs);
			desc->u.ri.imm = CTIR_IMM(regs);

			break;
		}
		case CT_INSDESC_B: {
			uint32_t regs = ctir_registers_from_dif(instr);

			desc->u.b.label = CTIR_LABEL(regs);

			break;
		}
		case CT_INSDESC_EUL: {
			/* TODO */
			break;
		}
		case CT_INSDESC_CHAN: {
			uint32_t regs = ctir_registers_from_dif(instr);
			uint16_t var_id = CTIR_IMM(regs);
			uint8_t ckind;
			void *chan = NULL;

			ckind = ctir_chankind(var_id);
			assert(ckind == CT_CHANKIND_S ||
			       ckind == CT_CHANKIND_D);

			if (ckind == CT_CHANKIND_S) {
				/* The channel is static. */
				ct_static_chan_t *schan;
				schan = malloc(sizeof(ct_static_chan_t));
				assert(schan != NULL);

				schan->name = ctir_var_name(var_id);
				schan->id = var_id;

				chan = schan;
			} else {
				/* The channel is dynamic. */
				ct_dynamic_chan_t *dchan;
				dchan = malloc(sizeof(ct_dynamic_chan_t));
				assert(dchan != NULL);

				/*
				 * We can easily give a human-facing name to the
				 * dynamic channel. It is simply the variable
				 * name.
				 */
				dchan->name = ctir_var_name(var_id);
				/*
				 * The ID is generated from the variable id and
				 * the boundary between static and dynamic
				 * channels.
				 */
				dchan->id = CT_CHAN_BOUNDARY + var_id;
				/*
				 * We now infer the ground types of each portion
				 * of the dynamic channel name.
				 */
				ctir_infer_ground_types(dt_list_next(first),
							dchan);

				chan = dchan;
			}

			assert(chan != NULL);

			desc->u.chanop.kind = ckind;
			desc->u.chanop.chan = chan;
			desc->u.chanop.rd = CTIR_R1(regs);
			break;
		}
		default:
			break;
		}
	}

	/*
	 * We return the first new instruction, as we will have to fix up the
	 * registers to be used correctly.
	 */
	return (dt_list_next(first));
}

static void
ctir_translate_action(ct_proc_t *p, dtrace_actdesc_t *ap)
{
	dtrace_actkind_t kind = ap->dtad_kind;
	dtrace_difo_t *dp = ap->dtad_difo;
	uint64_t nframes = 0;
	ct_ins_t *cti;

	/*
	 * Go through all of the instructions until we find a free spot.
	 *
	 * N.B.: This is kind of inefficient if you think of compilation going
	 *       probe-by-probe. However, we might want to incrementally compile
	 *       probes in some cases by combining a sequence of two probes into
	 *       a single one and add internal control flow, rather than rely
	 *       on probes 'firing' as an abstraction.
	 *
	 * FIXME: If we want to remember what is currently running in the probe,
	 *        and then be able to update the current code, we shouldn't
	 *        iterate all the way to the end, but find the patch points.
	 */
	for (cti = dt_list_next(&p->desc->insns); cti; cti = dt_list_next(cti))
		;

	switch (kind) {
       	/*
       	 * No-op action, ignore it.
	 */
	case DTRACEACT_NONE:
		break;

       	/*
       	 * DIF Expression, essentially a DIFO. Straight-forward
	 * instruction -> instruction translation.
       	 */
	case DTRACEACT_DIFEXPR:
		assert(dp != NULL);
		ctir_translate_difo(cti, dp);
		break;

	case DTRACEAGG_COUNT:
		break;

	case DTRACEAGG_MIN:
		break;

	case DTRACEAGG_MAX:
		break;

	case DTRACEAGG_AVG:
		break;

	case DTRACEAGG_SUM:
		break;

	case DTRACEAGG_STDDEV:
		break;

	case DTRACEAGG_QUANTIZE:
		break;

	case DTRACEAGG_LQUANTIZE:
		break;

	case DTRACEAGG_LLQUANTIZE:
		break;

	default:
		break;
	}
}

ct_ctir_t *
ctir_from_daf(dtrace_prog_t *pgp)
{
	ct_ctir_t *ctir;
	ct_proc_t *p;

	/*
	 * Here we just allocate a CTIR description to be used later.
	 */
	ctir = ctir_alloc();

	p = &ctir->proc;

	/*
	 * Go over _all_ of the DTrace programs that are present.
	 */
	for (; pgp; pgp = dt_list_next(pgp)) {
		dtrace_stmtdesc_t *stmt;
		dtrace_ecbdesc_t *edp, *last;
		dtrace_probedesc_t *pd;

		/*
		 * Iterate over the statements.
		 */
		for (stmt = dt_list_next(&pgp->dp_stmts);
		     stmt; stmt = dt_list_next(stmt)) {
			dtrace_actdesc_t *ap;

			edp = stmt->dtsd_ecbdesc;

			/*
			 * We don't care about it having many ECBs, just the
			 * statement itself.
			 */
			if (edp == last)
				continue;
			last = edp;
			pd = &edp->dted_probe;

			/*
			 * At this point, we have grabbed the probe description
			 * of the statement which will identify the process for
			 * us. This will let us populate the process with
			 * instructions that it will execute. We will use this
			 * to infer a number of types and statically check some
			 * properties. ctir_acquire_proc will always return a
			 * process or hard-fail. It either creates a new one, or
			 * finds the correct one.
			 */
			p = ctir_acquire_proc(&ctir->proc, pd);

			/*
			 * We now have the correct (or new) process, and we will
			 * populate it with all of the necessary instructions.
			 */
			for (ap = edp->dted_action; ap; ap = ap->dtad_next)
				ctir_translate_action(p, ap);
		}
	}

	return (ctir);
}
