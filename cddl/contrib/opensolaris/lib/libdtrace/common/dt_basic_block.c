/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2020, 2021 Domagoj Stolfa.
 * All rights reserved.
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

#include <dt_basic_block.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <assert.h>
#include <err.h>

dt_basic_block_t *
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

dt_bb_entry_t *
dt_alloc_bb_e(dtrace_difo_t *difo)
{
	dt_bb_entry_t *bb_e;

	bb_e = malloc(sizeof(dt_bb_entry_t));
	if (bb_e == NULL)
		errx(EXIT_FAILURE, "failed to allocate the BB list entry");

	memset(bb_e, 0, sizeof(dt_bb_entry_t));

	bb_e->dtbe_bb = dt_alloc_bb(difo);
	bb_e->dtbe_tovisit = 1;
	if (bb_e->dtbe_bb == NULL)
		errx(EXIT_FAILURE, "failed to allocate the basic block");

	return (bb_e);
}

void
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
	if (leaders == NULL)
		errx(EXIT_FAILURE, "failed to malloc leaders");

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
				    " of code length (%u)",
				    lbl, difo->dtdo_len);

			/*
			 * We have a valid label. Any DIFO which does not end
			 * with a ret instruction is not valid, so we check if
			 * position i + 1 is a valid instruction.
			 */
			if (i + 1 >= difo->dtdo_len)
				errx(EXIT_FAILURE, "malformed DIFO");

			/*
			 * For a direct branch, i + 1 is not a leader. We are
			 * skipping it all together.
			 */
			if (opcode != DIF_OP_BA)
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
