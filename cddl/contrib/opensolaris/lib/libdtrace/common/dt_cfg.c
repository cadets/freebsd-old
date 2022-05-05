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

#include <dt_cfg.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_basic_block.h>
#include <dt_ifgnode.h>
#include <dt_linker_subr.h>
#include <dt_impl.h>
#include <dt_list.h>
#include <dt_program.h>
#include <dt_list.h>

#include <assert.h>
#include <err.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

void
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

	for (bb_e1 = dt_list_next(&bb_list); bb_e1;
	    bb_e1 = dt_list_next(bb_e1)) {
		bb1 = bb_e1->dtbe_bb;
		if (bb1 == NULL)
			errx(EXIT_FAILURE, "bb1 should not be NULL");

		if (bb1->dtbb_difo != difo)
			continue;

		instr = bb1->dtbb_buf[bb1->dtbb_end];
		opcode = DIF_INSTR_OP(instr);

		if (opcode >= DIF_OP_BA && opcode <= DIF_OP_BLEU)
			lbl = DIF_INSTR_LABEL(instr);
		else
			lbl = -1;

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
				if (bb_new1 == NULL)
					errx(EXIT_FAILURE,
					    "failed to malloc bb_new1");

				memcpy(bb_new1, bb_e2, sizeof(dt_bb_entry_t));

				bb_new2 = malloc(sizeof(dt_bb_entry_t));
				if (bb_new2 == NULL)
					errx(EXIT_FAILURE,
					    "failed to malloc bb_new2");

				memcpy(bb_new2, bb_e1, sizeof(dt_bb_entry_t));

				dt_list_append(&bb1->dtbb_children, bb_new1);
				dt_list_append(&bb2->dtbb_parents, bb_new2);
			}

			if (opcode != DIF_OP_BA &&
			    bb1->dtbb_end + 1 == bb2->dtbb_start) {
				bb_new1 = malloc(sizeof(dt_bb_entry_t));
				if (bb_new1 == NULL)
					errx(EXIT_FAILURE,
					    "failed to malloc bb_new1");

				memcpy(bb_new1, bb_e2, sizeof(dt_bb_entry_t));

				bb_new2 = malloc(sizeof(dt_bb_entry_t));
				if (bb_new2 == NULL)
					errx(EXIT_FAILURE,
					    "failed to malloc bb_new2");

				memcpy(bb_new2, bb_e1, sizeof(dt_bb_entry_t));

				dt_list_append(&bb1->dtbb_children, bb_new1);
				dt_list_append(&bb2->dtbb_parents, bb_new2);
			}
		}
	}
}
