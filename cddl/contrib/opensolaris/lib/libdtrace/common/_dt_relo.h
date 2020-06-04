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

#ifndef __DT_RELO_H_
#define __DT_RELO_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_list.h>

typedef struct dt_rkind {
	int			r_kind;
#define DT_RKIND_REG	1
#define DT_RKIND_VAR	2
#define DT_RKIND_STACK	3
	union {
		uint8_t		rd;
		struct {
			uint16_t	var;
			uint8_t		scope;
			uint8_t		varkind;
		} v;
	} u;
#define r_rd		u.rd
#define r_var		u.v.var
#define r_scope		u.v.scope
#define r_varkind	u.v.varkind
} dt_rkind_t;

typedef struct dt_relo {
	size_t dr_uidx;			/* Index of the use site */
	dt_list_t dr_r1defs;
	dt_list_t dr_r2defs;
	dt_list_t dr_r1datadefs;
	dt_list_t dr_r2datadefs;
	dt_list_t dr_vardefs;
	int dr_type;			/* D type */
	ctf_id_t dr_ctfid;		/* CTF type */
	char *dr_sym;			/* symbol offset in symtab */
	dtrace_difo_t *dr_difo;		/* DIFO for this relocation */
#define dr_buf dr_difo->dtdo_buf
	ctf_membinfo_t *dr_mip;		/* CTF member info (type, offs) */
	dt_list_t dr_stacklist;		/* List of push instructions
					 * if the instruction uses the stack */
	struct dt_rkind dr_rkind;	/* rkind of the relocation */
	dt_list_t dr_usetxs;
	int dr_relocated;
} dt_relo_t;

typedef struct dt_rl_entry {
	dt_list_t drl_list;
	dt_relo_t *drl_rel;
} dt_rl_entry_t;

typedef struct dt_stacklist {
	dt_list_t dsl_list;
	int dsl_kind;
#define DT_SL_SPLIT	1
#define DT_SL_REL	2
	dt_list_t dsl_stack;
	dt_list_t dsl_identifier;
} dt_stacklist_t;

typedef struct dt_stack {
	dt_list_t ds_list;
	dt_relo_t *ds_rel;
} dt_stack_t;

#endif /* __DT_RELO_H_ */
