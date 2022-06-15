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

#ifndef __DT_RELO_H_
#define __DT_RELO_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_list.h>
#include <_dt_typefile.h>
#include <_dt_basic_block.h>

typedef struct dt_node_kind {
	int                             dtnk_kind; /* kind (see below) */
#define DT_NKIND_REG	1                          /* register */
#define DT_NKIND_VAR	2                          /* variable */
#define DT_NKIND_STACK	3                          /* stack */
	union {
		uint8_t                 rd;        /* DT_RKIND_REG */
		struct {                           /* DT_RKIND_VAR */
			uint16_t        var;
			uint8_t         scope;
			uint8_t         varkind;
		} v;
	} u;
#define dtnk_rd		u.rd
#define dtnk_var	u.v.var
#define dtnk_scope	u.v.scope
#define dtnk_varkind	u.v.varkind
} dt_node_kind_t;

typedef struct dt_ifg_node {
	size_t             din_uidx;       /* index of the use site */
	dt_list_t          din_r1defs;     /* type flow list for r1 */
	dt_list_t          din_r2defs;     /* type flow list for r2 */
	dt_list_t          din_r1datadefs; /* data flow list for r1 */
	dt_list_t          din_r2datadefs; /* data flow list for r2 */
	dt_list_t          din_vardefs;    /* list of variable defns in DIFO */
	dt_list_t          din_r1children; /* which r1s do we define */
	dt_list_t          din_r2children; /* which r2s do we define */
	dt_list_t          din_varsources; /* variable origin (if exists) */
	int                din_type;       /* D type */
	struct dt_typefile *din_tf;        /* type file */
	dtrace_ecbdesc_t   *din_edp;       /* node's ecbdesc */
	ctf_id_t           din_ctfid;      /* CTF type */
	char               *din_sym;       /* symbol (if applicable) */
	dtrace_prog_t      *din_pgp;       /* program this node belongs to */
	dtrace_difo_t      *din_difo;      /* DIFO which this node belongs to */
#define din_buf            din_difo->dtdo_buf
	dt_basic_block_t   *din_bb;        /* basic block that the node is in */
	ctf_membinfo_t     *din_mip;       /* CTF member info (type, offs) */
	dt_list_t          din_stacklist;  /* list of pushtr/pushtv nodes */
	dt_node_kind_t     din_kind;       /* node kind (reg, var, stack) */
	dt_list_t          din_usetxs;     /* usetx insn list defining the node */
	int                din_relocated;  /* relocated or not? */
	int                din_isnull;     /* can this node contain NULL? */
	uint64_t           din_int;        /* integer value from setx */
	int                din_hasint;     /* is there an int? */
} dt_ifg_node_t;

typedef struct dt_ifg_list {
	dt_list_t       dil_list;
	dt_ifg_node_t   *dil_ifgnode;
} dt_ifg_list_t;

typedef struct dt_stacklist {
	dt_list_t       dsl_list;       /* next/prev for dt_stacklist_t */
	dt_list_t       dsl_stack;      /* the stack itself */
	dt_list_t       dsl_identifier; /* identifies this list
	                                   (basic block id list) */
} dt_stacklist_t;

typedef struct dt_stack {
	dt_list_t       ds_list;
	dt_ifg_node_t   *ds_ifgnode;
} dt_stack_t;

#endif /* __DT_RELO_H_ */
