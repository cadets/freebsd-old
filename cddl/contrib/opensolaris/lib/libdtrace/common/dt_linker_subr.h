/*-
 * Copyright (c) 2020 Domagoj Stolfa
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

#ifndef _DT_LINKER_SUBR_H_
#define _DT_LINKER_SUBR_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#include <_dt_ifgnode.h>
#include <_dt_basic_block.h>

#include <dt_list.h>

typedef struct dt_pathlist {
	dt_list_t dtpl_list;
	dt_basic_block_t *dtpl_bb;
} dt_pathlist_t;

typedef struct dt_var_entry {
	dt_list_t dtve_list;
	dtrace_difv_t *dtve_var;
} dt_var_entry_t;

extern dt_list_t node_list;
extern dt_list_t bb_list;
extern dt_ifg_list_t *node_last;
extern dt_list_t var_list;
extern dt_ifg_node_t *r0node;

extern int dt_subr_clobbers(uint16_t);
extern int dt_clobbers_reg(dif_instr_t, uint8_t);
extern int dt_var_is_builtin(uint16_t);
extern int dt_clobbers_var(dif_instr_t, dt_node_kind_t *);
extern dtrace_difv_t *dt_get_variable(dtrace_difo_t *, uint16_t, int, int);
extern dtrace_difv_t *dt_get_var_from_varlist(uint16_t, int, int);
extern void dt_get_varinfo(dif_instr_t, uint16_t *, int *, int *);
extern void dt_insert_var(dtrace_difv_t *);
extern int dt_var_uninitialized(dtrace_difv_t *);
extern void dt_populate_varlist(dtrace_hdl_t *, dtrace_difo_t *);
extern dt_stacklist_t *dt_get_stack(dt_basic_block_t **, ssize_t,
    dt_ifg_node_t *);

#endif /* _DT_LINKER_SUBR_H_ */
