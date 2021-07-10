/*-
 * Copyright (c) 2021 Domagoj Stolfa
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

#ifndef _DT_TYPING_VAR_H_
#define _DT_TYPING_VAR_H_

#include <sys/types.h>
#include <sys/dtrace.h>

#include <_dt_ifgnode.h>
#include <dtrace.h>

typedef struct argcheck_cookie {
	dt_ifg_node_t *node;
	uint16_t varcode;
} argcheck_cookie_t;

extern void dt_builtin_type(dt_ifg_node_t *n, uint16_t var);
extern int dt_infer_type_arg(dtrace_hdl_t *, const dtrace_probedesc_t *,
    void *);
extern int dt_infer_type_var(dtrace_difo_t *, dt_ifg_node_t *, dtrace_difv_t *);
extern dt_ifg_node_t *dt_typecheck_vardefs(dtrace_difo_t *, dt_list_t *, int *);

#endif /* _DT_TYPING_VAR_H_ */
