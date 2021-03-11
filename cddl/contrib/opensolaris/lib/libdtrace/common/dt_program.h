/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DT_PROGRAM_H
#define	_DT_PROGRAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <dtrace.h>
#include <dt_list.h>

#define	DT_PROG_ERRLEN		4096
#define	DT_PROG_IDENTLEN	1024

#define	DT_PROG_NOEXEC		0
#define	DT_PROG_EXEC		1

#define	PGP_KIND_ID		0
#define	PGP_KIND_HYPERCALLS	1

typedef struct dt_stmt {
	dt_list_t ds_list;	/* list forward/back pointers */
	dtrace_stmtdesc_t *ds_desc; /* pointer to statement description */
} dt_stmt_t;

struct dtrace_prog {
	dt_list_t dp_list;		/* list forward/back pointers */
	dt_list_t dp_stmts;		/* linked list of dt_stmt_t's */
	ulong_t **dp_xrefs;		/* array of translator reference bitmaps */
	uint_t dp_xrefslen;		/* length of dp_xrefs array */
	uint8_t dp_dofversion;		/* DOF version this program requires */
	uint32_t dp_rflags;		/* resolver flags */
	int dp_haserror;		/* does this program have an error? */
	char dp_err[DT_PROG_ERRLEN];	/* error string */
	char dp_ident[1024];		/* 1024-byte identifier of this prog */
	int dp_exec;			/* should we exec this program? */
	int dp_relocated;		/* has the program been relocated? */
	uint32_t dp_neprobes;		/* number of enabled probes */
	dtrace_probedesc_t *dp_eprobes;	/* enabled probe array */
};

extern dtrace_prog_t *dt_program_create(dtrace_hdl_t *);
extern void dt_program_destroy(dtrace_hdl_t *, dtrace_prog_t *);

extern dtrace_ecbdesc_t *dt_ecbdesc_create(dtrace_hdl_t *,
    const dtrace_probedesc_t *);
extern void dt_ecbdesc_release(dtrace_hdl_t *, dtrace_ecbdesc_t *);
extern int dt_prog_verify(dtrace_hdl_t *, dtrace_prog_t *,
    dtrace_prog_t *, uint16_t);
extern void dt_prog_generate_ident(dtrace_prog_t *);
extern dtrace_prog_t *dt_vprog_from(dtrace_prog_t *, int);
#ifdef	__cplusplus
}
#endif

#endif	/* _DT_PROGRAM_H */
