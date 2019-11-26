/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Domagoj Stolfa.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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

#include <dt_elf.h>
#include <dt_program.h>
#include <dt_impl.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/stat.h>

#include <libelf.h>
#include <gelf.h>

#include <err.h>
#include <errno.h>

#define DTELF_MAXOPTNAME	64

/*
 * Helper structs
 */
typedef struct dt_elf_eact_list {
	dt_list_t list;
	dtrace_actdesc_t *act;
	dt_elf_ref_t eact_ndx;
	dt_elf_actdesc_t *eact;
} dt_elf_eact_list_t;

typedef struct _dt_elf_eopt {
	char eo_name[DTELF_MAXOPTNAME];
	uint64_t eo_option;
	size_t eo_len;
	char eo_arg[];
} _dt_elf_eopt_t;

/*
 * dt_elf_state_t: A state struct used during ELF generation and is
 * context-dependent.
 *
 * s_first_act_scn: The first action of the current stmt.
 * s_last_act_scn:  The last action of the current stmt.
 * s_first_ecbdesc_scn: The first ecbdesc of the current stmt.
 * s_actions: List that contains all the actions inside the ELF file.
 */
typedef struct dt_elf_state {
	dt_elf_ref_t s_first_act_scn;
	dt_elf_ref_t s_last_act_scn;
	dt_elf_ref_t s_first_ecbdesc_scn;
	dt_list_t s_actions;
} dt_elf_state_t;

char sec_strtab[] =
	"\0.shstrtab\0.dtrace_prog\0.dtrace_difo\0.dtrace_actdesc\0"
	".dtrace_ecbdesc\0.difo_strtab\0.difo_inttab\0"
	".difo_symtab\0.dtrace_stmtdesc\0.dtrace_predicate\0"
	".dtrace_opts\0.dtrace_vartab";


#define	DTELF_SHSTRTAB		  1
#define	DTELF_PROG		 11
#define	DTELF_DIFO		 24
#define	DTELF_ACTDESC		 37
#define	DTELF_ECBDESC		 53
#define	DTELF_DIFOSTRTAB	 69
#define	DTELF_DIFOINTTAB	 82
#define	DTELF_DIFOSYMTAB	 95
#define	DTELF_STMTDESC		108
#define	DTELF_PREDICATE		125
#define	DTELF_OPTS		143
#define	DTELF_DIFOVARTAB	156

#define	DTELF_VARIABLE_SIZE	  0

static dt_elf_state_t dtelf_state = {0};

dt_elf_opt_t dtelf_ctopts[] = {
	{ "aggpercpu", 0, NULL, DTRACE_A_PERCPU },
	{ "amin", 0, NULL, 0 },
	{ "argref", 0, NULL, DTRACE_C_ARGREF },
	{ "core", 0, NULL, 0 },
	{ "cpp", 0, NULL, DTRACE_C_CPP },
	{ "cpphdrs", 0, NULL, 0 },
	{ "cpppath", 0, NULL, 0 },
	{ "ctypes", 0, NULL, 0 },
	{ "defaultargs", 0, NULL, DTRACE_C_DEFARG },
	{ "dtypes", 0, NULL, 0 },
	{ "debug", 0, NULL, 0 },
	{ "define", 0, NULL, (uintptr_t)"-D" },
	{ "droptags", 0, NULL, 0 },
	{ "empty", 0, NULL, DTRACE_C_EMPTY },
	{ "encoding", 0, NULL, 0 },
	{ "errtags", 0, NULL, DTRACE_C_ETAGS },
	{ "evaltime", 0, NULL, 0 },
	{ "incdir", 0, NULL, (uintptr_t)"-I" },
	{ "iregs", 0, NULL, 0 },
	{ "kdefs", 0, NULL, DTRACE_C_KNODEF },
	{ "knodefs", 0, NULL, DTRACE_C_KNODEF },
	{ "late", 0, NULL, 0 },
	{ "lazyload", 0, NULL, 0 },
	{ "ldpath", 0, NULL, 0 },
	{ "libdir", 0, NULL, 0 },
	{ "linkmode", 0, NULL, 0 },
	{ "linktype", 0, NULL, 0 },
	{ "nolibs", 0, NULL, DTRACE_C_NOLIBS },
#ifdef __FreeBSD__
	{ "objcopypath", 0, NULL, 0 },
#endif
	{ "pgmax", 0, NULL, 0 },
	{ "pspec", 0, NULL, DTRACE_C_PSPEC },
	{ "setenv", 0, NULL, 1 },
	{ "stdc", 0, NULL, 0 },
	{ "strip", 0, NULL, DTRACE_D_STRIP },
	{ "syslibdir", 0, NULL, 0 },
	{ "tree", 0, NULL, 0 },
	{ "tregs", 0, NULL, 0 },
	{ "udefs", 0, NULL, DTRACE_C_UNODEF },
	{ "undef", 0, NULL, (uintptr_t)"-U" },
	{ "unodefs", 0, NULL, DTRACE_C_UNODEF },
	{ "unsetenv", 0, NULL, 0 },
	{ "verbose", 0, NULL, DTRACE_C_DIFV },
	{ "version", 0, NULL, 0 },
	{ "zdefs", 0, NULL, DTRACE_C_ZDEFS },
	{ NULL, 0, NULL, 0 }
};

dt_elf_opt_t dtelf_rtopts[] = {
	{ "aggsize", 0, NULL, DTRACEOPT_AGGSIZE },
	{ "bufsize", 0, NULL, DTRACEOPT_BUFSIZE },
	{ "bufpolicy", 0, NULL, DTRACEOPT_BUFPOLICY },
	{ "bufresize", 0, NULL, DTRACEOPT_BUFRESIZE },
	{ "cleanrate", 0, NULL, DTRACEOPT_CLEANRATE },
	{ "cpu", 0, NULL, DTRACEOPT_CPU },
	{ "destructive", 0, NULL, DTRACEOPT_DESTRUCTIVE },
	{ "dynvarsize", 0, NULL, DTRACEOPT_DYNVARSIZE },
	{ "grabanon", 0, NULL, DTRACEOPT_GRABANON },
	{ "jstackframes", 0, NULL, DTRACEOPT_JSTACKFRAMES },
	{ "ddtracearg", 0, NULL, DTRACEOPT_DDTRACEARG},
	{ "jstackstrsize", 0, NULL, DTRACEOPT_JSTACKSTRSIZE },
	{ "nspec", 0, NULL, DTRACEOPT_NSPEC },
	{ "specsize", 0, NULL, DTRACEOPT_SPECSIZE },
	{ "stackframes", 0, NULL, DTRACEOPT_STACKFRAMES },
	{ "statusrate", 0, NULL, DTRACEOPT_STATUSRATE },
	{ "strsize", 0, NULL, DTRACEOPT_STRSIZE },
	{ "ustackframes", 0, NULL, DTRACEOPT_USTACKFRAMES },
	{ "temporal", 0, NULL, DTRACEOPT_TEMPORAL },
	{ NULL, 0, NULL, 0 }
};

dt_elf_opt_t dtelf_drtopts[] = {
	{ "agghist", 0, NULL, DTRACEOPT_AGGHIST },
	{ "aggpack", 0, NULL, DTRACEOPT_AGGPACK },
	{ "aggrate", 0, NULL, DTRACEOPT_AGGRATE },
	{ "aggsortkey", 0, NULL, DTRACEOPT_AGGSORTKEY },
	{ "aggsortkeypos", 0, NULL, DTRACEOPT_AGGSORTKEYPOS },
	{ "aggsortpos", 0, NULL, DTRACEOPT_AGGSORTPOS },
	{ "aggsortrev", 0, NULL, DTRACEOPT_AGGSORTREV },
	{ "aggzoom", 0, NULL, DTRACEOPT_AGGZOOM },
	{ "flowindent", 0, NULL, DTRACEOPT_FLOWINDENT },
	{ "oformat", 0, NULL, DTRACEOPT_OFORMAT },
	{ "quiet", 0, NULL, DTRACEOPT_QUIET },
	{ "rawbytes", 0, NULL, DTRACEOPT_RAWBYTES },
	{ "stackindent", 0, NULL, DTRACEOPT_STACKINDENT },
	{ "switchrate", 0, NULL, DTRACEOPT_SWITCHRATE },
	{ NULL, 0, NULL, 0 }
};


static Elf_Scn *
dt_elf_new_inttab(Elf *e, dtrace_difo_t *difo, size_t *nsecs)
{
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	uint64_t *inttab = difo->dtdo_inttab;

	if (inttab == NULL)
		return (scn);

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	data->d_align = 8;
	data->d_buf = inttab;
	data->d_size = sizeof(uint64_t) * difo->dtdo_intlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOINTTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(uint64_t);

	return (scn);
}

static Elf_Scn *
dt_elf_new_strtab(Elf *e, dtrace_difo_t *difo, size_t *nsecs)
{
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	char *strtab = difo->dtdo_strtab;

	if (strtab == NULL)
		return (scn);

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	data->d_align = 1;
	data->d_buf = strtab;
	data->d_size = difo->dtdo_strlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOSTRTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

static Elf_Scn *
dt_elf_new_symtab(Elf *e, dtrace_difo_t *difo, size_t *nsecs)
{
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	char *symtab = difo->dtdo_symtab;

	if (symtab == NULL)
		return (scn);

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	data->d_align = 1;
	data->d_buf = symtab;
	data->d_size = difo->dtdo_symlen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOSYMTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

static Elf_Scn *
dt_elf_new_vartab(Elf *e, dtrace_difo_t *difo, size_t *nsecs)
{
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	dtrace_difv_t *vartab = difo->dtdo_vartab;

	if (vartab == NULL)
		return (scn);

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	data->d_align = 4;
	data->d_buf = vartab;
	data->d_size = difo->dtdo_varlen * sizeof(dtrace_difv_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFOVARTAB;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

static Elf_Scn *
dt_elf_new_difo(Elf *e, dtrace_difo_t *difo, size_t *nsecs)
{
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	uint64_t i;
	dt_elf_difo_t *edifo;

	if (difo == NULL)
		return (NULL);

	edifo = malloc(sizeof(dt_elf_difo_t) +
		       (difo->dtdo_len * sizeof(dif_instr_t)));
	memset(edifo, 0, sizeof(dt_elf_difo_t) +
	    (difo->dtdo_len * sizeof(dif_instr_t)));


	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	edifo->dted_inttab = elf_ndxscn(dt_elf_new_inttab(e, difo, nsecs));
	(*nsecs)++;

	edifo->dted_strtab = elf_ndxscn(dt_elf_new_strtab(e, difo, nsecs));
	(*nsecs)++;

	edifo->dted_symtab = elf_ndxscn(dt_elf_new_symtab(e, difo, nsecs));
	(*nsecs)++;

	edifo->dted_vartab = elf_ndxscn(dt_elf_new_vartab(e, difo, nsecs));
	(*nsecs)++;

	edifo->dted_intlen = difo->dtdo_intlen;
	edifo->dted_strlen = difo->dtdo_strlen;
	edifo->dted_symlen = difo->dtdo_symlen;
	edifo->dted_varlen = difo->dtdo_varlen;
	edifo->dted_rtype = difo->dtdo_rtype;
	edifo->dted_destructive = difo->dtdo_destructive;

	edifo->dted_len = difo->dtdo_len;

	for (i = 0; i < difo->dtdo_len; i++)
		edifo->dted_buf[i] = difo->dtdo_buf[i];

	data->d_align = 8;
	data->d_buf = edifo;
	data->d_size = sizeof(dt_elf_difo_t) +
	    (difo->dtdo_len * sizeof(dif_instr_t));
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_DIFO;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

static Elf_Scn *
dt_elf_new_action(Elf *e, dtrace_actdesc_t *ad, size_t *nsecs)
{
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf_Data *data;
	dt_elf_actdesc_t *eact = malloc(sizeof(dt_elf_actdesc_t));
	dt_elf_eact_list_t *el = malloc(sizeof(dt_elf_eact_list_t));
	memset(eact, 0, sizeof(dt_elf_actdesc_t));
	memset(el, 0, sizeof(dt_elf_eact_list_t));

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	if (ad->dtad_difo != NULL) {
	        eact->dtea_difo = elf_ndxscn(dt_elf_new_difo(e, ad->dtad_difo, nsecs));
		(*nsecs)++;
		eact->dtea_difo = 0;
	} else
		eact->dtea_difo = 0;

	eact->dtea_next = 0; /* Filled in later */
	eact->dtea_kind = ad->dtad_kind;
	eact->dtea_ntuple = ad->dtad_ntuple;
	eact->dtea_arg = ad->dtad_arg;
	eact->dtea_uarg = ad->dtad_uarg;

	data->d_align = 8;
	data->d_buf = eact;
	data->d_size = sizeof(dt_elf_actdesc_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_ACTDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_actdesc_t);

	el->eact_ndx = elf_ndxscn(scn);
	el->act = ad;
	el->eact = eact;

	dt_list_append(&dtelf_state.s_actions, el);
	return (scn);
}

static void
dt_elf_create_actions(Elf *e, dtrace_stmtdesc_t *stmt, size_t *nsecs)
{
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf_Data *data = NULL;
	dt_elf_actdesc_t *ead_prev = NULL;
	dtrace_actdesc_t *ad;

	if (stmt->dtsd_action == NULL)
		return;

	assert(stmt->dtsd_action_last != NULL);

	for (ad = stmt->dtsd_action; ad != stmt->dtsd_action_last->dtad_next;
	    ad = ad->dtad_next) {
		scn = dt_elf_new_action(e, ad, nsecs);
		(*nsecs)++;

		if (ead_prev != NULL)
			ead_prev->dtea_next = elf_ndxscn(scn);

		if ((data = elf_getdata(scn, NULL)) == NULL)
		    errx(EXIT_FAILURE, "elf_getdata(%p, %p) failed with %s",
			scn, data, elf_errmsg(-1));
		ead_prev = data->d_buf;
		if (ead_prev == NULL)
			errx(EXIT_FAILURE, "ead_prev == NULL");

		if (ad == stmt->dtsd_action)
			dtelf_state.s_first_act_scn = elf_ndxscn(scn);
	}

	/*
	 * We know that this is the last section that we could have
	 * created, so we simply set the state variable to it.
	 */
	dtelf_state.s_last_act_scn = elf_ndxscn(scn);
}

static Elf_Scn *
dt_elf_new_ecbdesc(Elf *e, dtrace_stmtdesc_t *stmt, size_t *nsecs)
{
	Elf_Scn *scn;
	Elf32_Shdr *shdr;
	Elf_Data *data = NULL;
	dtrace_ecbdesc_t *ecb;
	dt_elf_ecbdesc_t *eecb;
	dt_elf_eact_list_t *el = NULL;

	if (stmt->dtsd_ecbdesc == NULL)
		return (NULL);

	eecb = malloc(sizeof(dt_elf_ecbdesc_t));
	memset(eecb, 0, sizeof(dt_elf_ecbdesc_t));

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	ecb = stmt->dtsd_ecbdesc;

	/*
	 * Find the corresponding action's section number.
	 */
	for (el = dt_list_next(&dtelf_state.s_actions); el != NULL;
	    el = dt_list_next(el))
		if (ecb->dted_action == el->act)
			break;

	/*
	 * If the data structure is laid out correctly, we are guaranteed
	 * that during the action creation phase, we will have created the
	 * action needed for this ecbdesc. If this is not the case, bail out
	 * hard.
	 */
	assert(el != NULL);

	eecb->dtee_action = el->eact_ndx;
	eecb->dtee_action = 0;

	/*
	 * While the DTrace struct has a number of things associated with it
	 * that are not the DIFO, this is only useful in the context of the
	 * kernel. We do not need this in userspace, and therefore simply treat
	 * dtee_pred as a DIFO.
	 */
	eecb->dtee_pred = elf_ndxscn(
	    dt_elf_new_difo(e, ecb->dted_pred.dtpdd_difo, nsecs));
	(*nsecs)++;

	eecb->dtee_probe.dtep_pdesc = ecb->dted_probe;
	eecb->dtee_uarg = ecb->dted_uarg;

	data->d_align = 8;
	data->d_buf = eecb;
	data->d_size = sizeof(dt_elf_ecbdesc_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_ECBDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

static Elf_Scn *
dt_elf_new_stmt(Elf *e, dtrace_stmtdesc_t *stmt, size_t *nsecs)
{
	Elf_Scn *scn;
	Elf_Data *data;
	Elf32_Shdr *shdr;
	dt_elf_stmt_t *estmt;

	if (stmt == NULL)
		return (NULL);

        estmt = malloc(sizeof(dt_elf_stmt_t));
	memset(estmt, 0, sizeof(dt_elf_stmt_t));


	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	dt_elf_create_actions(e, stmt, nsecs);

	estmt->dtes_ecbdesc = elf_ndxscn(dt_elf_new_ecbdesc(e, stmt, nsecs));
	(*nsecs)++;

	estmt->dtes_action = dtelf_state.s_first_act_scn;
	estmt->dtes_action_last = dtelf_state.s_last_act_scn;
	estmt->dtes_descattr.dtea_attr = stmt->dtsd_descattr;
	estmt->dtes_stmtattr.dtea_attr = stmt->dtsd_stmtattr;

	data->d_align = 4;
	data->d_buf = estmt;
	data->d_size = sizeof(dt_elf_stmt_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_STMTDESC;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	(*nsecs)++;

	return (scn);
}

static void
dt_elf_cleanup(void)
{
	dt_elf_eact_list_t *el;
	dt_elf_eact_list_t *p_el;

	for (el = dt_list_next(&dtelf_state.s_actions);
	    el != NULL; el = dt_list_next(el)) {
		if (p_el)
			free(p_el);

		p_el = el;
	}

	/*
	 * The last iteration will free everything for this member,
	 * except itself.
	 */
	free(p_el);
}

static Elf_Scn *
dt_elf_options(Elf *e, size_t *nsecs)
{
	Elf_Scn *scn = NULL;
	Elf32_Shdr *shdr;
	Elf_Data *data;

	size_t buflen = 0; /* Current buffer length */
	size_t len = 0; /* Length of the new entry */
	size_t bufmaxlen = 1; /* Maximum buffer length */
	unsigned char *buf = NULL, *obuf = NULL;

	dt_elf_opt_t *op;
	_dt_elf_eopt_t *eop;

	/*
	 * Go over the compile-time options and fill them in.
	 *
	 * XXX: This may not be necessary for ctopts.
	 */
	for (op = dtelf_ctopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		len = sizeof(_dt_elf_eopt_t) + strlen(op->dteo_arg);
		eop = malloc(len);
		(void) strcpy(eop->eo_name, op->dteo_name);
		eop->eo_len = strlen(op->dteo_arg);
		(void) strcpy(eop->eo_arg, op->dteo_arg);

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0)
			(void) strcpy(
			    (char *)eop->eo_option, (char *)op->dteo_option);
		else
			eop->eo_option = op->dteo_option;

		if (buflen + len >= bufmaxlen) {
			if ((bufmaxlen << 1) <= bufmaxlen)
				errx(EXIT_FAILURE,
				    "buf realloc failed, bufmaxlen exceeded");
			bufmaxlen <<= 1;
			obuf = buf;

			buf = malloc(bufmaxlen);
			if (buf == NULL)
				errx(EXIT_FAILURE,
				    "buf realloc failed, %s", strerror(errno));

			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	/*
	 * Go over runtime options. If they are set, we add them to our data
	 * buffer which will be in the section that contains all of the options.
	 */
	for (op = dtelf_rtopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		len = sizeof(_dt_elf_eopt_t) + strlen(op->dteo_arg);
		eop = malloc(len);
		(void) strcpy(eop->eo_name, op->dteo_name);
		eop->eo_len = strlen(op->dteo_arg);
		(void) strcpy(eop->eo_arg, op->dteo_arg);

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0)
			(void) strcpy(
			    (char *)eop->eo_option, (char *)op->dteo_option);
		else
			eop->eo_option = op->dteo_option;

		/*
		 * Have we run out of space in our buffer?
		 */
		if (buflen + len >= bufmaxlen) {
			/*
			 * Check for overflow. Not great, but will have to do.
			 */
			if ((bufmaxlen << 1) <= bufmaxlen)
				errx(EXIT_FAILURE,
				    "buf realloc failed, bufmaxlen exceeded");
			bufmaxlen <<= 1;
			obuf = buf;

			buf = malloc(bufmaxlen);
			if (buf == NULL)
				errx(EXIT_FAILURE,
				    "buf realloc failed, %s", strerror(errno));

			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	/*
	 * Go over dynamic runtime options. If they are set, we add them to our data
	 * buffer which will be in the section that contains all of the options.
	 */
	for (op = dtelf_drtopts; op->dteo_name != NULL; op++) {
		if (op->dteo_set == 0)
			continue;

		len = sizeof(_dt_elf_eopt_t) + strlen(op->dteo_arg);
		eop = malloc(len);
		(void) strcpy(eop->eo_name, op->dteo_name);
		eop->eo_len = strlen(op->dteo_arg);
		(void) strcpy(eop->eo_arg, op->dteo_arg);

		if (strcmp("define", op->dteo_name) == 0 ||
		    strcmp("incdir", op->dteo_name) == 0 ||
		    strcmp("undef",  op->dteo_name) == 0)
			(void) strcpy(
			    (char *)eop->eo_option, (char *)op->dteo_option);
		else
			eop->eo_option = op->dteo_option;

		/*
		 * Have we run out of space in our buffer?
		 */
		if (buflen + len >= bufmaxlen) {
			/*
			 * Check for overflow. Not great, but will have to do.
			 */
			if ((bufmaxlen << 1) <= bufmaxlen)
				errx(EXIT_FAILURE,
				    "buf realloc failed, bufmaxlen exceeded");
			bufmaxlen <<= 1;
			obuf = buf;

			buf = malloc(bufmaxlen);
			if (buf == NULL)
				errx(EXIT_FAILURE,
				    "buf realloc failed, %s", strerror(errno));

			if (obuf) {
				memcpy(buf, obuf, buflen);
				free(obuf);
			}
		}

		memcpy(buf + buflen, eop, len);
		buflen += len;
	}

	if (buflen == 0)
		return (NULL);

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		    e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		    scn, elf_errmsg(-1));

	data->d_align = 8;
	data->d_buf = buf;
	data->d_size = buflen;
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		    elf_errmsg(-1));

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_OPTS;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = 0;

	return (scn);
}

void
dt_elf_create(dtrace_prog_t *dt_prog, int endian)
{
	int fd, err;
	Elf *e;
	Elf32_Ehdr *ehdr;
	Elf_Scn *scn, *f_scn;
	Elf_Data *data;
	Elf32_Shdr *shdr, *s0hdr;
	Elf32_Phdr *phdr;
	const char *file_name = "/var/ddtrace/tracing_spec.elf";
	size_t nsecs = 1;
	dt_stmt_t *stp;

	dtrace_stmtdesc_t *stmt = NULL;

	dt_elf_prog_t prog = {0};

	memset(&dtelf_state, 0, sizeof(dt_elf_state_t));

	/*
	 * Create the directory that contains the ELF file (if needed).
	 */
	err = mkdir("/var/ddtrace", 0755);
	if (err != 0 && errno != EEXIST)
		errx(EXIT_FAILURE,
		    "Failed to mkdir /var/ddtrace with permissions 0755 with %s",
		    strerror(errno));

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "ELF library initialization failed: %s",
		    elf_errmsg(-1));

	if ((fd = open(file_name, O_WRONLY | O_CREAT, 0777)) < 0)
		errx(EXIT_FAILURE, "Failed to open /var/ddtrace/%s", file_name);

	if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed with %s", elf_errmsg(-1));

	if ((ehdr = elf32_newehdr(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newehdr(%p) failed with %s",
		    e, elf_errmsg(-1));

	ehdr->e_ident[EI_DATA] = endian;
	ehdr->e_machine = EM_NONE;
	ehdr->e_type = ET_EXEC;
	ehdr->e_ident[EI_CLASS] = ELFCLASS32;

	/*
	 * Enable extended section numbering.
	 */
	ehdr->e_shstrndx = SHN_XINDEX;
	ehdr->e_shnum = 0;

	if ((phdr = elf32_newphdr(e, 1)) == NULL)
		errx(EXIT_FAILURE, "elf_newphdr(%p, 1) failed with %s",
		    e, elf_errmsg(-1));

	/*
	 * The very first section is a string table of section names.
	 */

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		     e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		     scn, elf_errmsg(-1));

	data->d_align = 1;
	data->d_buf = sec_strtab;
	data->d_size = sizeof(sec_strtab);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	nsecs++;

	shdr->sh_type = SHT_STRTAB;
	shdr->sh_name = DTELF_SHSTRTAB;
	shdr->sh_flags = SHF_STRINGS;
	shdr->sh_entsize = DTELF_VARIABLE_SIZE;

	/*
	 * For extended numbering
	 */
	if ((s0hdr = elf32_getshdr(elf_getscn(e, 0))) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		     elf_errmsg(-1));

	s0hdr->sh_size = 0; /* Number of sections -- filled in later! */
	s0hdr->sh_link = elf_ndxscn(scn); /* .shstrtab index */

	/*
	 * Second section gives us the necessary information about a DTrace
	 * program. What DOF version we need, reference to the section that
	 * contains the first statement, etc.
	 */
	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		    e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		    scn, elf_errmsg(-1));

	data->d_align = 4;
	data->d_buf = &prog;
	data->d_size = sizeof(dt_elf_prog_t);
	data->d_type = ELF_T_BYTE;
	data->d_version = EV_CURRENT;

	if ((shdr = elf32_getshdr(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		    elf_errmsg(-1));

	nsecs++;

	shdr->sh_type = SHT_DTRACE_elf;
	shdr->sh_name = DTELF_PROG;
	shdr->sh_flags = SHF_OS_NONCONFORMING; /* DTrace-specific */
	shdr->sh_entsize = sizeof(dt_elf_prog_t);

	/*
	 * Get the first stmt.
	 */
	stp = dt_list_next(&dt_prog->dp_stmts);
	stmt = stp->ds_desc;

	/*
	 * Create a section with the first statement.
	 */
	f_scn = dt_elf_new_stmt(e, stmt, &nsecs);

	/*
	 * Here, we populate the DTrace program with a reference to the ELF
	 * section that contains the first statement and the DOF version
	 * required for this program.
	 */
	prog.dtep_first_stmt = elf_ndxscn(f_scn);
	prog.dtep_dofversion = dt_prog->dp_dofversion;

	/*
	 * Iterate over the other statements and create ELF sections with them.
	 */
	for (stp = dt_list_next(stp); stp != NULL; stp = dt_list_next(stp)) {
		scn = dt_elf_new_stmt(e, stp->ds_desc, &nsecs);
	}

	scn = dt_elf_options(e, &nsecs);
	nsecs++;

	s0hdr->sh_size = nsecs; /* Number of sections */

	if (elf_update(e, ELF_C_NULL) < 0)
		errx(EXIT_FAILURE, "elf_update(%p, ELF_C_NULL) failed with %s",
		    e, elf_errmsg(-1));

	phdr->p_type = PT_PHDR;
	phdr->p_offset = ehdr->e_phoff;
	phdr->p_filesz = gelf_fsize(e, ELF_T_PHDR, 1, EV_CURRENT);

	(void) elf_flagphdr(e, ELF_C_SET, ELF_F_DIRTY);

	if (elf_update(e, ELF_C_WRITE) < 0)
		errx(EXIT_FAILURE, "elf_update(%p, ELF_C_WRITE) failed with %s",
		    e, elf_errmsg(-1));

	/*
	 * TODO: Cleanup of section data (free the pointers).
	 */
	//	dt_elf_cleanup();
	(void) elf_end(e);
	(void) close(fd);
}

dtrace_prog_t *
dt_elf_to_prog(int fd)
{

	return (NULL);
}


void
dtrace_use_elf(dtrace_hdl_t *dtp)
{

	dtp->dt_use_elf = 1;
}
