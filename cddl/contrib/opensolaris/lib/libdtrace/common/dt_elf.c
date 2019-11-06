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

#include <dt_elf.h>
#include <dt_program.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/stat.h>

#include <libelf.h>
#include <gelf.h>

#include <err.h>
#include <errno.h>

static size_t
dt_elf_add_difo(dtrace_difo_t *difo, void *data, size_t offs)
{

	return (offs);
}

static size_t
dt_elf_add_action(dtrace_actdesc_t *ad, void *data, size_t offs)
{
        uint64_t *_data = data;
	offs = dt_elf_add_difo(ad->dtad_difo, data, offs);

	_data[offs++] = ad->dtad_kind;
	_data[offs++] = ad->dtad_ntuple;
	_data[offs++] = ad->dtad_arg;
	_data[offs++] = ad->dtad_uarg;
	_data[offs++] = ad->dtad_refcnt;

	return (offs);
}

static ssize_t
dt_elf_add_ecbdesc(dtrace_ecbdesc_t *ed, void *data, size_t offs)
{

	return (offs);
}

static size_t
dt_elf_add_attribute(dtrace_attribute_t *attr, void *data, size_t offs)
{

	return (offs);
}

static size_t
dt_elf_add_stmt(dtrace_stmtdesc_t *stmt, void *data, size_t offs)
{
	dtrace_actdesc_t *ad = NULL;

	offs = dt_elf_add_ecbdesc(stmt->dtsd_ecbdesc, data, offs);

	for (ad = stmt->dtsd_action;
	     ad != stmt->dtsd_action_last->dtad_next;
	     ad = ad->dtad_next)
		offs = dt_elf_add_action(ad, data, offs);

	offs = dt_elf_add_attribute(&stmt->dtsd_descattr, data, offs);
	offs = dt_elf_add_attribute(&stmt->dtsd_stmtattr, data, offs);

	return (offs);
}

void
dt_elf_create(dtrace_prog_t *pcb, int elfclass, int endian)
{
	int fd, err;
	Elf *e;
	GElf_Ehdr *ehdr;
	Elf_Scn *scn;
	Elf_Data *data;
	GElf_Shdr shdr;
	const char *file_name = "/var/ddtrace/tracing_spec.elf";

	err = mkdir("/var/ddtrace", 0755);
	if (err != 0 || err != EEXIST)
		errx(EXIT_FAILURE, "Failed to mkdir /var/ddtrace with permissions 0755");

	if (elf_version(EV_CURRENT) == EV_NONE)
		errx(EXIT_FAILURE, "ELF library initialization failed: %s",
		    elf_errmsg(-1));

	if ((fd = open(file_name, O_WRONLY | O_CREAT, 0777)) < 0)
		errx(EXIT_FAILURE, "Failed to open /var/ddtrace/%s", file_name);

	if ((e = elf_begin(fd, ELF_C_WRITE, NULL)) == NULL)
		errx(EXIT_FAILURE, "elf_begin() failed with %s", elf_errmsg(-1));

	if ((ehdr = gelf_newehdr(e, elfclass)) == NULL)
		errx(EXIT_FAILURE, "gelf_newehdr(%p, %d) failed with %s",
		    e, elfclass, elf_errmsg(-1));

	ehdr->e_ident[EI_DATA] = endian;
	ehdr->e_machine = EM_NONE;
	ehdr->e_type = ET_EXEC;

	if ((scn = elf_newscn(e)) == NULL)
		errx(EXIT_FAILURE, "elf_newscn(%p) failed with %s",
		    e, elf_errmsg(-1));

	if ((data = elf_newdata(scn)) == NULL)
		errx(EXIT_FAILURE, "elf_newdata(%p) failed with %s",
		    scn, elf_errmsg(-1));

	/*
	 * TODO(dstolfa): Populate each section data with a statement.
	 *                Make sure they are ordered in some way.
	 *
	 *
	 * ecbdesc contains the same action pointers as the statement actions.
	 * We should identify them with some monotonically increasing counter in
	 * ELF (same as statements) and ensure we don't duplicate the actions.
	 * Basically, serialise it in a way that refers to actions that are separately
	 * serialised in a different section, rather than duplicating it.
	 *
	 */

	if (gelf_getshdr(scn, &shdr) != &shdr)
		errx(EXIT_FAILURE, "elf_getshdr() failed with %s",
		    elf_errmsg(-1));

	shdr.sh_type = SHT_SUNW_dof;
	shdr.sh_name = 0; /* TODO(dstolfa): compute this */
	shdr.sh_flags = SHF_ALLOC;
	shdr.sh_entsize = sizeof(uint64_t); /* XXX: Is this correct? */

	elf_end(e);
	close(fd);
}
