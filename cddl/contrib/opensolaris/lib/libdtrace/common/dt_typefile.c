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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/linker.h>

#include <sys/ctf.h>

#include <sys/dtrace.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <err.h>
#include <errno.h>

#include <dtrace.h>
#include <dt_module.h>
#include <dt_typefile.h>

dt_list_t typefiles;

void
dt_typefile_openall(dtrace_hdl_t *dtp)
{
	dt_module_t *mod;
	dt_typefile_t *typef;
	int again;
	int kld;
	struct kld_file_stat kldinfo;

	do {
		again = 0;
		dtrace_update(dtp);
		for (kld = kldnext(0); kld > 0; kld = kldnext(kld)) {
			kldinfo.version = sizeof(kldinfo);
			if (kldstat(kld, &kldinfo) < 0)
				errx(EXIT_FAILURE,
				    "kldstat() failed with: %s\n",
				    strerror(errno));

			mod = dt_module_lookup_by_name(dtp, kldinfo.name);
			if (mod == NULL) {
				again = 1;
				break;
			}

			typef = malloc(sizeof(dt_typefile_t));
			if (typef == NULL)
				errx(EXIT_FAILURE, "malloc() failed with: %s\n",
				    strerror(errno));

			typef->modhdl = mod;
			typef->dtp = dtp;
			memcpy(typef->modname, kldinfo.name, MAXPATHLEN);
			dt_list_append(&typefiles, typef);
		}

		/*
		 * This is a bit bad, but it will do for now.
		 */
		if (again) {
			while ((typef = dt_list_next(&typefiles)) != NULL) {
				dt_list_delete(&typefiles, typef);
				free(typef);
			}
		}
	} while (again);
}

ctf_id_t
dt_typefile_ctfid(dt_typefile_t *typef, const char *type)
{
	ctf_file_t *ctfp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_lookup_by_name(ctfp, type));
}

char *
dt_typefile_typename(dt_typefile_t *typef,
    ctf_id_t id, char *buf, size_t buflen)
{
	ctf_file_t *ctfp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (NULL);
	return (ctf_type_name(ctfp, id, buf, buflen));
}

ctf_id_t
dt_typefile_reference(dt_typefile_t *typef, ctf_id_t id)
{
	ctf_file_t *ctfp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_type_reference(ctfp, id));
}

uint32_t
dt_typefile_typesize(dt_typefile_t *typef, ctf_id_t id)
{
	ctf_file_t *ctfp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_type_size(ctfp, id));
}

const char *
dt_typefile_error(dt_typefile_t *typef)
{
	ctf_file_t *ctfp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return ("CTF file is NULL");
	return (ctf_errmsg(ctf_errno(ctfp)));
}

ctf_file_t *
dt_typefile_membinfo(dt_typefile_t *typef, ctf_id_t type,
    const char *s, ctf_membinfo_t *mp)
{
	dt_module_t *mod;
	ctf_file_t *fp;

	assert(typef->dtp != NULL);
	assert(typef->modhdl != NULL);

	mod = typef->modhdl;
	fp = dt_module_getctf(typef->dtp, mod);

	while (ctf_type_kind(fp, type) == CTF_K_FORWARD) {
		char n[DT_TYPE_NAMELEN];
		dtrace_typeinfo_t dtt;

		if (ctf_type_name(fp, type, n, sizeof (n)) == NULL ||
		    dt_type_lookup(n, &dtt) == -1 || (
		    dtt.dtt_ctfp == fp && dtt.dtt_type == type))
			break; /* unable to improve our position */

		fp = dtt.dtt_ctfp;
		type = ctf_type_resolve(fp, dtt.dtt_type);
	}

	if (ctf_member_info(fp, type, s, mp) == CTF_ERR)
		return (NULL); /* ctf_errno is set for us */

	return (fp);
}

ctf_id_t
dt_typefile_typekind(dt_typefile_t *typef, ctf_id_t type)
{
	ctf_file_t *ctfp;

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);

	return (ctf_type_kind(ctfp, type));
}

dt_typefile_t *
dt_typefile_kernel(void)
{
	dt_typefile_t *typef;
	dt_module_t *mod;

	for (typef = dt_list_next(&typefiles); typef;
	     typef = dt_list_next(typef))
		if (strcmp(typef->modname, "kernel") == 0) {
			mod = dt_module_lookup_by_name(typef->dtp, "kernel");
			assert(mod == typef->modhdl);
			return (typef);
		}

	return (NULL);
}

ctf_id_t
dt_typefile_resolve(dt_typefile_t *typef, ctf_id_t type)
{
	ctf_file_t *ctfp;

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);

	return (ctf_type_resolve(ctfp, type));
}

int
dt_typefile_encoding(dt_typefile_t *typef, ctf_id_t type, ctf_encoding_t *ep)
{
	ctf_file_t *ctfp;

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (-1);

	return (ctf_type_encoding(ctfp, type, ep));
}

const char *
dt_typefile_stringof(dt_typefile_t *typef)
{

	return ((const char *)typef->modname);
}

dt_typefile_t *
dt_typefile_mod(const char *mod)
{
	dt_typefile_t *typef;
	dt_module_t *_mod;

	for (typef = dt_list_next(&typefiles); typef;
	     typef = dt_list_next(typef))
		if (strcmp(typef->modname, mod) == 0) {
			_mod = dt_module_lookup_by_name(typef->dtp, mod);
			assert(_mod == typef->modhdl);
			return (typef);
		}

	return (NULL);
}
