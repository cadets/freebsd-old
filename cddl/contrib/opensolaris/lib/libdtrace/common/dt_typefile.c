/*-
 * Copyright (c) 2021 Domagoj Stolfa
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
#include <execinfo.h>

#include <dtrace.h>
#include <dt_module.h>
#include <dt_typefile.h>

dt_list_t typefiles;

typedef struct dtf_ctfid {
	dt_list_t list;
	ctf_id_t type;
} dtf_ctfid_t;

typedef struct dt_typefile_struct {
	dt_typefile_t *typefile;
	dt_list_t ctf_types;
	dtf_ctfid_t *current;
} dt_typefile_struct_t;

void
dt_typefile_openall(dtrace_hdl_t *dtp)
{
	dt_module_t *mod;
	dt_typefile_t *typef;
	int again;
	int kld;
	struct kld_file_stat kldinfo;

	for (kld = kldnext(0); kld > 0; kld = kldnext(kld)) {
		kldinfo.version = sizeof(kldinfo);
		if (kldstat(kld, &kldinfo) < 0)
			errx(EXIT_FAILURE, "kldstat() failed with: %s\n",
			    strerror(errno));

		mod = dt_module_lookup_by_name(dtp, kldinfo.name);
		if (mod == NULL) {
			fprintf(stderr,
			    "dt_typefile_openall(): WARNING - "
			    "skipping module %s\n",
			    kldinfo.name);
			continue;
		}

		typef = malloc(sizeof(dt_typefile_t));
		if (typef == NULL)
			errx(EXIT_FAILURE,
			    "dt_typefile_openall(): malloc failed "
			    "with %s\n",
			    strerror(errno));

		typef->modhdl = mod;
		typef->dtp = dtp;
		memcpy(typef->modname, kldinfo.name, MAXPATHLEN);
		dt_list_append(&typefiles, typef);
	}

	mod = dt_module_lookup_by_name(dtp, "C");
	if (mod == NULL)
		return;

	typef = malloc(sizeof(dt_typefile_t));
	if (typef == NULL)
		errx(EXIT_FAILURE,
		    "dt_typefile_openall(): malloc failed "
		    "with %s\n",
		    strerror(errno));

	typef->modhdl = mod;
	typef->dtp = dtp;
	strcpy(typef->modname, "C");
	dt_list_append(&typefiles, typef);

	mod = dt_module_lookup_by_name(dtp, "D");
	if (mod == NULL)
		return;

	typef = malloc(sizeof(dt_typefile_t));
	if (typef == NULL)
		errx(EXIT_FAILURE,
		    "dt_typefile_openall(): malloc failed "
		    "with %s\n",
		    strerror(errno));

	typef->modhdl = mod;
	typef->dtp = dtp;
	strcpy(typef->modname, "D");
	dt_list_append(&typefiles, typef);
}

ctf_id_t
dt_typefile_ctfid(dt_typefile_t *typef, const char *type)
{
	ctf_file_t *ctfp;
	dtrace_typeinfo_t tip;
	const char *obj;
	static char nonuser_type[4096];
	static size_t userland_len = strlen("userland ");
	int rv;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (CTF_ERR);

	obj = NULL;

	if (strncmp(type, "userland ", userland_len) == 0)
		strcpy(nonuser_type, type + userland_len);
	else
		strcpy(nonuser_type, type);

	if (strcmp(typef->modname, "C") == 0)
		obj = DTRACE_OBJ_CDEFS;
	else if (strcmp(typef->modname, "D") == 0)
		obj = DTRACE_OBJ_DDEFS;

	if (obj != NULL) {
		rv = dtrace_lookup_by_type(typef->dtp, obj, nonuser_type, &tip);
		if (rv != 0)
			return (CTF_ERR);

		return (tip.dtt_type);
	}

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_lookup_by_name(ctfp, nonuser_type));
}

char *
dt_typefile_typename(dt_typefile_t *typef,
    ctf_id_t id, char *buf, size_t buflen)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (NULL);
	return (ctf_type_name(ctfp, id, buf, buflen));
}

ctf_id_t
dt_typefile_reference(dt_typefile_t *typef, ctf_id_t id)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (CTF_ERR);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_type_reference(ctfp, id));
}

ssize_t
dt_typefile_typesize(dt_typefile_t *typef, ctf_id_t id)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (-1);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);
	return (ctf_type_size(ctfp, id));
}

const char *
dt_typefile_error(dt_typefile_t *typef)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return ("NOT INITIALIZED");

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
	dtrace_hdl_t *dtp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (NULL);

	mod = typef->modhdl;
	fp = dt_module_getctf(typef->dtp, mod);
	dtp = typef->dtp;

	while (ctf_type_kind(fp, type) == CTF_K_FORWARD) {
		char n[DT_TYPE_NAMELEN];
		dtrace_typeinfo_t dtt;

		if (ctf_type_name(fp, type, n, sizeof(n)) == NULL ||
		    dtrace_lookup_by_type(dtp, DTRACE_OBJ_EVERY, n, &dtt) == -1 ||
		    (dtt.dtt_ctfp == fp && dtt.dtt_type == type))
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

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (CTF_ERR);

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

dt_typefile_t *
dt_typefile_D(void)
{
	dt_typefile_t *typef;
	dt_module_t *mod;

	for (typef = dt_list_next(&typefiles); typef;
	     typef = dt_list_next(typef))
		if (strcmp(typef->modname, "D") == 0) {
			mod = dt_module_lookup_by_name(typef->dtp, "D");
			assert(mod == typef->modhdl);
			return (typef);
		}

	return (NULL);
}

ctf_id_t
dt_typefile_resolve(dt_typefile_t *typef, ctf_id_t type)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (CTF_ERR);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (CTF_ERR);

	return (ctf_type_resolve(ctfp, type));
}

int
dt_typefile_encoding(dt_typefile_t *typef, ctf_id_t type, ctf_encoding_t *ep)
{
	ctf_file_t *ctfp;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (-1);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (-1);

	return (ctf_type_encoding(ctfp, type, ep));
}

const char *
dt_typefile_stringof(dt_typefile_t *typef)
{

	if (typef == NULL)
		return ("NOT INITIALIZED");

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

int
dt_typefile_compat(
    dt_typefile_t *tf1, ctf_id_t id1, dt_typefile_t *tf2, ctf_id_t id2)
{
	ctf_file_t *ctfp1, *ctfp2;

	if (tf1 == NULL || tf2 == NULL)
		return (0);

	ctfp1 = dt_module_getctf(tf1->dtp, tf1->modhdl);
	ctfp2 = dt_module_getctf(tf2->dtp, tf2->modhdl);

	if (ctfp1 == NULL || ctfp2 == NULL)
		return (0);

	return (ctf_type_compat(ctfp1, id1, ctfp2, id2));
}

static int
process_struct_member(const char *name, ctf_id_t type, ulong_t offset, void *_s)
{
	dt_typefile_struct_t *s;
	dtf_ctfid_t *ctft;

	s = (dt_typefile_struct_t *)_s;
	assert(s != NULL);

	ctft = malloc(sizeof(dtf_ctfid_t));
	if (ctft == NULL)
		return (-1);

	memset(ctft, 0, sizeof(dtf_ctfid_t));
	ctft->type = type;
	dt_list_append(&s->ctf_types, ctft);

	return (0);
}

void *
dt_typefile_buildup_struct(dt_typefile_t *typef, ctf_id_t id)
{
	ctf_id_t kind;
	ctf_file_t *ctfp;
	dt_typefile_struct_t *s;

	if (typef == NULL || typef->dtp == NULL || typef->modhdl == NULL)
		return (NULL);

	ctfp = dt_module_getctf(typef->dtp, typef->modhdl);
	if (ctfp == NULL)
		return (NULL);

	s = malloc(sizeof(dt_typefile_struct_t));
	if (s == NULL)
		return (NULL);

	memset(s, 0, sizeof(dt_typefile_struct_t));
	s->typefile = typef;

	/*
	 * Populate the members of the struct.
	 */
	if (ctf_member_iter(ctfp, id, process_struct_member, s)) {
		free(s);
		return (NULL);
	}

	s->current = NULL;
	return (s);
}

void *
dt_typefile_struct_next(void *_s)
{
	dt_typefile_struct_t *s;

	s = (dt_typefile_struct_t *)_s;
	if (s == NULL)
		return (NULL);

	if (s->current)
		s->current = dt_list_next(s->current);
	else
		s->current = dt_list_next(&s->ctf_types);
	return (s->current);
}

ctf_id_t
dt_typefile_memb_ctfid(void *_m)
{
	dtf_ctfid_t *m = (dtf_ctfid_t *)_m;

	if (m == NULL)
		return (CTF_ERR);

	return (m->type);
}

ctf_file_t *
dt_typefile_getctfp(dt_typefile_t *tf)
{

	return dt_module_getctf(tf->dtp, tf->modhdl);
}

ctf_arinfo_t *
dt_typefile_array_info(dt_typefile_t *tf, ctf_id_t id)
{
	ctf_file_t *ctfp;
	ctf_arinfo_t *ai;

	ctfp = dt_typefile_getctfp(tf);
	if (ctfp == NULL)
		return (NULL);

	ai = malloc(sizeof(ctf_arinfo_t));
	if (ai == NULL)
		return (NULL);

	memset(ai, 0, sizeof(ctf_arinfo_t));
	if (ctf_array_info(ctfp, id, ai) == CTF_ERR) {
		free(ai);
		return (NULL);
	}

	return (ai);
}
