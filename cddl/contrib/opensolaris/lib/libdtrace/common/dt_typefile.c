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

int
dt_typefile_openall(void)
{
	int err = 0;
	int kld;
	struct kld_file_stat kldinfo;
	dt_typefile_t *typef;

	for (kld = kldnext(0); kld > 0; kld = kldnext(kld)) {
		kldinfo.version = sizeof(kldinfo);
		if (kldstat(kld, &kldinfo) < 0)
			return (-1);

		/*
		 * We open the type file and save it in a list that we will use
		 * later in type-checking and applying relocations.
		 */
		typef = malloc(sizeof(dt_typefile_t));
		if (typef == NULL)
			errx(EXIT_FAILURE, "malloc() failed with: %s\n",
			    strerror(errno));

		memcpy(typef->pathname, kldinfo.pathname, MAXPATHLEN);
		memcpy(typef->modname, kldinfo.name, MAXPATHLEN);
		typef->ctf_file = ctf_open(typef->pathname, &err);
		if (err != 0)
			errx(EXIT_FAILURE, "failed opening %s: %s\n",
			    typef->pathname,
			    ctf_errmsg(ctf_errno(typef->ctf_file)));
		dt_list_append(&typefiles, typef);
	}

	return (0);
}

void
dt_typefile_cleanup(void)
{
	dt_typefile_t *typef;

	while ((typef = dt_list_next(&typefiles)) != NULL) {
		dt_list_delete(&typefiles, typef);
		free(typef);
	}
}

dt_typefile_t *
dt_typefile_by_kmod(const char *kmod)
{
	dt_typefile_t *typef;

	for (typef = dt_list_next(&typefiles); typef;
	     typef = dt_list_next(typef)) {
		if (strcmp(typef->modname, kmod) == 0)
			return (typef);
	}

	return (NULL);
}

dt_typefile_t *
dt_typefile_by_ctfp(ctf_file_t *ctf)
{
	dt_typefile_t *typef;

	for (typef = dt_list_next(&typefiles); typef;
	     typef = dt_list_next(typef)) {
		if ((typef->ctf_file == ctf) == 0)
			return (typef);
	}

	return (NULL);
}

ctf_id_t
dt_typefile_ctfid_by_kmod(const char *kmod, const char *type)
{
	dt_typefile_t *typef;
	typef = dt_typefile_by_kmod(kmod);

	return (ctf_lookup_by_name(typef->ctf_file, type))
}

ctf_id_t
dt_typefile_ctfid(dt_typefile_t *typef, const char *type)
{

	return (ctf_lookup_by_name(typef->ctf_file, type));
}

char *
dt_typefile_typename_by_kmod(const char *kmod, ctf_id_t id,
    char *buf, size_t buflen)
{
	dt_typefile_t *typef;
	typef = dt_typefile_by_kmod(kmod);

	return (ctf_type_name(typef.ctf_file, id, buf, buflen));
}

char *
dt_typefile_typename(dt_typefile_t *typef,
    ctf_id_t id, char *buf, size_t buflen)
{

	return (ctf_type_name(typef.ctf_file, id, buf, buflen));
}

ctf_id_t
dt_typefile_reference(dt_typefile_t *typef, ctf_id_t id)
{

	return (ctf_type_reference(typef.ctf_file, id));
}

uint32_t
dt_typefile_typesize(dt_typefile *typef, ctf_id_t id)
{

	return (ctf_type_size(typef.ctf_file, id));
}

const char *
dt_typefile_error(dt_typefile_t *typef)
{

	return (ctf_errmsg(ctf_errno(typef->ctf_file)));
}

ctf_file_t *
dt_typefile_membinfo(dt_typefile_t *typef, ctf_id_t type,
    const char *s, ctf_membinfo_t *mp)
{
	ctf_file_t *fp;

	fp = typef.ctf_file;

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

dt_typefile_t *
dt_typefile_kernel(void)
{
	for (typef = dt_list_next(&typefiles); typef; typef = dt_list_next(typef))
		if (strcmp(typef.modname, "kernel"))
			return (typef);

	return (NULL);
}
