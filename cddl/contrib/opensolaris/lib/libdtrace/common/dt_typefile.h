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

#ifndef _DT_TYPEFILE_T_
#define _DT_TYPEFILE_T_

#include <dtrace.h>

#include <_dt_typefile.h>

void dt_typefile_openall(dtrace_hdl_t *);

ctf_id_t dt_typefile_ctfid(dt_typefile_t *, const char *);
char *dt_typefile_typename(dt_typefile_t *, ctf_id_t, char *, size_t);
ctf_id_t dt_typefile_reference(dt_typefile_t *, ctf_id_t);
uint32_t dt_typefile_typesize(dt_typefile_t *, ctf_id_t);
const char *dt_typefile_error(dt_typefile_t *);
ctf_file_t *dt_typefile_membinfo(dt_typefile_t *, ctf_id_t,
    const char *, ctf_membinfo_t *);
ctf_id_t dt_typefile_typekind(dt_typefile_t *, ctf_id_t);
dt_typefile_t *dt_typefile_kernel(void);
ctf_id_t dt_typefile_resolve(dt_typefile_t *, ctf_id_t);
dt_typefile_t *dt_typefile_mod(const char *);
int dt_typefile_encoding(dt_typefile_t *, ctf_id_t, ctf_encoding_t *);
const char *dt_typefile_stringof(dt_typefile_t *);

#endif
