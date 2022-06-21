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

#ifndef _DT_TYPEFILE_T_
#define _DT_TYPEFILE_T_

#include <dtrace.h>

#include <_dt_typefile.h>

extern dt_list_t typefiles;

void dt_typefile_openall(dtrace_hdl_t *);

ctf_id_t dt_typefile_ctfid(dt_typefile_t *, const char *);
char *dt_typefile_typename(dt_typefile_t *, ctf_id_t, char *, size_t);
ctf_id_t dt_typefile_reference(dt_typefile_t *, ctf_id_t);
ssize_t dt_typefile_typesize(dt_typefile_t *, ctf_id_t);
const char *dt_typefile_error(dt_typefile_t *);
ctf_file_t *dt_typefile_membinfo(dt_typefile_t *, ctf_id_t,
    const char *, ctf_membinfo_t *);
ctf_id_t dt_typefile_typekind(dt_typefile_t *, ctf_id_t);
dt_typefile_t *dt_typefile_kernel(void);
dt_typefile_t *dt_typefile_D(void);
ctf_id_t dt_typefile_resolve(dt_typefile_t *, ctf_id_t);
dt_typefile_t *dt_typefile_mod(const char *);
int dt_typefile_encoding(dt_typefile_t *, ctf_id_t, ctf_encoding_t *);
const char *dt_typefile_stringof(dt_typefile_t *);
int dt_typefile_compat(dt_typefile_t *, ctf_id_t, dt_typefile_t *, ctf_id_t);
void *dt_typefile_buildup_struct(dt_typefile_t *, ctf_id_t);
void *dt_typefile_struct_next(void *);
ctf_id_t dt_typefile_memb_ctfid(void *);
ctf_file_t *dt_typefile_getctfp(dt_typefile_t *);
ctf_arinfo_t *dt_typefile_array_info(dt_typefile_t *, ctf_id_t);

#endif
