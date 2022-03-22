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

#include <dt_typing.h>

#include <sys/types.h>
#include <sys/dtrace.h>

#include <dtrace.h>
#include <dt_impl.h>
#include <dt_program.h>
#include <dt_list.h>
#include <dt_linker_subr.h>
#include <dt_basic_block.h>
#include <dt_ifgnode.h>
#include <dt_typefile.h>
#include <dt_typing_helpers.h>

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <err.h>
#include <errno.h>
#include <assert.h>

#include <dt_typing_subr.h>

static void
dt_arg_cmpwith(dt_ifg_node_t *arg, dt_typefile_t **tfs, size_t ntfs,
    const char *type, char *buf, size_t bufsize, const char *loc,
    int subtype_relation)
{
	ctf_id_t arg_ctfid;
	ctf_id_t arg_kind;
	int which, rv;
	ctf_id_t passed_arg_ctfid;
	ctf_id_t passed_arg_kind;
	dt_typefile_t *tf;

	tf = dt_get_typename_tfcheck(arg, tfs, ntfs, buf, bufsize, loc);

	arg_ctfid = dt_typefile_ctfid(tf, type);
	if (arg_ctfid == CTF_ERR)
		dt_set_progerr(g_dtp, g_pgp, "%s: failed to get type %s: %s",
		    loc, type, dt_typefile_error(tf));

	arg_kind = dt_type_strip_typedef(tf, &arg_ctfid);
	assert(arg_kind != CTF_K_TYPEDEF);

	passed_arg_ctfid = arg->din_ctfid;
	passed_arg_kind = dt_type_strip_typedef(arg->din_tf, &passed_arg_ctfid);

	assert(passed_arg_kind != CTF_K_TYPEDEF);
	if ((strcmp(type, "void *") == 0 || strcmp(type, "uintptr_t") == 0) &&
	    strcmp(buf, "void *") && strcmp(buf, "uintptr_t")) {
		/*
		 * Since this is a void * / uintptr_t, any pointer will do, as D
		 * allows us to implicitly cast any pointer to void * /
		 * uintptr_t.
		 */
		if (passed_arg_kind != CTF_K_POINTER &&
		    passed_arg_kind != CTF_K_ARRAY)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: %s (%s) can't be cast to void *", loc, buf,
			    dt_typefile_stringof(tf));

		return;
	}

	if (arg_kind != passed_arg_kind)
		dt_set_progerr(g_dtp, g_pgp, "%s (argkind): %s (%s) != %s (%s)",
		    loc, type, dt_typefile_stringof(tf), buf,
		    dt_typefile_stringof(arg->din_tf));

	if (arg_kind == CTF_K_INTEGER) {
		rv = dt_type_subtype(arg->din_tf, arg->din_ctfid, tf, arg_ctfid,
		    &which);
		if (rv != 0 || ((which & subtype_relation) == 0))
			dt_set_progerr(g_dtp, g_pgp, "%s: %s (%s) != %s (%s)",
			    loc, type, dt_typefile_stringof(tf), buf,
			    dt_typefile_stringof(arg->din_tf));
	} else {
		/*
		 * If the argument type is wrong, fail to type check.
		 */
		if (dt_typefile_compat(
		    arg->din_tf, arg->din_ctfid, tf, arg_ctfid) == 0)
			dt_set_progerr(g_dtp, g_pgp, "%s: %s (%s) != %s (%s)",
			    loc, type, dt_typefile_stringof(tf), buf,
			    dt_typefile_stringof(arg->din_tf));
	}
}

int
dt_infer_type_subr(dt_ifg_node_t *n, dt_list_t *stack)
{
	uint16_t subr;
	dif_instr_t instr;
	dt_ifg_node_t *arg0, *arg1, *arg2, *arg3, *arg4, *arg5, *arg6, *arg7,
	    *arg8;
	dt_stack_t *se;
	dt_stacklist_t *sl;
	char buf[4096] = { 0 };
	ctf_id_t arg_ctfid;
	ctf_id_t arg_kind;

	const char *subr_name[] = {
		[DIF_SUBR_RAND]                = "rand()",
		[DIF_SUBR_MUTEX_OWNED]         = "mutex_owned()",
		[DIF_SUBR_MUTEX_OWNER]         = "mutex_owner()",
		[DIF_SUBR_MUTEX_TYPE_ADAPTIVE] = "mutex_type_adaptive()",
		[DIF_SUBR_MUTEX_TYPE_SPIN]     = "mutex_type_spin()",
		[DIF_SUBR_RW_READ_HELD]        = "rw_read_held()",
		[DIF_SUBR_RW_WRITE_HELD]       = "rw_write_held()",
		[DIF_SUBR_RW_ISWRITER]         = "rw_iswriter()",
		[DIF_SUBR_COPYIN]              = "copyin()",
		[DIF_SUBR_COPYINSTR]           = "copyinstr()",
		[DIF_SUBR_SPECULATION]         = "speculation()",
		[DIF_SUBR_PROGENYOF]           = "progenyof()",
		[DIF_SUBR_STRLEN]              = "strlen()",
		[DIF_SUBR_COPYOUT]             = "copyout()",
		[DIF_SUBR_COPYOUTSTR]          = "copyoutstr()",
		[DIF_SUBR_ALLOCA]              = "alloca()",
		[DIF_SUBR_BCOPY]               = "bcopy()",
		[DIF_SUBR_COPYINTO]            = "copyinto()",
		[DIF_SUBR_MSGDSIZE]            = "msgdsize()",
		[DIF_SUBR_MSGSIZE]             = "msgsize()",
		[DIF_SUBR_GETMAJOR]            = "getmajor()",
		[DIF_SUBR_GETMINOR]            = "getminor()",
		[DIF_SUBR_DDI_PATHNAME]        = "ddi_pathname()",
		[DIF_SUBR_STRJOIN]             = "strjoin()",
		[DIF_SUBR_LLTOSTR]             = "lltostr()",
		[DIF_SUBR_BASENAME]            = "basename()",
		[DIF_SUBR_DIRNAME]             = "dirname()",
		[DIF_SUBR_CLEANPATH]           = "cleanpath()",
		[DIF_SUBR_STRCHR]              = "strchr()",
		[DIF_SUBR_STRRCHR]             = "strrchr()",
		[DIF_SUBR_STRSTR]              = "strstr()",
		[DIF_SUBR_STRTOK]              = "strtok()",
		[DIF_SUBR_SUBSTR]              = "substr()",
		[DIF_SUBR_INDEX]               = "index()",
		[DIF_SUBR_RINDEX]              = "rindex()",
		[DIF_SUBR_HTONS]               = "htons()",
		[DIF_SUBR_HTONL]               = "htonl()",
		[DIF_SUBR_HTONLL]              = "htonll()",
		[DIF_SUBR_NTOHS]               = "ntohs()",
		[DIF_SUBR_NTOHL]               = "ntohl()",
		[DIF_SUBR_NTOHLL]              = "ntohll()",
		[DIF_SUBR_INET_NTOP]           = "inet_ntop()",
		[DIF_SUBR_INET_NTOA]           = "inet_ntoa()",
		[DIF_SUBR_INET_NTOA6]          = "inet_ntoa6()",
		[DIF_SUBR_TOUPPER]             = "toupper()",
		[DIF_SUBR_TOLOWER]             = "tolower()",
		[DIF_SUBR_MEMREF]              = "memref()",
		[DIF_SUBR_SX_SHARED_HELD]      = "sx_shared_held()",
		[DIF_SUBR_SX_EXCLUSIVE_HELD]   = "sx_exclusive_held()",
		[DIF_SUBR_SX_ISEXCLUSIVE]      = "sx_isexclusive()",
		[DIF_SUBR_MEMSTR]              = "memstr()",
		[DIF_SUBR_GETF]                = "getf()",
		[DIF_SUBR_JSON]                = "json()",
		[DIF_SUBR_STRTOLL]             = "strtoll()",
		[DIF_SUBR_RANDOM]              = "random()",
		[DIF_SUBR_PTINFO]              = "ptinfo()"
	};

	instr = n->din_buf[n->din_uidx];
	subr = DIF_INSTR_SUBR(instr);

	/*
	 * The return typefile of a call instruction will always be the
	 * kernel itself, so we just do it ahead of time.
	 */
	n->din_tf = dt_typefile_kernel();
	assert(n->din_tf != NULL);

	/*
	 * We don't care if there are more things on the stack than
	 * the arguments we need, because they will simply not be used.
	 *
	 * Therefore, the transformation where we have
	 *
	 *     foo(a, b);
	 *     bar(a, b, c);
	 *
	 * which results in
	 *
	 *     push a
	 *     push b
	 *     push c
	 *     call foo
	 *     call bar
	 *
	 * is perfectly valid, so we shouldn't fail to type check this.
	 */
	switch (subr) {
	case DIF_SUBR_RAND:
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MUTEX_OWNED:
	case DIF_SUBR_MUTEX_TYPE_ADAPTIVE:
	case DIF_SUBR_MUTEX_TYPE_SPIN:
		/*
		 * We expect a "struct mtx *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_mtx, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MUTEX_OWNER:
		/*
		 * We expect a "struct mtx *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_mtx, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);
#ifdef __FreeBSD__
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, t_thread);
#elif defined(illumos)
		/*
		 * illumos not quite supported yet.
		 */
		return (-1);
#endif
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get thread type: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_READ_HELD:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_rw, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_WRITE_HELD:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_rw, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RW_ISWRITER:
		/*
		 * We expect a "struct rwlock *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_rw, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYIN:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as the second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "void *");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYINSTR:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * Check if the second (optional) argument is present
		 */
		se = dt_list_next(se);
		if (sl != NULL) {
			if (se->ds_ifgnode == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s: ds_ifgnode is NULL", subr_name[subr]);

			arg1 = se->ds_ifgnode;
			assert(arg1->din_tf != NULL);

			dt_arg_cmpwith(arg1,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "size_t", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_SND | SUBTYPE_EQUAL);
		}

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_SPECULATION:
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_PROGENYOF:
		/*
		 * We expect a "pid_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "pid_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRLEN:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "size_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type size_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_COPYOUT:
		/*
		 * We expect a "void *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "uintptr_t" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: third argument is NULL", subr_name[subr]);

		arg2 = se->ds_ifgnode;
		assert(arg2->din_tf != NULL);

		dt_arg_cmpwith(arg2,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_COPYOUTSTR:
		/*
		 * We expect a "char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s :first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * We expect a "uintptr_t" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: third argument is NULL", subr_name[subr]);

		arg2 = se->ds_ifgnode;
		assert(arg2->din_tf != NULL);

		dt_arg_cmpwith(arg2,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_ALLOCA:
		/*
		 * We expect a "size_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "void *");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_BCOPY:
		/*
		 * We expect a "void *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "void *" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: third argument is NULL", subr_name[subr]);

		arg2 = se->ds_ifgnode;
		assert(arg2->din_tf != NULL);

		dt_arg_cmpwith(arg2,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_COPYINTO:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * We expect a "void *" as a third argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: third argument is NULL", subr_name[subr]);

		arg2 = se->ds_ifgnode;
		assert(arg2->din_tf != NULL);

		dt_arg_cmpwith(arg2,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		n->din_type = DIF_TYPE_NONE;
		break;

	case DIF_SUBR_MSGDSIZE:
	case DIF_SUBR_MSGSIZE:
		/*
		 * We expect a "mblk_t *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "mblk_t *", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "size_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type size_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_GETMAJOR:
		break;
	case DIF_SUBR_GETMINOR:
		break;

	case DIF_SUBR_DDI_PATHNAME:
		/*
		 * We expect a "void *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "int64_t" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "int64_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_LLTOSTR:
		/*
		 * We expect a "int64_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "int64_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * Check if the second (optional) argument is present
		 */
		se = dt_list_next(se);
		if (sl != NULL) {
			if (se->ds_ifgnode == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s: ds_ifgnode is NULL", subr_name[subr]);

			arg1 = se->ds_ifgnode;
			assert(arg1->din_tf != NULL);

			dt_arg_cmpwith(arg1,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "int", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_CLEANPATH:
	case DIF_SUBR_DIRNAME:
	case DIF_SUBR_BASENAME:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_STRRCHR:
	case DIF_SUBR_STRCHR:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * We expect a "char" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "char", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_SUBSTR:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * We expect a "int" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "int", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_ANY);

		/*
		 * Check if the third (optional) argument is present
		 */
		if (sl != NULL) {
			if (se->ds_ifgnode == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s: ds_ifgnode is NULL", subr_name[subr]);

			arg2 = se->ds_ifgnode;
			assert(arg2->din_tf != NULL);

			dt_arg_cmpwith(arg2,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "int", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_RINDEX:
	case DIF_SUBR_INDEX:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * We expect a "const char *" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg1,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg1 type is NONE",
			    subr_name[subr]);

		/*
		 * Check if the third (optional) argument is present
		 */
		if (sl != NULL) {
			if (se->ds_ifgnode == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s: ds_ifgnode is NULL", subr_name[subr]);

			arg2 = se->ds_ifgnode;
			assert(arg2->din_tf != NULL);

			dt_arg_cmpwith(arg2,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "int", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHS:
	case DIF_SUBR_HTONS:
		/*
		 * We expect a "uint16_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uint16_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_ANY);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint16_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uint16_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHL:
	case DIF_SUBR_HTONL:
		/*
		 * We expect a "uint32_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uint32_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_ANY);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint32_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uint32_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_NTOHLL:
	case DIF_SUBR_HTONLL:
		/*
		 * We expect a "uint64_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uint64_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_INET_NTOP:
		/*
		 * We expect a "int" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "int", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_ANY);

		/*
		 * We expect a "void *" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_INET_NTOA:
		/*
		 * We expect a "in_addr_t *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "in_addr_t *", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_INET_NTOA6:
		/*
		 * We expect a "struct in6_addr *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "struct in6_addr *", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_TOLOWER:
	case DIF_SUBR_TOUPPER:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_MEMREF:
		/*
		 * We expect a "void *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "size_t" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_ctfid =
		    dt_typefile_ctfid(n->din_tf, "uintptr_t *");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uintptr_t *: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_SX_SHARED_HELD:
	case DIF_SUBR_SX_EXCLUSIVE_HELD:
	case DIF_SUBR_SX_ISEXCLUSIVE:
		/*
		 * We expect a sx_str as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, t_sx, buf, sizeof(buf), subr_name[subr], SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int: %s", subr_name[subr],
			    dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_MEMSTR:
		/*
		 * We expect a "void *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "void *", buf, sizeof(buf), subr_name[subr], SUBTYPE_NONE);

		/*
		 * We expect a "char" as a second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;
		assert(arg1->din_tf != NULL);

		dt_arg_cmpwith(arg1,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "char", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		/*
		 * We expect a "size_t" as a third argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg2 = se->ds_ifgnode;
		assert(arg2->din_tf != NULL);

		dt_arg_cmpwith(arg2,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "size_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_SND | SUBTYPE_EQUAL);

		n->din_type = DIF_TYPE_STRING;
		break;

	case DIF_SUBR_GETF:
		/*
		 * We expect a "int" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: getf() first argument is NULL",
			    subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "int", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_ANY);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "file_t *");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type file_t *: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRTOLL:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * Check if the second (optional) argument is present
		 */
		se = dt_list_next(se);
		if (sl != NULL) {
			if (se->ds_ifgnode == NULL)
				dt_set_progerr(g_dtp, g_pgp,
				    "%s: ds_ifgnode is NULL", subr_name[subr]);

			arg1 = se->ds_ifgnode;
			assert(arg1->din_tf != NULL);

			dt_arg_cmpwith(arg1,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "int", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_ANY);
		}

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "int64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type int64_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_RANDOM:
		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "uint64_t");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type uint64_t: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_PTINFO:
		/*
		 * We expect a "uintptr_t" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;
		assert(arg0->din_tf != NULL);

		dt_arg_cmpwith(arg0,
		    (dt_typefile_t *[]) { dt_typefile_mod("D"),
		                          dt_typefile_kernel() },
		    2, "uintptr_t", buf, sizeof(buf), subr_name[subr],
		    SUBTYPE_EQUAL);

		n->din_ctfid = dt_typefile_ctfid(n->din_tf, "void *");
		if (n->din_ctfid == CTF_ERR)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: failed to get type void *: %s",
			    subr_name[subr], dt_typefile_error(n->din_tf));

		n->din_type = DIF_TYPE_CTF;
		break;

	case DIF_SUBR_STRTOK:
	case DIF_SUBR_STRSTR:
	case DIF_SUBR_STRJOIN:
	case DIF_SUBR_JSON:
		/*
		 * We expect a "const char *" as an argument.
		 */
		se = dt_list_next(stack);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: first argument is NULL", subr_name[subr]);

		arg0 = se->ds_ifgnode;

		if (arg0->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg0,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg0 type is NONE",
			    subr_name[subr]);

		/*
		 * We expect a "const char *" as the second argument.
		 */
		se = dt_list_next(se);
		if (se == NULL || se->ds_ifgnode == NULL)
			dt_set_progerr(g_dtp, g_pgp,
			    "%s: second argument is NULL", subr_name[subr]);

		arg1 = se->ds_ifgnode;

		if (arg1->din_type == DIF_TYPE_CTF)
			dt_arg_cmpwith(arg1,
			    (dt_typefile_t *[]) { dt_typefile_mod("D"),
			                          dt_typefile_kernel() },
			    2, "const char *", buf, sizeof(buf), subr_name[subr],
			    SUBTYPE_EQUAL);
		else if (arg0->din_type == DIF_TYPE_NONE)
			dt_set_progerr(g_dtp, g_pgp, "%s: arg1 type is NONE",
			    subr_name[subr]);

		n->din_type = DIF_TYPE_STRING;
		break;
	default:
		return (-1);
	}

	return (n->din_type);
}
