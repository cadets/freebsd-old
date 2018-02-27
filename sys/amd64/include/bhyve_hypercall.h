/*-
 * Copyright (c) 2016 Domagoj Stolfa <domagoj.stolfa@gmail.com>
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

#ifndef _MACHINE_HYPERCALL_H_
#define _MACHINE_HYPERCALL_H_

#define	HYPERCALL_PROTOTYPE		0
#define	HYPERCALL_DTRACE_PROBE		1
#define	HYPERCALL_INDEX_MAX		2

#define	HYPERCALL_RET_SUCCESS		0
#define	HYPERCALL_RET_ERROR		1
#define	HYPERCALL_RET_NOT_IMPL		-1

#ifndef __asm__

#include <sys/stdint.h>
#include <machine/cpufunc.h>

#include <sys/types.h>

/*
 * Hierarchical structure with hypercall arguments. It contains the hypercall
 * identifier and hypercall-specific arguments packed into a union of types.
 */
struct hypercall_args {
	union {
		struct {
			int probeid;
			uintptr_t args[10];
			size_t n_args;
			lwpid_t tid;
			/* XXX(dstolfa): Do we have to copyin here */
			char *execname;
			uint32_t stackdepth;
			/*
			 * FIXME: Needs usym for this -- not sure how to do it.
			 */
			uint64_t ucaller;
			pid_t ppid;
			uid_t uid;
			gid_t gid;
			int errno;
			struct pargs execargs; /* We fill this directly */
		} dt;
	} u;
};

/*
 * Arguments are only specified in this header file.
 * Do not move the arguments around in the assembly
 * file as the convention used is the SystemV ABI
 * calling convention.
 */
int	hypercall_prototype(void /* args */);
int	hypercall_dtrace_probe(uint32_t, uintptr_t, lwpid_t);

static __inline int
bhyve_hypercalls_enabled(void)
{
	u_int regs[4] = { 0 };
	do_cpuid(0x40000001, regs);

	return (regs[0]);
}

#endif

#endif
