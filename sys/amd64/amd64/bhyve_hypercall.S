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


#include <machine/asmacros.h>
#include <machine/bhyve_hypercall.h>

#define VENTER push %rbp ; mov %rsp, %rbp
#define VLEAVE pop %rbp

.globl __start_set_hypercall
.globl __stop_set_hypercall

/*
 * The hypercalls implemented here are only the ones
 * that are called from the kernel context. The
 * hypercalls that are intended to be called from
 * userland are expected to be implemented from each
 * program individually or within a library, as
 * opposed to here.
 */

ENTRY(hypercall_prototype)
	VENTER
	movq $HYPERCALL_PROTOTYPE, %rax
hc_prototype:
	.byte 0x0f,0x01,0xc1
	VLEAVE
	ret
END(hypercall_prototype)

ENTRY(hypercall_dtrace_probe)
	movq $HYPERCALL_DTRACE_PROBE, %rax
hc_dtrace_probe:
	.byte 0x0f,0x01,0xc1
	ret
END(hypercall_dtrace_probe)

ENTRY(hypercall_test)
	movq $HYPERCALL_TEST, %rax
hc_test:
	.byte 0x0f,0x01,0xc1
	ret
END(hypercall_test)

.type __set_hypercall_prototype, @object
.type __set_hypercall_dtrace_probe, @object
.type __set_hypercall_test, @object
.section set_hypercall, "a", @progbits
.align 8
__set_hypercall_prototype:
	.quad hc_prototype
	.size __set_hypercall_prototype, 3
__set_hypercall_dtrace_probe:
	.quad hc_dtrace_probe
	.size __set_hypercall_dtrace_probe, 3
__set_hypercall_test:
	.quad hc_test
	.size __set_hypercall_test, 3
