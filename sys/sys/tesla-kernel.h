/*
 * Copyright (c) 2013 Robert N. M. Watson
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract (FA8750-10-C-0237)
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#ifndef _SYS_TESLA_KERNEL_H_
#define	_SYS_TESLA_KERNEL_H_

/*
 * FreeBSD kernel-specific TESLA macros.
 */

/*
 * Un-protyped functions that we care about.
 *
 * XXXRW: Solution is actually to prototype them properly.  Some don't have
 * consistent prototypes across architectures.
 */
extern void syscall(void);
extern void trap_pfault(struct trapframe *, int, vm_offset_t);

/*
 * Convenient assertion wrappers for various scopes.
 */
#define	TESLA_SYSCALL(x)	TESLA_WITHIN(syscall, x)

/*
 * XXXRW: Not all architectures have a trap_pfault() function.  Can't use
 * vm_fault() as it is used in non-trap contexts -- e.g., PMAP initialisation.
 */
#if 0
#define	TESLA_PAGE_FAULT(x)	TESLA_WITHIN(trap_pfault, x)
#else
#define	TESLA_PAGE_FAULT(x)
#endif

#endif /* _SYS_TESLA_KERNEL_H_ */
