/*-
 * Copyright (c) 2018 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/dtrace.h>
#include <machine/vmm.h>

#include "dtvirt.h"

static MALLOC_DEFINE(M_DTVIRT, "dtvirt", "");
static void * dtvirt_priv_ptr(void *, uintptr_t, size_t);
static void dtvirt_priv_bcopy(void *, void *, void *, size_t);
static void dtvirt_priv_free(void *, size_t);
static lwpid_t dtvirt_priv_gettid(void *);
static uint16_t dtvirt_priv_getns(void *);

void * (*vmm_copyin)(void *biscuit,
    void *addr, size_t len, struct malloc_type *t);
void (*vmm_bcopy)(void *biscuit,
    void *src, void *dst, size_t len);
lwpid_t (*vmm_gettid)(void *biscuit);
uint16_t (*vmm_getid)(void *biscuit);

void
dtvirt_probe(void *biscuit, int probeid, uintptr_t arg0, uintptr_t arg1,
    uintptr_t arg2, uintptr_t arg3, uintptr_t arg4)
{

	dtrace_ns_probe(biscuit, probeid,
	    arg0, arg1, arg2, arg3, arg4);
}

static int
dtvirt_handler(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		dtvirt_ptr = dtvirt_priv_ptr;
		dtvirt_free = dtvirt_priv_free;
		dtvirt_bcopy = dtvirt_priv_bcopy;
		dtvirt_gettid = dtvirt_priv_gettid;
		dtvirt_getns = dtvirt_priv_getns;
		break;
	case MOD_UNLOAD:
		dtvirt_ptr = NULL;
		dtvirt_free = NULL;
		dtvirt_bcopy = NULL;
		dtvirt_gettid = NULL;
		dtvirt_getns = NULL;
		break;
	default:
		break;
	}
	return (0);
}

static void *
dtvirt_priv_ptr(void *biscuit, uintptr_t addr, size_t size)
{

	if (vmm_copyin != NULL)
		return (vmm_copyin(biscuit, (void *)addr, size, M_DTVIRT));
	return (NULL);
}

static void
dtvirt_priv_bcopy(void *biscuit, void *src, void *dst, size_t size)
{

	if (vmm_bcopy != NULL)
		vmm_bcopy(biscuit, src, dst, size);
}

static void
dtvirt_priv_free(void *addr, size_t size)
{

	free(addr, M_DTVIRT);
}

static lwpid_t
dtvirt_priv_gettid(void *biscuit)
{

	if (vmm_gettid != NULL)
		return (vmm_gettid(biscuit));
}

static uint16_t
dtvirt_priv_getns(void *biscuit)
{

	if (vmm_getid != NULL)
		return (vmm_getid(biscuit));
}

static moduledata_t dtvirt_kmod = {
	"dtvirt",
	dtvirt_handler,
	NULL
};

DECLARE_MODULE(dtvirt, dtvirt_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(dtvirt, 1);
MODULE_DEPEND(dtvirt, dtrace, 1, 1, 1);
