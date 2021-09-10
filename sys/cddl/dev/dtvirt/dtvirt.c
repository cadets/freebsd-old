/*-
 * Copyright (c) 2018, 2021 Domagoj Stolfa
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/module.h>
#include <sys/dtrace.h>
#include <machine/vmm.h>

#include "hypertrace.h"

static MALLOC_DEFINE(M_HYPERTRACE, "HyperTrace", "");
static lwpid_t hypertrace_priv_gettid(void *);
static uint16_t hypertrace_priv_getns(void *);
static const char *hypertrace_priv_getname(void *);

lwpid_t (*vmm_gettid)(void *vmhdl);
uint16_t (*vmm_getid)(void *vmhdl);
const char *(*vmm_getname)(void *vmhdl);

void
hypertrace_probe(void *vmhdl, int probeid, struct hypertrace_args *htr_args)
{

	dtrace_vprobe(vmhdl, probeid, htr_args);
}

static int
hypertrace_handler(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		hypertrace_gettid = hypertrace_priv_gettid;
		hypertrace_getns = hypertrace_priv_getns;
		hypertrace_getname = hypertrace_priv_getname;
		break;
	case MOD_UNLOAD:
		hypertrace_gettid = NULL;
		hypertrace_getns = NULL;
		hypertrace_getname = NULL;
		break;
	default:
		break;
	}
	return (0);
}

/*
 * Get the thread ID of the VM.
 */
static lwpid_t
hypertrace_priv_gettid(void *vmhdl)
{

	return (vmm_gettid == NULL ? 0 : vmm_gettid(vmhdl));
}

/*
 * Get a unique identifier of each vm (uint16_t). This is used to scope
 * thread-local storage in the DTrace probe context.
 */
static uint16_t
hypertrace_priv_getns(void *vmhdl)
{

	return (vmm_getid == NULL ? 0 : vmm_getid(vmhdl));
}

static const char *
hypertrace_priv_getname(void *vmhdl)
{

	return (vmm_getname == NULL ? 0 : vmm_getname(vmhdl));
}

static moduledata_t hypertrace_kmod = {
	"hypertrace",
	hypertrace_handler,
	NULL
};

DECLARE_MODULE(hypertrace, hypertrace_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(hypertrace, 1);
MODULE_DEPEND(hypertrace, dtrace, 1, 1, 1);
