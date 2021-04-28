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

/*
 * dtvirt.c is a simple proxy between DTrace and vmm due to linking problems.
 * It exposes a number of interfaces via function pointers to access internal
 * vmm state from the DTrace probe context.
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
static lwpid_t dtvirt_priv_gettid(void *);
static uint16_t dtvirt_priv_getns(void *);
static const char *dtvirt_priv_getname(void *);

lwpid_t (*vmm_gettid)(void *biscuit);
uint16_t (*vmm_getid)(void *biscuit);
const char *(*vmm_getname)(void *biscuit);

void
dtvirt_probe(void *biscuit, int probeid, struct dtvirt_args *dtv_args)
{

	dtrace_vprobe(biscuit, probeid, dtv_args);
}

static int
dtvirt_handler(module_t mod __unused, int what, void *arg __unused)
{
	switch (what) {
	case MOD_LOAD:
		dtvirt_gettid = dtvirt_priv_gettid;
		dtvirt_getns = dtvirt_priv_getns;
		dtvirt_getname = dtvirt_priv_getname;
		break;
	case MOD_UNLOAD:
		dtvirt_gettid = NULL;
		dtvirt_getns = NULL;
		dtvirt_getname = NULL;
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
dtvirt_priv_gettid(void *biscuit)
{

	return (vmm_gettid == NULL ? 0 : vmm_gettid(biscuit));
}

/*
 * Get a unique identifier of each vm (uint16_t). This is used to scope
 * thread-local storage in the DTrace probe context.
 */
static uint16_t
dtvirt_priv_getns(void *biscuit)
{

	return (vmm_getid == NULL ? 0 : vmm_getid(biscuit));
}

static const char *
dtvirt_priv_getname(void *biscuit)
{

	return (vmm_getname == NULL ? 0 : vmm_getname(biscuit));
}

static moduledata_t dtvirt_kmod = {
	"dtvirt",
	dtvirt_handler,
	NULL
};

DECLARE_MODULE(dtvirt, dtvirt_kmod, SI_SUB_DTRACE + 1, SI_ORDER_ANY);
MODULE_VERSION(dtvirt, 1);
MODULE_DEPEND(dtvirt, dtrace, 1, 1, 1);
