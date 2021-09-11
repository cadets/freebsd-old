/*-
 * Copyright (c) 2021 Domagoj Stolfa
 * All rights reserved.
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

#ifndef __HYPERTRACE_IMPL_H_
#define __HYPERTRACE_IMPL_H_

#include <sys/dtrace.h>
#include <sys/hypertrace.h>

typedef struct hypertrace_vprovider {
	char name[DTRACE_PROVNAMELEN]; /* Provider name */
	size_t nprobes;                /* Number of probes */
	uint32_t hash_ndx;             /* Index in the hash table */
} hypertrace_vprovider_t;

typedef struct hypertrace_probe {
	hypertrace_vprovider_t *htpb_provider; /* Provider for this probe */
	dtrace_id_t htpb_id;                   /* id of the probe */
	uint16_t htpb_vmid;                    /* vmid of the probe */
	int htpb_running;                      /* is the probe allowed to run */
	int htpb_enabled;                      /* is the probe enabled? */
} hypertrace_probe_t;

extern dtrace_provider_id_t hypertrace_id;

typedef struct hypertrace_map {
	hypertrace_probe_t **probes[HYPERTRACE_MAX_VMS];
	size_t             nprobes[HYPERTRACE_MAX_VMS];
} hypertrace_map_t;

hypertrace_map_t *map_init(void);
void map_teardown(hypertrace_map_t *);

hypertrace_probe_t *map_get(hypertrace_map_t *, uint16_t, dtrace_id_t);
void map_insert(hypertrace_map_t *, hypertrace_probe_t *);
void map_rm(hypertrace_map_t *, hypertrace_probe_t *);


#endif /* __HYPERTRACE_IMPL_H_ */
