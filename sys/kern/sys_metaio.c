/*-
 * Copyright (c) 2016 Robert N. M. Watson
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
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/cdefs.h>
__FBSDID("$FreeBSD$");

#include "opt_metaio.h"

#include <sys/param.h>
#include <sys/metaio.h>
#include <sys/proc.h>
#include <sys/sysproto.h>
#include <sys/systm.h>

#include <security/audit/audit.h>

#ifdef METAIO
/*
 * Fixed binary interface; compile-time assertion of size that should be the
 * same across all architectures.
 */
CTASSERT(sizeof(struct metaio) == 48);

/*
 * Initialise I/O metadata structure early in a system call.
 */
void
metaio_init(struct thread *td, struct metaio *miop)
{

	bzero(miop, sizeof(*miop));
	miop->mio_tid = td->td_tid;
}

/*
 * When I/O metadata is requested from a kernel I/O source, propagate this
 * information to the caller-provided (in-kernel) metaio buffer.
 */
void
metaio_from_uuid(struct uuid *uuidp, struct metaio *miop)
{

	if (miop == NULL)
		return;

	/* XXXRW: Should we also be propagating any other state here? */
	miop->mio_uuid = *uuidp;
}
#endif /* METAIO */
