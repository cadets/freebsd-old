/*-
 * Copyright (c) 2019 Domagoj Stolfa
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
#include <sys/mbufid.h>
#include <sys/msgid.h>
#include <sys/pcpu.h>
#include <sys/systm.h>
#include <sys/dtrace_bsd.h>

#include <sys/ddtrace.h>

void
mbufid_assert_sanity(mbufid_t *mbufidp)
{

	if (mbufid_isvalid(mbufidp))
		KASSERT(mbufidp->mid_magic == MBUFID_MAGIC_NUMBER,
			("%s: mbufid magic number is %lx but should be %lx",
			 __func__, mbufidp->mid_magic, MBUFID_MAGIC_NUMBER));
}

void
mbufid_generate(mbufid_t *mbufidp)
{

	/*
	 * Save the generated host ID in the mbuf id. The host ID
	 * is in network byte order already, so no conversion is
	 * needed here.
	 */
	mbufidp->mid_hostid = dtrace_node_id;
	msgid_generate(&mbufidp->mid_msgid);

	mbufidp->mid_magic = MBUFID_MAGIC_NUMBER;

	SDT_PROBE1(ddtrace, , tag, gen, mbufidp);
}

int
mbufid_isvalid(mbufid_t *mbufidp)
{

	/*
	 * Currently we just check for mid_hostid != 0, but there might be
	 * some room to take some well known uuids that are not to be used,
	 * precalculate their hashes (if possible) and check against that?
	 */
	return (msgid_isvalid(&mbufidp->mid_msgid) &&
	    mbufidp->mid_hostid != 0);
}
