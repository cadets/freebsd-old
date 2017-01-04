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
#include <sys/msgid.h>
#include <sys/pcpu.h>
#include <sys/systm.h>

#include <machine/atomic.h>

/*
 * The Message ID (msgid) framework provides a lightweight alternative to
 * UUIDs in allowing host-unique identifiers to be associated with ephemeral
 * kernel objects (most typically, IPC messages of various sorts).  Rather
 * than ensuring strong global uniqueness (i.e., across hosts), message IDs
 * must provide a host-local unique identifier produced in a highly affordable
 * way so as to be used in critical fast paths (such as IPC send).  And,
 * unlike UUIDs, the assumption is that a message ID will only be unique for
 * the current boot -- some external mechanism must be used to disambiguate
 * message IDs generated during one boot from message IDs generated in
 * another.
 *
 * This is currently accomplished through the use of per-CPU ID spaces, in
 * which each CPU is delegated its own portion of a larger space, through
 * which it increments.  It is assumed that the log(CPUs) space taken up by a
 * unique CPU identifier in each message ID still leaves sufficient bits of
 * uniqueness that incrementing through the remaining portion of a 64-bit
 * integer will be sufficient to count all message-send events that might be
 * experienced in a particular boot.  This might be called into question if
 * the number of cores gets too high.
 */

/*
 * Assert that we have enough bits in MSGID_CPUBITS for MAXCPU cores.
 */
CTASSERT(MAXCPU <= (1 << MSGID_CPUBITS));

/*
 * Assert that if we burned at least MSGID_MAXPPS IDs a second per core, then
 * we have enough message ID space to run for at least 20 years.
 *
 * NB: To avoid uint64_t overflow at compile time, MSGID_MAXPPS is on the
 * right-hand side of the comparison, rather than the left.
 */
#define	MSGID_MAXPPS		50000000ULL	/* 50M packets/sec/core */
#define	MSGID_SECSPERYEAR	(365ULL*24ULL*60ULL*60ULL)
#define	MSGID_MINYEARS		20ULL
CTASSERT((MSGID_MINYEARS * MSGID_SECSPERYEAR) <
    ((1ULL << MSGID_COUNTERBITS) / MSGID_MAXPPS));

/*
 * Per-CPU state: the next message ID value to be allocated by the CPU.
 * Initialise explicitly to a non-zero value so that uninitialised messsage
 * IDs can be more easily recognised.  The upper D_CPUBITS bits of ms_next
 * will be ignored.
 */
struct msgid_state {
	msgid_t		ms_next;
};
DPCPU_DEFINE(struct msgid_state, msgid_state) = { 1 };

void
msgid_generate(msgid_t *msgidp)
{
	msgid_t id;

	/*
	 * As the message ID is opaque to the consumer, and an atomic is used,
	 * it is safe for the current thread to be migrated even after
	 * calculating the pointer to per-CPU state.
	 *
	 * XXXRW: Is this cheaper than entering a critical section and using
	 * integer operations..?
	 */
	id = atomic_fetchadd_64(DPCPU_PTR(msgid_state.ms_next), 1);
	KASSERT(id < (1ULL << MSGID_COUNTERBITS),
	    ("%s: message ID overflow CPU %u", __func__, curcpu));
	MSGID_SETCPU(id, (uint64_t)curcpu);
	*msgidp = id;
}

/*
 * Check whether a message ID is valid.  This is simply a check for a zero
 * value, which should never be seen as all of the per-CPU counters start at
 * 1.  Consumers should therefore not assume that this differentiates garbage
 * from a valid message ID, just zero from a valid message ID.
 */
int
msgid_isvalid(msgid_t *msgidp)
{

	return (*msgidp != 0);
}
