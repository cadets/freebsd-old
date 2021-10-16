/*-
 * Copyright (c) 2020 Domagoj Stolfa
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

#ifndef _DTTRANSPORT_H_
#define _DTTRANSPORT_H_

#define DTT_MAXDATALEN 2048ul

#define	DTT_ELF			1
#define	DTT_KILL		2
#define	DTT_CLEANUP_DTRACED	3

typedef struct dtt_entry {
	uint8_t event_kind; /* kind of event */

	union {
		struct {
			size_t len; /* length of the current message */
			size_t totallen; /* total length of the data */
			uint32_t identifier; /* unique identifier for data */
			int hasmore; /* are there more segments? */
			unsigned char data[DTT_MAXDATALEN]; /* the data itself */
		} elf;

		struct {
			pid_t pid;
		} kill;
	} u;
} dtt_entry_t;

_Static_assert(sizeof(dtt_entry_t) <= 4096, "dtt_entry_t must fit in one page");

#define	DTT_ENTRYLEN	sizeof(dtt_entry_t)

extern int	dtt_queue_enqueue(dtt_entry_t *);

#endif // _DTTRANSPORT_H_
