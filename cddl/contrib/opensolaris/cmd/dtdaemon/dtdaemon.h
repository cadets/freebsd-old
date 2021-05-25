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

#ifndef __DTDAEMON_H_
#define __DTDAEMON_H_

#define	DTDAEMON_SOCKPATH               "/var/ddtrace/sub.sock"

#define	DTDAEMON_KIND_UNKNOWN           0
#define	DTDAEMON_KIND_CONSUMER          1
#define	DTDAEMON_KIND_FORWARDER         2
#define	DTDAEMON_KIND_DTDAEMON          3

#define DTD_SUB_READDATA                1
#define DTD_SUB_ELFWRITE                (1 << 1)

#define DTDAEMON_LOCSIZE                64ul

typedef struct dtdaemon_hdr {
	uint64_t msg_type;      /* message type (see DTDAEMON_MSG_*) */
	struct {
		char location[DTDAEMON_LOCSIZE]; /* elf location */
	} elf;

	struct {
		pid_t pid; /* process id to kill */
	} kill;
} dtdaemon_hdr_t;

typedef struct dtd_initmsg {
	int kind;       /* kind (see above) */
	uint64_t subs;  /* what are we subscribing to? */
} dtd_initmsg_t;

#define	DTDAEMON_MSGHDRSIZE             sizeof(dtdaemon_hdr_t)

/*
 * Public message API
 */
#define	DTDAEMON_MSG_ELF                1
#define	DTDAEMON_MSG_KILL               2
#define	DTDAEMON_MSG_LAST               2

#define	DTDAEMON_MSG_TYPE(m)            ((m).msg_type)
#define	DTDAEMON_MSG_LOC(m)             ((m).elf.location)
#define DTDAEMON_MSG_KILLPID(m)         ((m).kill.pid)

#endif // __DTDAEMON_H_
