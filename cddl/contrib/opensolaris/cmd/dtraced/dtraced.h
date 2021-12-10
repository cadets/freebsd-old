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

#ifndef __DTRACED_H_
#define __DTRACED_H_

#include <sys/types.h>

#include <stdint.h>

#define DTRACED_MAJOR                  0
#define DTRACED_MINOR                  3
#define DTRACED_PATCH                  0
#define DTRACED_EXTRA_IDENTIFIER       "BETA"

#define	DTRACED_SOCKPATH               "/var/ddtrace/sub.sock"

#define	DTRACED_KIND_UNKNOWN           0
#define	DTRACED_KIND_CONSUMER          1
#define	DTRACED_KIND_FORWARDER         2
#define	DTRACED_KIND_DTRACED           3

#define DTD_SUB_READDATA               1
#define DTD_SUB_ELFWRITE               (1 << 1)
#define DTD_SUB_KILL                   (1 << 2)
#define DTD_SUB_CLEANUP                (1 << 3)
#define DTD_SUB_INFO                   (1 << 4)

#define DTRACED_LOCSIZE                64ul
#define DTRACED_PROGIDENTLEN           128ull

#define DTRACED_FDIDENTLEN             128ull

typedef struct dtraced_hdr {
	uint64_t msg_type;      /* message type (see DTRACED_MSG_*) */
	struct {
		size_t len;                       /* elf length */
		int ident_present;                /* identifier present? */
		int filter_by_vmid;               /* should we filter? */
		uint16_t vmid;                    /* which VM? (if filtered) */
		char location[DTRACED_LOCSIZE];	  /* elf location */
		char ident[DTRACED_PROGIDENTLEN]; /* program identifier */
	} elf;

	struct {
		pid_t pid;     /* process id to kill */
		uint16_t vmid; /* vmid to kill the pid on */
	} kill;

	struct {
		size_t num_entries; /* number of entries to clean up */
	} cleanup;

	struct {
		size_t count; /* length of the buffer to follow */
	} info;
} dtraced_hdr_t;

typedef struct dtd_initmsg {
	int kind;                       /* kind (see above) */
	uint64_t subs;                  /* what are we subscribing to? */
	char ident[DTRACED_FDIDENTLEN]; /* human-readable string identifier */
} dtd_initmsg_t;

typedef struct dtraced_infomsg {
	int client_kind;
	char client_name[DTRACED_FDIDENTLEN];
} dtraced_infomsg_t;

#define	DTRACED_MSGHDRSIZE             sizeof(dtraced_hdr_t)

/*
 * Public message API
 */
#define DTRACED_MSG_ELF                1
#define DTRACED_MSG_KILL               2
#define DTRACED_MSG_CLEANUP            3
#define DTRACED_MSG_INFO               4
#define DTRACED_MSG_LAST               4

#define DTRACED_MSG_TYPE(m)            ((m).msg_type)
#define DTRACED_MSG_LOC(m)             ((m).elf.location)
#define DTRACED_MSG_IDENT(m)           ((m).elf.ident)
#define DTRACED_MSG_IDENT_PRESENT(m)   ((m).elf.ident_present)
#define DTRACED_MSG_LEN(m)             ((m).elf.len)
#define DTRACED_MSG_KILLPID(m)         ((m).kill.pid)
#define DTRACED_MSG_KILLVMID(m)        ((m).kill.vmid)
#define DTRACED_MSG_NUMENTRIES(m)      ((m).cleanup.num_entries)


#endif // __DTRACED_H_
