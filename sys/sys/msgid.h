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

#ifndef _SYS_MSGID_H_
#define	_SYS_MSGID_H_

/*
 * Message IDs: a lightweight alternative to UUIDs to provide unique
 * identifiers for ephemeral kernel objects.  This typedef should be preferred
 * to the underlying integer type as in the future this might need to change
 * to a larger integer type or even struct.
 */
typedef uint64_t	msgid_t;

/*
 * Assign various bits of the type to hold a CPU identifier, and the remaining
 * bits to be used as a counter.  See subr_msgid.c for compile-time assertions
 * constraining possible values for these bits.
 */
#define	MSGID_CPUBITS		9ULL		/* At most 512 CPUs. */
#define	MSGID_COUNTERBITS	(sizeof(msgid_t)*8ULL - MSGID_CPUBITS)
#define	MSGID_CPUMASK							\
	    (((1ULL << MSGID_CPUBITS) - 1ULL) << MSGID_COUNTERBITS)
#define	MSGID_COUNTERMASK	((1ULL << MSGID_COUNTERBITS) - 1ULL)

/*
 * Macros to get and set the CPU ID portion of a message ID.
 */
#define	MSGID_GETCPU(id)						\
	(((id) & MSGID_CPUMASK) >> MSGID_COUNTERBITS)

#define	MSGID_SETCPU(id, cpu) do {					\
	(id) &= ~MSGID_CPUMASK;						\
	(id) |= ((cpu) << MSGID_COUNTERBITS);				\
} while (0)

__BEGIN_DECLS
void	msgid_generate(msgid_t *);
int	msgid_isvalid(msgid_t *msgidp);
__END_DECLS

#endif /* _SYS_MSGID_H_ */
