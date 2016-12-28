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

#ifndef _SYS_METAIO_H_
#define	_SYS_METAIO_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/msgid.h>
#include <sys/uuid.h>

/*
 * First cut at a system-call metadata structure for I/O.  Undoubtably, in the
 * future it will want to be more generalised (e.g., to carry multiple UUIDs),
 * but this is sufficient for some initial experimentation.
 */
struct metaio {
	lwpid_t		mio_tid;	/* Unique thread ID. */
	uint32_t	_mio_pad0;
	msgid_t		mio_syscallid;	/* Unique system-call ID. */
	msgid_t		mio_msgid;	/* Message ID for data, if any. */
	uint64_t	_mio_pad1;
	struct uuid	mio_uuid;	/* UUID for data, if any. */
};

__BEGIN_DECLS
/*
 * System calls returning metadata from the kernel on completion.
 */
struct iovec;
struct msghdr;
struct sockaddr;
caddr_t	metaio_mmap(caddr_t addr, size_t len, int prot, int flags, int fd,
	    off_t pos, struct metaio *miop);
ssize_t	metaio_pread(int fd, void *buf, size_t nbyte, off_t offset,
	    struct metaio *miop);
ssize_t	metaio_preadv(int fd, struct iovec *iovp, u_int iovcnt, off_t offset,
	    struct metaio *miop);
int	metaio_read(int fd, void *buf, size_t nbyte, struct metaio *miop);
int	metaio_readv(int fd, struct iovec *iovp, u_int iovcnt,
	    struct metaio *miop);
int	metaio_recvfrom(int s, caddr_t buf, size_t len, int flags,
	    struct sockaddr * __restrict from,
	    __socklen_t * __restrict fromlenaddr, struct metaio *miop);
int	metaio_recvmsg(int s, struct msghdr *msg, int flags,
	    struct metaio *miop);

/*
 * System calls accepting metadata for the kernel as an argument.
 */
struct sf_hdtr;
ssize_t	metaio_pwrite(int fd, const void *buf, size_t nbyte, off_t offset,
	    struct metaio *miop);
ssize_t	metaio_pwritev(int fd, struct iovec *iovp, u_int iovcnt, off_t offset,
	    struct metaio *miop);
int	metaio_sendfile(int fd, int s, off_t offset, size_t nbytes,
	    struct sf_hdtr *hdtr, off_t *sbytes, int flags,
	    struct metaio *miop);
int	metaio_sendmsg(int s, struct msghdr *msg, int flags,
	    struct metaio *miop);
int	metaio_sendto(int s, caddr_t buf, size_t len, int flags, caddr_t to,
	    int tolen, struct metaio *miop);
int	metaio_write(int fd, void *buf, size_t nbyte, struct metaio *miop);
int	metaio_writev(int fd, struct iovec *iovp, u_int iovcnt,
	    struct metaio *miop);

/*
 * UUID system calls -- probably belong in another header at some point.
 * Perhaps <sys/uuid.h>?
 */
int	fgetuuid(int fd, struct uuid *uuidp);
int	getuuid(const char *path, struct uuid *uuidp);
int	lgetuuid(const char *path, struct uuid *uuidp);
__END_DECLS

/*
 * In-kernel calls to manage and propagate I/O metadata.
 */
#ifdef _KERNEL
struct thread;
void	metaio_init(struct thread *td, struct metaio *miop);
void	metaio_from_uuid(struct uuid *uuidp, struct metaio *miop);
#endif /* _KERNEL */

#endif /* !_SYS_METAIO_H_ */
