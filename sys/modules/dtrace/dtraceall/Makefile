# $FreeBSD: head/sys/modules/dtrace/dtraceall/Makefile 239971 2012-09-01 07:35:16Z rpaulo $

KMOD=		dtraceall
SRCS=		dtraceall.c opt_compat.h opt_nfs.h

CFLAGS+=	-I${.CURDIR}/../../..

.if !defined(KERNBUILDDIR)
.if ${MACHINE_ARCH} == "amd64"
opt_compat.h:
	echo "#define COMPAT_FREEBSD32 1" >> ${.TARGET}
.endif
.endif

.include <bsd.kmod.mk>
