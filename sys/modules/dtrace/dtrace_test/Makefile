# $FreeBSD: head/sys/modules/dtrace/dtrace_test/Makefile 251237 2013-06-02 00:33:36Z markj $

.PATH: ${.CURDIR}/../../../cddl/dev/dtrace

KMOD=		dtrace_test
SRCS=		dtrace_test.c

SRCS+=		opt_kdtrace.h
SRCS+=		vnode_if.h

CFLAGS+=	-I${.CURDIR}/../../..

CFLAGS+=	-D_KERNEL

.include <bsd.kmod.mk>
