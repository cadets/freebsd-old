# $FreeBSD$

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/hypertrace

KMOD=		hypertrace
SRCS=		hypertrace.c \
		hypertrace_map.c

SRCS+=		vnode_if.h


CFLAGS+=	${OPENZFS_CFLAGS}
CFLAGS+=	-I${SYSDIR}/cddl/dev/hypertrace -I${SYSDIR}/cddl/dev/dtrace

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h
CWARNFLAGS+=	${OPENZFS_CWARNFLAGS}
