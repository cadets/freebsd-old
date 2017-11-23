# $FreeBSD$

.include <src.opts.mk>

SYSDIR?=	${SRCTOP}/sys

.PATH:		${SYSDIR}/cddl/dev/vtdtr

KMOD=		vtdtr
SRCS=		vtdtr.c	\
		vnode_if.h

CFLAGS+=	-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common/dtrace \
		-I${SYSDIR}

EXPORT_SYMS=	vtdtr_enqueue

.include <bsd.kmod.mk>

CFLAGS+=	-include ${SYSDIR}/cddl/compat/opensolaris/sys/debug_compat.h

