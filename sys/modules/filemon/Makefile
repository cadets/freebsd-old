# $FreeBSD: head/sys/modules/filemon/Makefile 241828 2012-10-22 02:12:11Z eadler $

.PATH: ${.CURDIR}/../../dev/filemon

KMOD=	filemon
SRCS=	${KMOD}.c
SRCS+=	vnode_if.h opt_compat.h opt_capsicum.h

.include <bsd.kmod.mk>
