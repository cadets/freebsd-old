# $FreeBSD: head/sys/modules/cyclic/Makefile 233411 2012-03-24 05:16:26Z gonzo $

.PATH: ${.CURDIR}/../../cddl/dev/cyclic

KMOD=		cyclic
SRCS=		cyclic.c

SRCS+=		vnode_if.h

CFLAGS+=	-I${.CURDIR}/../../cddl/compat/opensolaris		\
		-I${.CURDIR}/../../cddl/contrib/opensolaris/uts/common	\
		-I${.CURDIR}/../..					\
		-I${.CURDIR}/../../cddl/dev/cyclic/i386

CFLAGS+=	-DDEBUG=1

IGNORE_PRAGMA=	1

.include <bsd.kmod.mk>
