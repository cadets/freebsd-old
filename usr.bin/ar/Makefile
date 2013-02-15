# $FreeBSD: head/usr.bin/ar/Makefile 234782 2012-04-29 09:32:44Z kib $

.include <bsd.own.mk>

PROG=	ar
SRCS=	ar.c acplex.l acpyacc.y read.c util.c write.c y.tab.h

DPADD=	${LIBARCHIVE} ${LIBELF}
LDADD=	-larchive -lelf

CFLAGS+=-I. -I${.CURDIR}

.if ${MK_SHARED_TOOLCHAIN} == "no"
NO_SHARED?=	yes
.endif
LINKS=	${BINDIR}/ar ${BINDIR}/ranlib
MLINKS= ar.1 ranlib.1

.include <bsd.prog.mk>
