# $FreeBSD$

.include <bsd.own.mk>

PACKAGE=lib${LIB}
LIB=	netbsd

MK_BITCODE_EVERYWHERE=no

CFLAGS+=	-I${.CURDIR}

SRCS+=	efun.c sockaddr_snprintf.c strsuftoll.c util.c util.h

INTERNALLIB=

.include <bsd.lib.mk>
