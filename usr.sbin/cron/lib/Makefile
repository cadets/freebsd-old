# $FreeBSD$

LIB=	cron
MK_BITCODE_EVERYWHERE=no

INTERNALLIB=
SRCS= entry.c env.c misc.c

WARNS?=	3

CFLAGS+= -I${.CURDIR:H}/cron
CFLAGS+= -DLOGIN_CAP -DPAM

.include <bsd.lib.mk>
