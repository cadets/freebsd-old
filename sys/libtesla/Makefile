# $FreeBSD$

LIB=		tesla
#MAN=		tesla.3

SHLIB_MAJOR=	1
CFLAGS+=	-I${.CURDIR}

INCS=		tesla.h libtesla.h
SRCS=		debug.c key.c state.c state-global.c state-perthread.c \
		store.c update.c util.c

.include <bsd.lib.mk>

