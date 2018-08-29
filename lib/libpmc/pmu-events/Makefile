# $FreeBSD$

PROG=	jevents
SRCS=	jevents.c jsmn.c json.c
CFLAGS+= -Wno-cast-qual
MAN=

MK_INSTRUMENT_BINARIES=	no

build-tools: jevents

.include <bsd.prog.mk>
