# $FreeBSD$

LIBBBUF=	${SRCTOP}/contrib/libbbuf

PACKAGE=lib${LIB}
LIB=		bbuf	
PRIVATELIB=	true
SHLIB_MAJOR=	1
SHLIB_MINOR=	0

SRCS=		bbuf.c

.PATH:		${LIBBBUF}/src

INCS=		bbuf.h
INCSDIR=	${INCLUDEDIR}/private/bbuf

WARNS=		1
CFLAGS+=	-I${LIBBBUF}/src
CFLAGS+=	-Wno-implicit-function-declaration

.include <bsd.lib.mk>
