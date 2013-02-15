# $FreeBSD: head/gnu/usr.bin/patch/Makefile 246074 2013-01-29 17:03:18Z gabor $

.include <bsd.own.mk>

.if ${MK_BSD_PATCH} == "yes"
PROG=	gnupatch
CLEANFILES+= gnupatch.1

gnupatch.1: patch.1
	cp ${.ALLSRC} ${.TARGET}
.else
PROG=	patch
.endif

SRCS=   backupfile.c inp.c patch.c pch.c util.c version.c
CFLAGS+=-DHAVE_CONFIG_H

.include <bsd.prog.mk>
