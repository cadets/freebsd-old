# $FreeBSD: head/usr.sbin/authpf/Makefile 240494 2012-09-14 11:51:49Z glebius $

.PATH:	${.CURDIR}/../../contrib/pf/authpf

PROG=	authpf
MAN=	authpf.8
BINOWN=	root
BINGRP= authpf
BINMODE= 6555

SRCS=   authpf.c

# XXX ALTQ:
CFLAGS+= -DENABLE_ALTQ

LDADD+= -lm -lmd -lutil
DPADD+= ${LIBM} ${LIBMD} ${LIBUTIL}

WARNS?=	3

.include <bsd.prog.mk>
