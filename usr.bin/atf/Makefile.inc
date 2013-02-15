# $FreeBSD: head/usr.bin/atf/Makefile.inc 241823 2012-10-22 01:18:41Z marcel $

ATF=		${.CURDIR}/../../../contrib/atf

CFLAGS+=	-DGDB=\"gdb\"

BINDIR?=	/usr/bin
WARNS?=		3
