# $Id$
# $FreeBSD: head/usr.sbin/bluetooth/hcsecd/Makefile 135245 2004-09-14 20:04:33Z emax $

PROG=		hcsecd
MAN=		hcsecd.8 hcsecd.conf.5
SRCS=		hcsecd.c lexer.l parser.y
WARNS?=		2
CFLAGS+=	-I${.CURDIR}

DPADD=		${LIBBLUETOOTH}
LDADD=		-lbluetooth

.include <bsd.prog.mk>
