# $Id$
# $FreeBSD: head/share/examples/autofs/driver/Makefile 204585 2010-03-02 16:58:04Z uqs $

PROG=		autodriver
NO_MAN=

SRCS=		autodriver.c
WARNS?=		4
CFLAGS+=	-g
BINDIR?=	/sbin

DPADD+=		${.OBJDIR}/../libautofs/libautofs.a
#LDADD+=		-lautofs
LDADD+=		${.OBJDIR}/../libautofs/libautofs.a
LDFLAGS+=	-L${.OBJDIR}/../libautofs
CFLAGS+=	-I${.CURDIR}/../libautofs

.include <bsd.prog.mk>
