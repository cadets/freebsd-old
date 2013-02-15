# $FreeBSD: head/gnu/usr.bin/dialog/Makefile 244933 2013-01-01 18:31:21Z antoine $

DIALOG=	${.CURDIR}/../../../contrib/dialog
PROG=   dialog

DPADD=	${LIBDIALOG} ${LIBNCURSESW} ${LIBM}
LDADD=	-ldialog -lncursesw -lm
CFLAGS+= -I${.CURDIR} -I${DIALOG}
.PATH:	${DIALOG}

WARNS?= 3

.include <bsd.prog.mk>
