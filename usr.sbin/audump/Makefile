#
# $FreeBSD$
#

OPENBSMDIR=${.CURDIR}/../../contrib/openbsm
.PATH: ${OPENBSMDIR}/tools

CFLAGS+=	-I${OPENBSMDIR}

PROG=	audump

LIBADD=	bsm

WARNS?=	5

.include <bsd.prog.mk>
