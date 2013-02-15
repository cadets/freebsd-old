#$FreeBSD: head/kerberos5/lib/libheimipcc/Makefile 236337 2012-05-30 22:21:25Z obrien $

LIB=	heimipcc
INTERNALLIB=
LDADD=	-lheimbase -lroken -lpthread
DPADD=	${LIBHEIMBASE} ${LIBROKEN} ${LIBPTHREAD}

SRCS=	\
	client.c \
	common.c

CFLAGS+=	-DPIC ${PICFLAG}
CFLAGS+=	-I${KRB5DIR}/lib/roken \
		-I${KRB5DIR}/base \
		-I${KRB5DIR}/lib/ipc

.include <bsd.lib.mk>

.PATH: ${KRB5DIR}/lib/ipc
