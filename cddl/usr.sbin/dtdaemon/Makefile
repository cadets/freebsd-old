# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/dtdaemon

PROG=		dtdaemon
SRCS=		dtdaemon.c
BINDIR?=	/usr/sbin

WARNS?=		1

CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libproc/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/compat \
		-I${SRCTOP}/sys/dev/dttransport

# Optional debugging stuff...
#CFLAGS+=	-DNEED_ERRLOC
#YFLAGS+=	-d

LIBADD=	dtrace ctf elf proc pthread crypto

CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined

.include <bsd.prog.mk>
