# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/dtrace

PROG=		dtrace
SRCS=		dtrace.c
BINDIR?=	/usr/sbin

WARNS?=		1

CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libproc/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/compat \
		-I${SRCTOP}/cddl/contrib/opensolaris/cmd/dtdaemon


CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined

# Optional debugging stuff...
#CFLAGS+=	-DNEED_ERRLOC
#YFLAGS+=	-d

LIBADD=	dtrace ctf elf proc pthread

.if ${MK_DTRACE_TESTS} != "no"
SUBDIR+=	tests
.endif

.include <bsd.prog.mk>
