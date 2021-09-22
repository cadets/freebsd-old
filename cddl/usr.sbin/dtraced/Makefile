# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/dtraced

PROG=		dtraced
SRCS=		dtraced.c \
		dtraced_chld.c \
		dtraced_connection.c \
		dtraced_directory.c \
		dtraced_dttransport.c \
		dtraced_errmsg.c \
		dtraced_job.c \
		dtraced_lock.c \
		dtraced_misc.c \
		dtraced_state.c

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

LIBADD=	dtrace ctf elf proc pthread crypto execinfo util

.if ${MK_DTRACE_DEBUG} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.endif

.include <bsd.prog.mk>
