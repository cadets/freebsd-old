# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/dtraced

PROG=		dtraced
SRCS=		dtraced.c \
		dtraced_chld.c \
		dtraced_cleanupjob.c \
		dtraced_connection.c \
		dtraced_directory.c \
		dtraced_dttransport.c \
		dtraced_elfjob.c \
		dtraced_errmsg.c \
		dtraced_job.c \
		dtraced_killjob.c \
		dtraced_lock.c \
		dtraced_misc.c \
		dtraced_readjob.c \
		dtraced_sendinfojob.c \
		dtraced_state.c


MAN=		dtraced.8

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

.if ${MK_DTRACE_OPTIMIZED} != "no" && ${MACHINE_ARCH} != mips && \
    ${MACHINE_ARCH} != mips64 && ${MACHINE_ARCH} != powerpc64 && \
    ${MACHINE_ARCH} != riscv64
CFLAGS+=	-flto
LDFLAGS+=	-flto
.endif

.if ${MK_DTRACE_DEBUG_ASAN} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.elif ${MK_DTRACE_DEBUG_TSAN} != "no"
CFLAGS+=	-fsanitize=thread
LDFLAGS+=	-fsanitize=thread
.endif

.if ${MK_DTRACED_ROBUST} != "no"
CFLAGS+=	-DDTRACED_ROBUST
.endif

.if ${MK_DTRACED_DEBUG} != "no"
CFLAGS+=	-DDTRACED_DEBUG
.endif

.include <bsd.prog.mk>
