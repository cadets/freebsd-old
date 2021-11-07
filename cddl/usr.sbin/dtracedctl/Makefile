# $FreeBSD$

.include <src.opts.mk>

.PATH: ${SRCTOP}/cddl/contrib/opensolaris/cmd/dtracedctl

PROG=		dtracedctl
SRCS=		dtracedctl.c

MAN=		dtracedctl.8

BINDIR?=	/usr/sbin

WARNS?=		1

CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${SRCTOP}/cddl/contrib/opensolaris/cmd/dtraced \
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

# TODO: LLVM changes this to ignorelist. Needs to be fixed in the future.
.if ${MK_DTRACE_DEBUG_ASAN} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.elif ${MK_DTRACE_DEBUG_TSAN} != "no"
CFLAGS+=	-fsanitize=thread
LDFLAGS+=	-fsanitize=thread
.endif

.include <bsd.prog.mk>
