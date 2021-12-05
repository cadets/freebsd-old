.include <src.opts.mk>

CFLAGS+= -DIN_BASE
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/include
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/
CFLAGS+= -I${SRCTOP}/sys/contrib/openzfs/lib/libspl/include/os/freebsd
CFLAGS+= -I${SRCTOP}/sys
CFLAGS+= -I${SRCTOP}/cddl/compat/opensolaris/include
CFLAGS+= -I${SRCTOP}/sys/cddl/compat/opensolaris
CFLAGS+=	-I${SRCTOP}/sys/cddl/compat/opensolaris \
		-I${SRCTOP}/cddl/compat/opensolaris/include \
		-I${OPENSOLARIS_USR_DISTDIR}/head \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libdtrace/common \
		-I${OPENSOLARIS_USR_DISTDIR}/lib/libproc/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/uts/common \
		-I${OPENSOLARIS_SYS_DISTDIR}/compat \
		-I${SRCTOP}/sys
CFLAGS+= -DHAVE_ISSETUGID

PROG=	dtracetsc
SRCS=	dtracetsc.c
MAN=	dtracetsc.8

.if ${MK_DTRACE_DEBUG_ASAN} != "no"
CFLAGS+=	-fsanitize=address -fsanitize=undefined
LDFLAGS+=	-fsanitize=address -fsanitize=undefined
.elif ${MK_DTRACE_DEBUG_TSAN} != "no"
CFLAGS+=	-fsanitize=thread
LDFLAGS+=	-fsanitize=thread
.endif

LIBADD=	elf dtrace rt

.include <bsd.prog.mk>
