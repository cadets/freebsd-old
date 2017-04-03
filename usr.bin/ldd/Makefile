# $FreeBSD$

# TODO: investigate why this fails to build (llvm-link not found!?)
MK_INSTRUMENT_BINARIES=	no

PROG?=		ldd
SRCS=		ldd.c
.if ${MACHINE_CPUARCH} == "i386"
SRCS+=		sods.c
.endif

.include <bsd.prog.mk>
