# $FreeBSD$

.include "Makefile.inc"
.include <src.opts.mk>

SUBDIR=		dtaudit		\
		dtmalloc	\
		dtnfscl		\
		dtrace		\
		dtraceall	\
		dtrace_test	\
		hypertrace	\
		profile		\
		prototype	\
		sdt		\
		systrace

.if ${MACHINE_CPUARCH} == "amd64" || ${MACHINE_CPUARCH} == "i386"
SUBDIR+=	fasttrap fbt systrace_linux
.endif
.if ${MACHINE_CPUARCH} == "amd64"
SUBDIR+=	systrace_linux32
.endif
.if ${MACHINE_CPUARCH} == "powerpc"
SUBDIR+=	fbt fasttrap
.endif
.if ${MACHINE_CPUARCH} == "amd64" || \
    ${MACHINE_CPUARCH} == "aarch64" || \
    ${MACHINE_ARCH} == "mips64" || \
    ${MACHINE_ARCH} == "powerpc64"
SUBDIR+=	systrace_freebsd32
.endif
.if ${MACHINE_CPUARCH} == "aarch64" || \
    ${MACHINE_CPUARCH} == "arm" || \
    ${MACHINE_CPUARCH} == "mips" || \
    ${MACHINE_CPUARCH} == "powerpc" || \
    ${MACHINE_CPUARCH} == "riscv"
SUBDIR+=	fbt
.endif

.include <bsd.subdir.mk>
