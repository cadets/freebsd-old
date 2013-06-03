# $FreeBSD: head/gnu/usr.bin/cc/include/Makefile 250393 2013-05-08 22:54:53Z dim $

.include <bsd.own.mk>

.include "../Makefile.inc"

INCSDIR=${INCLUDEDIR}/gcc/${GCCVER}

.PATH: ${GCCDIR}/config/${GCC_CPU}

.if ${TARGET_ARCH} == "i386" || ${TARGET_ARCH} == "amd64"
INCS=	emmintrin.h mmintrin.h mm3dnow.h pmmintrin.h tmmintrin.h xmmintrin.h \
	mm_malloc.h
.elif ${TARGET_ARCH} == "ia64"
INCS=	ia64intrin.h
.elif ${TARGET_ARCH} == "arm"
INCS=	mmintrin.h
.elif ${TARGET_ARCH} == "powerpc" || ${TARGET_ARCH} == "powerpc64"
INCS=	ppc-asm.h altivec.h spe.h
.endif

mm_malloc.h: pmm_malloc.h
	@rm -rf ${.TARGET}
	@cp ${.ALLSRC} ${.TARGET}
CLEANFILES+=	mm_malloc.h

.include <bsd.prog.mk>
