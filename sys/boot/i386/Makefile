# $FreeBSD$

.include <src.opts.mk>

SUBDIR=		mbr pmbr boot0 boot0sio btx boot2 cdboot gptboot kgzldr \
		libi386 libfirewire loader

# special boot programs, 'self-extracting boot2+loader'
SUBDIR+=	pxeldr

.if ${MK_ZFS} != "no"
SUBDIR+=	zfsboot gptzfsboot zfsloader
.endif

.if ${MK_LLVM_INSTRUMENTED} == "yes"
# External clang currently breaks in boot2
SUBDIR:=	${SUBDIR:Nboot2}
.endif

.include <bsd.subdir.mk>
