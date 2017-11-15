SYSDIR?= ${SRCTOP}/sys

.PATH: ${SYSDIR}/cddl/dev/dtvirt

KMOD= dtvirt
SRCS= dtvirt.c


CFLAGS+=	-I${SYSDIR}/cddl/dev/dtvirt \
		-I${SYSDIR}/cddl/compat/opensolaris \
		-I${SYSDIR}/cddl/contrib/opensolaris/uts/common \
		-I${SYSDIR}

.include <bsd.kmod.mk>
