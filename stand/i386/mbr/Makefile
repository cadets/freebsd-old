# $FreeBSD$

PROG=	mbr
STRIP=
BINMODE=${NOBINMODE}
SRCS=	${PROG}.S

MK_INSTRUMENT_BINARIES=	no

# MBR flags: 0x80 -- try packet interface (also known as EDD or LBA)
BOOT_MBR_FLAGS?=	0x80

ORG=	0x600

ACFLAGS+=-Wa,-defsym,FLAGS=${BOOT_MBR_FLAGS}
LDFLAGS+=${LDFLAGS_BIN}

.include <bsd.prog.mk>
