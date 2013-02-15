# $Id$

PROG=	mount_smbfs
SRCS=	mount_smbfs.c getmntopts.c
MAN8=	mount_smbfs.8

BINDIR=	/sbin
#NOSHARED=yes

MOUNT=	${.CURDIR}/../mount
CFLAGS+= -DSMBFS -I${MOUNT}

.PATH:	${MOUNT}

LDADD+= -lsmb
DPADD+= ${LIBSMB}

.include <bsd.prog.mk>
