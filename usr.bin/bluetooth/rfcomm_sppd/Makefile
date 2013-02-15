# $Id$
# $FreeBSD: head/usr.bin/bluetooth/rfcomm_sppd/Makefile 140941 2005-01-28 16:08:11Z ru $

PROG=		rfcomm_sppd
SRCS=		rfcomm_sppd.c rfcomm_sdp.c
WARNS?=		2

DPADD=		${LIBBLUETOOTH} ${LIBSDP}
LDADD=		-lbluetooth -lsdp

.include <bsd.prog.mk>
