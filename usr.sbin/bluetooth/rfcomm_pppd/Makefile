# $Id$
# $FreeBSD: head/usr.sbin/bluetooth/rfcomm_pppd/Makefile 121054 2003-10-12 22:04:24Z emax $

.PATH:	${.CURDIR}/../../../usr.bin/bluetooth/rfcomm_sppd

PROG=		rfcomm_pppd
MAN=		rfcomm_pppd.8
SRCS=		rfcomm_pppd.c rfcomm_sdp.c
WARNS?=		2

DPADD=		${LIBBLUETOOTH} ${LIBSDP}
LDADD=		-lbluetooth -lsdp

.include <bsd.prog.mk>
