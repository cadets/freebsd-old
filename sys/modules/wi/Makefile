# $FreeBSD: head/sys/modules/wi/Makefile 231838 2012-02-16 21:57:50Z uqs $

.PATH: ${.CURDIR}/../../dev/wi

KMOD=	if_wi
SRCS=	if_wi.c if_wi_pccard.c if_wi_pci.c \
	card_if.h device_if.h bus_if.h pci_if.h pccarddevs.h \
	opt_wlan.h

.include <bsd.kmod.mk>
