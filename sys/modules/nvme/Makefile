# $FreeBSD: head/sys/modules/nvme/Makefile 249420 2013-04-12 17:48:45Z jimharris $

.PATH: ${.CURDIR}/../../dev/nvme

KMOD = nvme

SRCS =	nvme.c			\
	nvme_ctrlr.c		\
	nvme_ctrlr_cmd.c	\
	nvme_ns.c		\
	nvme_ns_cmd.c		\
	nvme_qpair.c		\
	nvme_sysctl.c		\
	nvme_test.c		\
				\
	bus_if.h		\
	device_if.h		\
	pci_if.h

.include <bsd.kmod.mk>
