#
# $FreeBSD$
#

.include <bsd.mkopt.mk>
.include <src.opts.mk>

PROG=	bhyve
PACKAGE=	bhyve

DEBUG_FLAGS= -g -O0

MAN=	bhyve.8

BHYVE_SYSDIR?=${SRCTOP}

SRCS=	\
	atkbdc.c		\
	acpi.c			\
	bhyvegc.c		\
	bhyverun.c		\
	block_if.c		\
	bootrom.c		\
	console.c		\
	consport.c		\
	dbgport.c		\
	fwctl.c			\
	inout.c			\
	ioapic.c		\
	mem.c			\
	mevent.c		\
	mptbl.c			\
	pci_ahci.c		\
	pci_e82545.c		\
	pci_emul.c		\
	pci_fbuf.c		\
	pci_hostbridge.c	\
	pci_irq.c		\
	pci_lpc.c		\
	pci_passthru.c		\
	pci_virtio_block.c	\
	pci_virtio_console.c	\
	pci_virtio_net.c	\
	pci_virtio_rnd.c	\
	pci_uart.c		\
	pci_xhci.c		\
	pm.c			\
	post.c			\
	ps2kbd.c		\
	ps2mouse.c		\
	rfb.c			\
	rtc.c			\
	smbiostbl.c		\
	sockstream.c		\
	task_switch.c		\
	uart_emul.c		\
	usb_emul.c		\
	usb_mouse.c		\
	virtio.c		\
	vga.c			\
	xmsr.c			\
	spinup_ap.c


.if ${MK_DTVIRT} != "no"
SRCS+=  dthyve.c pci_virtio_dtrace.c
DTHYVE_INCLUDES= -I${.CURDIR}/../../cddl/compat/opensolaris/include
DTHYVE_INCLUDES+= -I${.CURDIR}/../../cddl/contrib/opensolaris/lib/libdtrace/common
DTHYVE_INCLUDES+= -I${.CURDIR}/../../cddl/contrib/opensolaris/lib/libctf/common
DTHYVE_INCLUDES+= -I${.CURDIR}/../../cddl/lib/libdtrace
DTHYVE_INCLUDES+= -I${.CURDIR}/../../sys/cddl/compat/opensolaris
DTHYVE_INCLUDES+= -I${.CURDIR}/../../sys/cddl/contrib/opensolaris/uts/common
DTHYVE_CFLAGS= -O2 -Wall -Wextra
DTHYVE_LDFLAGS= -l dtrace -l proc -l ctf -l elf -l z -l rtld_db -l pthread -l util

dthyve.o:
	${CC} -D NEED_SOLARIS_BOOLEAN -c ${DTHYVE_INCLUDES} ${DTHYVE_CFLAGS} \
		${.IMPSRC} -o ${.TARGET}

CFLAGS+= -D DTVIRT
LDFLAGS+= -l dtrace -l proc -l ctf -l elf -l z -l rtld_db -l pthread -l util
.endif

.PATH:  ${BHYVE_SYSDIR}/sys/amd64/vmm
SRCS+=	vmm_instruction_emul.c

LIBADD=	vmmapi md pthread z

.if ${MK_OPENSSL} == "no"
CFLAGS+=-DNO_OPENSSL
.else
LIBADD+=	crypto
.endif

CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/e1000
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/mii
CFLAGS+= -I${BHYVE_SYSDIR}/sys/dev/usb/controller

WARNS?=	2

.include <bsd.prog.mk>
