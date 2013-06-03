# $FreeBSD: head/usr.sbin/bsdconfig/share/media/Makefile 247280 2013-02-25 19:55:32Z dteske $

NO_OBJ=

FILESDIR=	${SHAREDIR}/bsdconfig/media
FILES=		any.subr cdrom.subr common.subr directory.subr dos.subr \
		floppy.subr ftp.subr httpproxy.subr network.subr nfs.subr \
		options.subr tcpip.subr ufs.subr usb.subr

beforeinstall:
	mkdir -p ${DESTDIR}${FILESDIR}

.include <bsd.prog.mk>
