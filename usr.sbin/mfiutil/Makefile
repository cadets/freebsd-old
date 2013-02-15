# $FreeBSD: head/usr.sbin/mfiutil/Makefile 237260 2012-06-19 06:18:42Z eadler $
PROG=	mfiutil

SRCS=	mfiutil.c mfi_cmd.c mfi_config.c mfi_drive.c mfi_evt.c mfi_flash.c \
	mfi_patrol.c mfi_show.c mfi_volume.c
MAN8=	mfiutil.8

CFLAGS+= -fno-builtin-strftime

DPADD=	${LIBUTIL}
LDADD=	-lutil

# Here be dragons
.ifdef DEBUG
CFLAGS+= -DDEBUG
.endif

.include <bsd.prog.mk>
