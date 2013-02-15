# $FreeBSD: head/usr.bin/bmake/Makefile.inc 243115 2012-11-16 01:37:25Z sjg $ 

.include "bsd.own.mk"

.if defined(.PARSEDIR)
# make sure this is available to unit-tests/Makefile
.export SRCTOP
.endif

.if ${MK_BMAKE} != "no"
PROG= make
.endif

.if ${MK_SHARED_TOOLCHAIN} == "no"
NO_SHARED?=     YES
.endif

WARNS=3
