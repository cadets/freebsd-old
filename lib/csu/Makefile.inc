# $FreeBSD: head/lib/csu/Makefile.inc 232832 2012-03-11 20:04:09Z kib $

SSP_CFLAGS=

SED_FIX_NOTE = -i "" -e '/\.note\.tag/s/progbits/note/'

.include "../Makefile.inc"
