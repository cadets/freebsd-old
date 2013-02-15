#	From: @(#)Makefile	8.1 (Berkeley) 6/5/93
# $FreeBSD: head/share/doc/Makefile 241823 2012-10-22 01:18:41Z marcel $

.include <bsd.own.mk>

SUBDIR=	${_IPv6} \
	${_atf} \
	${_bind9} \
	legal \
	${_llvm} \
	${_roffdocs}

.if ${MK_ATF} != "no"
_atf= atf
.endif

.if ${MK_BIND} != "no"
_bind9=	bind9
.endif

.if ${MK_CLANG} != "no"
_llvm=	llvm
.endif

.if ${MK_INET6} != "no"
_IPv6=	IPv6
.endif

# FIXME this is not a real solution ...
.if ${MK_GROFF} != "no"
_roffdocs=	papers psd smm usd
.endif

# Default output format for troff documents is ascii.
# To generate postscript versions of troff documents, use:
#  make PRINTERDEVICE=ps

.include <bsd.subdir.mk>
