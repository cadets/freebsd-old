# $FreeBSD: head/usr.bin/clang/llvm-ar/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-ar

SRCDIR=	tools/llvm-ar
SRCS=	llvm-ar.cpp
LLVM_REQUIRES_EH=

LIBDEPS=llvmarchive \
	llvmbitreader \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
