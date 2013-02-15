# $FreeBSD: head/usr.bin/clang/llvm-as/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-as

SRCDIR=	tools/llvm-as
SRCS=	llvm-as.cpp
LLVM_REQUIRES_EH=

LIBDEPS=llvmbitwriter \
	llvmasmparser \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
