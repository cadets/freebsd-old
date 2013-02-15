# $FreeBSD: head/usr.bin/clang/llvm-bcanalyzer/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-bcanalyzer

SRCDIR=	tools/llvm-bcanalyzer
SRCS=	llvm-bcanalyzer.cpp
LLVM_REQUIRES_EH=

LIBDEPS=llvmbitreader \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
