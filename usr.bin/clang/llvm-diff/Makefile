# $FreeBSD: head/usr.bin/clang/llvm-diff/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-diff

SRCDIR=	tools/llvm-diff
SRCS=	llvm-diff.cpp \
	DiffConsumer.cpp \
	DiffLog.cpp \
	DifferenceEngine.cpp

LIBDEPS=llvmbitreader \
	llvmasmparser \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
