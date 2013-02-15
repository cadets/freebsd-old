# $FreeBSD: head/usr.bin/clang/llvm-link/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-link

SRCDIR=	tools/llvm-link
SRCS=	llvm-link.cpp

LIBDEPS=llvmasmparser \
	llvmbitwriter \
	llvmlinker \
	llvmtransformutils \
	llvmipa \
	llvmanalysis \
	llvmtarget \
	llvmmc \
	llvmobject \
	llvmarchive \
	llvmbitreader \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
