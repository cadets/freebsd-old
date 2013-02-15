# $FreeBSD: head/usr.bin/clang/llvm-extract/Makefile 246705 2013-02-12 05:56:00Z andrew $

.include <bsd.own.mk>

PROG_CXX=llvm-extract

SRCDIR=	tools/llvm-extract
SRCS=	llvm-extract.cpp

LIBDEPS=llvmasmparser \
	llvmbitwriter \
	llvmbitreader \
	llvmipo \
	llvmvectorize \
	llvmscalaropts \
	llvminstcombine \
	llvmtransformutils \
	llvmipa \
	llvmanalysis \
	llvmtarget \
	llvmmc \
	llvmobject \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
