# $FreeBSD: head/usr.bin/clang/Makefile 239513 2012-08-21 18:24:11Z dim $

.include <bsd.own.mk>

SUBDIR=	clang clang-tblgen tblgen

.if ${MK_CLANG_EXTRAS} != "no" && !defined(TOOLS_PREFIX)
SUBDIR+=bugpoint \
	llc \
	lli \
	llvm-ar \
	llvm-as \
	llvm-bcanalyzer \
	llvm-diff \
	llvm-dis \
	llvm-extract \
	llvm-link \
	llvm-mc \
	llvm-nm \
	llvm-objdump \
	llvm-prof \
	llvm-ranlib \
	llvm-rtdyld \
	macho-dump \
	opt
.endif

.include <bsd.subdir.mk>
