# $FreeBSD: head/lib/clang/libllvmx86asmparser/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvmx86asmparser

SRCDIR=	lib/Target/X86/AsmParser
INCDIR=	lib/Target/X86
SRCS=	X86AsmLexer.cpp \
	X86AsmParser.cpp

TGHDRS=	X86GenAsmMatcher \
	X86GenInstrInfo \
	X86GenRegisterInfo \
	X86GenSubtargetInfo

.include "../clang.lib.mk"
