# $FreeBSD: head/lib/clang/libllvmx86disassembler/Makefile 249423 2013-04-12 17:57:40Z dim $

.include <bsd.own.mk>

LIB=	llvmx86disassembler

SRCDIR=	lib/Target/X86/Disassembler
INCDIR=	lib/Target/X86
SRCS=	X86Disassembler.cpp

.if ${MK_CLANG_EXTRAS} != "no"
SRCS+=	X86DisassemblerDecoder.c
.endif

TGHDRS=	X86GenDisassemblerTables \
	X86GenInstrInfo \
	X86GenRegisterInfo

.include "../clang.lib.mk"
