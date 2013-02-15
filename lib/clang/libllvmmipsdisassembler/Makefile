# $FreeBSD: head/lib/clang/libllvmmipsdisassembler/Makefile 246259 2013-02-02 22:28:29Z dim $

.include <bsd.own.mk>

LIB=	llvmmipsdisassembler

SRCDIR=	lib/Target/Mips/Disassembler
INCDIR=	lib/Target/Mips
SRCS=	MipsDisassembler.cpp

TGHDRS=	MipsGenDisassemblerTables \
	MipsGenEDInfo \
	MipsGenInstrInfo \
	MipsGenRegisterInfo \
	MipsGenSubtargetInfo

.include "../clang.lib.mk"
