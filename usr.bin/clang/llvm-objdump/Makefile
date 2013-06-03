# $FreeBSD: head/usr.bin/clang/llvm-objdump/Makefile 249423 2013-04-12 17:57:40Z dim $

NO_MAN=
.include <bsd.own.mk>

PROG_CXX=llvm-objdump

SRCDIR=	tools/llvm-objdump
SRCS=	llvm-objdump.cpp \
	COFFDump.cpp \
	ELFDump.cpp \
	MachODump.cpp \
	MCFunction.cpp

LIBDEPS=llvmmcdisassembler \
	llvmdebuginfo \
	llvmarmdisassembler \
	llvmarmcodegen \
	llvmarmasmparser \
	llvmarmdesc \
	llvmarminfo \
	llvmarminstprinter \
	llvmmipsdisassembler \
	llvmmipscodegen \
	llvmmipsasmparser \
	llvmmipsdesc \
	llvmmipsinfo \
	llvmmipsinstprinter \
	llvmpowerpccodegen \
	llvmpowerpcdesc \
	llvmpowerpcinfo \
	llvmpowerpcinstprinter \
	llvmx86disassembler \
	llvmx86asmparser \
	llvmx86codegen \
	llvmselectiondag \
	llvmasmprinter \
	llvmmcparser \
	llvmcodegen \
	llvmobjcarcopts \
	llvmscalaropts \
	llvminstcombine \
	llvmtransformutils \
	llvmipa \
	llvmanalysis \
	llvmx86desc \
	llvmx86info \
	llvmtarget \
	llvmx86instprinter \
	llvmmc \
	llvmobject \
	llvmx86utils \
	llvmcore \
	llvmsupport

.include "../clang.prog.mk"
