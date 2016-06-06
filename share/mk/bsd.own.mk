# $FreeBSD$
#
# The include file <bsd.own.mk> set common variables for owner,
# group, mode, and directories. Defaults are in brackets.
#
#
# +++ variables +++
#
# DESTDIR	Change the tree where the file gets installed. [not set]
#
# DISTDIR	Change the tree where the file for a distribution
# 		gets installed (see /usr/src/release/Makefile). [not set]
#
# COMPRESS_CMD	Program to compress documents.
#		Output is to stdout. [gzip -cn]
#
# COMPRESS_EXT	File name extension of ${COMPRESS_CMD} command. [.gz]
#
# BINOWN	Binary owner. [root]
#
# BINGRP	Binary group. [wheel]
#
# BINMODE	Binary mode. [555]
#
# NOBINMODE	Mode for non-executable files. [444]
#
# LIBDIR	Base path for libraries. [/usr/lib]
#
# LIBCOMPATDIR	Base path for compat libraries. [/usr/lib/compat]
#
# LIBDATADIR	Base path for misc. utility data files. [/usr/libdata]
#
# LIBEXECDIR	Base path for system daemons and utilities. [/usr/libexec]
#
# LINTLIBDIR	Base path for lint libraries. [/usr/libdata/lint]
#
# SHLIBDIR	Base path for shared libraries. [${LIBDIR}]
#
# LIBOWN	Library owner. [${BINOWN}]
#
# LIBGRP	Library group. [${BINGRP}]
#
# LIBMODE	Library mode. [${NOBINMODE}]
#
#
# DEBUGDIR	Base path for standalone debug files. [/usr/lib/debug]
#
# DEBUGMODE	Mode for debug files. [${NOBINMODE}]
#
#
# KMODDIR	Base path for loadable kernel modules
#		(see kld(4)). [/boot/kernel]
#
# KMODOWN	Kernel and KLD owner. [${BINOWN}]
#
# KMODGRP	Kernel and KLD group. [${BINGRP}]
#
# KMODMODE	KLD mode. [${BINMODE}]
#
#
# SHAREDIR	Base path for architecture-independent ascii
#		text files. [/usr/share]
#
# SHAREOWN	ASCII text file owner. [root]
#
# SHAREGRP	ASCII text file group. [wheel]
#
# SHAREMODE	ASCII text file mode. [${NOBINMODE}]
#
#
# CONFDIR	Base path for configuration files. [/etc]
#
# CONFOWN	Configuration file owner. [root]
#
# CONFGRP	Configuration file group. [wheel]
#
# CONFMODE	Configuration file mode. [644]
#
#
# DOCDIR	Base path for system documentation (e.g. PSD, USD,
#		handbook, FAQ etc.). [${SHAREDIR}/doc]
#
# DOCOWN	Documentation owner. [${SHAREOWN}]
#
# DOCGRP	Documentation group. [${SHAREGRP}]
#
# DOCMODE	Documentation mode. [${NOBINMODE}]
#
#
# INFODIR	Base path for GNU's hypertext system
#		called Info (see info(1)). [${SHAREDIR}/info]
#
# INFOOWN	Info owner. [${SHAREOWN}]
#
# INFOGRP	Info group. [${SHAREGRP}]
#
# INFOMODE	Info mode. [${NOBINMODE}]
#
#
# MANDIR	Base path for manual installation. [${SHAREDIR}/man/man]
#
# MANOWN	Manual owner. [${SHAREOWN}]
#
# MANGRP	Manual group. [${SHAREGRP}]
#
# MANMODE	Manual mode. [${NOBINMODE}]
#
#
# NLSDIR	Base path for National Language Support files
#		installation. [${SHAREDIR}/nls]
#
# NLSOWN	National Language Support files owner. [${SHAREOWN}]
#
# NLSGRP	National Language Support files group. [${SHAREGRP}]
#
# NLSMODE	National Language Support files mode. [${NOBINMODE}]
#
# INCLUDEDIR	Base path for standard C include files [/usr/include]

.if !target(__<bsd.own.mk>__)
__<bsd.own.mk>__:

.include <bsd.opts.mk>		# options now here or src.opts.mk

.if !defined(_WITHOUT_SRCCONF)

.if ${MK_CTF} != "no"
CTFCONVERT_CMD=	${CTFCONVERT} ${CTFFLAGS} ${.TARGET}
.elif defined(.PARSEDIR) || (defined(MAKE_VERSION) && ${MAKE_VERSION} >= 5201111300)
CTFCONVERT_CMD=
.else
CTFCONVERT_CMD=	@:
.endif 

.if ${MK_INSTALL_AS_USER} != "no"
.if !defined(_uid)
_uid!=	id -u
.export _uid
.endif
.if ${_uid} != 0
.if !defined(USER)
# Avoid exporting USER
.if !defined(_USER)
_USER!=	id -un
.export _USER
.endif
USER=	${_USER}
.endif
.if !defined(_gid)
_gid!=	id -g
.export _gid
.endif
.for x in BIN CONF DOC DTB INFO KMOD LIB MAN NLS SHARE
$xOWN=	${USER}
$xGRP=	${_gid}
.endfor
.endif
.endif

.endif # !_WITHOUT_SRCCONF

# Binaries
BINOWN?=	root
BINGRP?=	wheel
BINMODE?=	555
NOBINMODE?=	444

KMODDIR?=	/boot/modules
KMODOWN?=	${BINOWN}
KMODGRP?=	${BINGRP}
KMODMODE?=	${BINMODE}
DTBDIR?=	/boot/dtb
DTBOWN?=	root
DTBGRP?=	wheel
DTBMODE?=	444

LIBDIR?=	/usr/lib
LIBCOMPATDIR?=	/usr/lib/compat
LIBDATADIR?=	/usr/libdata
LIBEXECDIR?=	/usr/libexec
LINTLIBDIR?=	/usr/libdata/lint
SHLIBDIR?=	${LIBDIR}
LIBOWN?=	${BINOWN}
LIBGRP?=	${BINGRP}
LIBMODE?=	${NOBINMODE}

DEBUGDIR?=	/usr/lib/debug
DEBUGMODE?=	${NOBINMODE}


# Share files
SHAREDIR?=	/usr/share
SHAREOWN?=	root
SHAREGRP?=	wheel
SHAREMODE?=	${NOBINMODE}

CONFDIR?=	/etc
CONFOWN?=	root
CONFGRP?=	wheel
CONFMODE?=	644

MANDIR?=	${SHAREDIR}/man/man
MANOWN?=	${SHAREOWN}
MANGRP?=	${SHAREGRP}
MANMODE?=	${NOBINMODE}

DOCDIR?=	${SHAREDIR}/doc
DOCOWN?=	${SHAREOWN}
DOCGRP?=	${SHAREGRP}
DOCMODE?=	${NOBINMODE}

INFODIR?=	${SHAREDIR}/info
INFOOWN?=	${SHAREOWN}
INFOGRP?=	${SHAREGRP}
INFOMODE?=	${NOBINMODE}

NLSDIR?=	${SHAREDIR}/nls
NLSOWN?=	${SHAREOWN}
NLSGRP?=	${SHAREGRP}
NLSMODE?=	${NOBINMODE}

INCLUDEDIR?=	/usr/include

#
# install(1) parameters.
#
HRDLINK?=	-l h
SYMLINK?=	-l s
RSYMLINK?=	-l rs

INSTALL_LINK?=		${INSTALL} ${HRDLINK}
INSTALL_SYMLINK?=	${INSTALL} ${SYMLINK}
INSTALL_RSYMLINK?=	${INSTALL} ${RSYMLINK}

# Common variables
.if !defined(DEBUG_FLAGS)
STRIP?=		-s
.endif

COMPRESS_CMD?=	gzip -cn
COMPRESS_EXT?=	.gz

# Set XZ_THREADS to 1 to disable multi-threading.
XZ_THREADS?=	0

.if !empty(XZ_THREADS)
XZ_CMD?=	xz -T ${XZ_THREADS}
.else
XZ_CMD?=	xz
.endif

# Pointer to the top directory into which tests are installed.  Should not be
# overriden by Makefiles, but the user may choose to set this in src.conf(5).
TESTSBASE?= /usr/tests

DEPENDFILE?=	.depend

# Compat for the moment -- old bsd.own.mk only included this when _WITHOUT_SRCCONF
# wasn't defined. bsd.ports.mk and friends depend on this behavior. Remove in 12.
.if !defined(_WITHOUT_SRCCONF)
.include <bsd.compiler.mk>

#
# Some targets require a different build process in order to allow LLVM
# instrumentation passes to be applied.
#
# XXX: The current construction allow an empty instrumentation path or
# a TESLA one.
#
.if defined(WITH_LLVM_INSTRUMENTED) && defined(WITHOUT_LLVM_INSTRUMENTED)
.error WITH_LLVM_INSTRUMENTED and WITHOUT_LLVM_INSTRUMENTED can't both be set.
.endif
.if defined(MK_LLVM_INSTRUMENTED)
.error MK_LLVM_INSTRUMENTED can't be set by a user.
.endif

.if ${MK_TESLA} == "no" && ${MK_SOAAP} == "no"
.if defined(WITH_LLVM_INSTRUMENTED)
MK_LLVM_INSTRUMENTED:=	yes
.else
MK_LLVM_INSTRUMENTED:=	no
.endif
.endif

.if ${MK_SOAAP} != "no"
.if !defined(SOAAP_INCLUDE_DIR)
.if !defined(SOAAP_SOURCE_DIR)
.error Must set one of SOAAP_INCLUDE_DIR or SOAAP_SOURCE_DIR with WITH_SOAAP
.else
.warning SOAAP_SOURCE_DIR is deprecated, use SOAAP_INCLUDE_DIR
SOAAP_INCLUDE_DIR=${SOAAP_SOURCE_DIR}/include
.endif
.endif
.if !defined(SOAAP_LIB_DIR)
.if !defined(SOAAP_BUILD_DIR)
.error Must set one of SOAAP_LIB_DIR or SOAAP_BUILD_DIR with WITH_SOAAP
.else
.warning SOAAP_BUILD_DIR is deprecated, use SOAAP_LIB_DIR
SOAAP_LIB_DIR=${SOAAP_BUILD_DIR}
.endif
.endif
CFLAGS+= -DSOAAP -I${SOAAP_INCLUDE_DIR}
.if defined(WITHOUT_LLVM_INSTRUMENTED)
.error WITHOUT_LLVM_INSTRUMENTED and WITH_SOAAP can't both be set.
.else
MK_LLVM_INSTRUMENTED:=	yes
.endif
.endif

.if ${MK_TESLA} == "no"
LLVM_INSTR_DEP?=
LLVM_INSTR_COMMAND?= cp ${.IMPSRC} ${.TARGET}
.else
LLVM_INSTR_DEP= tesla.manifest
.if ${LLVM_IR_TYPE} == "bc"
LLVM_INSTR_COMMAND= ${TESLA} instrument -tesla-manifest \
    tesla.manifest ${.IMPSRC} -o ${.TARGET}
.elif ${LLVM_IR_TYPE} == "ll"
LLVM_INSTR_COMMAND= ${TESLA} instrument -S -tesla-manifest \
    tesla.manifest ${.IMPSRC} -o ${.TARGET}
.else
.error unknown LLVM IR type ${LLVM_IR_TYPE}
.endif
.if defined(WITHOUT_LLVM_INSTRUMENTED)
.error WITHOUT_LLVM_INSTRUMENTED and WITH_TESLA can't both be set.
.else
MK_LLVM_INSTRUMENTED:=	yes
.endif
.endif
.endif # !_WITHOUT_SRCCONF

.endif	# !target(__<bsd.own.mk>__)
