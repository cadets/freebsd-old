# $FreeBSD: head/gnu/lib/Makefile 235727 2012-05-21 16:03:44Z marcel $

.include <bsd.own.mk>

SUBDIR= csu libgcc libgcov libdialog libgomp libregex libreadline

.if ${MK_SSP} != "no"
SUBDIR+= libssp
.endif

# libsupc++ uses libstdc++ headers, although 'make includes' should
# have taken care of that already.
.if ${MK_CXX} != "no"
SUBDIR+= libstdc++ libsupc++
.endif

.include <bsd.subdir.mk>
