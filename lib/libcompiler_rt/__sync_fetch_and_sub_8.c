/* $FreeBSD: head/lib/libcompiler_rt/__sync_fetch_and_sub_8.c 228919 2011-12-27 22:13:51Z ed $ */
#define	NAME		__sync_fetch_and_sub_8
#define	TYPE		uint64_t
#define	FETCHADD(x, y)	atomic_fetchadd_64(x, -(y))

#include "__sync_fetch_and_op_n.h"
