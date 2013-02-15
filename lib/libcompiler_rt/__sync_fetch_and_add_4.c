/* $FreeBSD: head/lib/libcompiler_rt/__sync_fetch_and_add_4.c 228919 2011-12-27 22:13:51Z ed $ */
#define	NAME		__sync_fetch_and_add_4
#define	TYPE		uint32_t
#define	FETCHADD(x, y)	atomic_fetchadd_32(x, y)

#include "__sync_fetch_and_op_n.h"
