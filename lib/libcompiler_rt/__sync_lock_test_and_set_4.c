/* $FreeBSD: head/lib/libcompiler_rt/__sync_lock_test_and_set_4.c 228919 2011-12-27 22:13:51Z ed $ */
#define	NAME		__sync_lock_test_and_set_4
#define	TYPE		uint32_t
#define	CMPSET		atomic_cmpset_32
#define	EXPRESSION	value

#include "__sync_fetch_and_op_n.h"
