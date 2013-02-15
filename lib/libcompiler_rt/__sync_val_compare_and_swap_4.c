/* $FreeBSD: head/lib/libcompiler_rt/__sync_val_compare_and_swap_4.c 228919 2011-12-27 22:13:51Z ed $ */
#define	NAME		__sync_val_compare_and_swap_4
#define	TYPE		uint32_t
#define	CMPSET		atomic_cmpset_32

#include "__sync_val_compare_and_swap_n.h"
