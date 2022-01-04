/*-
 * SPDX-License-Identifier: MIT-CMU
 *
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * Copyright (c) 2021 Domagoj Stolfa
 * All Rights Reserved.
 *
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 *
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 *
 * Carnegie Mellon requests users of this software to return to
 *
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 *
 * any improvements or extensions that they make and grant Carnegie the
 * rights to redistribute these changes.
 *
 * This software were developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory (Department of Computer Science and
 * Technology) under DARPA contract HR0011-18-C-0016 ("ECATS"), as part of the
 * DARPA SSITH research programme.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from Arm Limited.
 *
 * This software was developed by the University of Cambridge Computer
 * Laboratory (Department of Computer Science and Technology) with support
 * from the Kenneth Hayter Scholarship Fund.
 */

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/systm.h>

#include <ddb/ddb.h>
#include <ddb/db_sym.h>

#include <sys/_link_elf.h>
#include <sys/link_elf.h>

struct dtrace_db_private {
	char*		strtab;
	vm_offset_t	relbase;
};

typedef struct dtrace_db_private *dtrace_db_private_t;

#define DTRACE_DB_PRIVATE(x) ((dtrace_db_private_t)(x->private))

static db_expr_t dtrace_db_maxoff = 0x10000; /* taken from db_sym.c */

static int
dtrace_linker_elf_symbol_values(linker_file_t lf, c_linker_sym_t sym,
    linker_symval_t *symval)
{
	elf_file_t ef;
	const Elf_Sym *es;
	caddr_t val;

	ef = (elf_file_t)lf;
	es = (const Elf_Sym *)sym;
	if (es >= ef->symtab && es < (ef->symtab + ef->nchains)) {
		symval->name = ef->strtab + es->st_name;
		val = (caddr_t)ef->address + es->st_value;
		if (ELF_ST_TYPE(es->st_info) == STT_GNU_IFUNC)
			val = ((caddr_t (*)(void))val)();
		symval->value = val;
		symval->size = es->st_size;
		return (0);
	}
	if (ef->symtab == ef->ddbsymtab)
		return (ENOENT);
	if (es >= ef->ddbsymtab && es < (ef->ddbsymtab + ef->ddbsymcnt)) {
		symval->name = ef->ddbstrtab + es->st_name;
		val = (caddr_t)ef->address + es->st_value;
		if (ELF_ST_TYPE(es->st_info) == STT_GNU_IFUNC)
			val = ((caddr_t (*)(void))val)();
		symval->value = val;
		symval->size = es->st_size;
		return (0);
	}
	return (ENOENT);
}

static int
dtrace_linker_symbol_values(c_linker_sym_t sym, linker_symval_t *symval)
{
	linker_file_t lf;

	TAILQ_FOREACH(lf, &linker_files, link) {
		if (dtrace_linker_elf_symbol_values(lf, sym, symval) == 0)
			return (0);
	}
	return (ENOENT);
}

static int
dtrace_linker_elf_search_symbol(linker_file_t lf, caddr_t value,
    c_linker_sym_t *sym, long *diffp)
{
	elf_file_t ef = (elf_file_t) lf;
	u_long off = (uintptr_t) (void *) value;
	u_long diff = off;
	u_long st_value;
	const Elf_Sym* es;
	const Elf_Sym* best = NULL;
	int i;

	for (i = 0, es = ef->ddbsymtab; i < ef->ddbsymcnt; i++, es++) {
		if (es->st_name == 0)
			continue;
		st_value = es->st_value + (uintptr_t) (void *) ef->address;
		if (off >= st_value) {
			if (off - st_value < diff) {
				diff = off - st_value;
				best = es;
				if (diff == 0)
					break;
			} else if (off - st_value == diff) {
				best = es;
			}
		}
	}
	if (best == NULL)
		*diffp = off;
	else
		*diffp = diff;
	*sym = (c_linker_sym_t) best;

	return (0);
}

static int
dtrace_linker_search_symbol(caddr_t value, c_linker_sym_t *sym, long *diffp)
{
	linker_file_t lf;
	c_linker_sym_t best, es;
	u_long diff, bestdiff, off;

	best = 0;
	off = (uintptr_t)value;
	bestdiff = off;
	TAILQ_FOREACH(lf, &linker_files, link) {
		if (dtrace_linker_elf_search_symbol(lf, value, &es, &diff) != 0)
			continue;

		if (es != 0 && diff < bestdiff) {
			best = es;
			bestdiff = diff;
		}
		if (bestdiff == 0)
			break;
	}
	if (best) {
		*sym = best;
		*diffp = bestdiff;
		return (0);
	} else {
		*sym = 0;
		*diffp = off;
		return (ENOENT);
	}
}

static c_db_sym_t
_dtrace_search_symbol(db_symtab_t *symtab, db_addr_t off, db_strategy_t strat,
    db_expr_t *diffp)
{
	c_linker_sym_t lsym;
	Elf_Sym *sym, *match;
	unsigned long diff;
	db_addr_t stoffs = off;

	if (symtab->private == NULL) {
		if (!dtrace_linker_search_symbol((caddr_t)off, &lsym, &diff)) {
			*diffp = (db_expr_t)diff;
			return ((c_db_sym_t)lsym);
		}
		return (NULL);
	} else
		stoffs -= DTRACE_DB_PRIVATE(symtab)->relbase;

	diff = ~0UL;
	match = NULL;
	for (sym = (Elf_Sym*)symtab->start; (char*)sym < symtab->end; sym++) {
		if (sym->st_name == 0 || sym->st_shndx == SHN_UNDEF)
			continue;
		if (stoffs < sym->st_value)
			continue;
		if (ELF_ST_TYPE(sym->st_info) != STT_OBJECT &&
		    ELF_ST_TYPE(sym->st_info) != STT_FUNC &&
		    ELF_ST_TYPE(sym->st_info) != STT_NOTYPE)
			continue;
		if ((stoffs - sym->st_value) > diff)
			continue;
		if ((stoffs - sym->st_value) < diff) {
			diff = stoffs - sym->st_value;
			match = sym;
		} else {
			if (match == NULL)
				match = sym;
			else if (ELF_ST_BIND(match->st_info) == STB_LOCAL &&
			    ELF_ST_BIND(sym->st_info) != STB_LOCAL)
				match = sym;
		}
		if (diff == 0) {
			if (strat == DB_STGY_PROC &&
			    ELF_ST_TYPE(sym->st_info) == STT_FUNC &&
			    ELF_ST_BIND(sym->st_info) != STB_LOCAL)
				break;
			if (strat == DB_STGY_ANY &&
			    ELF_ST_BIND(sym->st_info) != STB_LOCAL)
				break;
		}
	}

	*diffp = (match == NULL) ? off : diff;
	return ((c_db_sym_t)match);
}

/*
 * Find the closest symbol to val, and return its name
 * and the difference between val and the symbol found.
 */
static c_db_sym_t
dtrace_search_symbol(db_addr_t val, db_strategy_t strategy, db_expr_t *offp)
{
	unsigned int diff;
	size_t newdiff;
	int i;
	c_db_sym_t ret, sym;

	/*
	 * The kernel will never map the first page, so any symbols in that
	 * range cannot refer to addresses.  Some third-party assembly files
	 * define internal constants which appear in their symbol table.
	 * Avoiding the lookup for those symbols avoids replacing small offsets
	 * with those symbols during disassembly.
	 */
	if (val < PAGE_SIZE) {
		*offp = 0;
		return (C_DB_SYM_NULL);
	}

	ret = C_DB_SYM_NULL;
	newdiff = diff = val;
	for (i = 0; i < db_nsymtab; i++) {
		sym = _dtrace_search_symbol(&db_symtabs[i], val, strategy,
		    &newdiff);

		if ((uintmax_t)newdiff < (uintmax_t)diff) {
			db_last_symtab = &db_symtabs[i];
			diff = newdiff;
			ret = sym;
		}
	}
	*offp = diff;
	return ret;
}

static void dtrace_symbol_values(c_db_sym_t, const char **, db_expr_t *);

/*
 * Diff minimizer.
 */
static bool
dtrace_symbol_is_ambiguous(c_db_sym_t sym)
{

	return (false);
}

/*
 *  db_qualify("vm_map", "ux") returns "unix:vm_map".
 *
 *  Note: return value points to static data whose content is
 *  overwritten by each call... but in practice this seems okay.
 */
static char *
dtrace_qualify(c_db_sym_t sym, char *symtabname)
{
	const char	*symname;
	static char     tmp[256];

	dtrace_symbol_values(sym, &symname, 0);
	/* FIXME: Unwind this snprintf */
	snprintf(tmp, sizeof(tmp), "%s:%s", symtabname, symname);
	return tmp;
}

static void
_dtrace_symbol_values(db_symtab_t *symtab, c_db_sym_t sym, const char **namep,
    db_expr_t *valp)
{
	linker_symval_t lval;

	if (symtab->private == NULL) {
		dtrace_linker_symbol_values((c_linker_sym_t)sym, &lval);
		if (namep != NULL)
			*namep = (const char*)lval.name;
		if (valp != NULL)
			*valp = (db_expr_t)lval.value;
	} else {
		if (namep != NULL)
			*namep =
			    (const char *)DTRACE_DB_PRIVATE(symtab)->strtab +
			    ((const Elf_Sym *)sym)->st_name;
		if (valp != NULL)
			*valp = (db_expr_t)((const Elf_Sym *)sym)->st_value +
			    DTRACE_DB_PRIVATE(symtab)->relbase;
	}
}

/*
 * Return name and value of a symbol
 */
static void
dtrace_symbol_values(c_db_sym_t sym, const char **namep, db_expr_t *valuep)
{
	db_expr_t	value;

	if (sym == DB_SYM_NULL) {
		*namep = NULL;
		return;
	}

	_dtrace_symbol_values(db_last_symtab, sym, namep, &value);

	if (dtrace_symbol_is_ambiguous(sym))
		*namep = dtrace_qualify(sym, db_last_symtab->name);
	if (valuep)
		*valuep = value;
}
