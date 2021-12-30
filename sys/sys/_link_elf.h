#ifndef __LINK_ELF_H_
#define __LINK_ELF_H_

#include <sys/linker.h>

typedef struct link_map {
	caddr_t		l_base;			/* Base Address of library */
#ifdef __mips__
	caddr_t		l_xxx;			/* unused */
#endif
	const char	*l_name;		/* Absolute Path to Library */
	const void	*l_ld;			/* Pointer to .dynamic in memory */
	struct link_map	*l_next, *l_prev;	/* linked list of of mapped libs */
	caddr_t		l_addr;			/* Load Offset of library */
	const char	*l_refname;		/* object we are filtering for */
} Link_map;

struct r_debug {
	int		r_version;		/* Currently '1' */
	struct link_map *r_map;			/* list of loaded images */
	void		(*r_brk)(struct r_debug *, struct link_map *);
						/* pointer to break point */
	enum {
		RT_CONSISTENT,			/* things are stable */
		RT_ADD,				/* adding a shared library */
		RT_DELETE			/* removing a shared library */
	}		r_state;
	void		*r_ldbase;		/* Base address of rtld */
};

typedef struct elf_file {
	struct linker_file lf;		/* Common fields */
	int		preloaded;	/* Was file pre-loaded */
	caddr_t		address;	/* Relocation address */
#ifdef SPARSE_MAPPING
	vm_object_t	object;		/* VM object to hold file pages */
#endif
	Elf_Dyn		*dynamic;	/* Symbol table etc. */
	Elf_Hashelt	nbuckets;	/* DT_HASH info */
	Elf_Hashelt	nchains;
	const Elf_Hashelt *buckets;
	const Elf_Hashelt *chains;
	caddr_t		hash;
	caddr_t		strtab;		/* DT_STRTAB */
	int		strsz;		/* DT_STRSZ */
	const Elf_Sym	*symtab;		/* DT_SYMTAB */
	Elf_Addr	*got;		/* DT_PLTGOT */
	const Elf_Rel	*pltrel;	/* DT_JMPREL */
	int		pltrelsize;	/* DT_PLTRELSZ */
	const Elf_Rela	*pltrela;	/* DT_JMPREL */
	int		pltrelasize;	/* DT_PLTRELSZ */
	const Elf_Rel	*rel;		/* DT_REL */
	int		relsize;	/* DT_RELSZ */
	const Elf_Rela	*rela;		/* DT_RELA */
	int		relasize;	/* DT_RELASZ */
	caddr_t		modptr;
	const Elf_Sym	*ddbsymtab;	/* The symbol table we are using */
	long		ddbsymcnt;	/* Number of symbols */
	caddr_t		ddbstrtab;	/* String table */
	long		ddbstrcnt;	/* number of bytes in string table */
	caddr_t		symbase;	/* malloc'ed symbold base */
	caddr_t		strbase;	/* malloc'ed string base */
	caddr_t		ctftab;		/* CTF table */
	long		ctfcnt;		/* number of bytes in CTF table */
	caddr_t		ctfoff;		/* CTF offset table */
	caddr_t		typoff;		/* Type offset table */
	long		typlen;		/* Number of type entries. */
	Elf_Addr	pcpu_start;	/* Pre-relocation pcpu set start. */
	Elf_Addr	pcpu_stop;	/* Pre-relocation pcpu set stop. */
	Elf_Addr	pcpu_base;	/* Relocated pcpu set address. */
#ifdef VIMAGE
	Elf_Addr	vnet_start;	/* Pre-relocation vnet set start. */
	Elf_Addr	vnet_stop;	/* Pre-relocation vnet set stop. */
	Elf_Addr	vnet_base;	/* Relocated vnet set address. */
#endif
#ifdef GDB
	struct link_map	gdb;		/* hooks for gdb */
#endif
} *elf_file_t;

#endif /* __LINK_ELF_H_ */