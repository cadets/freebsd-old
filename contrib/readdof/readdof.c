/*-
 * Copyright (c) 2019 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <sys/utsname.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <dtrace.h>
#include <sysmacros.h>

#ifdef PRIVATE_BBUF
#include <private/bbuf/bbuf.h>
#else
#include "bbuf.h"
#endif

extern void dt_dis(dtrace_difo_t *, FILE *);

static void display_dof_header(int);
static void display_dof_header_hex(int);
static void display_dof_sect_header(int,  uint32_t);
static void display_dof_sect_header_helper(int, off_t, dof_hdr_t *,
    uint32_t);
static void display_dof_sect_headers(int);
static void display_dof_section(int, uint32_t);
static void display_dof_sect_hex(int, uint32_t);
static void display_hex(struct bbuf *);
static void display_sect_hex(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_actdesc(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_comments(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_difohdr(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_ecbdesc(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_probdesc(int, off_t, dof_hdr_t *, dof_sec_t *, uint32_t);
static void display_sect_probdesc_helper(int, dof_hdr_t *, off_t, uint32_t);
static void display_sect_probdescs(int);
static void display_sect_strtab(int, off_t, dof_sec_t *, uint32_t);
static void display_sect_strtabs(int);
static void display_sect_utsname(int, dof_hdr_t *, off_t, uint32_t);
static int hex2int(char);
static char const * get_section_name(dof_sec_t *);
static int load_dof_header(int, dof_hdr_t *, off_t *);
static int load_sect_actdesc(int, dof_hdr_t *, off_t, dof_sec_t *, dof_actdesc_t *);
static int load_sect_difohdr(int, off_t, dof_hdr_t *, dof_sec_t *, dtrace_difo_t *);
static int load_sect_ecbdesc(int, dof_hdr_t *, off_t, dof_sec_t *, dof_ecbdesc_t *);
static int load_sect_header(int, off_t, dof_hdr_t *, uint32_t, dof_sec_t *);
static int load_sect_hex(int, off_t, dof_sec_t *, struct bbuf **);
static int load_sect_hex_into(int, off_t, dof_sec_t *, struct bbuf *);
static int load_sect_probedesc(int, off_t, dof_hdr_t *, dof_sec_t *, dof_probedesc_t *);

typedef uint16_t readdof_flags_t;

enum RDOF_ENDIANNESS {
	RDOF_LITTLE,
	RDOF_BIG
};

/* libbbuf memory allocation and freeing functions. */
const bbuf_malloc_func bbuf_alloc = malloc;
const bbuf_free_func bbuf_free = free;

static char const * const RDOF_SECT_NAMES[] = {
    "DOF_SECT_NONE",
    "DOF_SECT_COMMENTS",
    "DOF_SECT_SOURCE",
    "DOF_SECT_ECBDESC",
    "DOF_SECT_PROBEDESC",
    "DOF_SECT_ACTDESC",
    "DOF_SECT_DIFOHDR",
    "DOF_SECT_DIF",
    "DOF_SECT_STRTAB",
    "DOF_SECT_VARTAB",
    "DOF_SECT_RELTAB",
    "DOF_SECT_TYPTAB",
    "DOF_SECT_URELHDR",
    "DOF_SECT_KRELHDR",
    "DOF_SECT_OPTDESC",
    "DOF_SECT_PROVIDER",
    "DOF_SECT_PROBES",
    "DOF_SECT_PRARGS",
    "DOF_SECT_PROFFS",
    "DOF_SECT_INTTAB",
    "DOF_SECT_UTSNAME",
    "DOF_SECT_XLTAB",
    "DOF_SECT_XLMEMBERS",
    "DOF_SECT_XLIMPORT",
    "DOF_SECT_XLEXPORT",
    "DOF_SECT_PREXPORT",
    "DOF_SECT_PRENOFFS"
};

static char const * const RDOF_USAGE = \
    "Usage: %s [options] file\n"
    "  Display information about DOF.\n\n"
    "  Options:\n"
    "  -B | --big-endian\t\t\tHex output (-x) in big endian.\n"
    "  -f | --file-header\t\t\tOutput the DOF file header.\n"
    "  -g octs | --octet-grp=octs\t\tHex output (-x) grouped by <octs>.\n"
    "  -l len | --len=len\t\t\tLimit hex output to <len> bytes.\n"
    "  -L | --little-endian\t\t\tHex output (-x) in little endian.\n"
    "  -p sec | --string-dump=sec\t\tPrint DOF section <sec>.\n"
    "  -P | --probedesc\t\t\tOutput PROBEDESC section\n"
    "  -S[sec] | --section-headers=[sec]"
    "\tDisplay the DOF section header <sec>\n"
    "\t\t\t\t\t(all if no SECTION specified).\n"
    "  -T | --strtab\t\t\t\tPrint all DOF_SECT_STRTAB sections.\n"
    "  -v | --version\t\t\treaddof version information.\n"
    "  -x | --hex-dump\t\t\tHex dump of SECTION.\n";

static char const * const RDOF_VER = "%s (DOF v%d)\n";

/* readdof output mode. */
static const int RDOF_HDR = (0x01 << 0);
static const int RDOF_PROBES = (0x01 << 1);
static const int RDOF_SECHDR = (0x01 << 2);
static const int RDOF_PRINT = (0x01 << 3);
static const int RDOF_STRTABS = (0x01 << 4);

/* Default hex output groups two octets. */
static const unsigned char RDOF_DEFAULT_OCTET_GRP = 2;

static unsigned char octet_grp = RDOF_DEFAULT_OCTET_GRP;
static unsigned long len = LONG_MAX;
static enum RDOF_ENDIANNESS endian = RDOF_LITTLE;

static void 
display_dof_header(int fd)
{
	dof_hdr_t hdr;
	off_t offset;
	int rc;

	rc = load_dof_header(fd, &hdr, &offset);
	if (rc == 0) {

		printf("===DOF Header===\n");
		if (hdr.dofh_ident[DOF_ID_MODEL] == DOF_MODEL_LP64) {

			if (DOF_MODEL_LP64 == DOF_MODEL_NATIVE) {

				printf("Model: LP64 (native)\n");
			} else {

				printf("Model: LP64\n");
			}
		} else if (hdr.dofh_ident[DOF_ID_MODEL] == DOF_MODEL_ILP32) {

			if (DOF_MODEL_ILP32 == DOF_MODEL_NATIVE) {

				printf("Model: ILP32 (native)\n");
			} else {

				printf("Model: ILP32\n");
			}
		} else {

			printf("Model: Invalid\n");
		}

		if (hdr.dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_MSB) {

			printf("Encoding: MSB\n");
		} else if (hdr.dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {

			printf("Encoding: LSB\n");
		} else {

			printf("Encoding: Invalid\n");
		}
		printf("DOF version: %d\n", hdr.dofh_ident[DOF_ID_VERSION]);
		printf("DIF instr version: %d\n", hdr.dofh_ident[DOF_ID_DIFVERS]);
		printf("DIF tup reg: %d\n", hdr.dofh_ident[DOF_ID_DIFTREG]);
		printf("Size of header (bytes): %u\n", hdr.dofh_hdrsize);
		printf("Size of section headers (bytes): %u\n", hdr.dofh_secsize);
		printf("Number of section headers: %u\n", hdr.dofh_secnum);
		printf("File offset of section headers: %lu\n", hdr.dofh_secoff);
		printf("Loadable section(s) size (bytes): %lu\n", hdr.dofh_loadsz);
		printf("File size (bytes): %lu\n", hdr.dofh_filesz);
	} else {

		errx(EXIT_FAILURE, "Error loading DOF header\n");
	}
}

static void 
display_dof_header_hex(int dof)
{
	dof_hdr_t hdr;
	off_t offset;
	int rc;

	rc = load_dof_header(dof, &hdr, &offset);
	if (rc == 0) {

		unsigned char * data = (unsigned char *) &hdr;
		struct bbuf *buf;

		rc = bbuf_new(&buf, data, sizeof(dof_hdr_t), BBUF_LITTLEENDIAN);
		if (rc == 0) {

			printf("===DOF Header===\n");

			/* Print the hex data */
			display_hex(buf);

			bbuf_delete(buf);
		} else {
		}	
	} else {

		errx(EXIT_FAILURE, "Error loading DOF header\n");
	}
}

static void 
display_dof_sect_header(int dof, uint32_t sec_num)
{
	dof_hdr_t hdr;
	off_t start;
	int rc;

	rc = load_dof_header(dof, &hdr, &start);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header %u (DOF malformed)", sec_num);
	}

	display_dof_sect_header_helper(dof, start, &hdr, sec_num);
}

static void 
display_dof_sect_header_helper(int dof, off_t start, dof_hdr_t *hdr,
    uint32_t sec_num)
{
	dof_sec_t sec;
	int rc;

	rc = load_sect_header(dof, start, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header %u (DOF malformed)", sec_num);
	}

	printf("===Section Header (%u) %s=========\n", sec_num, get_section_name(&sec));
	printf("Alignment: %u\n", sec.dofs_align);
	printf("Flags: %X\n", sec.dofs_flags);
	printf("Entry size: %u\n", sec.dofs_entsize);
	printf("Offset: %lu\n", sec.dofs_offset);
	printf("Size (bytes): %lu\n", sec.dofs_size);
}

static void 
display_dof_sect_headers(int dof)
{
	dof_hdr_t hdr;
	off_t start;
	int rc;

	rc = load_dof_header(dof, &hdr, &start);
	if (rc == 0) {

		for (uint32_t sec_num = 1; sec_num < hdr.dofh_secnum; sec_num++) {

			display_dof_sect_header_helper(dof, start, &hdr, sec_num);
		}
	} else {

		errx(EXIT_FAILURE, "Error loading DOF header\n");
	}
}

static void
display_hex(struct bbuf *buf)
{
	unsigned char * data;
	char hexxa[] = "0123456789abcdef0123456789ABCDEF";
	size_t cols = 16, p = 0;
	size_t grplen, addrlen;
	static char l[1024];
	size_t c;

	data = bbuf_data(buf);
	grplen = (2 * octet_grp) + 1;

	for (size_t i = 0; i < bbuf_len(buf) && i < len; i++) {

		if (p == 0) {

			addrlen = sprintf(l, "%08lx:", i);
			for (size_t j = addrlen; j < 1024; l[j++] = ' ');
		}

		if (endian == RDOF_BIG) {
			int x = p ^ (octet_grp - 1);
			c = addrlen + 1 + (grplen * x) / octet_grp;
		} else {

			c = addrlen + 1 + (grplen * p) / octet_grp;
		}

		l[c++] = hexxa[(data[i] >> 4) & 0x0F];
		l[c++] = hexxa[data[i] & 0x0F];

		l[addrlen + 3 + (grplen * cols - 1)/octet_grp + p] =
		(data[i] > 31 && data[i] < 127) ? data[i] : '.';
		p++;
		if (p == cols) {

			c = addrlen + 3 + (grplen * cols - 1)/octet_grp + p;
			l[c] = '\n'; l[++c] = '\0';

			fprintf(stdout, "%s", l);
			p = 0;
		}
	}
	if (p != 0) {

		c = addrlen + 3 + (grplen * cols - 1)/octet_grp + p;
		l[c] = '\n'; l[++c] = '\0';

		fprintf(stdout, "%s", l);
	}
}

static void
display_sect_utsname(int dof, dof_hdr_t *hdr, off_t start_off, uint32_t sec_num)
{
	struct bbuf *buf;
	dof_sec_t sec;
	struct utsname *dof_uname;
	int rc;
			
	/* Load the section header. */
	rc = load_sect_header(dof, start_off, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header (DOF malformed)");
	}

	/* Load the probedesc strtab section. */
	rc = load_sect_hex(dof, start_off, &sec, &buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing strtab (DOF malformed)");
	}

	/* Print the utsname */
	printf("===DOF Section UTSNAME===\n");

	dof_uname = (struct utsname *) bbuf_data(buf);

	printf("%s %s %s %s %s\n", dof_uname->sysname, dof_uname->nodename,
	    dof_uname->release, dof_uname->version, dof_uname->machine);

	bbuf_delete(buf);
}


static void
display_sect_comments(int dof, dof_hdr_t *hdr, off_t start_off, uint32_t sec_num)
{
	struct bbuf *buf;
	dof_sec_t sec;
	char *comments;
	int rc;
			
	/* Load the section header. */
	rc = load_sect_header(dof, start_off, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header (DOF malformed)");
	}

	/* Load the probedesc strtab section. */
	rc = load_sect_hex(dof, start_off, &sec, &buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing strtab (DOF malformed)");
	}

	/* Print the comments */
	printf("===DOF Section COMMENTS===\n");

	comments = (char *) bbuf_data(buf);

	printf("%s\n", comments);

	bbuf_delete(buf);
}

static void
display_sect_hex(int dof, dof_hdr_t *hdr, off_t start, uint32_t sec_num)
{
	struct bbuf *buf;
	dof_sec_t sec;
	int rc;

	/* Load the section header. */
	rc = load_sect_header(dof, start, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header %u (DOF malformed)", sec_num);
	}

	/* Load the section. */
	rc = load_sect_hex(dof, start, &sec, &buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing section %u (DOF malformed)", sec_num);
	}

	printf("===Section (%u) %s=========\n", sec_num, get_section_name(&sec));
			
	/* Print the hex data */
	display_hex(buf);

	bbuf_delete(buf);
}

static void
display_dof_sect_hex(int dof, uint32_t sec_num)
{
	dof_hdr_t hdr;
	off_t start_off;
	int rc;

	rc = load_dof_header(dof, &hdr, &start_off);
	if (rc == 0) {

		if (sec_num <= hdr.dofh_secnum) {

			display_sect_hex(dof, &hdr, start_off, sec_num);
		} else {

			printf("Invalid section number %u (> %u)\n", sec_num, hdr.dofh_secnum);
		}
	} else {

		fprintf(stderr, "Error loading DOF header\n");
	}
}

static void
display_dof_section(int dof, uint32_t sec_num)
{
	dof_hdr_t hdr;
	off_t start_off;
	int rc;

	rc = load_dof_header(dof, &hdr, &start_off);
	if (rc == 0) {

		if (sec_num <= hdr.dofh_secnum) {

			dof_sec_t sec;
			rc = load_sect_header(dof, start_off, &hdr, sec_num, &sec);

			switch (sec.dofs_type) {
			case DOF_SECT_ACTDESC: {

				display_sect_actdesc(dof, &hdr, start_off, sec_num);
				break;
			}
			case DOF_SECT_COMMENTS: {

				display_sect_comments(dof, &hdr, start_off, sec_num);
				break;
			}
			case DOF_SECT_DIFOHDR: {

				display_sect_difohdr(dof, &hdr, start_off, sec_num);
				break;
			}
			case DOF_SECT_ECBDESC: {

				display_sect_ecbdesc(dof, &hdr, start_off, sec_num);
				break;
			}
			case DOF_SECT_STRTAB: {

				display_sect_strtab(dof, start_off, &sec, sec_num);
				break;
			}
			case DOF_SECT_PROBEDESC: {

				display_sect_probdesc_helper(dof, &hdr, start_off, sec_num);
				break;
			}
			case DOF_SECT_UTSNAME: {

				display_sect_utsname(dof, &hdr, start_off, sec_num);
				break;
			}
			default:
				/* Default prints section as raw hex. */
				display_sect_hex(dof, &hdr, start_off, sec_num);
				return;
			}
		} else {

			printf("Invalid section number %u (> %u)\n", sec_num, hdr.dofh_secnum);
		}
	} else {

		fprintf(stderr, "Error loading DOF header\n");
	}
}

static void
display_sect_probdesc(int dof, off_t start_off, dof_hdr_t *hdr, dof_sec_t *sec,
    uint32_t sec_num)
{
	struct bbuf *strtab_buf;
	dof_probedesc_t pdesc;
	char *strtab;
	int rc;

	rc = load_sect_probedesc(dof, start_off, hdr, sec, &pdesc);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing probedesc (DOF malformed)");
	}

	//rc = load_sect_strtab(dof, start_off, &sec, &strtab_buf);
	rc = load_sect_hex(dof, start_off, sec, &strtab_buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing strtab (DOF malformed)");
	}

	strtab = (char *) bbuf_data(strtab_buf);
	
	printf("===Section (%u) %s=========\n", sec_num, get_section_name(sec));

	/* Print the probedesc (using the same formatting as dtrace -l). */
	printf("%5s %10s %17s %33s %s\n",
	    "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");

	printf("%5d %10s %17s %33s %s\n", pdesc.dofp_id,
		&strtab[pdesc.dofp_provider], &strtab[pdesc.dofp_mod],
		&strtab[pdesc.dofp_func], &strtab[pdesc.dofp_name]);

	bbuf_delete(strtab_buf);
}

static void
display_sect_probdesc_helper(int dof, dof_hdr_t *hdr, off_t start_off, uint32_t sec_num)
{
	struct bbuf *strtab_buf;
	dof_probedesc_t pdesc;
	dof_sec_t sec;
	char *strtab;
	int rc;

	/* Load the probedesc strtab section. */
	rc = load_sect_header(dof, start_off, hdr, sec_num, &sec);
	if (rc != 0) {

	}

	rc = load_sect_probedesc(dof, start_off, hdr, &sec, &pdesc);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing probedesc (DOF malformed)");
	}

	/* Load the probedesc strtab section. */
	rc = load_sect_header(dof, start_off, hdr, sec_num, &sec);
	if (rc != 0) {

	}

	//rc = load_sect_strtab(dof, start_off, &sec, &strtab_buf);
	rc = load_sect_hex(dof, start_off, &sec, &strtab_buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing strtab (DOF malformed)");
	}

	strtab = (char *) bbuf_data(strtab_buf);
	
	printf("===Section (%u) %s=========\n", sec_num, get_section_name(&sec));

	/* Print the probedesc (using the same formatting as dtrace -l). */
	printf("%5s %10s %17s %33s %s\n",
	    "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");

	printf("%5d %10s %17s %33s %s\n", pdesc.dofp_id,
		&strtab[pdesc.dofp_provider], &strtab[pdesc.dofp_mod],
		&strtab[pdesc.dofp_func], &strtab[pdesc.dofp_name]);

	bbuf_delete(strtab_buf);
}

static void
display_sect_probdescs(int dof)
{
	dof_hdr_t hdr;
	off_t start;
	int rc;

	rc = load_dof_header(dof, &hdr, &start);
	if (rc == 0) {

		for (uint32_t sec_num = 0; sec_num < hdr.dofh_secnum; sec_num++) {

			dof_sec_t sec;

			load_sect_header(dof, start, &hdr, sec_num, &sec);
			if (sec.dofs_type == DOF_SECT_PROBEDESC) { 
			
				display_sect_probdesc(dof, start, &hdr, &sec, sec_num);
			}
		}
	}
}

static void
display_sect_strtab(int dof, off_t start_off, dof_sec_t *sec, uint32_t sec_num)
{
	struct bbuf *strtab_buf;
	char *strtab;
	size_t str_idx = 0;
	int rc;
			
	/* Load the probedesc strtab section. */
	rc = load_sect_hex(dof, start_off, sec, &strtab_buf);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing strtab (DOF malformed)");
	}

	strtab = (char *) bbuf_data(strtab_buf);

	printf("===Section (%u) %s=========\n", sec_num, get_section_name(sec));

	/* Print the probedesc (using the same formatting as dtrace -l). */
	printf("%10s %60s\n", "INDEX", "FORMAT");

	for (size_t i = 0; i < bbuf_len(strtab_buf); i++) {
		
		if (strtab[i] == '\0') {

			printf("%10zu %60s\n", str_idx, &strtab[str_idx]); 
			str_idx = i + 1;
		}
	}

	bbuf_delete(strtab_buf);
}

static void
display_sect_strtabs(int dof)
{
	dof_hdr_t hdr;
	off_t start;
	int rc;

	rc = load_dof_header(dof, &hdr, &start);
	if (rc == 0) {

		for (uint32_t sec_num = 0; sec_num < hdr.dofh_secnum; sec_num++) {

			dof_sec_t sec;

			rc = load_sect_header(dof, start, &hdr, sec_num, &sec);
			if (rc != 0) {

				errx(EXIT_FAILURE,
				    "Error parsing section header %u (DOF malformed)", sec_num);
			} else if (sec.dofs_type == DOF_SECT_STRTAB) { 
			
				display_sect_strtab(dof, start, &sec, sec_num);
			}
		}
	}
}

static void
display_sect_difohdr(int fd, dof_hdr_t *hdr, off_t start, uint32_t sec_num)
{
	dof_sec_t sec;
	dtrace_difo_t difo;
	int rc;

	/* Load the section header. */
	rc = load_sect_header(fd, start, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header (DOF malformed)");
	}

	rc = load_sect_difohdr(fd, start, hdr, &sec, &difo);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing difohdr(DOF malformed)");
	}
	
	printf("===Section (%u) %s=========\n", sec_num, get_section_name(&sec));
	dt_dis(&difo, stdout);
}

static void
display_sect_actdesc(int fd, dof_hdr_t *hdr, off_t start, uint32_t sec_num)
{
	dof_sec_t sec;
	dof_actdesc_t actdesc;
	int rc;
	
	/* Load the section header. */
	rc = load_sect_header(fd, start, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header (DOF malformed)");
	}

	rc = load_sect_actdesc(fd, hdr, start, &sec, &actdesc);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing actdesc (DOF malformed)");
	}
	
	printf("===Section (%u) %s=========\n", sec_num, get_section_name(&sec));
	printf("No. of subsequent tuple actions: %d\n", actdesc.dofa_ntuple);
	printf("Action argument: %ld\n", actdesc.dofa_arg);
	printf("User argument: %ld\n", actdesc.dofa_uarg);
	switch (actdesc.dofa_kind) {
	case DTRACEACT_NONE:
		printf("Action: None\n");
		break;
	case DTRACEACT_DIFEXPR:
		printf("Action: DIF expression\n");
		break;
	case DTRACEACT_EXIT:
		printf("Action: Exit\n");
		break;
	case DTRACEACT_PRINTF:
		printf("Action: Printf\n");
		break;
	default:
		printf("Action: %d\n", actdesc.dofa_kind);
		break;
	}

	display_sect_difohdr(fd, hdr, start, actdesc.dofa_difo);
}

static void
display_sect_ecbdesc(int fd, dof_hdr_t *hdr, off_t start, uint32_t sec_num)
{
	dof_sec_t sec;
	dof_ecbdesc_t ecbdesc;
	int rc;
			
	/* Load the section header. */
	rc = load_sect_header(fd, start, hdr, sec_num, &sec);
	if (rc != 0) {

		errx(EXIT_FAILURE, "Error parsing section header (DOF malformed)");
	}

	rc = load_sect_ecbdesc(fd, hdr, start, &sec, &ecbdesc);
	if (rc != 0) {
		
		errx(EXIT_FAILURE, "Error parsing ecbdesc (DOF malformed)");
	}
	
	printf("===Section (%u) %s=========\n", sec_num, get_section_name(&sec));
	display_sect_probdesc_helper(fd, hdr, start, ecbdesc.dofe_probes);
	if (ecbdesc.dofe_pred != DOF_SECIDX_NONE) {

		display_sect_difohdr(fd, hdr, start, ecbdesc.dofe_pred);
	}
	if (ecbdesc.dofe_actions != DOF_SECIDX_NONE) {

		display_sect_actdesc(fd, hdr, start, ecbdesc.dofe_actions);
	}
}

static int
hex2int(char ch)
{
	if (ch >= '0' && ch <= '9')
        	return ch - '0';
    
	if (ch >= 'A' && ch <= 'F')
        	return ch - 'A' + 10;

	if (ch >= 'a' && ch <= 'f')
        	return ch - 'a' + 10;

	return -1;
}

static char const *
get_section_name(dof_sec_t *sec)
{
	assert(sec != NULL);

	if (sec->dofs_type <= DOF_SECT_PRENOFFS) { 

		return RDOF_SECT_NAMES[sec->dofs_type];
	}

	return  NULL;
}

static int
load_dof_header(int fd, dof_hdr_t *hdr, off_t *start)
{
	uint64_t sec_len;
	int offset;
	uint8_t raw_hdr[sizeof(dof_hdr_t)];

	/* Advance the file to the start of the DOF header. */	
#ifdef __FreeBSD__
	offset = snprintf(NULL, 0, "dof-data-%d=", 0);
#else
	offset = snprintf(NULL, 0, "dof-data-%d=", 0);
#endif

	*start = lseek(fd, offset, SEEK_SET);
	if (*start == -1) {

		return -1;
	}

	/* Read the header from the file ASCII->bin */
	for (uint64_t i = 0; i < sizeof(dof_hdr_t); i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		if (bytes == -1) {

			return -1;
		}
		raw_hdr[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	/* Copy the byes read from the file to the header structure. */
	memcpy(hdr, raw_hdr, sizeof(dof_hdr_t));

	/* Validate the DOF file header. */
	if (hdr->dofh_ident[DOF_ID_MAG0] != DOF_MAG_MAG0 ||
	    hdr->dofh_ident[DOF_ID_MAG1] != DOF_MAG_MAG1 ||
	    hdr->dofh_ident[DOF_ID_MAG2] != DOF_MAG_MAG2 ||
	    hdr->dofh_ident[DOF_ID_MAG3] != DOF_MAG_MAG3) {

		fprintf(stderr, "DOF file magic invalid\n");
		return -1;
	} 
	
	if (hdr->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_ILP32 &&
	    hdr->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_LP64) {

		fprintf(stderr, "DOF model invalid\n");
		return -1;
	}

	if (hdr->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_LSB &&
	    hdr->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_MSB) {

		fprintf(stderr, "DOF encoding invalid\n");
		return -1;
	}

	if (hdr->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_1 &&
	    hdr->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_2) {

		fprintf(stderr, "DOF version invalid\n");
		return -1;
	}

	if (hdr->dofh_ident[DOF_ID_DIFVERS] != DIF_VERSION_2) {

		fprintf(stderr, "DIF version invalid\n");
		return -1;
	}

	for (int i = DOF_ID_PAD; i < DOF_ID_SIZE; i++) {

		if (hdr->dofh_ident[i] != 0) {

			fprintf(stderr, "DOF padding invalid\n");
			return -1;
		}
	}

	if (hdr->dofh_flags & ~DOF_FL_VALID) {

		fprintf(stderr, "DOF flag invalid\n");
		return -1;
	}

	if (hdr->dofh_secsize == 0) {

		fprintf(stderr, "DOF secsize invalid\n");
		return -1;
	}

	sec_len = (uint64_t) hdr->dofh_secnum * (uint64_t) hdr->dofh_secsize;
	if (hdr->dofh_secoff > hdr->dofh_loadsz ||
	    sec_len > hdr->dofh_loadsz ||
	    hdr->dofh_secoff + sec_len > hdr->dofh_loadsz) {

		return -1;
	}

	if (!IS_P2ALIGNED(hdr->dofh_secoff, sizeof(uint64_t))) {

		fprintf(stderr, "DOF secoff improperly aligned\n");
		return -1;
	}

	if (!IS_P2ALIGNED(hdr->dofh_secsize, sizeof(uint64_t))) {

		fprintf(stderr, "DOF secsize improperly aligned\n");
		return -1;
	}

	return 0;
}

static int
load_sect_actdesc(int fd, dof_hdr_t *hdr, off_t start_off, dof_sec_t *sec,
    dof_actdesc_t *actdesc)
{
	struct bbuf *buf;
	off_t off;
	unsigned char *data;
	int rc;

	off = lseek(fd, start_off + (2 * sec->dofs_offset), SEEK_SET);
	if (off == -1) {

		return -1;
	}
		
	if (hdr->dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {
	
		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_LITTLEENDIAN);
	} else {

		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_BIGENDIAN);
	}

	data = bbuf_data(buf);

	/* Load the section ASCII->binary. */ 
	for (uint64_t i = 0; i < sec->dofs_size; i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		data[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	rc |= bbuf_get_uint32(buf, &actdesc->dofa_difo);
	rc |= bbuf_get_uint32(buf, &actdesc->dofa_strtab);
	rc |= bbuf_get_uint32(buf, &actdesc->dofa_kind);
	rc |= bbuf_get_uint32(buf, &actdesc->dofa_ntuple);
	rc |= bbuf_get_uint64(buf, &actdesc->dofa_arg);
	rc |= bbuf_get_uint64(buf, &actdesc->dofa_uarg);
	if (rc != 0) {

		bbuf_delete(buf);
		errx(EXIT_FAILURE, "Error parsing probedesc (DOF malformed)");
	}

	bbuf_delete(buf);
	return 0;
}

static int
load_sect_difohdr(int fd, off_t start, dof_hdr_t *hdr, dof_sec_t *sec, 
    dtrace_difo_t *difo)
{
	struct bbuf *buf;
	dof_secidx_t secidx;
	off_t off;
	unsigned char *data;
	int rc;

	off = lseek(fd, start + (2 * sec->dofs_offset), SEEK_SET);
	if (off == -1) {

		return -1;
	}
		
	if (hdr->dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {
	
		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_LITTLEENDIAN);
	} else {

		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_BIGENDIAN);
	}

	data = bbuf_data(buf);

	/* Load the section ASCII->binary. */ 
	for (uint64_t i = 0; i < sec->dofs_size; i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		data[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	memset(difo, 0, sizeof(dtrace_difo_t));
	rc |= bbuf_get_uint8(buf, &difo->dtdo_rtype.dtdt_kind);
	rc |= bbuf_get_uint8(buf, &difo->dtdo_rtype.dtdt_ckind);
	rc |= bbuf_get_uint8(buf, &difo->dtdo_rtype.dtdt_flags);
	rc |= bbuf_get_uint8(buf, &difo->dtdo_rtype.dtdt_pad);
	rc |= bbuf_get_uint32(buf, &difo->dtdo_rtype.dtdt_size);

	while(bbuf_get_uint32(buf, &secidx) == 0) {

		dof_sec_t tmp_sec;
	
		rc = load_sect_header(fd, start, hdr, secidx, &tmp_sec);
		if (rc != 0) {

		}

		switch (tmp_sec.dofs_type) {
		case DOF_SECT_DIF: {

			struct bbuf *dif_buf;
			dif_instr_t *dtdo_buf;

			dtdo_buf = malloc(tmp_sec.dofs_size);

			rc = bbuf_new(&dif_buf, (unsigned char *) dtdo_buf, tmp_sec.dofs_size, BBUF_LITTLEENDIAN);
			if (rc != 0) {

				// TODO clean up DIFO
				return -1;
			}

			rc = load_sect_hex_into(fd, start, &tmp_sec, dif_buf);
			if (rc == 0) {

				difo->dtdo_buf = dtdo_buf;
				difo->dtdo_len = tmp_sec.dofs_size / sizeof(dif_instr_t);
			}
			break;
		}
		case DOF_SECT_STRTAB: {

			struct bbuf *strtab_buf;
			unsigned char *dtdo_buf;

			dtdo_buf = malloc(tmp_sec.dofs_size);

			rc = bbuf_new(&strtab_buf, dtdo_buf, tmp_sec.dofs_size, BBUF_LITTLEENDIAN);
			if (rc != 0) {

				// TODO clean up DIFO
				return -1;
			}


			rc = load_sect_hex_into(fd, start, &tmp_sec, strtab_buf);
			if (rc == 0) {

				difo->dtdo_strtab = (char *) dtdo_buf;
				difo->dtdo_strlen = tmp_sec.dofs_size;
			}
			break;
		}
		default:
			break;
		}	
	}	

	//bbuf_delete(buf);
	return 0;
}


static int
load_sect_ecbdesc(int fd, dof_hdr_t *hdr, off_t start_off, dof_sec_t *sec,
    dof_ecbdesc_t *ecbdesc)
{
	struct bbuf *buf;
	off_t off;
	unsigned char *data;
	int rc;

	off = lseek(fd, start_off + (2 * sec->dofs_offset), SEEK_SET);
	if (off == -1) {

		return -1;
	}
		
	if (hdr->dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {
	
		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_LITTLEENDIAN);
	} else {

		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_BIGENDIAN);
	}

	data = bbuf_data(buf);

	/* Load the section ASCII->binary. */ 
	for (uint64_t  i = 0; i < sec->dofs_size; i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		data[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	rc |= bbuf_get_uint32(buf, &ecbdesc->dofe_probes);
	rc |= bbuf_get_uint32(buf, &ecbdesc->dofe_pred);
	rc |= bbuf_get_uint32(buf, &ecbdesc->dofe_actions);
	rc |= bbuf_get_uint32(buf, &ecbdesc->dofe_pad);
	rc |= bbuf_get_uint64(buf, &ecbdesc->dofe_uarg);
	if (rc != 0) {

		bbuf_delete(buf);
		errx(EXIT_FAILURE, "Error parsing probedesc (DOF malformed)");
	}

	bbuf_delete(buf);
	return 0;
}

static int
load_sect_header(int fd, off_t start, dof_hdr_t *hdr, uint32_t sec_num, dof_sec_t *sec)
{
	struct bbuf *buf;
	off_t off;
	uint32_t sec_idx = sec_num - 1;
	int rc;
	uint8_t raw_sec[sizeof(dof_sec_t)];
	
	off = lseek(fd, start + (hdr->dofh_secoff * 2) + (sec_idx * sizeof(dof_sec_t) * 2), SEEK_SET);
	if (off == -1) {

		return -1;
	}

	/* Load the section header ASCII->binary. */ 
	for (uint64_t i = 0; i < sizeof(dof_sec_t); i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		if (bytes == -1) {

			return -1;
		}

		raw_sec[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	/* Construct a dof_sec_t respecting DOF endianness. */
	if (hdr->dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {
	
		rc = bbuf_new(&buf, raw_sec, sizeof(dof_sec_t), BBUF_LITTLEENDIAN);
	} else {
	
		bbuf_new(&buf, raw_sec, sizeof(dof_sec_t), BBUF_BIGENDIAN);
	}
	rc = bbuf_get_uint32(buf, &sec->dofs_type);
	rc |= bbuf_get_uint32(buf, &sec->dofs_align);
	rc |= bbuf_get_uint32(buf, &sec->dofs_flags);
	rc |= bbuf_get_uint32(buf, &sec->dofs_entsize);
	rc |= bbuf_get_uint64(buf, &sec->dofs_offset);
	rc |= bbuf_get_uint64(buf, &sec->dofs_size);
	bbuf_delete(buf);

	return rc;
}

static int
load_sect_hex(int fd, off_t start, dof_sec_t *sec, struct bbuf **buf)
{
	int rc;

	rc = bbuf_new(buf, NULL, sec->dofs_size, BBUF_LITTLEENDIAN);
	if (rc == 0) {

		return load_sect_hex_into(fd, start, sec, *buf);
	}
		
	return rc;
}

static int
load_sect_hex_into(int fd, off_t start_off, dof_sec_t *sec, struct bbuf *buf)
{
	off_t off;
	char * strtab;

	off = lseek(fd, start_off + (2 * sec->dofs_offset), SEEK_SET);
	if (off == -1) {

		return -1;
	}

	/* Load the section ASCII->binary. */ 
	strtab = (char *) bbuf_data(buf);

	for (uint64_t i = 0; i < sec->dofs_size; i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		strtab[i] = (((uint16_t) hex2int(ch[0]) << 4) & 0xF0) | hex2int(ch[1]);
	}

	return 0;
}

static int
load_sect_probedesc(int fd, off_t start_off, dof_hdr_t *hdr, dof_sec_t *sec,
    dof_probedesc_t *pdesc)
{
	struct bbuf *buf;
	off_t off;
	unsigned char *data;
	int rc;

	off = lseek(fd, start_off + (2 * sec->dofs_offset), SEEK_SET);
	if (off == -1) {

		return -1;
	}
		
	if (hdr->dofh_ident[DOF_ID_ENCODING] == DOF_ENCODE_LSB) {
	
		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_LITTLEENDIAN);
	} else {

		rc = bbuf_new(&buf, NULL, sec->dofs_size, BBUF_BIGENDIAN);
	}

	data = bbuf_data(buf);

	/* Load the section ASCII->binary. */ 
	for (uint64_t i = 0; i < sec->dofs_size; i++) {

		uint8_t ch[2];
		ssize_t bytes;

		bytes = read(fd, (void *) ch, sizeof(ch));
		data[i] = ((uint16_t) hex2int(ch[0]) << 4) | hex2int(ch[1]);
	}

	rc |= bbuf_get_uint32(buf, &pdesc->dofp_strtab);
	rc |= bbuf_get_uint32(buf, &pdesc->dofp_provider);
	rc |= bbuf_get_uint32(buf, &pdesc->dofp_mod);
	rc |= bbuf_get_uint32(buf, &pdesc->dofp_func);
	rc |= bbuf_get_uint32(buf, &pdesc->dofp_name);
	rc |= bbuf_get_uint32(buf, &pdesc->dofp_id);
	if (rc != 0) {

		bbuf_delete(buf);
		errx(EXIT_FAILURE, "Error parsing probedesc (DOF malformed)");
	}

	bbuf_delete(buf);
	return 0;
}

int
main(int argc, char **argv)
{
	static struct option options[] = {
		{"big-endian", no_argument, NULL, 'B'},
		{"file-header", no_argument, NULL, 'f'},
		{"octet-grp", no_argument, NULL, 'g'},
		{"len", no_argument, NULL, 'l'},
		{"little_endian", no_argument, NULL, 'L'},
		{"string-dump", no_argument, NULL, 'p'},
		{"probedesc", no_argument, NULL, 'P'},
		{"section-headers", optional_argument, NULL, 'S'},
		{"strtab", no_argument, NULL, 'T'},
		{"version", no_argument, NULL, 'v'},
		{"hex-dump", no_argument, NULL, 'x'},
		{0, 0, 0, 0}
	};
	uint32_t sec_num = 0;
	readdof_flags_t mode = 0;
	char *pname;
	int c, dof;
	bool isHex = false;

	pname = basename(argv[0]);

	/* Parse the rest of the command line arguments */
	while ((c = getopt_long(argc, argv, "Bfg:l:S::p:PTvx", options, NULL)) != -1) {
		switch(c) {
		case 'B':
			/* Display hex output as big endian */
			endian = RDOF_BIG;
			break;
		case 'f':
			/* Print the details of the DOF header */
			mode |= RDOF_HDR;
			break;
		case 'g':
			/* Octet group */
			if (sscanf(optarg, "%hhu", &octet_grp) != 1) {

				errx(EXIT_FAILURE, RDOF_USAGE, pname);
			}
			break;
		case 'l':
			/* Length */
			if (sscanf(optarg, "%lu", &len) != 1) {

				errx(EXIT_FAILURE, RDOF_USAGE, pname);
			}
			break;
		case 'L':
			/* Display hex output as little endian */
			endian = RDOF_LITTLE;
			break;
		case 'S':
			/* Print the details of the DOF section headers */
			mode |= RDOF_SECHDR;

			if (optarg != NULL &&
			    sscanf(optarg, "%u", &sec_num) != 1) {

				errx(EXIT_FAILURE, RDOF_USAGE, pname);
			}
			break;
		case 'p':
			/* Print the details of the DOF section */
			mode |= RDOF_PRINT;

			if (sscanf(optarg, "%u", &sec_num) != 1) {

				errx(EXIT_FAILURE, RDOF_USAGE, pname);
			}
			break;
		case 'P':

			mode |= RDOF_PROBES;
			break;
		case 'T':
			/* Display all DOF_SECT_STRTAB sections. */
			mode |= RDOF_STRTABS;
			break;
		case 'v':
			/* Print the readdof version information. */
			errx(EXIT_SUCCESS, RDOF_VER, pname, DOF_VERSION);
			break;
		case 'x':
			/* Output in hex. */
			isHex = true;
			break;
		case '?':
		default:
			errx(EXIT_FAILURE, RDOF_USAGE, pname);
		}
	}

	argv += optind;
	argc -= optind;

	if (argc == 0 || mode == 0) {

		errx(EXIT_FAILURE, RDOF_USAGE, pname);
	}

	/* Open the DOF file. */
	dof = open(argv[0], O_RDONLY);
	if (dof == -1) {

		errx(EXIT_FAILURE, "Failed opening DOF file: %s\n", argv[0]);
	}

	if (mode & RDOF_HDR) {

		/* Print the details of the DOF header */
		if (isHex) {

			display_dof_header_hex(dof);
		} else {

			display_dof_header(dof);
		}
	}

	if (mode & RDOF_SECHDR) {

		if (sec_num == 0) {
			
			display_dof_sect_headers(dof);
		} else {

			display_dof_sect_header(dof, sec_num);
		}
	}
	
	if (mode & RDOF_PROBES) {

		display_sect_probdescs(dof);
	}
	
	if (mode & RDOF_STRTABS) {

		display_sect_strtabs(dof);
	}

	if (mode & RDOF_PRINT) {

		if (isHex) {

			display_dof_sect_hex(dof, sec_num);
		} else {

			display_dof_section(dof, sec_num);
		}
	}

	close(dof);

	return EXIT_SUCCESS;
}
