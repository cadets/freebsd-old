/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2013, Joyent, Inc. All rights reserved.
 * Copyright (c) 2020 Domagoj Stolfa. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <machine/vmm.h>

#include <dtrace.h>
#include <dt_elf.h>
#include <dt_resolver.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>
#ifdef illumos
#include <alloca.h>
#endif
#include <libgen.h>
#ifdef illumos
#include <libproc.h>
#endif
#ifdef __FreeBSD__
#include <spawn.h>
#include <dt_prog_link.h>
#endif
#include <dtdaemon.h>

#include <pthread.h>

typedef struct dtrace_cmd {
	void (*dc_func)(struct dtrace_cmd *);	/* function to compile arg */
	dtrace_probespec_t dc_spec;		/* probe specifier context */
	char *dc_arg;				/* argument from main argv */
	const char *dc_name;			/* name for error messages */
	const char *dc_desc;			/* desc for error messages */
	dtrace_prog_t *dc_prog;			/* program compiled from arg */
	char dc_ofile[PATH_MAX];		/* derived output file name */
} dtrace_cmd_t;

typedef struct dtd_arg {
	int sock;
	dtrace_prog_t *hostpgp;
} dtd_arg_t;

typedef struct dt_pgplist {
	dt_list_t list;
	dtrace_prog_t *pgp;
	/*
	 * NOTE: We call this "guest program" because even though for now it's
	 * just a list, we might want to do some work in the future to achieve
	 * more type-checking, etc.
	 */
	dtrace_prog_t *gpgp;
	uint16_t vmid;
} dt_pgplist_t;

typedef struct dt_probelist {
	dt_list_t list;
	const dtrace_probedesc_t *pdesc;
} dt_probelist_t;

#define	DMODE_VERS	0	/* display version information and exit (-V) */
#define	DMODE_EXEC	1	/* compile program for enabling (-a/e/E) */
#define	DMODE_ANON	2	/* compile program for anonymous tracing (-A) */
#define	DMODE_LINK	3	/* compile program for linking with ELF (-G) */
#define	DMODE_LIST	4	/* compile program and list probes (-l) */
#define	DMODE_HEADER	5	/* compile program for headergen (-h) */

#define	E_SUCCESS	0
#define	E_ERROR		1
#define	E_USAGE		2

static const char DTRACE_OPTSTR[] =
	"3:6:aAb:Bc:CD:eEf:FGhHi:I:lL:m:n:o:p:P:qs:SU:vVwx:y:Y:X:Z";

static char **g_argv;
static int g_argc;
static int g_guest = 0;
static char **g_objv;
static int g_objc;
static dtrace_cmd_t *g_cmdv;
static int g_cmdc;
static struct ps_prochandle **g_psv;
static int g_psc;
static int g_pslive;
static char *g_pname;
static int g_quiet;
static int g_flowindent;
static _Atomic int g_intr;
static _Atomic int g_impatient;
static _Atomic int g_newline;

/*
 * Program list for HyperTrace
 */
static dt_list_t g_probe_advlist;
static dt_list_t g_pgplist;
static pthread_mutex_t g_pgplistmtx;
static pthread_cond_t g_pgpcond;
static pthread_mutex_t g_pgpcondmtx;

#ifdef __FreeBSD__
static _Atomic int g_siginfo;
static uint32_t rslv;
#endif
static int g_total;
static int g_cflags;
static int g_oflags;
static int g_verbose;
static int g_exec = 1;
static int g_elf = 0;
static const char *g_graphfile = NULL;
static int g_mode = DMODE_EXEC;
static int g_status = E_SUCCESS;
static int g_grabanon = 0;

static pthread_t g_dtdaemontd;
static pthread_t g_worktd;

static const char *g_ofile = NULL;
static FILE *g_ofp;

static pthread_mutex_t g_dtpmtx;
static dtrace_hdl_t *g_dtp;

#ifdef illumos
static char *g_etcfile = "/etc/system";
static const char *g_etcbegin = "* vvvv Added by DTrace";
static const char *g_etcend = "* ^^^^ Added by DTrace";

static const char *g_etc[] =  {
"*",
"* The following forceload directives were added by dtrace(1M) to allow for",
"* tracing during boot.  If these directives are removed, the system will",
"* continue to function, but tracing will not occur during boot as desired.",
"* To remove these directives (and this block comment) automatically, run",
"* \"dtrace -A\" without additional arguments.  See the \"Anonymous Tracing\"",
"* chapter of the Solaris Dynamic Tracing Guide for details.",
"*",
NULL };
#endif

#if !defined(illumos) && defined(NEED_ERRLOC)
void dt_get_errloc(dtrace_hdl_t *, char **, int *);
#endif /* !illumos && NEED_ERRLOC */

static void go(void);

static int
usage(FILE *fp)
{
	static const char predact[] = "[[ predicate ] action ]";

	(void) fprintf(fp, "Usage: %s [-32|-64] [-aACeFGhHlqSvVwZ] "
	    "[-b bufsz] [-c cmd] [-D name[=def]]\n\t[-g gv_output] [-I path] "
	    "[-L path] [-o output] [-p pid] [-s script] [-U name]\n\t"
	    "[-x opt[=val]] [-X a|c|s|t]\n\n"
	    "\t[-P provider %s]\n"
	    "\t[-m [ provider: ] module %s]\n"
	    "\t[-f [[ provider: ] module: ] func %s]\n"
	    "\t[-n [[[ provider: ] module: ] func: ] name %s]\n"
	    "\t[-i probe-id %s] [ args ... ]\n\n", g_pname,
	    predact, predact, predact, predact, predact);

	(void) fprintf(fp, "\tpredicate -> '/' D-expression '/'\n");
	(void) fprintf(fp, "\t   action -> '{' D-statements '}'\n");

	(void) fprintf(fp, "\n"
	    "\t-32 generate 32-bit D programs and ELF files\n"
	    "\t-64 generate 64-bit D programs and ELF files\n\n"
	    "\t-a  claim anonymous tracing state\n"
	    "\t-A  generate driver.conf(4) directives for anonymous tracing\n"
	    "\t-b  set trace buffer size\n"
	    "\t-c  run specified command and exit upon its completion\n"
	    "\t-C  run cpp(1) preprocessor on script files\n"
	    "\t-D  define symbol when invoking preprocessor\n"
	    "\t-e  exit after compiling request but prior to enabling probes\n"
	    "\t-E  generate an ELF file instead of a DOF file\n"
	    "\t-f  enable or list probes matching the specified function name\n"
	    "\t-F  coalesce trace output by function\n"
	    "\t-G  generate an ELF file containing embedded dtrace program\n"
	    "\t-g  output GraphViz Dot representation of script actions\n"
	    "\t-h  generate a header file with definitions for static probes\n"
	    "\t-H  print included files when invoking preprocessor\n"
	    "\t-i  enable or list probes matching the specified probe id\n"
	    "\t-I  add include directory to preprocessor search path\n"
	    "\t-l  list probes matching specified criteria\n"
	    "\t-L  add library directory to library search path\n"
	    "\t-m  enable or list probes matching the specified module name\n"
	    "\t-n  enable or list probes matching the specified probe name\n"
	    "\t-o  set output file\n"
	    "\t-p  grab specified process-ID and cache its symbol tables\n"
	    "\t-P  enable or list probes matching the specified provider name\n"
	    "\t-q  set quiet mode (only output explicitly traced data)\n"
	    "\t-s  enable or list probes according to the specified D script\n"
	    "\t-S  print D compiler intermediate code\n"
	    "\t-U  undefine symbol when invoking preprocessor\n"
	    "\t-v  set verbose mode (report stability attributes, arguments)\n"
	    "\t-V  report DTrace API version\n"
	    "\t-w  permit destructive actions\n"
	    "\t-x  enable or modify compiler and tracing options\n"
	    "\t-X  specify ISO C conformance settings for preprocessor\n"
	    "\t-Z  permit probe descriptions that match zero probes\n");

	return (E_USAGE);
}

static void
verror(const char *fmt, va_list ap)
{
	int error = errno;

	(void) fprintf(stderr, "%s: ", g_pname);
	(void) vfprintf(stderr, fmt, ap);

	if (fmt[strlen(fmt) - 1] != '\n')
		(void) fprintf(stderr, ": %s\n", strerror(error));
}

/*PRINTFLIKE1*/
static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);

	/*
	 * Close the DTrace handle to ensure that any controlled processes are
	 * correctly restored and continued.
	 */
	if (g_dtp)
		dtrace_close(g_dtp);

	sleep(10);
	exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
dfatal(const char *fmt, ...)
{
#if !defined(illumos) && defined(NEED_ERRLOC)
	char *p_errfile = NULL;
	int errline = 0;
#endif
	va_list ap;

	va_start(ap, fmt);

	(void) fprintf(stderr, "%s: ", g_pname);
	if (fmt != NULL)
		(void) vfprintf(stderr, fmt, ap);

	va_end(ap);

	if (fmt != NULL && fmt[strlen(fmt) - 1] != '\n') {
		(void) fprintf(stderr, ": %s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	} else if (fmt == NULL) {
		(void) fprintf(stderr, "%s\n",
		    dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
	}
#if !defined(illumos) && defined(NEED_ERRLOC)
	dt_get_errloc(g_dtp, &p_errfile, &errline);
	if (p_errfile != NULL)
		printf("File '%s', line %d\n", p_errfile, errline);
#endif

	/*
	 * Close the DTrace handle to ensure that any controlled processes are
	 * correctly restored and continued.
	 */
	pthread_mutex_lock(&g_dtpmtx);
	dtrace_close(g_dtp);
	g_dtp = NULL;
	pthread_mutex_unlock(&g_dtpmtx);
	
	pthread_mutex_destroy(&g_dtpmtx);

	exit(E_ERROR);
}

/*PRINTFLIKE1*/
static void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
notice(const char *fmt, ...)
{
	va_list ap;

	if (g_quiet)
		return; /* -q or quiet pragma suppresses notice()s */

	va_start(ap, fmt);
	verror(fmt, ap);
	va_end(ap);
}

/*PRINTFLIKE1*/
static void
oprintf(const char *fmt, ...)
{
	va_list ap;
	int n;

	if (g_ofp == NULL)
		return;

	va_start(ap, fmt);
	n = vfprintf(g_ofp, fmt, ap);
	va_end(ap);

	if (n < 0) {
		if (errno != EINTR) {
			fatal("failed to write to %s",
			    g_ofile ? g_ofile : "<stdout>");
		}
		clearerr(g_ofp);
	}
}

static char **
make_argv(char *s)
{
	const char *ws = "\f\n\r\t\v ";
	char **argv = malloc(sizeof (char *) * (strlen(s) / 2 + 1));
	int argc = 0;
	char *p = s;

	if (argv == NULL)
		return (NULL);

	for (p = strtok(s, ws); p != NULL; p = strtok(NULL, ws))
		argv[argc++] = p;

	if (argc == 0)
		argv[argc++] = s;

	argv[argc] = NULL;
	return (argv);
}

/*ARGSUSED*/
static void
intr(int signo)
{
	if (!atomic_load(&g_intr))
		atomic_store(&g_newline, 1);

	if (atomic_fetch_add(&g_intr, 1))
		atomic_store(&g_impatient, 1);
}

#ifdef __FreeBSD__
static void
siginfo(int signo __unused)
{

	atomic_fetch_add(&g_siginfo, 1);
	atomic_store(&g_newline, 1);
}
#endif

static void
installsighands(void)
{
	struct sigaction act, oact;

	(void) sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = intr;

	if (sigaction(SIGINT, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void) sigaction(SIGINT, &act, NULL);

	if (sigaction(SIGTERM, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void) sigaction(SIGTERM, &act, NULL);

#ifdef __FreeBSD__
	if (sigaction(SIGPIPE, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void) sigaction(SIGPIPE, &act, NULL);

	if (sigaction(SIGUSR1, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void) sigaction(SIGUSR1, &act, NULL);

	act.sa_handler = siginfo;
	if (sigaction(SIGINFO, NULL, &oact) == 0 && oact.sa_handler != SIG_IGN)
		(void) sigaction(SIGINFO, &act, NULL);
#endif
}

static void
dof_prune(const char *fname)
{
	struct stat sbuf;
	size_t sz, i, j, mark, len;
	char *buf;
	int msg = 0, fd;

	if ((fd = open(fname, O_RDONLY)) == -1) {
		/*
		 * This is okay only if the file doesn't exist at all.
		 */
		if (errno != ENOENT)
			fatal("failed to open %s", fname);
		return;
	}

	if (fstat(fd, &sbuf) == -1)
		fatal("failed to fstat %s", fname);

	if ((buf = malloc((sz = sbuf.st_size) + 1)) == NULL)
		fatal("failed to allocate memory for %s", fname);

	if (read(fd, buf, sz) != sz)
		fatal("failed to read %s", fname);

	buf[sz] = '\0';
	(void) close(fd);

	if ((fd = open(fname, O_WRONLY | O_TRUNC)) == -1)
		fatal("failed to open %s for writing", fname);

	len = strlen("dof-data-");

	for (mark = 0, i = 0; i < sz; i++) {
		if (strncmp(&buf[i], "dof-data-", len) != 0)
			continue;

		/*
		 * This is only a match if it's in the 0th column.
		 */
		if (i != 0 && buf[i - 1] != '\n')
			continue;

		if (msg++ == 0) {
			error("cleaned up old anonymous "
			    "enabling in %s\n", fname);
		}

		/*
		 * We have a match.  First write out our data up until now.
		 */
		if (i != mark) {
			if (write(fd, &buf[mark], i - mark) != i - mark)
				fatal("failed to write to %s", fname);
		}

		/*
		 * Now scan forward until we scan past a newline.
		 */
		for (j = i; j < sz && buf[j] != '\n'; j++)
			continue;

		/*
		 * Reset our mark.
		 */
		if ((mark = j + 1) >= sz)
			break;

		i = j;
	}

	if (mark < sz) {
		if (write(fd, &buf[mark], sz - mark) != sz - mark)
			fatal("failed to write to %s", fname);
	}

	(void) close(fd);
	free(buf);
}

#ifdef __FreeBSD__
/*
 * Use nextboot(8) to tell the loader to load DTrace kernel modules during
 * the next boot of the system. The nextboot(8) configuration is removed during
 * boot, so it will not persist indefinitely.
 */
static void
bootdof_add(void)
{
	char * const nbargv[] = {
		"nextboot", "-a",
		"-e", "dtraceall_load=\"YES\"",
		"-e", "dtrace_dof_load=\"YES\"",
		"-e", "dtrace_dof_name=\"/boot/dtrace.dof\"",
		"-e", "dtrace_dof_type=\"dtrace_dof\"",
		NULL,
	};
	pid_t child;
	int err, status;

	err = posix_spawnp(&child, "nextboot", NULL, NULL, nbargv,
	    NULL);
	if (err != 0) {
		error("failed to execute nextboot: %s", strerror(err));
		exit(E_ERROR);
	}

	if (waitpid(child, &status, 0) != child)
		fatal("waiting for nextboot");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		error("nextboot returned with status %d", status);
		exit(E_ERROR);
	}
}
#else
static void
etcsystem_prune(void)
{
	struct stat sbuf;
	size_t sz;
	char *buf, *start, *end;
	int fd;
	char *fname = g_etcfile, *tmpname;

	if ((fd = open(fname, O_RDONLY)) == -1)
		fatal("failed to open %s", fname);

	if (fstat(fd, &sbuf) == -1)
		fatal("failed to fstat %s", fname);

	if ((buf = malloc((sz = sbuf.st_size) + 1)) == NULL)
		fatal("failed to allocate memory for %s", fname);

	if (read(fd, buf, sz) != sz)
		fatal("failed to read %s", fname);

	buf[sz] = '\0';
	(void) close(fd);

	if ((start = strstr(buf, g_etcbegin)) == NULL)
		goto out;

	if (strlen(buf) != sz) {
		fatal("embedded nul byte in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if (strstr(start + 1, g_etcbegin) != NULL) {
		fatal("multiple start sentinels in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if ((end = strstr(buf, g_etcend)) == NULL) {
		fatal("missing end sentinel in %s; manual repair of %s "
		    "required\n", fname, fname);
	}

	if (start > end) {
		fatal("end sentinel preceeds start sentinel in %s; manual "
		    "repair of %s required\n", fname, fname);
	}

	end += strlen(g_etcend) + 1;
	bcopy(end, start, strlen(end) + 1);

	tmpname = alloca(sz = strlen(fname) + 80);
	(void) snprintf(tmpname, sz, "%s.dtrace.%d", fname, getpid());

	if ((fd = open(tmpname,
	    O_WRONLY | O_CREAT | O_EXCL, sbuf.st_mode)) == -1)
		fatal("failed to create %s", tmpname);

	if (write(fd, buf, strlen(buf)) < strlen(buf)) {
		(void) unlink(tmpname);
		fatal("failed to write to %s", tmpname);
	}

	(void) close(fd);

	if (chown(tmpname, sbuf.st_uid, sbuf.st_gid) != 0) {
		(void) unlink(tmpname);
		fatal("failed to chown(2) %s to uid %d, gid %d", tmpname,
		    (int)sbuf.st_uid, (int)sbuf.st_gid);
	}

	if (rename(tmpname, fname) == -1)
		fatal("rename of %s to %s failed", tmpname, fname);

	error("cleaned up forceload directives in %s\n", fname);
out:
	free(buf);
}

static void
etcsystem_add(void)
{
	const char *mods[20];
	int nmods, line;

	if ((g_ofp = fopen(g_ofile = g_etcfile, "a")) == NULL)
		fatal("failed to open output file '%s'", g_ofile);

	oprintf("%s\n", g_etcbegin);

	for (line = 0; g_etc[line] != NULL; line++)
		oprintf("%s\n", g_etc[line]);

	nmods = dtrace_provider_modules(g_dtp, mods,
	    sizeof (mods) / sizeof (char *) - 1);

	if (nmods >= sizeof (mods) / sizeof (char *))
		fatal("unexpectedly large number of modules!");

	mods[nmods++] = "dtrace";

	for (line = 0; line < nmods; line++)
		oprintf("forceload: drv/%s\n", mods[line]);

	oprintf("%s\n", g_etcend);

	if (fclose(g_ofp) == EOF)
		fatal("failed to close output file '%s'", g_ofile);

	error("added forceload directives to %s\n", g_ofile);
}
#endif /* !__FreeBSD__ */

static void
print_probe_info(const dtrace_probeinfo_t *p)
{
	char buf[BUFSIZ];
	char *user;
	int i;

	oprintf("\n\tProbe Description Attributes\n");

	oprintf("\t\tIdentifier Names: %s\n",
	    dtrace_stability_name(p->dtp_attr.dtat_name));
	oprintf("\t\tData Semantics:   %s\n",
	    dtrace_stability_name(p->dtp_attr.dtat_data));
	oprintf("\t\tDependency Class: %s\n",
	    dtrace_class_name(p->dtp_attr.dtat_class));

	oprintf("\n\tArgument Attributes\n");

	oprintf("\t\tIdentifier Names: %s\n",
	    dtrace_stability_name(p->dtp_arga.dtat_name));
	oprintf("\t\tData Semantics:   %s\n",
	    dtrace_stability_name(p->dtp_arga.dtat_data));
	oprintf("\t\tDependency Class: %s\n",
	    dtrace_class_name(p->dtp_arga.dtat_class));

	oprintf("\n\tArgument Types\n");

	for (i = 0; i < p->dtp_argc; i++) {
		if (p->dtp_argv[i].dtt_flags & DTT_FL_USER)
			user = "userland ";
		else
			user = "";
		if (ctf_type_name(p->dtp_argv[i].dtt_ctfp,
		    p->dtp_argv[i].dtt_type, buf, sizeof (buf)) == NULL)
			(void) strlcpy(buf, "(unknown)", sizeof (buf));
		oprintf("\t\targs[%d]: %s%s\n", i, user, buf);
	}

	if (p->dtp_argc == 0)
		oprintf("\t\tNone\n");

	oprintf("\n");
}

/*ARGSUSED*/
static int
info_stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmtdesc_t *stp, dtrace_ecbdesc_t **last)
{
	dtrace_ecbdesc_t *edp = stp->dtsd_ecbdesc;
	dtrace_probedesc_t *pdp = &edp->dted_probe;
	dtrace_probeinfo_t p;

	if (edp == *last)
		return (0);

	oprintf("\n%s:%s:%s:%s\n",
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	if (dtrace_probe_info(dtp, pdp, &p) == 0)
		print_probe_info(&p);

	*last = edp;
	return (0);
}

static bool
checkmodref(int action_modref, int cumulative_modref,
    const dtrace_probedesc_t *dp, FILE *output)
{

	if ((cumulative_modref & DTRACE_MODREF_ANY_MOD) == 0) {
		// We don't care about pre-modification behaviour.
		return (true);
	}

	if (action_modref & DTRACE_MODREF_ANY_REF) {
		fprintf(output, "ref-after-mod in %s:%s:%s:%s:",
			dp->dtpd_provider, dp->dtpd_mod, dp->dtpd_func,
			dp->dtpd_name);
		if (action_modref & DTRACE_MODREF_GLOBAL_REF)
			fprintf(output, " global");
		if (action_modref & DTRACE_MODREF_THREAD_LOCAL_REF)
			fprintf(output, " thread");
		if (action_modref & DTRACE_MODREF_CLAUSE_LOCAL_REF)
			fprintf(output, " clause");
		if (action_modref & DTRACE_MODREF_MEMORY_REF)
			fprintf(output, " external");
		if (action_modref & DTRACE_MODREF_STATE_REF)
			fprintf(output, " internal");
		fprintf(output, "\n");

		return (false);
	}

	return (true);
}

static void
get_randname(char *b, size_t len)
{
	size_t i;

	/*
	 * Generate lower-case random characters.
	 */
	for (i = 0; i < len; i++)
		b[i] = arc4random_uniform(25) + 97;
}

static char *
gen_filename(const char *dir)
{
	char *filename;
	char *elfpath;
	size_t len;

	len = (MAXPATHLEN - strlen(dir)) / 64;
	assert(len > 10);

	filename = malloc(len);
	if (filename == NULL)
		return (NULL);
	
	filename[0] = '.';
	get_randname(filename + 1, len - 2);
	filename[len - 1] = '\0';

	elfpath = malloc(MAXPATHLEN);
	strcpy(elfpath, dir);
	strcpy(elfpath + strlen(dir), filename);

	while (access(elfpath, F_OK) != -1) {
		filename[0] = '.';
		get_randname(filename + 1, len - 2);
		filename[len - 1] = '\0';
		strcpy(elfpath + strlen(dir), filename);
	}

	free(filename);

	return (elfpath);
}

static dt_pgplist_t *
get_pgplist_entry(char *ident, uint16_t vmid, int *found)
{
	dt_pgplist_t *pgpl;
	dtrace_prog_t *pgp;

	*found = 0;
	for (pgpl = dt_list_next(&g_pgplist); pgpl;
	    pgpl = dt_list_next(pgpl)) {
		pgp = pgpl->pgp;

		if (memcmp(pgp->dp_ident, ident, DT_PROG_IDENTLEN) == 0 &&
		    pgp->dp_vmid == vmid) {
			*found = 1;
			return (pgpl);
		}
	}

	pgpl = malloc(sizeof(dt_pgplist_t));
	if (pgpl == NULL)
		return (NULL);

	memset(pgpl, 0, sizeof(dt_pgplist_t));
	return (pgpl);
}

static int
pgpl_valid(dt_pgplist_t *pgpl)
{
	if (pgpl == NULL)
		return (0);

	return ((pgpl->vmid > 0 && pgpl->pgp && pgpl->gpgp) ||
	    (pgpl->vmid == 0 && pgpl->pgp));
}

static int
send_elf(int fromfd, int tofd)
{
	unsigned char *buf, *_buf;
	size_t total_size;
	struct stat sb;
	dtdaemon_hdr_t header;

	if (fromfd == -1 || tofd == -1) {
		fprintf(stderr,
		    "both file descriptors must be != -1 (%d, %d)\n", fromfd,
		    tofd);
		return (-1);
	}

	if (fstat(fromfd, &sb)) {
		fprintf(stderr, "fstat() failed on %d: %s\n", fromfd,
		    strerror(errno));
		return (-1);
	}

	total_size = DTDAEMON_MSGHDRSIZE + sb.st_size;
	buf = malloc(total_size);
	if (buf == NULL) {
		fprintf(stderr, "malloc() failed: %s\n", strerror(errno));
		return (-1);
	}

	_buf = buf + DTDAEMON_MSGHDRSIZE;
	if (read(fromfd, _buf, sb.st_size) < 0) {
		fprintf(stderr, "read() from %d failed: %s\n", fromfd,
		    strerror(errno));
		free(buf);
		return (-1);
	}

	DTDAEMON_MSG_TYPE(header) = DTDAEMON_MSG_ELF;

	/*
	 * Populate the header to the buffer that we will send to dtdaemon.
	 */
	memcpy(buf, &header, DTDAEMON_MSGHDRSIZE);
	if (send(tofd, buf, total_size, 0) < 0) {
		fprintf(
		    stderr, "send() to %d failed: %s\n", tofd, strerror(errno));
		free(buf);
		return (-1);
	}

	free(buf);
	return (0);
}

static void *
listen_dtdaemon(void *arg)
{
	int sockfd;
	int novm = 0;
	size_t elflen;
	char *elf, *elfpath;
	size_t *size;
	dtrace_prog_t *newprog;
	dtrace_prog_t *hostpgp, *guestpgp;
	int fd;
	int err;
	char template[] = "/tmp/ddtrace-elf.XXXXXXXX";
	int tmpfd;
	char elfdir[MAXPATHLEN] = "/var/ddtrace/outbound/";
	char vm_name[VM_MAX_NAMELEN] = { 0 };
	char *name;
	dtd_arg_t *dtd_arg = (dtd_arg_t *)arg;
	dt_pgplist_t *newpgpl;
	int done;
	uint16_t vmid;
	size_t lentowrite;
	int found;
	char donepath[MAXPATHLEN] = { 0 };
	size_t dirlen;
	size_t donepathlen;
	ssize_t r;
	uintptr_t elf_ptr;
	size_t len_to_recv;
	dtdaemon_hdr_t hdr;

	sockfd = 0;
	elflen = 0;
	elf = NULL;
	size = NULL;
	newprog = NULL;
	fd = 0;
	err = 0;
	name = NULL;
	done = 0;
	vmid = 0;
	lentowrite = 0;
	dirlen = strlen(elfdir);
	
	/*
	 * Assume this is an int.
	 */
	sockfd = dtd_arg->sock;
	hostpgp = dtd_arg->hostpgp;
	guestpgp = NULL;

	do {
		/*
		 * Now that we have created an ELF file, we wait for dtdaemon
		 * to give us the new ELF file that contains all the applied
		 * relocations. We will then verify that the relocations that
		 * were applied are sensible, get the identifier of which VM
		 * it actually is and fill in the necessary filters.
		 */
		if (!done && !atomic_load(&g_intr) &&
		    ((r = recv(sockfd, &elflen, sizeof(elflen), 0)) < 0) &&
		    errno != EINTR)
			dfatal("failed to read elf length");

		if (atomic_load(&g_intr)) {
			done = 1;
			break;
		}

		if (r != sizeof(elflen)) {
			fprintf(stderr, "received %zu bytes, expected %zu\n", r,
			    sizeof(elflen));
			/*
			 * FIXME(dstolfa): Just for now.
			 */
			assert(0);
		}

		if (elflen <= 0)
			dfatal("elflen is <= 0");

		elf = malloc(elflen);
		if (elf == NULL)
			dfatal("malloc(elf) failed");
		memset(elf, 0, elflen);

		elf_ptr = (uintptr_t)elf;
		len_to_recv = elflen;

		while (!done && !atomic_load(&g_intr) && len_to_recv > 0 &&
		    ((r = recv(
		    sockfd, (void *)elf_ptr, len_to_recv, 0)) != len_to_recv)) {
			if (r < 0)
				dfatal("failed to read from dtdaemon: %s",
				    strerror(errno));

			len_to_recv -= r;
			elf_ptr += r;
		}

		if (atomic_load(&g_intr)) {
			done = 1;
			break;
		}

		/*
		 * 8-byte aligned
		 */
		assert(((uintptr_t)elf & 7) == 0);
		memcpy(&hdr, elf, sizeof(hdr));
		elf += DTDAEMON_MSGHDRSIZE;
		elflen -= DTDAEMON_MSGHDRSIZE;

		if (hdr != DTDAEMON_MSG_ELF) {
			/*
			 * We shouldn't be receiving a kill command, so let's
			 * just report it and ignore it...
			 */
			fprintf(stderr,
			    "received unknown message (%lu), ignoring...\n",
			    hdr);
			continue;
		}

		assert(hdr == DTDAEMON_MSG_ELF);

		if (elf[0] == 0x7F && elf[1] == 'E' &&
		    elf[2] == 'L'  && elf[3] == 'F') {
			novm = 1;
			goto process_prog;
		}

		novm = 0;

		/*
		 * 2-byte aligned
		 */
		assert(((uintptr_t)elf & 1) == 0);
		vmid = *((uint16_t *)elf);
		elf += sizeof(uint16_t) + 6;

		/*
		 * 8-byte aligned
		 */
		assert(((uintptr_t)elf & 7) == 0);
		size = (uint64_t *)elf;

		elf += sizeof(uint64_t);

		name = elf;
		elf += *size;

		if (*size > VM_MAX_NAMELEN)
			dfatal("size (%zu) > VM_MAX_NAMELEN (%zu)",
			    *size, VM_MAX_NAMELEN);

		memcpy(vm_name, name, *size);

process_prog:
		fd = mkstemp(template);
		if (fd == -1)
			dfatal("failed to create a temporary file (%s)",
			    strerror(errno));
		strcpy(template, "/tmp/ddtrace-elf.XXXXXXXX");

		lentowrite = novm ?
		    elflen :
		    (elflen - *size - sizeof(uint64_t) - sizeof(uint16_t) - 6);
		if (write(fd, elf, lentowrite) < 0)
			dfatal("failed to write to a temporary file");

		if (fsync(fd))
			dfatal("failed to sync file");

		newprog = dt_elf_to_prog(g_dtp, fd, 0, &err, hostpgp);
		printf("newprog = %p\n", newprog);
		if (newprog == NULL) {
			fprintf(stderr, "newprog is NULL\n");
			continue;
		}

		newprog->dp_vmid = vmid;
		if (dt_prog_verify(g_dtp, hostpgp, newprog)) {
			fprintf(stderr, "failed to verify DIF from %s (%u)\n",
			    vm_name == NULL ? "host" : vm_name, vmid);
			continue;
		}

		if (!done && newprog == NULL && err != EACCES)
			dfatal("failed to parse elf file");

		/*
		 * If this program was not meant for us, we simply move on.
		 */
		if (err == EACCES && newprog == NULL)
			continue;

		/*
		 * srcident only is not sufficient here, as it's an one-to-many
		 * relation. However, scoping it with vmid as well *should* give
		 * us a unique program.
		 */
		newpgpl = get_pgplist_entry(newprog->dp_srcident, vmid, &found);
		if (newpgpl == NULL)
			dfatal("malloc of newpgpl failed");

		/*
		 * vmid is only 0 when we haven't filled in the program we will
		 * execute on the host.
		 *
		 * We check that we don't have a guest trying to pretend that it
		 * is someone else.
		 */
		if (newpgpl->vmid != 0 && (newpgpl->vmid != vmid)) {
			syslog(LOG_SECURITY, "vmid (%u) is claiming to be %u\n",
			    vmid, newpgpl->vmid);
			fprintf(stderr, "vmid (%u) is claiming to be %u\n",
			    vmid, newpgpl->vmid);
			continue;
		}

		if (found)
			newpgpl->gpgp = newprog;
		else {
			newpgpl->vmid = vmid;
			newpgpl->pgp = newprog;
		}

		if (!found && novm == 0) {
			guestpgp =
			    dt_vprog_from(g_dtp, newprog, PGP_KIND_HYPERCALLS);
			if (guestpgp == NULL)
				dfatal("failed to create a guest program");

			guestpgp->dp_exec = 1;

			tmpfd = mkstemp(template);
			if (tmpfd == -1)
				fatal("failed to mkstemp()");
			strcpy(template, "/tmp/ddtrace-elf.XXXXXXXX");

			dt_elf_create(guestpgp, ELFDATA2LSB, tmpfd);

			if (send_elf(tmpfd, sockfd))
				fatal("failed to send_elf()");

			close(tmpfd);
		}

		/*
		 * If this is a new program, we add it to the list.
		 */
		if (newpgpl->pgp == newprog) {
			pthread_mutex_lock(&g_pgplistmtx);
			dt_list_append(&g_pgplist, newpgpl);
			pthread_mutex_unlock(&g_pgplistmtx);
		}

		/*
		 * For vmid == 0, we allow signalling because there will never
		 * be a guest program that will be run.
		 */
		if (pgpl_valid(newpgpl)) {
			pthread_mutex_lock(&g_pgpcondmtx);
			pthread_cond_signal(&g_pgpcond);
			pthread_mutex_unlock(&g_pgpcondmtx);
		}
	} while (!done);

	return (arg);
}

/*ARGSUSED*/
static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
	dtrace_actkind_t act;
	uintptr_t addr;

	if (rec == NULL) {
		/*
		 * We have processed the final record; output the newline if
		 * we're not in quiet mode.
		 */
		if (!g_quiet)
			oprintf("\n");

		return (DTRACE_CONSUME_NEXT);
	}

	act = rec->dtrd_action;
	addr = (uintptr_t)data->dtpda_data;

	if (act == DTRACEACT_EXIT) {
		g_status = *((uint32_t *)addr);
		return (DTRACE_CONSUME_NEXT);
	}

	return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
	dtrace_probedesc_t *pd = data->dtpda_pdesc;
	processorid_t cpu = data->dtpda_cpu;
	static int heading;

	if (atomic_load(&g_impatient)) {
		atomic_store(&g_newline, 0);
		return (DTRACE_CONSUME_ABORT);
	}

	if (heading == 0) {
		if (!g_flowindent) {
			if (!g_quiet) {
				oprintf("%3s %6s %32s\n",
				    "CPU", "ID", "FUNCTION:NAME");
			}
		} else {
			oprintf("%3s %-41s\n", "CPU", "FUNCTION");
		}
		heading = 1;
	}

	if (!g_flowindent) {
		if (!g_quiet) {
			char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];

			(void) snprintf(name, sizeof (name), "%s:%s",
			    pd->dtpd_func, pd->dtpd_name);

			oprintf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
		}
	} else {
		int indent = data->dtpda_indent;
		char *name;
		size_t len;

		if (data->dtpda_flow == DTRACEFLOW_NONE) {
			len = indent + DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 5;
			name = alloca(len);
			(void) snprintf(name, len, "%*s%s%s:%s", indent, "",
			    data->dtpda_prefix, pd->dtpd_func,
			    pd->dtpd_name);
		} else {
			len = indent + DTRACE_FUNCNAMELEN + 5;
			name = alloca(len);
			(void) snprintf(name, len, "%*s%s%s", indent, "",
			    data->dtpda_prefix, pd->dtpd_func);
		}

		oprintf("%3d %-41s ", cpu, name);
	}

	return (DTRACE_CONSUME_THIS);
}

static void
setup_tracing(void)
{
	dtrace_optval_t opt;
	int i;
	
	/*
	 * Start tracing.  Once we dtrace_go(), reload any options that affect
	 * our globals in case consuming anonymous state has changed them.
	 */
	go();

	if (g_elf == 0) {
		(void) dtrace_getopt(g_dtp, "flowindent", &opt);
		g_flowindent = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "grabanon", &opt);
		g_grabanon = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "quiet", &opt);
		g_quiet = opt != DTRACEOPT_UNSET;

		(void) dtrace_getopt(g_dtp, "destructive", &opt);
		if (opt != DTRACEOPT_UNSET)
			notice("allowing destructive actions\n");
	}
	
	installsighands();

	/*
	 * Now that tracing is active and we are ready to consume trace data,
	 * continue any grabbed or created processes, setting them running
	 * using the /proc control mechanism inside of libdtrace.
	 */
	for (i = 0; i < g_psc; i++)
		dtrace_proc_continue(g_dtp, g_psv[i]);

	g_pslive = g_psc; /* count for prochandler() */
}

static void *
dtc_work(void *arg)
{
	int done = 0;
	dtrace_consumer_t con;

	con.dc_consume_probe = chew;
	con.dc_consume_rec = chewrec;
	con.dc_get_buf = NULL;
	con.dc_put_buf = NULL;

	do {
		if (!atomic_load(&g_intr) && !done)
			dtrace_sleep(g_dtp);

#ifdef __FreeBSD__
		if (atomic_load(&g_siginfo)) {
			(void)dtrace_aggregate_print(g_dtp, g_ofp, NULL);
			atomic_store(&g_siginfo, 0);
		}
#endif

		if (atomic_load(&g_newline)) {
			/*
			 * Output a newline just to make the output look
			 * slightly cleaner.  Note that we do this even in
			 * "quiet" mode...
			 */
			oprintf("\n");
			atomic_store(&g_newline, 0);
		}

		if (done || atomic_load(&g_intr) || (g_psc != 0 && g_pslive == 0)) {
			done = 1;
			if (dtrace_stop(g_dtp) == -1)
				dfatal("couldn't stop tracing");
		}

		pthread_mutex_lock(&g_dtpmtx);
		switch (dtrace_work(g_dtp, g_ofp, &con, NULL)) {
		case DTRACE_WORKSTATUS_DONE:
			done = 1;
			break;
		case DTRACE_WORKSTATUS_OKAY:
			break;
		default:
			if (!atomic_load(&g_impatient) &&
			    dtrace_errno(g_dtp) != EINTR) {
				pthread_mutex_unlock(&g_dtpmtx);
				dfatal("processing aborted");
			}
		}
		pthread_mutex_unlock(&g_dtpmtx);

		if (g_ofp != NULL && fflush(g_ofp) == EOF)
			clearerr(g_ofp);

	} while (!done);

	oprintf("\n");

	if (!atomic_load(&g_impatient)) {
		if (dtrace_aggregate_print(g_dtp, g_ofp, NULL) == -1 &&
		    dtrace_errno(g_dtp) != EINTR)
			dfatal("failed to print aggregations");
	}

	pthread_mutex_lock(&g_pgpcondmtx);
	pthread_cond_signal(&g_pgpcond);
	pthread_mutex_unlock(&g_pgpcondmtx);

	return (NULL);
}

static void
process_new_pgp(dtrace_prog_t *pgp, dtrace_prog_t *gpgp)
{
	static size_t n_pgps = 0;
	dtrace_proginfo_t dpi;
	int i, n;

	dtrace_dump_actions(pgp);
	if (gpgp == NULL && pgp->dp_vmid != 0) {
		atomic_store(&g_intr, 1);
		fprintf(stderr,
		    "the guest program can only be NULL if program's vmid "
		    "is 0, but it is %u\n",
		    pgp->dp_vmid);
	}

	if (gpgp && (pgp->dp_vmid != gpgp->dp_vmid)) {
		atomic_store(&g_intr, 1);
		fprintf(stderr,
		    "mismatch between pgp and gpgp vmids (%u != %u)",
		    pgp->dp_vmid, gpgp->dp_vmid);
	}

	if (pgp->dp_vmid != 0) {
		n = dt_vprobes_create(g_dtp, gpgp);
		if (n == -1) {
			atomic_store(&g_intr, 1);
			fprintf(stderr, "failed to create vprobes: %s\n",
			    strerror(errno));
		}
	}

	if (n_pgps == 0) {
		if (dtrace_program_exec(g_dtp, pgp, &dpi) == -1) {
			atomic_store(&g_intr, 1);
			fprintf(stderr, "failed to enable program: %s",
			    strerror(errno));
		} else {
			notice("matched %u probe%s\n", dpi.dpi_matches,
			    dpi.dpi_matches == 1 ? "" : "s");
		}

		setup_tracing();
		pthread_create(&g_worktd, NULL, dtc_work, NULL);
	} else {
		if (dt_augment_tracing(g_dtp, pgp)) {
			atomic_store(&g_intr, 1);
			fprintf(stderr, "failed to augment tracing: %s",
			    strerror(errno));
		}
	}

	n_pgps++;
}

static int
open_dtdaemon(void)
{
	int dtdaemon_sock;
	struct sockaddr_un addr;
	int kind;
	size_t l;

	dtdaemon_sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if (dtdaemon_sock == -1)
		fatal("failed to open dtdaemon socket");

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = PF_UNIX;
	l = strlcpy(addr.sun_path, DTDAEMON_SOCKPATH, sizeof(addr.sun_path));
	if (l >= sizeof(addr.sun_path)) {
		fprintf(stderr, "failed to copy %s into sun_path\n",
		    DTDAEMON_SOCKPATH);
		return (-1);
	}

	if (connect(dtdaemon_sock,
	    (struct sockaddr *)&addr, sizeof(addr)) == -1) {
		fprintf(stderr, "failed to connect to dtdaemon socket: %s\n",
		    strerror(errno));
		return (-1);
	}

	kind = 0;
	if (recv(dtdaemon_sock, &kind, sizeof(kind), 0) < 0) {
		fprintf(stderr, "failed to recv from dtdaemon socket: %s\n",
		    strerror(errno));
		close(dtdaemon_sock);
		return (-1);
	}

	if (kind != DTDAEMON_KIND_DTDAEMON) {
		fprintf(stderr, "expected kind %d but got %d\n",
		    DTDAEMON_KIND_DTDAEMON, kind);
		close(dtdaemon_sock);
		return (-1);
	}

	kind = DTDAEMON_KIND_CONSUMER;
	if (send(dtdaemon_sock, &kind, sizeof(kind), 0) < 0) {
		fprintf(stderr, "failed to send to dtdaemon socket: %s\n",
		    strerror(errno));
		close(dtdaemon_sock);
		return (-1);
	}

	return (dtdaemon_sock);
}

/*
 * Execute the specified program by enabling the corresponding instrumentation.
 * If -e has been specified, we get the program info but do not enable it.  If
 * -v has been specified, we print a stability report for the program.
 */
static void
exec_prog(const dtrace_cmd_t *dcp)
{
	dtrace_ecbdesc_t *last = NULL;
	dtrace_proginfo_t dpi;
	char *elfpath;
	char elfdir[MAXPATHLEN] = "/var/ddtrace/base/";
	char template[MAXPATHLEN] = "/tmp/dtrace-execprog.XXXXXXXX";
	char *elf;
	size_t elflen;
	int dtdaemon_sock;
	size_t l;
	int fd;
	char donepath[MAXPATHLEN] = { 0 };
	size_t dirlen;
	size_t donepathlen;
	int err = 0;
	dtd_arg_t *dtd_arg = NULL;
	void *rval;
	dt_pgplist_t *pgpl = NULL;
	int again = 0;
	int tmpfd;

	dirlen = strlen(elfdir);
	elfpath = gen_filename(elfdir);
	if (elfpath == NULL)
		dfatal("gen_filename() failed");
	/*
	 * Don't take any action based on unwanted mod/ref behaviour;
	 * checkmodref emits warnings and that's the end of it.
	 */
	(void) dtrace_analyze_program_modref(dcp->dc_prog, checkmodref, stderr);

	dcp->dc_prog->dp_rflags = rslv;

	if (g_graphfile) {
		FILE *graph_file = fopen(g_graphfile, "w");
		if (graph_file == NULL) {
			fprintf(stderr, "Failed to open %s for writing\n",
				g_graphfile);
			return;
		}

		dtrace_graph_program(g_dtp, dcp->dc_prog, graph_file);
		fclose(graph_file);
	}

	if (!g_exec) {
		dtrace_program_info(g_dtp, dcp->dc_prog, &dpi);
		if (g_elf) {
			tmpfd = mkstemp(template);
			if (tmpfd == -1)
				fatal("failed to mkstemp()");

			/*
			 * In this case we don't really send anything, we just
			 * create the ELF file for debugging purposes and output
			 * where it was created.
			 */
			dt_elf_create(dcp->dc_prog, ELFDATA2LSB, tmpfd);
			notice("created %s (ELF file)", template);
			strcpy(template, "/tmp/dtrace-execprog.XXXXXXXX");

			close(tmpfd);
		}
		free(elfpath);
	} else if (g_elf) {
		/*
		 * We open a dtdaemon socket because we expect the following
		 * things to happen:
		 *  (1) We write our ELF file to /var/ddtrace/outbound
		 *  (2) dtdaemon forwards it to the traced machine (can be host)
		 *  (3) traced DTrace applies relocations to the program
		 *  (4) traced dtdaemon sends it back to host dtdaemon
		 *  (5) dtdaemon writes out the ELF file to this DTrace
		 *      instance for further processing.
		 */

		if ((err = pthread_mutex_init(&g_pgplistmtx, NULL)) != 0)
			fatal("failed to init pgplistmtx");

		if ((err = pthread_mutex_init(&g_pgpcondmtx, NULL)) != 0)
			fatal("failed to init pgpcondmtx");

		if ((err = pthread_cond_init(&g_pgpcond, NULL)) != 0)
			fatal("failed to init pgpcond");

		dtdaemon_sock = open_dtdaemon();
		if (dtdaemon_sock == -1)
			fatal("failed to open dtdaemon");

		tmpfd = mkstemp(template);
		if (tmpfd == -1)
			fatal("failed to mkstemp()");
		strcpy(template, "/tmp/dtrace-execprog.XXXXXXXX");

		dt_elf_create(dcp->dc_prog, ELFDATA2LSB, tmpfd);

		if (send_elf(tmpfd, dtdaemon_sock))
			fatal("failed to send_elf()");

		close(tmpfd);

		dtd_arg = malloc(sizeof(dtd_arg_t));
		if (dtd_arg == NULL)
			fatal("failed to malloc dtd_arg");

		dtd_arg->sock = dtdaemon_sock;
		dtd_arg->hostpgp = dcp->dc_prog;
		
		err = pthread_create(&g_dtdaemontd, NULL,
		    listen_dtdaemon, dtd_arg);
		if (err != 0)
			fatal("failed to create g_dtdaemontd");

		for (;;) {
			/*
			 * Wait for us to actually have a program in the list
			 */
again:
			pthread_mutex_lock(&g_pgpcondmtx);
			pthread_mutex_lock(&g_pgplistmtx);
			while (!atomic_load(&g_intr) &&
			    ((pgpl = dt_list_next(&g_pgplist)) == NULL ||
			    again == 1)) {
				pthread_mutex_unlock(&g_pgplistmtx);
				pthread_cond_wait(&g_pgpcond, &g_pgpcondmtx);
				again = 0;
				pthread_mutex_lock(&g_pgplistmtx);
			}
			pthread_mutex_unlock(&g_pgplistmtx);
			pthread_mutex_unlock(&g_pgpcondmtx);

			assert(pgpl != NULL || atomic_load(&g_intr));

			if (atomic_load(&g_intr))
				break;

			/*
			 * We are in a situation where the condition variable
			 * has been triggered and we expect to have at least one
			 * pgplist entry which contains both the probe
			 * specification that we need to create on the host and
			 * the program that we need to run.
			 */
			for (; pgpl; pgpl = dt_list_next(pgpl)) {
				if (pgpl_valid(pgpl))
					break;
			}

			if (pgpl == NULL) {
				again = 1;
				goto again;
			}

			/*
			 * Something's gone horribly wrong, report it and go to
			 * sleep again.
			 */
			if (!pgpl_valid(pgpl)) {
				fprintf(stderr, "%s",
				    pgpl->pgp ? "probe specification is NULL"
						", sleeping...\n" :
						"program to run is NULL"
						", sleeping...\n");
				again = 1;
				goto again;
			}

			process_new_pgp(pgpl->pgp, pgpl->gpgp);
			
			pthread_mutex_lock(&g_pgplistmtx);
			dt_list_delete(&g_pgplist, pgpl);
			pthread_mutex_unlock(&g_pgplistmtx);

			free(pgpl);
		}

		err = pthread_kill(g_dtdaemontd, SIGTERM);
		if (err != 0)
			fatal("failed to send SIGTERM to g_dtdaemontd");
		err = pthread_kill(g_worktd, SIGTERM);
		if (err != 0)
			fatal("failed to send SIGTERM to g_worktd");

		err = pthread_join(g_dtdaemontd, &rval);
		if (err != 0)
			fatal("failed to join g_dtdaemontd");
		err = pthread_join(g_worktd, &rval);
		if (err != 0)
			fatal("failed to join g_worktd");

		pthread_mutex_destroy(&g_pgplistmtx);
		pthread_mutex_destroy(&g_pgpcondmtx);
		pthread_cond_destroy(&g_pgpcond);
		exit(0);
		/*
		 * At this point we have processed the program as much as we
		 * could. We now go over the DIFOs and simply add a new DIFO
		 * for each modified probe in the new program.
		 */
	} else if (dt_prog_apply_rel(g_dtp, dcp->dc_prog) == 0) {
		if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1) {
			dfatal("failed to enable '%s'", dcp->dc_name);
		} else {
			notice("%s '%s' matched %u probe%s\n",
			    dcp->dc_desc, dcp->dc_name,
			    dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s");
		}
	} else
		dfatal("failed to apply relocations");


	if (g_verbose) {
		oprintf("\nStability attributes for %s %s:\n",
		    dcp->dc_desc, dcp->dc_name);

		oprintf("\n\tMinimum Probe Description Attributes\n");
		oprintf("\t\tIdentifier Names: %s\n",
		    dtrace_stability_name(dpi.dpi_descattr.dtat_name));
		oprintf("\t\tData Semantics:   %s\n",
		    dtrace_stability_name(dpi.dpi_descattr.dtat_data));
		oprintf("\t\tDependency Class: %s\n",
		    dtrace_class_name(dpi.dpi_descattr.dtat_class));

		oprintf("\n\tMinimum Statement Attributes\n");

		oprintf("\t\tIdentifier Names: %s\n",
		    dtrace_stability_name(dpi.dpi_stmtattr.dtat_name));
		oprintf("\t\tData Semantics:   %s\n",
		    dtrace_stability_name(dpi.dpi_stmtattr.dtat_data));
		oprintf("\t\tDependency Class: %s\n",
		    dtrace_class_name(dpi.dpi_stmtattr.dtat_class));

		if (!g_exec) {
			(void) dtrace_stmt_iter(g_dtp, dcp->dc_prog,
			    (dtrace_stmt_f *)info_stmt, &last);
		} else
			oprintf("\n");
	}

	g_total += dpi.dpi_matches;
}

/*
 * Print out the specified DOF buffer as a set of ASCII bytes appropriate for
 * storing in a driver.conf(4) file associated with the dtrace driver.
 */
static void
anon_prog(const dtrace_cmd_t *dcp, dof_hdr_t *dof, int n)
{
	const uchar_t *p, *q;

	if (dof == NULL)
		dfatal("failed to create DOF image for '%s'", dcp->dc_name);

	p = (uchar_t *)dof;
	q = p + dof->dofh_filesz;

#ifdef __FreeBSD__
	/*
	 * On FreeBSD, the DOF file is read directly during boot - just write
	 * two hex characters per byte.
	 */
	oprintf("dof-data-%d=", n);

	while (p < q)
		oprintf("%02x", *p++);

	oprintf("\n");
#else
	oprintf("dof-data-%d=0x%x", n, *p++);

	while (p < q)
		oprintf(",0x%x", *p++);

	oprintf(";\n");
#endif

	dtrace_dof_destroy(g_dtp, dof);
}

/*
 * Link the specified D program in DOF form into an ELF file for use in either
 * helpers, userland provider definitions, or both.  If -o was specified, that
 * path is used as the output file name.  If -o wasn't specified and the input
 * program is from a script whose name is %.d, use basename(%.o) as the output
 * file name.  Otherwise we use "d.out" as the default output file name.
 */
static void
link_prog(dtrace_cmd_t *dcp)
{
	char *p;

	if (g_cmdc == 1 && g_ofile != NULL) {
		(void) strlcpy(dcp->dc_ofile, g_ofile, sizeof (dcp->dc_ofile));
	} else if ((p = strrchr(dcp->dc_arg, '.')) != NULL &&
	    strcmp(p, ".d") == 0) {
		p[0] = '\0'; /* strip .d suffix */
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "%s.o", basename(dcp->dc_arg));
	} else if (g_cmdc > 1) {
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "d.out.%td", dcp - g_cmdv);
	} else {
		(void) snprintf(dcp->dc_ofile, sizeof (dcp->dc_ofile),
		    "d.out");
	}

	if (dtrace_program_link(g_dtp, dcp->dc_prog, DTRACE_D_PROBES,
	    dcp->dc_ofile, g_objc, g_objv) != 0)
		dfatal("failed to link %s %s", dcp->dc_desc, dcp->dc_name);
}

/*ARGSUSED*/
static int
list_probe(dtrace_hdl_t *dtp, const dtrace_probedesc_t *pdp, void *arg)
{
	dtrace_probeinfo_t p;

	oprintf("%5d %10s %17s %33s %s\n", pdp->dtpd_id,
	    pdp->dtpd_provider, pdp->dtpd_mod, pdp->dtpd_func, pdp->dtpd_name);

	if (g_verbose && dtrace_probe_info(dtp, pdp, &p) == 0)
		print_probe_info(&p);

	if (atomic_load(&g_intr) != 0)
		return (1);

	return (0);
}

/*ARGSUSED*/
static int
list_stmt(dtrace_hdl_t *dtp, dtrace_prog_t *pgp,
    dtrace_stmtdesc_t *stp, dtrace_ecbdesc_t **last)
{
	dtrace_ecbdesc_t *edp = stp->dtsd_ecbdesc;

	if (edp == *last)
		return (0);

	if (dtrace_probe_iter(g_dtp, &edp->dted_probe, list_probe, NULL) != 0) {
		error("failed to match %s:%s:%s:%s: %s\n",
		    edp->dted_probe.dtpd_provider, edp->dted_probe.dtpd_mod,
		    edp->dted_probe.dtpd_func, edp->dted_probe.dtpd_name,
		    dtrace_errmsg(dtp, dtrace_errno(dtp)));
	}

	*last = edp;
	return (0);
}

/*
 * List the probes corresponding to the specified program by iterating over
 * each statement and then matching probes to the statement probe descriptions.
 */
static void
list_prog(const dtrace_cmd_t *dcp)
{
	dtrace_ecbdesc_t *last = NULL;

	(void) dtrace_stmt_iter(g_dtp, dcp->dc_prog,
	    (dtrace_stmt_f *)list_stmt, &last);
}

static void
compile_file(dtrace_cmd_t *dcp)
{
	char *arg0;
	FILE *fp;

	if ((fp = fopen(dcp->dc_arg, "r")) == NULL)
		fatal("failed to open %s", dcp->dc_arg);

	arg0 = g_argv[0];
	g_argv[0] = dcp->dc_arg;

	if ((dcp->dc_prog = dtrace_program_fcompile(g_dtp, fp,
	    g_cflags, g_argc, g_argv)) == NULL)
		dfatal("failed to compile script %s", dcp->dc_arg);

	g_argv[0] = arg0;
	(void) fclose(fp);

	dcp->dc_desc = "script";
	dcp->dc_name = dcp->dc_arg;
}

static int 
link_elf(dtrace_cmd_t *dcp, char *progpath)
{
	int fd;
	dt_stmt_t *stp;
	int err = 0;
	void *dof = NULL;
	int prog_exec = 0;

	assert(g_elf == 1);

	if ((fd = open(progpath, O_RDONLY)) < 0)
		fatal("failed to open %s with %s", progpath, strerror(errno));

	if ((dcp->dc_prog = dt_elf_to_prog(g_dtp, fd, 1, &err, NULL)) == NULL)
		dfatal("failed to parse the ELF file %s", dcp->dc_arg);

	prog_exec = dcp->dc_prog->dp_exec;
	close(fd);

	dcp->dc_desc = "ELF file";
	dcp->dc_name = dcp->dc_arg;

	return (prog_exec);
}

static void
process_elf(dtrace_cmd_t *dcp)
{

	/*
	 * FIXME: This won't work.
	 */
	(void) link_elf(dcp, dcp->dc_arg);
}

static void
process_elf_hypertrace(dtrace_cmd_t *dcp)
{
	char elfdir[MAXPATHLEN] = { 0 };
	char *dirpath;
	char donepath[MAXPATHLEN] = { 0 };
	size_t donepathlen;
	char template[MAXPATHLEN] = "/tmp/dtrace-process-elf.XXXXXXXX";
	size_t dirlen;
	char *elfpath, *progpath;
	int prog_exec;
	dtrace_proginfo_t dpi;
	int i;
	int dtdaemon_sock;
	int tmpfd;

	progpath = strtok(dcp->dc_arg, ",");
	if (progpath == NULL)
		fatal("failed to tokenize %s", dcp->dc_arg);
	
	dirpath = strtok(NULL, ",");
	strcpy(elfdir, dirpath ? dirpath : "/var/ddtrace/outbound/");

	dirlen = strlen(elfdir);

	prog_exec = link_elf(dcp, progpath);

	dtrace_dump_actions(dcp->dc_prog);

	if (dt_prog_apply_rel(g_dtp, dcp->dc_prog) != 0)
		dfatal("Failed to apply relocations");

	dtrace_dump_actions(dcp->dc_prog);

	if (prog_exec == DT_PROG_EXEC) {
		if (dtrace_program_exec(g_dtp, dcp->dc_prog, &dpi) == -1) {
			dfatal("failed to enable program");
		} else {
			notice(
			    "process_elf_hypertrace(): matched %u probes%s\n",
			    dpi.dpi_matches, dpi.dpi_matches == 1 ? "" : "s");
		}

		/*
		 * If we are actually tracing things, we will need to stop at
		 * some point. Get the pid so that the host can send a message
		 * to dtdaemon to kill us later.
		 */
		assert(dtrace_is_guest(g_dtp) != 0);
		dcp->dc_prog->dp_pid = getpid();
		setup_tracing();
		pthread_create(&g_worktd, NULL, dtc_work, NULL);
	}

	
	dtdaemon_sock = open_dtdaemon();
	if (dtdaemon_sock == -1)
		fatal("failed to open dtdaemon");

	tmpfd = mkstemp(template);
	if (tmpfd == -1)
		fatal("mkstemp() failed (%s)", template);
	strcpy(template, "/tmp/dtrace-process-elf.XXXXXXXX");

	dt_elf_create(dcp->dc_prog, ELFDATA2LSB, tmpfd);

	if (send_elf(tmpfd, dtdaemon_sock))
		fatal("failed to send_elf()");

	close(tmpfd);
	close(dtdaemon_sock);

	if (prog_exec == DT_PROG_EXEC) {
		if (pthread_join(g_worktd, NULL))
			fatal("failed to join worktd (%s)", strerror(errno));
	}

	pthread_mutex_lock(&g_dtpmtx);
	dtrace_close(g_dtp);
	g_dtp = NULL;
	pthread_mutex_unlock(&g_dtpmtx);

	pthread_mutex_destroy(&g_dtpmtx);
	exit(g_status);
}

static void
compile_str(dtrace_cmd_t *dcp)
{
	char *p;

	if ((dcp->dc_prog = dtrace_program_strcompile(g_dtp, dcp->dc_arg,
	    dcp->dc_spec, g_cflags | DTRACE_C_PSPEC, g_argc, g_argv)) == NULL)
		dfatal("invalid probe specifier %s", dcp->dc_arg);

	if ((p = strpbrk(dcp->dc_arg, "{/;")) != NULL)
		*p = '\0'; /* crop name for reporting */

	dcp->dc_desc = "description";
	dcp->dc_name = dcp->dc_arg;
}

/*ARGSUSED*/
static void
prochandler(struct ps_prochandle *P, const char *msg, void *arg)
{
#ifdef illumos
	const psinfo_t *prp = Ppsinfo(P);
	int pid = Pstatus(P)->pr_pid;
	char name[SIG2STR_MAX];
#else
	int wstatus = proc_getwstat(P);
	int pid = proc_getpid(P);
#endif

	if (msg != NULL) {
		notice("pid %d: %s\n", pid, msg);
		return;
	}

#ifdef illumos
	switch (Pstate(P)) {
#else
	switch (proc_state(P)) {
#endif
	case PS_UNDEAD:
#ifdef illumos
		/*
		 * Ideally we would like to always report pr_wstat here, but it
		 * isn't possible given current /proc semantics.  If we grabbed
		 * the process, Ppsinfo() will either fail or return a zeroed
		 * psinfo_t depending on how far the parent is in reaping it.
		 * When /proc provides a stable pr_wstat in the status file,
		 * this code can be improved by examining this new pr_wstat.
		 */
		if (prp != NULL && WIFSIGNALED(prp->pr_wstat)) {
			notice("pid %d terminated by %s\n", pid,
			    proc_signame(WTERMSIG(prp->pr_wstat),
			    name, sizeof (name)));
#else
		if (WIFSIGNALED(wstatus)) {
			notice("pid %d terminated by %d\n", pid,
			    WTERMSIG(wstatus));
#endif
#ifdef illumos
		} else if (prp != NULL && WEXITSTATUS(prp->pr_wstat) != 0) {
			notice("pid %d exited with status %d\n",
			    pid, WEXITSTATUS(prp->pr_wstat));
#else
		} else if (WEXITSTATUS(wstatus) != 0) {
			notice("pid %d exited with status %d\n",
			    pid, WEXITSTATUS(wstatus));
#endif
		} else {
			notice("pid %d has exited\n", pid);
		}
		g_pslive--;
		break;

	case PS_LOST:
		notice("pid %d exec'd a set-id or unobservable program\n", pid);
		g_pslive--;
		break;
	}
}

/*ARGSUSED*/
static int
errhandler(const dtrace_errdata_t *data, void *arg)
{
	error(data->dteda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
drophandler(const dtrace_dropdata_t *data, void *arg)
{
	error(data->dtdda_msg);
	return (DTRACE_HANDLE_OK);
}

/*ARGSUSED*/
static int
setopthandler(const dtrace_setoptdata_t *data, void *arg)
{
	if (strcmp(data->dtsda_option, "quiet") == 0)
		g_quiet = data->dtsda_newval != DTRACEOPT_UNSET;

	if (strcmp(data->dtsda_option, "flowindent") == 0)
		g_flowindent = data->dtsda_newval != DTRACEOPT_UNSET;

	return (DTRACE_HANDLE_OK);
}

#define	BUFDUMPHDR(hdr) \
	(void) printf("%s: %s%s\n", g_pname, hdr, strlen(hdr) > 0 ? ":" : "");

#define	BUFDUMPSTR(ptr, field) \
	(void) printf("%s: %20s => ", g_pname, #field);	\
	if ((ptr)->field != NULL) {			\
		const char *c = (ptr)->field;		\
		(void) printf("\"");			\
		do {					\
			if (*c == '\n') {		\
				(void) printf("\\n");	\
				continue;		\
			}				\
							\
			(void) printf("%c", *c);	\
		} while (*c++ != '\0');			\
		(void) printf("\"\n");			\
	} else {					\
		(void) printf("<NULL>\n");		\
	}

#define	BUFDUMPASSTR(ptr, field, str) \
	(void) printf("%s: %20s => %s\n", g_pname, #field, str);

#define	BUFDUMP(ptr, field) \
	(void) printf("%s: %20s => %lld\n", g_pname, #field, \
	    (long long)(ptr)->field);

#define	BUFDUMPPTR(ptr, field) \
	(void) printf("%s: %20s => %s\n", g_pname, #field, \
	    (ptr)->field != NULL ? "<non-NULL>" : "<NULL>");

/*ARGSUSED*/
static int
bufhandler(const dtrace_bufdata_t *bufdata, void *arg)
{
	const dtrace_aggdata_t *agg = bufdata->dtbda_aggdata;
	const dtrace_recdesc_t *rec = bufdata->dtbda_recdesc;
	const dtrace_probedesc_t *pd;
	uint32_t flags = bufdata->dtbda_flags;
	char buf[512], *c = buf, *end = c + sizeof (buf);
	int i, printed;

	struct {
		const char *name;
		uint32_t value;
	} flagnames[] = {
	    { "AGGVAL",		DTRACE_BUFDATA_AGGVAL },
	    { "AGGKEY",		DTRACE_BUFDATA_AGGKEY },
	    { "AGGFORMAT",	DTRACE_BUFDATA_AGGFORMAT },
	    { "AGGLAST",	DTRACE_BUFDATA_AGGLAST },
	    { "???",		UINT32_MAX },
	    { NULL }
	};

	if (bufdata->dtbda_probe != NULL) {
		pd = bufdata->dtbda_probe->dtpda_pdesc;
	} else if (agg != NULL) {
		pd = agg->dtada_pdesc;
	} else {
		pd = NULL;
	}

	BUFDUMPHDR(">>> Called buffer handler");
	BUFDUMPHDR("");

	BUFDUMPHDR("  dtrace_bufdata");
	BUFDUMPSTR(bufdata, dtbda_buffered);
	BUFDUMPPTR(bufdata, dtbda_probe);
	BUFDUMPPTR(bufdata, dtbda_aggdata);
	BUFDUMPPTR(bufdata, dtbda_recdesc);

	(void) snprintf(c, end - c, "0x%x ", bufdata->dtbda_flags);
	c += strlen(c);

	for (i = 0, printed = 0; flagnames[i].name != NULL; i++) {
		if (!(flags & flagnames[i].value))
			continue;

		(void) snprintf(c, end - c,
		    "%s%s", printed++ ? " | " : "(", flagnames[i].name);
		c += strlen(c);
		flags &= ~flagnames[i].value;
	}

	if (printed)
		(void) snprintf(c, end - c, ")");

	BUFDUMPASSTR(bufdata, dtbda_flags, buf);
	BUFDUMPHDR("");

	if (pd != NULL) {
		BUFDUMPHDR("  dtrace_probedesc");
		BUFDUMPSTR(pd, dtpd_provider);
		BUFDUMPSTR(pd, dtpd_mod);
		BUFDUMPSTR(pd, dtpd_func);
		BUFDUMPSTR(pd, dtpd_name);
		BUFDUMPHDR("");
	}

	if (rec != NULL) {
		BUFDUMPHDR("  dtrace_recdesc");
		BUFDUMP(rec, dtrd_action);
		BUFDUMP(rec, dtrd_size);

		if (agg != NULL) {
			uint8_t *data;
			int lim = rec->dtrd_size;

			(void) sprintf(buf, "%d (data: ", rec->dtrd_offset);
			c = buf + strlen(buf);

			if (lim > sizeof (uint64_t))
				lim = sizeof (uint64_t);

			data = (uint8_t *)agg->dtada_data + rec->dtrd_offset;

			for (i = 0; i < lim; i++) {
				(void) snprintf(c, end - c, "%s%02x",
				    i == 0 ? "" : " ", *data++);
				c += strlen(c);
			}

			(void) snprintf(c, end - c,
			    "%s)", lim < rec->dtrd_size ? " ..." : "");
			BUFDUMPASSTR(rec, dtrd_offset, buf);
		} else {
			BUFDUMP(rec, dtrd_offset);
		}

		BUFDUMPHDR("");
	}

	if (agg != NULL) {
		dtrace_aggdesc_t *desc = agg->dtada_desc;

		BUFDUMPHDR("  dtrace_aggdesc");
		BUFDUMPSTR(desc, dtagd_name);
		BUFDUMP(desc, dtagd_varid);
		BUFDUMP(desc, dtagd_id);
		BUFDUMP(desc, dtagd_nrecs);
		BUFDUMPHDR("");
	}

	return (DTRACE_HANDLE_OK);
}

static void
go(void)
{
	int i;

	struct {
		char *name;
		char *optname;
		dtrace_optval_t val;
	} bufs[] = {
		{ "buffer size", "bufsize" },
		{ "aggregation size", "aggsize" },
		{ "speculation size", "specsize" },
		{ "dynamic variable size", "dynvarsize" },
		{ NULL }
	}, rates[] = {
		{ "cleaning rate", "cleanrate" },
		{ "status rate", "statusrate" },
		{ NULL }
	};

	for (i = 0; bufs[i].name != NULL; i++) {
		if (dtrace_getopt(g_dtp, bufs[i].optname, &bufs[i].val) == -1)
			fatal("couldn't get option %s", bufs[i].optname);
	}

	for (i = 0; rates[i].name != NULL; i++) {
		if (dtrace_getopt(g_dtp, rates[i].optname, &rates[i].val) == -1)
			fatal("couldn't get option %s", rates[i].optname);
	}

	if (dtrace_go(g_dtp) == -1)
		dfatal("could not enable tracing");

	for (i = 0; bufs[i].name != NULL; i++) {
		dtrace_optval_t j = 0, mul = 10;
		dtrace_optval_t nsize;

		if (bufs[i].val == DTRACEOPT_UNSET)
			continue;

		(void) dtrace_getopt(g_dtp, bufs[i].optname, &nsize);

		if (nsize == DTRACEOPT_UNSET || nsize == 0)
			continue;

		if (nsize >= bufs[i].val - sizeof (uint64_t))
			continue;

		for (; (INT64_C(1) << mul) <= nsize; j++, mul += 10)
			continue;

		if (!(nsize & ((INT64_C(1) << (mul - 10)) - 1))) {
			error("%s lowered to %lld%c\n", bufs[i].name,
			    (long long)nsize >> (mul - 10), " kmgtpe"[j]);
		} else {
			error("%s lowered to %lld bytes\n", bufs[i].name,
			    (long long)nsize);
		}
	}

	for (i = 0; rates[i].name != NULL; i++) {
		dtrace_optval_t nval;
		char *dir;

		if (rates[i].val == DTRACEOPT_UNSET)
			continue;

		(void) dtrace_getopt(g_dtp, rates[i].optname, &nval);

		if (nval == DTRACEOPT_UNSET || nval == 0)
			continue;

		if (rates[i].val == nval)
			continue;

		dir = nval > rates[i].val ? "reduced" : "increased";

		if (nval <= NANOSEC && (NANOSEC % nval) == 0) {
			error("%s %s to %lld hz\n", rates[i].name, dir,
			    (long long)NANOSEC / (long long)nval);
			continue;
		}

		if ((nval % NANOSEC) == 0) {
			error("%s %s to once every %lld seconds\n",
			    rates[i].name, dir,
			    (long long)nval / (long long)NANOSEC);
			continue;
		}

		error("%s %s to once every %lld nanoseconds\n",
		    rates[i].name, dir, (long long)nval);
	}
}

int
main(int argc, char *argv[])
{
	dtrace_bufdesc_t buf;
	dtrace_status_t status[2];
	dtrace_cmd_t *dcp;
	dtrace_optval_t opt;

	g_ofp = stdout;
	int done = 0, mode = 0;
	int err, i, c;
	char *p, *p2, **v;
	struct ps_prochandle *P;
	pid_t pid;
	size_t len1, len2;

	p2 = NULL;

	rslv = (1 << DT_RSLV_HOSTNAME) | (1 << DT_RSLV_VERSION);
	len1 = len2 = 0;

	g_pname = basename(argv[0]);

	if (argc == 1)
		return (usage(stderr));

	if ((g_argv = malloc(sizeof (char *) * argc)) == NULL ||
	    (g_cmdv = malloc(sizeof (dtrace_cmd_t) * argc)) == NULL ||
	    (g_psv = malloc(sizeof (struct ps_prochandle *) * argc)) == NULL)
		fatal("failed to allocate memory for arguments");

	g_argv[g_argc++] = argv[0];	/* propagate argv[0] to D as $0/$$0 */
	argv[0] = g_pname;		/* rewrite argv[0] for getopt errors */

	bzero(status, sizeof (status));
	bzero(&buf, sizeof (buf));

	/*
	 * Make an initial pass through argv[] processing any arguments that
	 * affect our behavior mode (g_mode) and flags used for dtrace_open().
	 * We also accumulate arguments that are not affiliated with getopt
	 * options into g_argv[], and abort if any invalid options are found.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case '3':
				if (strcmp(optarg, "2") != 0) {
					(void) fprintf(stderr,
					    "%s: illegal option -- 3%s\n",
					    argv[0], optarg);
					return (usage(stderr));
				}
				g_oflags &= ~DTRACE_O_LP64;
				g_oflags |= DTRACE_O_ILP32;
				break;

			case '6':
				if (strcmp(optarg, "4") != 0) {
					(void) fprintf(stderr,
					    "%s: illegal option -- 6%s\n",
					    argv[0], optarg);
					return (usage(stderr));
				}
				g_oflags &= ~DTRACE_O_ILP32;
				g_oflags |= DTRACE_O_LP64;
				break;

			case 'a':
				g_grabanon++; /* also checked in pass 2 below */
				break;

			case 'A':
				g_mode = DMODE_ANON;
				g_exec = 0;
				mode++;
				break;

			case 'e':
				g_exec = 0;
				done = 1;
				break;

			case 'E':
				g_elf = 1;
				done = 1;
				break;

			case 'g':
				g_graphfile = optarg;
				break;

			case 'h':
				g_mode = DMODE_HEADER;
				g_oflags |= DTRACE_O_NODEV;
				g_cflags |= DTRACE_C_ZDEFS; /* -h implies -Z */
				g_exec = 0;
				mode++;
				break;

			case 'G':
				g_mode = DMODE_LINK;
				g_oflags |= DTRACE_O_NODEV;
				g_cflags |= DTRACE_C_ZDEFS; /* -G implies -Z */
				g_exec = 0;
				mode++;
				break;

			case 'y':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = process_elf;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				g_elf = 1;
				break;

			case 'Y':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = process_elf_hypertrace;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				g_elf = 1;
				g_guest = 1;
				break;

			case 'l':
				g_mode = DMODE_LIST;
				g_cflags |= DTRACE_C_ZDEFS; /* -l implies -Z */
				mode++;
				break;

			case 'V':
				g_mode = DMODE_VERS;
				mode++;
				break;

			default:
				if (strchr(DTRACE_OPTSTR, c) == NULL)
					return (usage(stderr));
			}
		}

		if (optind < argc)
			g_argv[g_argc++] = argv[optind];
	}

	if (mode > 1) {
		(void) fprintf(stderr, "%s: only one of the [-AGhlV] options "
		    "can be specified at a time\n", g_pname);
		return (E_USAGE);
	}

	if (g_mode == DMODE_VERS)
		return (printf("%s: %s\n", g_pname, _dtrace_version) <= 0);

	/*
	 * If we're in linker mode and the data model hasn't been specified,
	 * we try to guess the appropriate setting by examining the object
	 * files. We ignore certain errors since we'll catch them later when
	 * we actually process the object files.
	 */
	if (g_mode == DMODE_LINK &&
	    (g_oflags & (DTRACE_O_ILP32 | DTRACE_O_LP64)) == 0 &&
	    elf_version(EV_CURRENT) != EV_NONE) {
		int fd;
		Elf *elf;
		GElf_Ehdr ehdr;

		for (i = 1; i < g_argc; i++) {
			if ((fd = open64(g_argv[i], O_RDONLY)) == -1)
				break;

			if ((elf = elf_begin(fd, ELF_C_READ, NULL)) == NULL) {
				(void) close(fd);
				break;
			}

			if (elf_kind(elf) != ELF_K_ELF ||
			    gelf_getehdr(elf, &ehdr) == NULL) {
				(void) close(fd);
				(void) elf_end(elf);
				break;
			}

			(void) close(fd);
			(void) elf_end(elf);

			if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
				if (g_oflags & DTRACE_O_ILP32) {
					fatal("can't mix 32-bit and 64-bit "
					    "object files\n");
				}
				g_oflags |= DTRACE_O_LP64;
			} else if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
				if (g_oflags & DTRACE_O_LP64) {
					fatal("can't mix 32-bit and 64-bit "
					    "object files\n");
				}
				g_oflags |= DTRACE_O_ILP32;
			} else {
				break;
			}
		}
	}

	/*
	 * Open libdtrace.  If we are not actually going to be enabling any
	 * instrumentation attempt to reopen libdtrace using DTRACE_O_NODEV.
	 */
	if (pthread_mutex_init(&g_dtpmtx, NULL))
		fatal("failed to create the dtp mutex");

	while ((g_dtp = dtrace_open(DTRACE_VERSION, g_oflags, &err)) == NULL) {
		if (!(g_oflags & DTRACE_O_NODEV) && !g_exec && !g_grabanon) {
			g_oflags |= DTRACE_O_NODEV;
			continue;
		}

		fatal("failed to initialize dtrace: %s\n",
		    dtrace_errmsg(NULL, err));
	}

	if (g_guest)
		dtrace_set_guest(g_dtp);
	
	if (g_elf)
		dtrace_use_elf(g_dtp);


#if defined(__i386__)
	/* XXX The 32-bit seems to need more buffer space by default -sson */
	(void) dtrace_setopt(g_dtp, "bufsize", "12m");
	(void) dtrace_setopt(g_dtp, "aggsize", "12m");
#else
	(void) dtrace_setopt(g_dtp, "bufsize", "4m");
	(void) dtrace_setopt(g_dtp, "aggsize", "4m");
#endif
	(void) dtrace_setopt(g_dtp, "temporal", "yes");

	/*
	 * If -G is specified, enable -xlink=dynamic and -xunodefs to permit
	 * references to undefined symbols to remain as unresolved relocations.
	 * If -A is specified, enable -xlink=primary to permit static linking
	 * only to kernel symbols that are defined in a primary kernel module.
	 */
	if (g_mode == DMODE_LINK) {
		(void) dtrace_setopt(g_dtp, "linkmode", "dynamic");
		(void) dtrace_setopt(g_dtp, "unodefs", NULL);

		/*
		 * Use the remaining arguments as the list of object files
		 * when in linker mode.
		 */
		g_objc = g_argc - 1;
		g_objv = g_argv + 1;

		/*
		 * We still use g_argv[0], the name of the executable.
		 */
		g_argc = 1;
	} else if (g_mode == DMODE_ANON)
		(void) dtrace_setopt(g_dtp, "linkmode", "primary");

	/*
	 * Now that we have libdtrace open, make a second pass through argv[]
	 * to perform any dtrace_setopt() calls and change any compiler flags.
	 * We also accumulate any program specifications into our g_cmdv[] at
	 * this time; these will compiled as part of the fourth processing pass.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case 'a':
				if (dtrace_setopt(g_dtp, "grabanon", 0) != 0)
					dfatal("failed to set -a");
				break;

			case 'b':
				if (dtrace_setopt(g_dtp,
				    "bufsize", optarg) != 0)
					dfatal("failed to set -b %s", optarg);
				break;

			case 'B':
				g_ofp = NULL;
				break;

			case 'C':
				g_cflags |= DTRACE_C_CPP;
				break;

			case 'D':
				if (dtrace_setopt(g_dtp, "define", optarg) != 0)
					dfatal("failed to set -D %s", optarg);
				break;

			case 'f':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_FUNC;
				dcp->dc_arg = optarg;
				break;

			case 'F':
				if (dtrace_setopt(g_dtp, "flowindent", 0) != 0)
					dfatal("failed to set -F");
				break;

			case 'H':
				if (dtrace_setopt(g_dtp, "cpphdrs", 0) != 0)
					dfatal("failed to set -H");
				break;

			case 'i':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_NAME;
				dcp->dc_arg = optarg;
				break;

			case 'I':
				if (dtrace_setopt(g_dtp, "incdir", optarg) != 0)
					dfatal("failed to set -I %s", optarg);
				break;

			case 'L':
				if (dtrace_setopt(g_dtp, "libdir", optarg) != 0)
					dfatal("failed to set -L %s", optarg);
				break;

			case 'm':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_MOD;
				dcp->dc_arg = optarg;
				break;

			case 'n':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_NAME;
				dcp->dc_arg = optarg;
				break;

			case 'P':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_str;
				dcp->dc_spec = DTRACE_PROBESPEC_PROVIDER;
				dcp->dc_arg = optarg;
				break;

			case 'q':
				if (dtrace_setopt(g_dtp, "quiet", 0) != 0)
					dfatal("failed to set -q");
				break;

			case 'o':
				g_ofile = optarg;
				break;

			case 's':
				dcp = &g_cmdv[g_cmdc++];
				dcp->dc_func = compile_file;
				dcp->dc_spec = DTRACE_PROBESPEC_NONE;
				dcp->dc_arg = optarg;
				break;

			case 'S':
				g_cflags |= DTRACE_C_DIFV;
				break;

			case 'U':
				if (dtrace_setopt(g_dtp, "undef", optarg) != 0)
					dfatal("failed to set -U %s", optarg);
				break;

			case 'v':
				g_verbose++;
				break;

			case 'w':
				if (dtrace_setopt(g_dtp, "destructive", 0) != 0)
					dfatal("failed to set -w");
				break;

			case 'x':
				if ((p = strchr(optarg, '=')) != NULL)
					*p++ = '\0';

				len1 = strlen(optarg);
				len2 = strlen("resolvers");

				/*
				 * If the option is of form
				 * "resolvers=hostname,version"
				 * we get the two arguments, set the global
				 * variable to have the appropriate flags and
				 * break out of the switch statement.
				 */
				if (len1 == len2 &&
				    strncmp(optarg, "resolvers", len1) == 0) {
					if ((p2 = strchr(p, ',')) != NULL)
						*p2++ = '\0';

					if (strcmp(p, "hostname") != 0      &&
					    ((p2 && strcmp(p2, "hostname")) ||
					    p2 == NULL))
						rslv &= ~(1 << DT_RSLV_HOSTNAME);

					if (strcmp(p, "version") != 0      &&
					    ((p2 && strcmp(p2, "version")) ||
					    p2 == NULL))
						rslv &= ~(1 << DT_RSLV_VERSION);

					break;
				}

				if (dtrace_setopt(g_dtp, optarg, p) != 0)
					dfatal("failed to set -x %s", optarg);
				break;

			case 'X':
				if (dtrace_setopt(g_dtp, "stdc", optarg) != 0)
					dfatal("failed to set -X %s", optarg);
				break;

			case 'Z':
				g_cflags |= DTRACE_C_ZDEFS;
				break;

			default:
				if (strchr(DTRACE_OPTSTR, c) == NULL)
					return (usage(stderr));
			}
		}
	}

	dt_resolver_setflags(rslv);

	if (g_ofp == NULL && g_mode != DMODE_EXEC) {
		(void) fprintf(stderr, "%s: -B not valid in combination"
		    " with [-AGl] options\n", g_pname);
		return (E_USAGE);
	}

	if (g_ofp == NULL && g_ofile != NULL) {
		(void) fprintf(stderr, "%s: -B not valid in combination"
		    " with -o option\n", g_pname);
		return (E_USAGE);
	}

	/*
	 * In our third pass we handle any command-line options related to
	 * grabbing or creating victim processes.  The behavior of these calls
	 * may been affected by any library options set by the second pass.
	 */
	for (optind = 1; optind < argc; optind++) {
		while ((c = getopt(argc, argv, DTRACE_OPTSTR)) != -1) {
			switch (c) {
			case 'c':
				if ((v = make_argv(optarg)) == NULL)
					fatal("failed to allocate memory");

				P = dtrace_proc_create(g_dtp, v[0], v, NULL, NULL);
				if (P == NULL)
					dfatal(NULL); /* dtrace_errmsg() only */

				g_psv[g_psc++] = P;
				free(v);
				break;

			case 'p':
				errno = 0;
				pid = strtol(optarg, &p, 10);

				if (errno != 0 || p == optarg || p[0] != '\0')
					fatal("invalid pid: %s\n", optarg);

				P = dtrace_proc_grab(g_dtp, pid, 0);
				if (P == NULL)
					dfatal(NULL); /* dtrace_errmsg() only */

				g_psv[g_psc++] = P;
				break;
			}
		}
	}

	/*
	 * In our fourth pass we finish g_cmdv[] by calling dc_func to convert
	 * each string or file specification into a compiled program structure.
	 */
	for (i = 0; i < g_cmdc; i++)
		g_cmdv[i].dc_func(&g_cmdv[i]);

	if (g_mode != DMODE_LIST) {
		if (dtrace_handle_err(g_dtp, &errhandler, NULL) == -1)
			dfatal("failed to establish error handler");

		if (dtrace_handle_drop(g_dtp, &drophandler, NULL) == -1)
			dfatal("failed to establish drop handler");

		if (dtrace_handle_proc(g_dtp, &prochandler, NULL) == -1)
			dfatal("failed to establish proc handler");

		if (dtrace_handle_setopt(g_dtp, &setopthandler, NULL) == -1)
			dfatal("failed to establish setopt handler");

		if (g_ofp == NULL &&
		    dtrace_handle_buffered(g_dtp, &bufhandler, NULL) == -1)
			dfatal("failed to establish buffered handler");
	}

	(void) dtrace_getopt(g_dtp, "flowindent", &opt);
	g_flowindent = opt != DTRACEOPT_UNSET;

	(void) dtrace_getopt(g_dtp, "grabanon", &opt);
	g_grabanon = opt != DTRACEOPT_UNSET;

	(void) dtrace_getopt(g_dtp, "quiet", &opt);
	g_quiet = opt != DTRACEOPT_UNSET;

	/*
	 * Now make a fifth and final pass over the options that have been
	 * turned into programs and saved in g_cmdv[], performing any mode-
	 * specific processing.  If g_mode is DMODE_EXEC, we will break out
	 * of the switch() and continue on to the data processing loop.  For
	 * other modes, we will exit dtrace once mode-specific work is done.
	 */
	switch (g_mode) {
	case DMODE_EXEC:
		if (g_ofile != NULL && (g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);


		for (i = 0; i < g_cmdc; i++)
			exec_prog(&g_cmdv[i]);

		if (done && !g_grabanon) {
			pthread_mutex_lock(&g_dtpmtx);
			if (g_dtp)
				dtrace_close(g_dtp);
			g_dtp = NULL;
			pthread_mutex_unlock(&g_dtpmtx);

			pthread_mutex_destroy(&g_dtpmtx);

			return (g_status);
		}
		break;

	case DMODE_ANON:
		if (g_ofile == NULL)
#ifdef illumos
			g_ofile = "/kernel/drv/dtrace.conf";
#else
			/*
			 * On FreeBSD, anonymous DOF data is written to
			 * the DTrace DOF file.
			 */
			g_ofile = "/boot/dtrace.dof";
#endif

		dof_prune(g_ofile); /* strip out any old DOF directives */
#ifdef illumos
		etcsystem_prune(); /* string out any forceload directives */
#endif

		if (g_cmdc == 0) {
			pthread_mutex_lock(&g_dtpmtx);
			dtrace_close(g_dtp);
			g_dtp = NULL;
			pthread_mutex_unlock(&g_dtpmtx);

			pthread_mutex_destroy(&g_dtpmtx);

			return (g_status);
		}

		if ((g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);

		for (i = 0; i < g_cmdc; i++) {
			anon_prog(&g_cmdv[i],
			    dtrace_dof_create(g_dtp, g_cmdv[i].dc_prog, 0), i);
		}

		/*
		 * Dump out the DOF corresponding to the error handler and the
		 * current options as the final DOF property in the .conf file.
		 */
		anon_prog(NULL, dtrace_geterr_dof(g_dtp), i++);
		anon_prog(NULL, dtrace_getopt_dof(g_dtp), i++);

		if (fclose(g_ofp) == EOF)
			fatal("failed to close output file '%s'", g_ofile);

		/*
		 * These messages would use notice() rather than error(), but
		 * we don't want them suppressed when -A is run on a D program
		 * that itself contains a #pragma D option quiet.
		 */
		error("saved anonymous enabling in %s\n", g_ofile);

#ifdef __FreeBSD__
		bootdof_add();
#else
		etcsystem_add();
		error("run update_drv(1M) or reboot to enable changes\n");
#endif
		
		dtrace_close(g_dtp);

		return (g_status);

	case DMODE_LINK:
		if (g_cmdc == 0) {
			(void) fprintf(stderr, "%s: -G requires one or more "
			    "scripts or enabling options\n", g_pname);
			dtrace_close(g_dtp);

			return (E_USAGE);
		}

		for (i = 0; i < g_cmdc; i++)
			link_prog(&g_cmdv[i]);

		if (g_cmdc > 1 && g_ofile != NULL) {
			char **objv = alloca(g_cmdc * sizeof (char *));

			for (i = 0; i < g_cmdc; i++)
				objv[i] = g_cmdv[i].dc_ofile;

			if (dtrace_program_link(g_dtp, NULL, DTRACE_D_PROBES,
			    g_ofile, g_cmdc, objv) != 0)
				dfatal(NULL); /* dtrace_errmsg() only */
		}

		dtrace_close(g_dtp);
		return (g_status);

	case DMODE_LIST:
		if (g_ofile != NULL && (g_ofp = fopen(g_ofile, "a")) == NULL)
			fatal("failed to open output file '%s'", g_ofile);

		installsighands();

		oprintf("%5s %10s %17s %33s %s\n",
		    "ID", "PROVIDER", "MODULE", "FUNCTION", "NAME");

		for (i = 0; i < g_cmdc; i++)
			list_prog(&g_cmdv[i]);

		if (g_cmdc == 0)
			(void) dtrace_probe_iter(g_dtp, NULL, list_probe, NULL);

		dtrace_close(g_dtp);
		
		return (g_status);

	case DMODE_HEADER:
		if (g_cmdc == 0) {
			(void) fprintf(stderr, "%s: -h requires one or more "
			    "scripts or enabling options\n", g_pname);
			dtrace_close(g_dtp);
			
			return (E_USAGE);
		}

		if (g_ofile == NULL) {
			char *p;

			if (g_cmdc > 1) {
				(void) fprintf(stderr, "%s: -h requires an "
				    "output file if multiple scripts are "
				    "specified\n", g_pname);
				dtrace_close(g_dtp);
				
				return (E_USAGE);
			}

			if ((p = strrchr(g_cmdv[0].dc_arg, '.')) == NULL ||
			    strcmp(p, ".d") != 0) {
				(void) fprintf(stderr, "%s: -h requires an "
				    "output file if no scripts are "
				    "specified\n", g_pname);
				
				dtrace_close(g_dtp);
				return (E_USAGE);
			}

			p[0] = '\0'; /* strip .d suffix */
			g_ofile = p = g_cmdv[0].dc_ofile;
			(void) snprintf(p, sizeof (g_cmdv[0].dc_ofile),
			    "%s.h", basename(g_cmdv[0].dc_arg));
		}

		if ((g_ofp = fopen(g_ofile, "w")) == NULL)
			fatal("failed to open header file '%s'", g_ofile);

		oprintf("/*\n * Generated by dtrace(1M).\n */\n\n");

		if (dtrace_program_header(g_dtp, g_ofp, g_ofile) != 0 ||
		    fclose(g_ofp) == EOF)
			dfatal("failed to create header file %s", g_ofile);

		dtrace_close(g_dtp);
		return (g_status);
	}

	/*
	 * If -a and -Z were not specified and no probes have been matched, no
	 * probe criteria was specified on the command line and we abort.
	 */
	if (g_total == 0 && !g_grabanon && !(g_cflags & DTRACE_C_ZDEFS))
		dfatal("no probes %s\n", g_cmdc ? "matched" : "specified");

	setup_tracing();
	(void) dtc_work(NULL);
	pthread_mutex_lock(&g_dtpmtx);
	if (g_dtp)
		dtrace_close(g_dtp);
	pthread_mutex_unlock(&g_dtpmtx);

	pthread_mutex_destroy(&g_dtpmtx);
	return (g_status);
}
