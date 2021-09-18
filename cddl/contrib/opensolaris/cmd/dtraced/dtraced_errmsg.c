#include <err.h>
#include <execinfo.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "dtraced_errmsg.h"

#define DTRACED_BACKTRACELEN    128

static int quiet;

void
be_quiet(void)
{

	quiet = 1;
}

void
dump_errmsg(const char *msg, ...)
{
	va_list ap;
	time_t __time;
	char *__time_s;

	if (quiet)
		return;

	__time = time(NULL);
	__time_s = asctime(localtime(&__time));
	__time_s[strlen(__time_s) - 1] = '\0';

	va_start(ap, msg);
	if (msg) {
		fprintf(stderr, "ERROR(%s):    ", __time_s);
		vfprintf(stderr, msg, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		va_start(ap, msg);
		vsyslog(LOG_ERR, msg, ap);
	}
	va_end(ap);
}

void
dump_warnmsg(const char *msg, ...)
{
	va_list ap;
	time_t __time;
	char *__time_s;

	if (quiet)
		return;

	__time = time(NULL);
	__time_s = asctime(localtime(&__time));
	__time_s[strlen(__time_s) - 1] = '\0';

	va_start(ap, msg);
	if (msg) {
		fprintf(stderr, "WARNING(%s):  ", __time_s);
		vfprintf(stderr, msg, ap);
		va_end(ap);
		fprintf(stderr, "\n");
		va_start(ap, msg);
		vsyslog(LOG_WARNING, msg, ap);
	}
	va_end(ap);
}

void
dump_debugmsg(const char *msg, ...)
{
	va_list ap;
	time_t __time;
	char *__time_s;

	if (quiet)
		return;

	__time = time(NULL);
	__time_s = asctime(localtime(&__time));
	__time_s[strlen(__time_s) - 1] = '\0';

	va_start(ap, msg);
	if (msg) {
		fprintf(stdout, "DEBUG(%s):    ", __time_s);
		vfprintf(stdout, msg, ap);
		va_end(ap);
		fprintf(stdout, "\n");
		va_start(ap, msg);
		vsyslog(LOG_DEBUG, msg, ap);
	}
	va_end(ap);
}

void
dump_backtrace(void)
{
	int nptrs;
	void *buffer[DTRACED_BACKTRACELEN];
	char **strings;

	nptrs = backtrace(buffer, DTRACED_BACKTRACELEN);
	strings = backtrace_symbols(buffer, nptrs);

	if (strings == NULL) {
		dump_errmsg("Failed to get backtrace symbols: %m");
		exit(EXIT_FAILURE);
	}

	for (int j = 0; j < nptrs; j++)
		dump_errmsg("%s", strings[j]);

	free(strings);
}

