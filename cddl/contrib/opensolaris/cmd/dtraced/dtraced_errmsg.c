#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <time.h>

#include "dtraced_errmsg.h"

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

