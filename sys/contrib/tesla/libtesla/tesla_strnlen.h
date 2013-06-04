#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef _KERNEL
#include <sys/libkern.h>
#else
#ifdef HAVE_STRNLEN
#include <string.h>
#else
/* If we don't have strnlen(), fake it. */
#warning Platform does not supply strnlen(); faking it with strlen().
#define strnlen(s, len) strlen(s)
#endif
#endif
