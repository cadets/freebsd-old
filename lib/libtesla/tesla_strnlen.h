#include "config.h"

#ifdef HAVE_STRNLEN
#include <string.h>

#else
/* If we don't have strnlen(), fake it. */
#warning Platform does not supply strnlen(); faking it with strlen().
#define strnlen(s, len) strlen(s)
#endif
