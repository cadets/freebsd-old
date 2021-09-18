#include <sys/types.h>
#include <sys/param.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "dtraced_misc.h"

/*
 * Used for generating a random name of the outbound ELF file.
 */
void
get_randname(char *b, size_t len)
{
	size_t i;

	/*
	 * Generate lower-case random characters.
	 */
	for (i = 0; i < len; i++)
		b[i] = arc4random_uniform(25) + 97;
}

char *
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

