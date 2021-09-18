#ifndef _DTRACED_DIRECTORY_H_
#define _DTRACED_DIRECTORY_H_

#include <dirent.h>

#include "dtraced_lock.h"

struct dtd_dir;
struct dtd_state;

typedef int (*foreach_fn_t)(struct dirent *, struct dtd_dir *);

typedef struct dtd_dir {
	char *dirpath;		 /* directory path */
	int dirfd;		 /* directory filedesc */
	DIR *dir;		 /* directory pointer */
	char **existing_files;	 /* files that exist in the dir */
	size_t efile_size;	 /* vector size */
	size_t efile_len;	 /* number of elements */
	mutex_t dirmtx;		 /* directory mutex */
	foreach_fn_t processfn;	 /* function to process the dir */
	struct dtd_state *state; /* backpointer to state */
} dtd_dir_t;

int         write_data(dtd_dir_t *, unsigned char *, size_t);
void        *listen_dir(void *);
int         populate_existing(struct dirent *, dtd_dir_t *);
int         file_foreach(DIR *, foreach_fn_t, dtd_dir_t *);
dtd_dir_t   *dtd_mkdir(const char *, foreach_fn_t);
void        dtd_closedir(dtd_dir_t *);
int         process_inbound(struct dirent *, dtd_dir_t *);
int         process_base(struct dirent *, dtd_dir_t *);
int         process_outbound(struct dirent *, dtd_dir_t *);

#endif // _DTRACED_DIRECTORY_H_
