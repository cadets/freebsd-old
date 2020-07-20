/*-
 * Copyright (c) 2018-2020 (Graeme Jenkinson)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-10-C-0237
 * ("CTSRD"), as part of the DARPA CRASH research programme.
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

#include <sys/file.h>
#include <sys/mman.h>
#include <sys/param.h>

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_offset.h"
#include "dl_utils.h"

struct dl_offset {
	pthread_mutex_t dlo_mtx; /* Mutex protecting the dlo_value */
	uint32_t *dlo_value; /* Offset value */
};

static const int OFFSET_PERMS = 0600;
static char const * const OFFSET_FMT= "%s/offset";

static int dl_offset_ctor(struct dl_offset const **, char *, bool);

static inline void
assert_integrity(struct dl_offset *offset)
{

	DL_ASSERT(offset != NULL, ("Offset instance cannot be NULL"));
	DL_ASSERT(offset->dlo_value != NULL,
	    ("Offset value cannot be invalid"));
}

static int
dl_offset_ctor(struct dl_offset const **self, char *path_name,
    bool from_beginning)
{
	struct dl_offset *offset;
	struct sbuf offset_name;
	int fd, rc;
	char name[MAXPATHLEN];

	/* Validate the method's preconditions */	
	if (self == NULL || path_name == NULL) {
		
		DL_ASSERT(false,
		    ("Invalid parameter passed to Offset constructor"));
		DLOGTR0(PRIO_HIGH, 
		    "Invalid parameter passed to Offset constructor\n");
		return -1;
	}

	/* Allocate the Offset instance. */
	offset = (struct dl_offset *) dlog_alloc(sizeof(struct dl_offset));
	if (offset == NULL) {
		
		goto err_offset_ctor;
	}

	bzero(offset, sizeof(struct dl_offset));

	/* Construct the path for the Offset file */
	(void) sbuf_new(&offset_name, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&offset_name, OFFSET_FMT, path_name);
	sbuf_finish(&offset_name);
	if (sbuf_error(&offset_name) != 0) {

		sbuf_delete(&offset_name);
		goto err_offset_ctor;
	}
	sbuf_delete(&offset_name);

	fd = open(name, O_RDWR | O_CREAT, OFFSET_PERMS);
	if (fd == -1) {

		DLOGTR0(PRIO_LOW,
		    "Failed opening file to perist Offset value\n");
		goto err_offset_free;
	}

	/* Truncate the file to the size of the dlo_value */
	ftruncate(fd, sizeof(*offset->dlo_value));

	offset->dlo_value =(uint32_t *) mmap(
	    NULL, sizeof(*offset->dlo_value),
	    PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (offset->dlo_value == NULL)  {

		DLOGTR1(PRIO_HIGH,
		    "Failed mapping Offset file %d\n", errno);
		goto err_offset_close;
	}

	if (from_beginning) {

		*offset->dlo_value = 0;
		rc = msync(offset->dlo_value, sizeof(offset->dlo_value), MS_SYNC);
		DL_ASSERT(rc == 0, ("Failed syncing Offset file"));
	}

	rc = pthread_mutex_init(&offset->dlo_mtx, NULL);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed initializing Offset mutex\n");
		munmap(offset->dlo_value, sizeof(*offset->dlo_value));
		goto err_offset_free;
	}

	/* Validate the method's postconditions */	
	assert_integrity(offset);

	*self = offset;
	return 0;


err_offset_close:
	close(fd);

err_offset_free:
	dlog_free(offset);
	
err_offset_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Offset instance\n");

	*self = NULL;
	return -1;
}

int
dl_offset_new(struct dl_offset const **self, char *path_name)
{

	return dl_offset_ctor(self, path_name, false);
}

int
dl_offset_from_beginning_new(struct dl_offset const **self, char *path_name)
{

	return dl_offset_ctor(self, path_name, true);
}

void
dl_offset_delete(struct dl_offset const *self)
{

	assert_integrity(self);

	/* Close and unmap the Offset file. */
	msync(self->dlo_value, sizeof(*self->dlo_value), MS_SYNC);
	munmap(self->dlo_value, sizeof(*self->dlo_value));

	/* Destroy the mutex used to protect the Offset value. */
	pthread_mutex_destroy(&self->dlo_mtx);

	/* Free the memory for the Offset instance. */
	dlog_free(self);
}


uint32_t
dl_offset_get_val(struct dl_offset const * const self)
{
	uint32_t value;
	int rc;

	assert_integrity(self);

	rc = pthread_mutex_lock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed locking Offset mutex"));

	value = *self->dlo_value;

	rc = pthread_mutex_unlock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed unlocking Offset mutex"));

	return value;
}

int
dl_offset_inc(struct dl_offset const *self)
{
	int rc;

	assert_integrity(self);

	rc = pthread_mutex_lock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed locking Offset mutex"));

	/* Increment the Offset value and sync this new value to disk. */
	(* self->dlo_value)++;

	rc = msync(self->dlo_value, sizeof(self->dlo_value), MS_SYNC);
	DL_ASSERT(rc == 0, ("Failed syncing Offset file"));

	rc = pthread_mutex_unlock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed unlocking Offset mutex"));

	return 0;
}
