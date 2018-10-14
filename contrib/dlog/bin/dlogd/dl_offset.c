/*-
 * Copyright (c) 2018 (Graeme Jenkinson)
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

#include <errno.h>
#include <pthread.h>
#include <strings.h>
#include <unistd.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_offset.h"
#include "dl_utils.h"

struct dl_offset {
	pthread_mutex_t dlo_mtx; /* Mutex protecting the dlo_value */
	uint32_t dlo_value; /* Offset value (32bit value so atoomic) */
	int dlo_fd; /* File descriptor used to persist the Offset */
};

static inline void
dl_offset_assert_intergity(struct dl_offset *offset)
{

	DL_ASSERT(offset != NULL, ("Offset instance cannot be NULL"));
	DL_ASSERT(offset->dlo_fd >= 0,
	    ("Offset file descriptor cannot be invalid"));
}

int
dl_offset_new(struct dl_offset **self, struct sbuf *path_name)
{
	struct dl_offset *offset;
	struct sbuf *offset_name;
	int32_t offset_val;
	int fd, rc;
	
	DL_ASSERT(self != NULL, ("Offset instance cannot be NULL"));
	DL_ASSERT(path_name != NULL, ("Offset file path name cannot be NULL"));

	offset = (struct dl_offset *) dlog_alloc(sizeof(struct dl_offset));
	if (offset == NULL) {
		
		DLOGTR0(PRIO_LOW,
		    "Failed allocating memory for Offset instance\n");
		goto err_offset_ctor;
	}

	bzero(offset, sizeof(struct dl_offset));

	/* Construct the path for the Offset file */
	offset_name = sbuf_new_auto();
	sbuf_printf(offset_name, "%s/offset", sbuf_data(path_name));
	sbuf_finish(offset_name);

	fd = open(sbuf_data(offset_name), O_RDWR | O_CREAT, 0666);
	if (fd == -1) {

		DLOGTR0(PRIO_LOW,
		    "Failed opening file to perist Offset value\n");
		sbuf_delete(offset_name);
		goto err_offset_alloc_ctor;
	}
	sbuf_delete(offset_name);

	/* Attempt to apply an advisory lock the offset file;
	 * if a lock is present, exit.
	 */
	rc = flock(fd, LOCK_EX | LOCK_NB);
        if (rc == -1) {

		DLOGTR0(PRIO_LOW,
		    "Failed locking file to perist Offset value\n");
		goto err_offset_open_ctor;
	}

	/* Read the offset value from the file. */
	rc = pread(fd, &offset_val, sizeof(offset_val), 0);
	if (rc == -1) {

		DLOGTR0(PRIO_HIGH,
		    "Failed reading offset value from the file.\n"); 
		goto err_offset_open_ctor;
	} else if (rc == 0) {
		/* EOF - set the offset value to zero */

		offset->dlo_value = 0;
		rc = pwrite(fd, &offset->dlo_value,
		    sizeof(offset->dlo_value), 0);
		if (rc == -1) {

			DLOGTR0(PRIO_LOW,
			    "Failed writing Offset value to file\n");
			goto err_offset_open_ctor;
		}
	} else {
		/* Set the offset value to the value read from the file. */
		offset->dlo_value = offset_val;
	}

	offset->dlo_fd = fd;
	rc = pthread_mutex_init(&offset->dlo_mtx, NULL);
	if (rc != 0) {

		DLOGTR0(PRIO_LOW, "Failed initializing Offset mutex\n");
		goto err_offset_open_ctor;
	}

	dl_offset_assert_intergity(offset);

	*self = offset;
	return 0;


err_offset_open_ctor:
	close(offset->dlo_fd);

err_offset_alloc_ctor:
	dlog_free(offset);
	
err_offset_ctor:
	DLOGTR0(PRIO_HIGH, "Failed instantiating Offset instance\n");

	*self = NULL;
	return -1;
}

void
dl_offset_delete(struct dl_offset *self)
{
	int rc;

	dl_offset_assert_intergity(self);

	/* Unlock and close the file backing the offset. */
	rc = flock(self->dlo_fd, LOCK_UN);
	if (rc != 0) {

		DLOGTR1(PRIO_HIGH, "Failed unlocking Offset file (%d)\n",
		    errno);
	}
	close(self->dlo_fd);

	/* Destroy the mutex used to prtect the Offset value. */
	pthread_mutex_destroy(&self->dlo_mtx);

	/* Free the memory for the Offset instance. */
	dlog_free(self);
}

int
dl_offset_inc(struct dl_offset *self)
{
	int rc;

	dl_offset_assert_intergity(self);

	rc = pthread_mutex_lock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed locking Offset mutex"));
	/* Increment the Offset value and sync this new value to disk. */
	self->dlo_value++;
	rc = pwrite(self->dlo_fd, &self->dlo_value,
	    sizeof(self->dlo_value), 0);
	if (rc == -1) {

		DLOGTR0(PRIO_LOW, "Failed writing Offset value to file\n");
		/* Restore the original Offset value. */
		self->dlo_value--;
	}
	rc = fsync(self->dlo_fd);
	DL_ASSERT(rc == 0, ("Failed syncing Offset file"));
	rc = pthread_mutex_unlock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed unlocking Offset mutex"));

	return 0;
}

int32_t
dl_offset_val(struct dl_offset *self)
{
	uint32_t value;
	int rc;

	dl_offset_assert_intergity(self);

	rc = pthread_mutex_lock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed locking Offset mutex"));
	value = self->dlo_value;
	rc = pthread_mutex_unlock(&self->dlo_mtx);
	DL_ASSERT(rc == 0, ("Failed unlocking Offset mutex"));
	return value;
}
