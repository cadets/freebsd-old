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

#include <sys/types.h>
#include <sys/uio.h>

#ifdef _KERNEL
#include <sys/capsicum.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#else
#include <dirent.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <math.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>
#include <unistd.h>
#endif

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_utils.h"


static inline void dl_segment_check_integrity(struct dl_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
}

void
dl_segment_delete(struct dl_segment *self)
{

	dl_segment_check_integrity(self);

#ifndef _KERNEL
	close(self->_klog);
	close(self->_log);
#endif
#ifdef _KERNEL
	sx_destroy(&self->dls_lock);
#else
	pthread_mutex_destroy(&self->dls_lock);
	dl_index_delete(self->dls_idx);
#endif
	dlog_free(self);
}

#ifndef _KERNEL
static const long int DL_SEGMENT_DEFAULT_SIZE = 1024*1024;

int
dl_segment_new_default(struct dl_segment **self, struct sbuf *partition_name)
{

	return dl_segment_new(self, 0, DL_SEGMENT_DEFAULT_SIZE, partition_name);
}

int
dl_segment_new_default_sized(struct dl_segment **self, long int base_offset,
    struct sbuf *partition_name)
{

	return dl_segment_new(self, base_offset, 1024*1024, partition_name);
}

int
dl_segment_new(struct dl_segment **self, long int base_offset,
    long int length, struct sbuf *partition_name)
{
	struct dl_segment *seg;
	struct sbuf *log_name;

	DL_ASSERT(self != NULL, (""));
	DL_ASSERT(partition_name != NULL, (""));

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
	if (seg == NULL) {
	
		DLOGTR0(PRIO_HIGH, "Failed allocating segment instance");
		return -1;
	}

	log_name = sbuf_new_auto();
	sbuf_printf(log_name, "%s/%.*ld.log",
	    sbuf_data(partition_name), 20, base_offset);
	sbuf_finish(log_name);
	seg->_log = open(sbuf_data(log_name), O_RDWR | O_APPEND | O_CREAT, 0666);
	// TODO
	//sbuf_delete(log_name);
	//dlog_free(seg);
	
	sbuf_delete(log_name);
	dl_alloc_big_file(seg->_log, 0, length);

	seg->offset = base_offset;
	seg->base_offset = base_offset;
	seg->segment_size = length;
	seg->last_sync_pos = 0;

	if (pthread_mutex_init(&seg->dls_lock, NULL) != 0){
		dl_debug(PRIO_HIGH, "Segment mutex init failed\n");
	}

	*self = seg;
	dl_segment_check_integrity(*self);
	return 0;
}
#endif

int
dl_segment_from_desc(struct dl_segment **self,
    struct dl_segment_desc *seg_desc)
{
#ifdef _KERNEL
	struct thread *td = curthread;
	cap_rights_t rights;
	struct file *fp;
#endif
	struct dl_segment *seg;

	seg = (struct dl_segment *) dlog_alloc(sizeof(struct dl_segment));
#ifdef _KERNEL
	DL_ASSERT(seg != NULL, ("Failed allocating segment instance"));
#else
	if (seg == NULL) {
	
		DLOGTR0(PRIO_HIGH, "Failed allocating segment instance");
		return -1;
	}
#endif
	DLOGTR0(PRIO_HIGH, "Zeroing segment instance");
	bzero(seg, sizeof(struct dl_segment));

	seg->offset = seg_desc->dlsd_base_offset;
	seg->base_offset = seg_desc->dlsd_base_offset;
	seg->segment_size = seg_desc->dlsd_seg_size;
	seg->last_sync_pos = 0;

#ifdef _KERNEL
	seg->ucred = td->td_ucred;
	fget_write(td, seg_desc->dlsd_log,
	    cap_rights_init(&rights, CAP_WRITE), &fp); 
	seg->_log = fp->f_vnode;
	sx_init(&seg->dls_lock, "segment mtx");
#else
	seg->_log = seg_desc->dlsd_log;
	if (pthread_mutex_init(&seg->dls_lock, NULL) != 0){
		dl_debug(PRIO_HIGH, "Segment mutex init failed\n");
	}
#endif

	*self = seg;
	dl_segment_check_integrity(*self);
	return 0;
}

int
dl_segment_insert_message(struct dl_segment *self, struct dl_bbuf *buffer)
{
#ifdef _KERNEL
	struct mount *mp;
	struct thread *td = curthread;
	struct uio u;
	//uint64_t ? timestamp;
#endif
	struct iovec log_bufs[2];
	uint32_t offset;
	//uint64_t ? timestamp;

	dl_segment_check_integrity(self);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	DLOGTR1(PRIO_HIGH, "Inserting (%d bytes) into the log\n",
	    dl_bbuf_pos(buffer));

	dl_segment_lock(self);

	/* Update the log file. */
	offset = htobe32(self->offset); 

	log_bufs[0].iov_base = &offset;
	log_bufs[0].iov_len = sizeof(offset);
	
	//log_bufs[1].iov_base = &timestamp;
	//log_bufs[1].iov_len = sizeof(timestamp);

	log_bufs[1].iov_base = dl_bbuf_data(buffer);
	log_bufs[1].iov_len = dl_bbuf_pos(buffer);

#ifdef _KERNEL
	bzero(&u, sizeof(struct uio));
	u.uio_iov = log_bufs;
	u.uio_iovcnt = 2;
	u.uio_offset = -1;
        u.uio_resid = log_bufs[0].iov_len + log_bufs[1].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	VREF(self->_log);
	crhold(self->ucred);
	vn_start_write(self->_log, &mp, V_WAIT);
	vn_lock(self->_log, LK_EXCLUSIVE | LK_RETRY);
	VOP_WRITE(self->_log, &u, IO_UNIT | IO_APPEND, self->ucred);
	VOP_UNLOCK(self->_log, 0);
	vn_finished_write(mp);
	crfree(self->ucred);
#else
	writev(self->_log, log_bufs, 2);	
#endif

	/* Update the offset. */
	self->offset++;

	dl_segment_unlock(self);
	return 0;
}

#ifndef _KERNEL
int
dl_segment_get_message_by_offset(struct dl_segment *self, int offset,
    struct dl_bbuf **msg_buf)
{
	struct dl_bbuf *t;
	int32_t poffset, tmp_buf[2], cid, size;
	int rc;

	dl_segment_check_integrity(self);

	poffset = dl_index_lookup(self->dls_idx, offset);
	if (poffset >= 0) {
#ifndef DEBUG
		DLOGTR2(PRIO_LOW,
		    "Log offset %X indexs to physical log offset %x\n",
		    offset, poffset);
#endif
		rc = pread(self->_log, tmp_buf, sizeof(tmp_buf), poffset);
	
		unsigned char *bufval = (unsigned char *) tmp_buf;
		for (unsigned int i = 0; i < sizeof(tmp_buf); i++) {
			DLOGTR1(PRIO_LOW, "<0x%02hhX>", bufval[i]);
		};
		DLOGTR0(PRIO_LOW, "\n");

		dl_bbuf_new(&t, (unsigned char *) tmp_buf,
		    sizeof(tmp_buf), DL_BBUF_BIGENDIAN);
		dl_bbuf_get_int32(t, &cid);
		dl_bbuf_get_int32(t, &size);
		dl_bbuf_delete(t);

		DLOGTR1(PRIO_LOW, "Correlation id = %u\n", cid);
		DLOGTR1(PRIO_LOW, "Message set size = %u\n", size);
		
		unsigned char *msg_tmp =
		    dlog_alloc(size * sizeof(unsigned char) + sizeof(int32_t));

		rc = pread(self->_log, msg_tmp, size + sizeof(int32_t),
		    poffset + sizeof(int32_t));

		dl_bbuf_new(msg_buf, NULL, size + sizeof(int32_t), DL_BBUF_BIGENDIAN);
		dl_bbuf_bcat(*msg_buf, msg_tmp, size + sizeof(int32_t));
		return 0;
	} else {
		DLOGTR2(PRIO_HIGH, "For offset %d no message found (%d).\n",
		    offset, errno);
		return -1;
	}
	return 0;
}
#endif

void
dl_segment_close(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
#ifdef _KERNEL
#else
	close(self->_log);
#endif
}

void
dl_segment_lock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_segment_check_integrity(self);
#ifdef _KERNEL
	sx_slock(&self->dls_lock);
#else
	pthread_mutex_lock(&self->dls_lock);
#endif
}

void
dl_segment_unlock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_segment_check_integrity(self);
#ifdef _KERNEL
	sx_sunlock(&self->dls_lock);
#else
	pthread_mutex_unlock(&self->dls_lock);
#endif
}

u_int64_t
dl_segment_get_base_offset(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return self->base_offset;
}

#ifndef _KERNEL
// TODO: remove
int
dl_segment_get_log(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return self->_log;
}
#endif

off_t
dl_segment_get_last_sync_pos(struct dl_segment *self)
{

	dl_segment_check_integrity(self);
	return self->last_sync_pos;
}

void
dl_segment_set_last_sync_pos(struct dl_segment *self, off_t pos)
{

	dl_segment_check_integrity(self);
	self->last_sync_pos = pos;
}
