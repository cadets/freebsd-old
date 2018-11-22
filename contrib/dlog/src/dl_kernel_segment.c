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
#include <sys/capsicum.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/sx.h>

#include "dl_assert.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_kernel_segment.h"
#include "dl_kernel_segment.h"
#include "dl_segment.h"
#include "dl_utils.h"

struct dl_kernel_segment {
	SLIST_ENTRY(dl_segment) dls_entries;
	struct sx dls_lock; /* Lock for whilst updating segment. */
	uint32_t offset;
	struct file *_log;
};

static void dl_kernel_segment_lock(struct dl_segment *);
static void dl_kernel_segment_unlock(struct dl_segment *);
static int dl_kernel_segment_insert_message(struct dl_segment *,
    struct dl_bbuf *);
static int dl_kernel_segment_get_message_by_offset(
    struct dl_segment *, int, struct dl_bbuf **);
static void dl_kernel_segment_delete(struct dl_segment *);
static uint32_t dl_kernel_get_offset(struct dl_segment *);

static inline void dl_kernel_segment_check_integrity(
    struct dl_kernel_segment *self)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL."));
}

static void
dl_kernel_segment_delete(struct dl_segment *self)
{
	struct thread *td = curthread;
	struct dl_kernel_segment *kseg = self->dls_kernel;

	dl_kernel_segment_check_integrity(kseg);

	sx_destroy(&(self->dls_kernel->dls_lock));
	fdrop(self->dls_kernel->_log, td);
	dlog_free(self);
}

int
dl_kernel_segment_from_desc(struct dl_segment **self,
    struct dl_segment_desc *seg_desc)
{
	struct thread *td = curthread;
	cap_rights_t rights;
	struct dl_segment *seg;
	struct dl_kernel_segment *kseg;
	struct vnode *vp;
	int rc;

	/* Initalise the super class. */
	rc = dl_segment_new(&seg, seg_desc->dlsd_base_offset,
	    seg_desc->dlsd_seg_size,
	    dl_kernel_segment_insert_message,
	    dl_kernel_segment_get_message_by_offset,
	    dl_kernel_get_offset,
	    dl_kernel_segment_lock,
	    dl_kernel_segment_unlock,
	    dl_kernel_segment_delete);
	if (rc != 0) {

		return -1;
	}
	
	kseg = seg->dls_kernel = (struct dl_kernel_segment *) dlog_alloc(
	    sizeof(struct dl_kernel_segment));
	DL_ASSERT(kseg != NULL, ("Failed allocating segment instance"));
	DLOGTR0(PRIO_HIGH, "Zeroing segment instance");
	bzero(kseg, sizeof(struct dl_kernel_segment));

	kseg->offset = seg_desc->dlsd_offset;

	//kseg->ucred = td->td_ucred;
	fget_write(td, seg_desc->dlsd_log,
	    cap_rights_init(&rights, CAP_WRITE), &kseg->_log); 

	/* Check that it is a regular file. */
	if (kseg->_log->f_type != DTYPE_VNODE) {

		return -1;
	}

	/* Check that the vnode is non-NULL */
	vp = kseg->_log->f_vnode;
	if (vp->v_type != VREG) {

		return -1;
	}

	sx_init(&kseg->dls_lock, "segment mtx");

	dl_kernel_segment_check_integrity(kseg);
	*self = seg;
	return 0;
}

static int
dl_kernel_segment_insert_message(struct dl_segment *self,
    struct dl_bbuf *buffer)
{
	struct mount *mp;
	struct thread *td = curthread;
	struct uio u;
	struct iovec log_bufs[2];
	struct dl_bbuf *metadata;
	struct vnode *vp;
	struct dl_kernel_segment *kseg = self->dls_kernel;
	int rc;

	dl_kernel_segment_check_integrity(self->dls_kernel);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	dl_kernel_segment_lock(self);

	/* Update the log file. */
	dl_bbuf_new(&metadata, NULL, sizeof(uint32_t),
	    DL_BBUF_AUTOEXTEND|DL_BBUF_BIGENDIAN);
	dl_bbuf_put_int32(metadata, self->dls_kernel->offset);

	log_bufs[0].iov_base = dl_bbuf_data(metadata);
	log_bufs[0].iov_len = dl_bbuf_pos(metadata);
	
	log_bufs[1].iov_base = dl_bbuf_data(buffer);
	log_bufs[1].iov_len = dl_bbuf_pos(buffer);

	bzero(&u, sizeof(struct uio));
	u.uio_iov = log_bufs;
	u.uio_iovcnt = 2;
	u.uio_offset = -1;
        u.uio_resid = log_bufs[0].iov_len + log_bufs[1].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	/* Check that the vnode is non-NULL */
	vp = kseg->_log->f_vnode;
	if (vp->v_type != VREG) {

		return -1;
	}

	vn_start_write(vp, &mp, V_WAIT);
	VOP_LOCK(vp, LK_EXCLUSIVE | LK_RETRY);
	VOP_WRITE(vp, &u, IO_UNIT | IO_APPEND, self->dls_kernel->_log->f_cred);
	VOP_UNLOCK(vp, 0);
	vn_finished_write(mp);

	/* Delete the buffer holding the log metadata */
	dl_bbuf_delete(metadata);

	/* Update the offset. */
	self->dls_kernel->offset++;

	dl_kernel_segment_unlock(self);
	return 0;
}

static int
dl_kernel_segment_get_message_by_offset(struct dl_segment *self, int offset,
    struct dl_bbuf **msg_buf)
{
	/* Unimplemented. */
	return -1;
}

static void
dl_kernel_segment_lock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_kernel_segment_check_integrity(self->dls_kernel);
	sx_slock(&self->dls_kernel->dls_lock);
}

static void
dl_kernel_segment_unlock(struct dl_segment *self) __attribute((no_thread_safety_analysis))
{

	dl_kernel_segment_check_integrity(self->dls_kernel);
	sx_sunlock(&self->dls_kernel->dls_lock);
}

static uint32_t 
dl_kernel_get_offset(struct dl_segment *self)
{

	dl_kernel_segment_check_integrity(self->dls_kernel);
	return self->dls_kernel->offset;
}

struct file*
dl_kernel_segment_get_log(struct dl_segment *self)
{

	dl_kernel_segment_check_integrity(self->dls_kernel);
	return self->dls_kernel->_log;
}

int
dl_kernel_segment_sync(struct dl_segment *self)
{
	struct dl_kernel_segment *kseg = self->dls_kernel;
	struct mount *mp;
	struct vnode *vp;
	int rc;

	dl_kernel_segment_check_integrity(kseg);

	/* Check that the vnode is non-NULL */
	vp = kseg->_log->f_vnode;
	if (vp->v_type != VREG) {

		return -1;
	}

	rc = vn_start_write(vp, &mp, V_WAIT);
	if (rc == 0) {

		VOP_LOCK(vp, LK_EXCLUSIVE | LK_RETRY);
		VOP_FSYNC(vp, MNT_WAIT, curthread);
		VOP_UNLOCK(vp, 0);
		vn_finished_write(mp);
		return 0;
	}

	return -1;
}

