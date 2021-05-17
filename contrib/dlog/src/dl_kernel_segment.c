/*-
 * Copyright (c) 2018-2019 (Graeme Jenkinson)
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
#include <sys/libkern.h>
#include <sys/uio.h>
#include <sys/syscallsubr.h>
#include <sys/vnode.h>
#include <sys/unistd.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/fcntl.h>
#include <sys/namei.h>
#include <sys/stat.h>
#include <sys/proc.h>

#include "dl_assert.h"
#include "dl_kernel_segment.h"
#include "dl_memory.h"
#include "dl_primitive_types.h"
#include "dl_segment.h"
#include "dl_utils.h"

/**
 * Class representing a segment of the Log file.
 */
struct dl_kernel_segment {
	struct dl_segment dlks_segment; /* Segment superclass */
	struct mtx dlks_mtx; /* Lock for whilst updating segment */
	struct vnode *dlks_vp;
	char dlks_base_name[MAXPATHLEN];
	uint64_t dlks_max_size;
	uint32_t dlks_offset;
};

static int dl_kernel_segment_ctor(void *, va_list *);
static void dl_kernel_segment_dtor(void *);

static int dlks_insert_message(struct dl_segment *, struct dl_bbuf *);
static int dlks_get_message_by_offset(struct dl_segment *, int,
    struct dl_bbuf **);
static uint32_t dlks_get_offset(struct dl_segment *);
static int dlks_sync(struct dl_segment *);

extern const void *DL_SEGMENT;

static const struct dl_segment_class TYPE = {
	{
		sizeof(struct dl_kernel_segment),
		dl_kernel_segment_ctor,
		dl_kernel_segment_dtor,
		NULL	
	},
	dlks_get_message_by_offset,
	dlks_insert_message,
	dlks_sync,
	dlks_get_offset
};

static const void *DL_KERNEL_SEGMENT = &TYPE;

/**
 * Check the integrity of a KernelSegment instance.
 *
 * @param self KernelSegment instance.
 */
static inline void
assert_integrity(struct dl_kernel_segment *self)
{

	DL_ASSERT(self != NULL, ("KernelSegment instance cannot be NULL"));
	DL_ASSERT(self->dlks_vp != NULL, ("KernelSegment vnode cannot be NULL"));
}

static int
create_segment_file(struct vnode **vp, char *base_name, uint64_t base_offset)
{
	struct nameidata nd;
	struct sbuf sb;
	struct thread *td = curthread;
	struct vattr vattr;
	int cmode, error, flags, oflags;
	char *name;

	/* Allocate a buffer for the Segment filepath.
	 * The formatted filepath is written into the allocated buffer
	 * using an sbuf().
	 */
	name = malloc(MAXPATHLEN, M_TEMP, M_WAITOK | M_ZERO);
	DL_ASSERT(name != NULL, ("Allocating temp buffer for filepath failed"));
	     
	(void) sbuf_new(&sb, name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, "%s/%.*ld.log", base_name, DL_LOG_DIGITS, base_offset);
	if (sbuf_error(&sb) != 0) {

		DLOGTR0(PRIO_HIGH,
		    "Failed formatting the KernelSegment filepath\n");
		sbuf_finish(&sb);
		sbuf_delete(&sb);
		free(name, M_TEMP);
		return -1;
	}

	sbuf_finish(&sb);
	sbuf_delete(&sb);

	/* Create the KernelSegment file */
	cmode = S_IRUSR | S_IWUSR;
	oflags = VN_OPEN_NOAUDIT | VN_OPEN_NAMECACHE;
	flags = O_CREAT | FWRITE | O_NOFOLLOW;

	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, name, td);
	error = vn_open_cred(&nd, &flags, cmode, oflags, td->td_ucred, NULL);
	if (error != 0) {

		DLOGTR1(PRIO_HIGH,
		    "Error creating KernelSegment file name  %s\n",
		    name);
		NDFREE(&nd, NDF_ONLY_PNBUF);
		free(name, M_TEMP);
		return -1;
	}

	*vp = nd.ni_vp;

	NDFREE(&nd, NDF_ONLY_PNBUF);
	free(name, M_TEMP);

	/* Check that the vnode is a regular file and that
	 * it doesn't posses links.
	 */
	if ((*vp)->v_type != VREG ||
	    VOP_GETATTR(*vp, &vattr, td->td_ucred) != 0 ||
	    vattr.va_nlink != 1 ||
	    ((*vp)->v_vflag & VV_SYSTEM) != 0) {

		DLOGTR0(PRIO_HIGH,
		    "KernelSegment vnode is NULL or not a regular file\n");
		VOP_UNLOCK(*vp, 0);
		return -1;
	}

	VOP_UNLOCK(*vp, 0);
	return 0;
}

static int
dl_kernel_segment_ctor(void *_super, va_list *ap)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) _super;
	struct dl_segment *super = (struct dl_segment *) _super;
	struct nameidata path_nd, base_nd;
	struct sbuf sb;
	struct thread *td = curthread;
	struct vattr vattr;
	struct vnode *base_vp, *vp;
	char *path, *base_name, *topic_name;
	int rc;

	DL_ASSERT(self != NULL, ("KernelSegment instance cannot be NULL"));

	/* Initialize the KernelSegment super class */
	if (((const struct dl_class *) DL_SEGMENT)->dl_ctor != NULL)
		((const struct dl_class *) DL_SEGMENT)->dl_ctor(self, ap);
	
	/* Extract the constructor arguments. */
	path = va_arg(*ap, char *);
	DL_ASSERT(path != NULL, ("KernelSegment path cannot be NULL"));
	topic_name = va_arg(*ap, char *);
	DL_ASSERT(topic_name != NULL, ("KernelSegment topic name cannot be NULL"));
	self->dlks_max_size = va_arg(*ap, uint64_t); 
	self->dlks_offset = va_arg(*ap, uint32_t);

	/* Create the directory for the KernelSegment file (
	 * if not already present).
	 */
	NDINIT(&path_nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, path, td);
	if (namei(&path_nd) == -1 || path_nd.ni_vp == NULL) {

		DLOGTR1(PRIO_HIGH,
		    "Failed KernelSegment file path is invalid: %s\n", path);
		NDFREE(&path_nd, NDF_ONLY_PNBUF);
		goto err_kseg_ctor;
	}
	NDFREE(&path_nd, NDF_ONLY_PNBUF);

	(void) sbuf_new(&sb, self->dlks_base_name, MAXPATHLEN, SBUF_FIXEDLEN);
	sbuf_printf(&sb, "%s/%s", path, topic_name);
	if (sbuf_error(&sb) != 0) {

		DLOGTR0(PRIO_HIGH,
		    "Failed formatting the KernelSegment filepath\n");
		sbuf_finish(&sb);
		sbuf_delete(&sb);
		goto err_kseg_ctor;
	}

	sbuf_finish(&sb);
	sbuf_delete(&sb);
	
	struct nameidata nd;
	NDINIT(&nd, LOOKUP, NOFOLLOW, UIO_SYSSPACE, self->dlks_base_name, td);
	if (namei(&nd) != 0) {	

		if (kern_mkdirat(td, 0, self->dlks_base_name, UIO_SYSSPACE,
		    S_IRUSR | S_IWUSR) != 0) {


			DLOGTR1(PRIO_HIGH,
			    "Failed KernelSegment file path is invalid: %s\n", path);
			goto err_kseg_ctor;
		}
	}
	NDFREE(&nd, NDF_ONLY_PNBUF);
	vrele(nd.ni_vp);

	/* Create the KernelSegment file. */
	rc = create_segment_file(&self->dlks_vp, self->dlks_base_name,
	    super->dls_base_offset);
	if (rc != 0) {

		DLOGTR0(PRIO_HIGH, "Failed creating KernelSegment file\n");
		goto err_kseg_ctor;
	}

	/* Initialize mutex used to atomically write to the 
	 * log and update to offset.
	 */
	mtx_init(&self->dlks_mtx, NULL, "KernelSegment", MTX_DEF);

	assert_integrity(self);
	return 0;

err_kseg_ctor:
	DLOGTR0(PRIO_HIGH, "Failed constructing KernelSegment instance\n");

	return -1;
}

static void 
dl_kernel_segment_dtor(void *_super)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) _super;
	struct thread *td = curthread;

	assert_integrity(self);

	/* Destroy the KernelSegment super class */
	if (((const struct dl_class *) DL_SEGMENT)->dl_dtor != NULL)
		((const struct dl_class *) DL_SEGMENT)->dl_dtor(_super);

	/* Destroy the Mutex protecting the Segment */
	mtx_destroy(&self->dlks_mtx);

	/* Decrease the reference count on the file and close the vnode(). */
	vn_close(self->dlks_vp, FWRITE, td->td_ucred, td);
}

/**
 * KernelSegment destructor.
 *
 * @param self KernelSegment instance.
 */
void
dl_kernel_segment_delete(struct dl_kernel_segment *self)
{

	assert_integrity(self);
	dl_delete(self);
}

/**
 * Static factory methof for constructing a KernelSegment from a SegmentDescription.
 *
 * @param self KernelSegment instance.
 * @param seg_desc KernelSegment instance.
 * @return 0 is successful, -1 otherwise
 */
int
dl_kernel_segment_from_desc(struct dl_kernel_segment **self,
    char *path, char *topic_name, uint64_t max_seg_size,
    struct dl_segment_desc *seg_desc)
{

	DL_ASSERT(self != NULL, ("Segment instance cannot be NULL"));	
	DL_ASSERT(seg_desc != NULL, ("SegmentDesc instance cannot be NULL"));	

	return dl_new((void **) self, DL_KERNEL_SEGMENT,
	    seg_desc->dlsd_base_offset, path, topic_name,
	    max_seg_size, seg_desc->dlsd_offset);
}

static int
dlks_insert_message(struct dl_segment *super, struct dl_bbuf *buffer)
{
	struct mount *mp;
	struct thread *td = curthread;
	struct uio u;
	struct iovec log_bufs[1];
	struct vattr vattr;
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;
	int rc;

	assert_integrity(self);
	DL_ASSERT(buffer != NULL,
	    ("Buffer to insert into segment cannot be NULL."));

	/* Update the log file. */
	log_bufs[0].iov_base = dl_bbuf_data(buffer);
	log_bufs[0].iov_len = dl_bbuf_pos(buffer);

	bzero(&u, sizeof(struct uio));
	u.uio_iov = log_bufs;
	u.uio_iovcnt = 1;
	u.uio_offset = 0;
        u.uio_resid = log_bufs[0].iov_len;
        u.uio_segflg  = UIO_SYSSPACE;
        u.uio_rw = UIO_WRITE;
        u.uio_td = td;

	/* Ensure the write to the file and increment of the offset are performed
	 * atomically.
	 */
	mtx_lock(&self->dlks_mtx);

	/* Write to the vnode.
	 * Assume that each operation is successfull as there is very little
	 * error recovery that can be done should an individual operation fail.
	 */
	rc = vn_start_write(self->dlks_vp, &mp, V_WAIT);
	rc |= VOP_LOCK(self->dlks_vp, LK_EXCLUSIVE | LK_RETRY);
	rc |= VOP_WRITE(self->dlks_vp, &u, IO_UNIT | IO_APPEND, td->td_ucred);
	VOP_GETATTR(self->dlks_vp, &vattr, td->td_ucred);
	rc |= VOP_UNLOCK(self->dlks_vp, 0);
	vn_finished_write(mp);

	if (rc == 0) {

		/* Update the offset. */
		self->dlks_offset++;
	}

	/* Check with the Kernel segment file should be rotated */
	if (vattr.va_size > self->dlks_max_size) {

		struct vnode *vp;
		int rc;

		rc = create_segment_file(&vp, self->dlks_base_name,
		    self->dlks_offset);
		if (rc != 0) {

			DLOGTR0(PRIO_HIGH, "Failed creating KernelSegment file\n");
			mtx_unlock(&self->dlks_mtx);
			return rc;
		}

		dl_segment_set_base_offset((struct dl_segment *) self,
		    self->dlks_offset);

		/* Decrease the reference count on the file and close the
		 * vnode().
		 */
		vn_close(self->dlks_vp, FWRITE, td->td_ucred, td);

		/* Update the KernelSegment vnode */
		self->dlks_vp = vp;
	}

	mtx_unlock(&self->dlks_mtx);

	return rc;
}

static int
dlks_get_message_by_offset(struct dl_segment *super, int offset,
    struct dl_bbuf **msg_buf)
{
	/* Unimplemented. */
	return -1;
}

static uint32_t 
dlks_get_offset(struct dl_segment *super)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;

	assert_integrity(self);
	return self->dlks_offset;
}

/**
 * Method for syncing the KernelSegment vnode.
 	
* @param self KernelSegment instance.
 * @return 0 is success, otherwise an error code
 */
static int
dlks_sync(struct dl_segment *super)
{
	struct dl_kernel_segment *self = (struct dl_kernel_segment *) super;
	struct mount *mp;
	int rc;

	assert_integrity(self);

	/* Sync the vnode.
	 * Assume that each operation is successfull as there is very little
	 * error recovery that can be done should an individual operation fail.
	 */
	rc = vn_start_write(self->dlks_vp, &mp, V_WAIT);
	rc |= VOP_LOCK(self->dlks_vp, LK_EXCLUSIVE | LK_RETRY);
	rc |= VOP_FSYNC(self->dlks_vp, MNT_WAIT, curthread);
	rc |= VOP_UNLOCK(self->dlks_vp, 0);
	vn_finished_write(mp);

	return rc;
}
