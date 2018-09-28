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
#include <sys/systm.h>
#include <sys/module.h>
#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/malloc.h>
#include <sys/ioccom.h>
#include <sys/stat.h>
#include <sys/eventhandler.h>
#include <sys/mount.h>
#include <sys/vnode.h>

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_topic.h"
#include "dl_utils.h"
#include "dlog.h"
#include "dlog_client.h"
#include "dl_kernel_segment.h"

MALLOC_DECLARE(M_DLOG);
MALLOC_DEFINE(M_DLOG, "dlog", "DLog memory");

extern uint32_t hashlittle(const void *, size_t, uint32_t);

static int dlog_init(void);
static void dlog_fini(void);
static void dlog_sync(void);

static void dl_client_close(void *);
static int dlog_event_handler(struct module *, int, void *);
static void dlog_main(void *argp);

static inline void *
dl_alloc(unsigned long len)
{

	return malloc(len, M_DLOG, M_NOWAIT);
}
	
static inline void
dl_free(void *addr)
{

	return free(addr, M_DLOG);
}

static char const * const DLOG_NAME = "dlog";

const dlog_malloc_func dlog_alloc = dl_alloc;
const dlog_free_func dlog_free = dl_free;

static d_open_t dlog_open;
static d_close_t dlog_close;
static d_read_t dlog_read;
static d_ioctl_t dlog_ioctl;

static struct cdevsw dlog_cdevsw = {
	.d_version = D_VERSION,
	.d_open = dlog_open,
	.d_close = dlog_close,
	.d_ioctl = dlog_ioctl,
	.d_read = dlog_read,
	.d_name = DLOG_NAME,
};
static struct cdev *dlog_dev;

static struct proc *dlog_client_proc;

static struct mtx dlog_mtx;
static struct cv dlog_cv;
static int dlog_exit = 0;

static eventhandler_tag dlog_pre_sync = NULL;

static int 
dlog_init()
{
	struct make_dev_args dlog_args;
	int rc, e;

	/* Allocate the topic hashmap. */
	topic_hashmap = dl_topic_hashmap_new(10, &topic_hashmask);
	DL_ASSERT(topic_hashmap != NULL,
	    ("DLog failed instiating new topic hashmap."));
	if (topic_hashmap == NULL)
		return -1;

	mtx_init(&dlog_mtx, "dlog mtx", DLOG_NAME, MTX_DEF);
	mtx_assert(&dlog_mtx, MA_NOTOWNED);

	cv_init(&dlog_cv, "dlog cv");

	/* Create a kernel process, each topic creates threads 
	 * within this process.
	 */
	rc = kproc_create(dlog_main, NULL, &dlog_client_proc, 0, 0,
	    DLOG_NAME);
	DL_ASSERT(rc == 0, ("DLog kproc_create failed %d", rc));
	if (rc != 0) {

		dl_topic_hashmap_delete(topic_hashmap);
		cv_destroy(&dlog_cv);
		mtx_destroy(&dlog_mtx);
		return -1;
	}

	make_dev_args_init(&dlog_args);
	dlog_args.mda_flags = MAKEDEV_CHECKNAME | MAKEDEV_WAITOK;
	dlog_args.mda_devsw = &dlog_cdevsw;
	dlog_args.mda_uid = UID_ROOT;
	dlog_args.mda_gid = GID_WHEEL;
	dlog_args.mda_mode = S_IRUSR | S_IWUSR;

	e = make_dev_s(&dlog_args, &dlog_dev, DLOG_NAME);
	DL_ASSERT(e == 0, ("Failed to create dlog device"));
	if (e != 0) {

		dl_topic_hashmap_delete(topic_hashmap);
		cv_destroy(&dlog_cv);
		mtx_destroy(&dlog_mtx);
	}

	dlog_pre_sync = EVENTHANDLER_REGISTER(shutdown_pre_sync,
	    dlog_sync, NULL, SHUTDOWN_PRI_LAST);

	return e;
}

static void 
dlog_fini()
{

	DLOGTR1(PRIO_LOW, "Stoping %s process...\n", DLOG_NAME);

	if (dlog_pre_sync != NULL)	
	    EVENTHANDLER_DEREGISTER(shutdown_pre_sync, dlog_pre_sync);

	dlog_sync();
}

static void
dlog_sync(void)
{
	struct dl_segment *s;
	struct dl_topic *topic, *tmp;
	struct mount *mp;
	int t, rc, error;
	
	mtx_assert(&dlog_mtx, MA_NOTOWNED);
	mtx_lock(&dlog_mtx);
	dlog_exit = 1;
	mtx_assert(&dlog_mtx, MA_OWNED);
	mtx_unlock(&dlog_mtx);
	cv_broadcast(&dlog_cv);

	/* Attempt to stop the DLog process. */
	rc = tsleep(dlog_client_proc, 0, "DLog terminating...",
	    60 * hz / 9);
	DL_ASSERT(rc == 0, ("Failed to stop %s process.", DLOG_NAME));

	DLOGTR1(PRIO_NORMAL, "%s process stopped successfully\n",
	    DLOG_NAME);
	cv_destroy(&dlog_cv);
	mtx_destroy(&dlog_mtx);

	for (t = 0; t < topic_hashmask + 1 ; t++) {
		LIST_FOREACH_SAFE(topic, &topic_hashmap[t],
		    dlt_entries, tmp) {
/*
			s = dl_topic_get_active_segment(topic);

			error = vn_start_write(
			    dl_kernel_segment_get_log(s), &mp, V_WAIT);
			if (error == 0) {

				VOP_LOCK(dl_kernel_segment_get_log(s), LK_EXCLUSIVE | LK_RETRY);
				VOP_FSYNC(dl_kernel_segment_get_log(s), MNT_WAIT, curthread);
				VOP_UNLOCK(dl_kernel_segment_get_log(s), 0);
				vn_finished_write(mp);
			}
*/
			LIST_REMOVE(topic, dlt_entries);
			dl_topic_delete(topic);
		}
	}
	
	/* Delete the topic hash map. */
	dl_topic_hashmap_delete(topic_hashmap);

	destroy_dev(dlog_dev);
}

static int
dlog_event_handler(struct module *module, int event, void *arg)
{
	int e = 0;

	switch(event) {
	case MOD_LOAD:
		DLOGTR0(PRIO_LOW, "Loading DLog kernel module\n");

		if (dlog_init() != 0)
			e = EFAULT;
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading DLog kernel module\n");

		dlog_fini();
		break;
	default:
		e = EOPNOTSUPP;
		break;
	}

	return e;
}

static void
dlog_main(void *argp)
{

	for (;;) {
		mtx_assert(&dlog_mtx, MA_NOTOWNED);
		mtx_lock(&dlog_mtx);
		cv_timedwait(&dlog_cv, &dlog_mtx, 10 * hz / 9);
		if (dlog_exit == 1)  {
			mtx_assert(&dlog_mtx, MA_OWNED);
			mtx_unlock(&dlog_mtx);
	 		DLOGTR0(PRIO_HIGH, "Stopping DLog process..\n");
			break;
		}
		mtx_assert(&dlog_mtx, MA_OWNED);
		mtx_unlock(&dlog_mtx);
	}

	DLOGTR0(PRIO_LOW, "DLog process exited successfully.\n");
	kproc_exit(0);
}

static int 
dlog_open(struct cdev *dev, int oflags, int devtype, struct thread *td)
{

	DLOGTR1(PRIO_LOW, "Opening the %s device.\n", DLOG_NAME);
	return 0;
}

static int 
dlog_close(struct cdev *dev, int fflag, int devtype, struct thread *td)
{

	DLOGTR1(PRIO_LOW, "Closing the %s device.\n", DLOG_NAME);

	/* Clean up the associated private state (that is the DLog handle,
	 * if configured).
	 */
	devfs_clear_cdevpriv();
	return 0;	
}

static int 
dlog_read(struct cdev *dev, struct uio *uio, int flag)
{

	return 0;
}

static int 
dlog_ioctl(struct cdev *dev, u_long cmd, caddr_t addr, int flags,
    struct thread *td)
{
	struct dl_client_config *conf;
	struct dl_client_config_desc conf_desc;
	struct dl_client_config_desc **pconf_desc =
	    (struct dl_client_config_desc **) addr;
	struct dlog_handle *handle;
	nvlist_t *props;
	void *packed_nvlist;
	struct dl_topic_desc **ptp_desc =
	    (struct dl_topic_desc **) addr;
	struct dl_topic_desc tp_desc;	
	struct sbuf *tp_name;
	struct dl_topic *t, *t_tmp;
	uint32_t h;

	switch(cmd) {
	case DLOGIOC_ADDTOPICPART:
		DLOGTR0(PRIO_LOW, "Adding new Topic/Partition.\n");

		/* Copyin the description of the new topic. */
		if (copyin((void *) *ptp_desc, &tp_desc,
		    sizeof(struct dl_topic_desc)) != 0)
			return EFAULT; 
		
		if (tp_desc.dltd_name == NULL)
			return EINVAL;
	
		/* Copyin the topic name into a new sbuf. */	
		tp_name = sbuf_new_auto();
		DL_ASSERT(tp_name != NULL,
		    ("Failed creating sbuf instance.")); 
		if (sbuf_copyin(tp_name, tp_desc.dltd_name,
		    strlen(tp_desc.dltd_name)) == -1) {

			sbuf_delete(tp_name);
			return EFAULT;
		}
		sbuf_finish(tp_name);
		
		/* Lookup the topic in the topic hashmap. */
		h = hashlittle(sbuf_data(tp_name), sbuf_len(tp_name), 0);
		DLOGTR4(PRIO_LOW, "topic %s (%zu) hashes to %u (%zu)\n",
		    sbuf_data(tp_name), sbuf_len(tp_name), h,
		    h & topic_hashmask);

		LIST_FOREACH(t, &topic_hashmap[h & topic_hashmask],
		    dlt_entries) {
			if (strcmp(sbuf_data(tp_name),
			    sbuf_data(t->dlt_name)) == 0) {

				DLOGTR1(PRIO_HIGH,
				    "Topic %s is already present\n",
				    sbuf_data(tp_name));
				sbuf_delete(tp_name);
				return 0;
			}
		}

		/* Construct the new topic and add to the topic hashmap. */
		if (dl_topic_from_desc(&t, tp_name,
		    &tp_desc.dltd_active_seg) == 0) {

			LIST_INSERT_HEAD(&topic_hashmap[h & topic_hashmask], t,
			    dlt_entries); 
		} else {
			sbuf_delete(tp_name);
			return -1;
		}
		sbuf_delete(tp_name);

		break;
	case DLOGIOC_DELTOPICPART:
		DLOGTR0(PRIO_LOW, "Deleting Topic/Partition.\n");

		/* Copyin the description of the new topic. */
		if (copyin((void *) *ptp_desc, &tp_desc,
		    sizeof(struct dl_topic_desc)) != 0)
			return EFAULT; 
		
		if (tp_desc.dltd_name == NULL)
			return EINVAL;
	
		/* Copyin the topic name into a new sbuf. */	
		tp_name = sbuf_new_auto();
		DL_ASSERT(tp_name != NULL,
		    ("Failed creating sbuf instance.")); 
		if (sbuf_copyin(tp_name, tp_desc.dltd_name,
		    strlen(tp_desc.dltd_name)) == -1) {

			sbuf_delete(tp_name);
			return EFAULT;
		}
		sbuf_finish(tp_name);
		
		/* Lookup the topic in the topic hashmap. */
		h = hashlittle(sbuf_data(tp_name), sbuf_len(tp_name), 0);
		DLOGTR4(PRIO_LOW, "topic %s (%zu) hashes to %u (%zu)\n",
		    sbuf_data(tp_name), sbuf_len(tp_name), h,
		    h & topic_hashmask);

		LIST_FOREACH_SAFE(t, &topic_hashmap[h & topic_hashmask],
		    dlt_entries, t_tmp) {
			if (strcmp(sbuf_data(tp_name),
			    sbuf_data(t->dlt_name)) == 0) {

				DLOGTR1(PRIO_HIGH, "Topic %s found\n",
				    sbuf_data(tp_name));

				LIST_REMOVE(t, dlt_entries);
				dl_topic_delete(t);
				sbuf_delete(tp_name);
				return 0;
			}
		}
		
		DLOGTR1(PRIO_HIGH, "Topic %s not found\n",
		    sbuf_data(tp_name));
		sbuf_delete(tp_name);

		break;
	case DLOGIOC_PRODUCER:
		DLOGTR0(PRIO_LOW, "Configuring DLog producer.\n");

		/* Copyin the description of the client configuration. */
		if (copyin((void *) *pconf_desc, &conf_desc,
		    sizeof(struct dl_client_config_desc)) != 0)
			return EFAULT; 

		packed_nvlist = dlog_alloc(conf_desc.dlcc_packed_nvlist_len);
		DL_ASSERT(packed_nvlist != NULL,
		    ("Failed allocating memory for the nvlist.")); 

		if (copyin(conf_desc.dlcc_packed_nvlist, packed_nvlist,
		    conf_desc.dlcc_packed_nvlist_len) != 0)
			return EFAULT; 

		/* Unpack the nvlist of properties used for configuring the
		 * DLog client instance.
		 */
		props = nvlist_unpack(packed_nvlist,
		    conf_desc.dlcc_packed_nvlist_len, 0); 
		dlog_free(packed_nvlist);
		if (props == NULL)
			return EINVAL;

		/* Open the DLog client with the specified properties. */
		conf = (struct dl_client_config *) dlog_alloc(
		    sizeof(struct dl_client_config));
		DL_ASSERT(conf != NULL,
		    ("Failed allocating DLog client configuration."));
		conf->dlcc_on_response = conf_desc.dlcc_on_response;
		conf->dlcc_props = props;

		if (dlog_client_open(&handle, conf) != 0) {

			DLOGTR0(PRIO_HIGH, "Error opening Dlog client.\n");
			dlog_free(conf);
			return -1;
		}

		/* Associate the the DLog client handle with the device file. */
		if (devfs_set_cdevpriv(handle, dl_client_close) != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error associating the DLog client handle.\n");
			dlog_client_close(handle);
			dlog_free(conf);
			return -1;
		}
		break;
	default:
		return -1;
	}
	return 0;
}

static void
dl_client_close(void *arg)
{
	//struct dlog_handle *handle = (struct dlog_handle *) arg;

	//DL_ASSERT(handle != NULL, ("DLog client handle cannot be NULL."));

	DLOGTR0(PRIO_LOW, "Closing DLog producer.\n");
	//dlog_client_close(handle);
}


DEV_MODULE(dlog, dlog_event_handler, NULL);
MODULE_VERSION(dlog, 1);
