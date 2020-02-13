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
#include <sys/sysctl.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/kthread.h>

#include "dlog.h"

#include "dl_assert.h"
#include "dl_config.h"
#include "dl_memory.h"
#include "dl_topic.h"
#include "dl_utils.h"
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

static struct cdevsw topic_cdevsw = {
	.d_version = D_VERSION,
	.d_open = dlog_open,
	.d_close = dlog_close,
	.d_ioctl = dlog_ioctl,
	.d_read = dlog_read,
	.d_name = DLOG_NAME,
};
static struct cdev *topic_dev;

static struct proc *dlog_client_proc;

static struct mtx dlog_mtx;
static struct cv dlog_cv;
static int dlog_exit = 0;

static eventhandler_tag dlog_pre_sync = NULL;

static struct sysctl_ctx_list clist;
static struct sysctl_oid *dlog_oipd;

struct dl_topic_hashmap *topic_hashmap;

static void
dlog_sync_topic(struct dl_topic *topic, void *arg __attribute((unused)))
{
	struct dl_segment *s;

	DL_ASSERT(topic != NULL, ("Topic instance cannot be NULL."));

	s = dl_topic_get_active_segment(topic);
	DL_ASSERT(s != NULL, ("Segment instance cannot be NULL."));
	if (dl_segment_sync(s) != 0) {

		DLOGTR1(PRIO_NORMAL, "Failed syncing topic %s\n",
		    dl_topic_get_name(topic));
	}
}

static void
dlog_topic_to_desc(struct dl_topic *topic, void *arg)
{
	struct dl_topic_desc **pdesc = (struct dl_topic_desc **) arg;
	struct dl_topic_desc *desc = *pdesc, *tmp;
	int rc;

	DL_ASSERT(desc == 0, ("Topic desc cannot be NULL"));

	rc = dl_topic_as_desc(topic, &tmp);
	DL_ASSERT(rc == 0, ("Failed coverting Topic to description"));
	if (rc == 0) {

		/* Copy the Topic description into the output. */
		bcopy(tmp, desc, sizeof(struct dl_topic_desc));
		dlog_free(tmp);

		/* Advance the output pointer. */
		++(*pdesc);
	}
}

static void
dlog_topic_count(struct dl_topic *topic, void *arg)
{
	size_t *count = (size_t *)arg;
			
	/* Increment the count of topics.*/	
	*count = *count + 1;
}

static int 
dlog_init()
{
	struct make_dev_args dlog_args;
	int rc, e;

	/* Allocate the topic hashmap. */
	rc = dl_topic_hashmap_new(&topic_hashmap, 10);
	DL_ASSERT(rc == 0, ("DLog failed instiating new topic hashmap."));
	if (rc != 0)
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
	struct dl_kernel_segment *s;
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
	rc = tsleep(dlog_client_proc, 0, "DLog terminating...", 60 * hz / 9);
	DL_ASSERT(rc == 0, ("Failed to stop %s process.", DLOG_NAME));

	DLOGTR1(PRIO_NORMAL, "%s process stopped successfully\n", DLOG_NAME);
	cv_destroy(&dlog_cv);
	mtx_destroy(&dlog_mtx);

	/* Sync all the topics. */ 
	dl_topic_hashmap_foreach(topic_hashmap, dlog_sync_topic, NULL);

	/* Delete all the topics. */
	dl_topic_hashmap_clear(topic_hashmap);

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

		sysctl_ctx_init(&clist);
		dlog_oipd = SYSCTL_ADD_ROOT_NODE(&clist, OID_AUTO, DLOG_NAME,
		    CTLFLAG_RW, 0, "Distributed log (dlog)");

		if (dlog_init() != 0)
			e = EFAULT;
		break;
	case MOD_UNLOAD:
		DLOGTR0(PRIO_LOW, "Unloading DLog kernel module\n");

		dlog_fini();
		sysctl_ctx_free(&clist);
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

	switch(cmd) {
	case DLOGIOC_ADDTOPICPART: {
		struct dl_kernel_segment *kseg;
		struct dl_topic *topic;
		struct dl_topic_desc **pdesc =
		    (struct dl_topic_desc **) addr;
		struct dl_topic_desc desc;	
		nvlist_t *props;
		void *packed_nvlist;
		char *path;
		uint64_t max_seg_size;

		/* Copyin the description of the new topic. */
		if (copyin((void *) *pdesc, &desc, sizeof(desc)) != 0)
			return EFAULT; 
	
		packed_nvlist = dlog_alloc(desc.dltd_conf.dlcc_packed_nvlist_len);
		DL_ASSERT(packed_nvlist != NULL,
		    ("Failed allocating memory for the nvlist.")); 

		if (copyin(desc.dltd_conf.dlcc_packed_nvlist, packed_nvlist,
		    desc.dltd_conf.dlcc_packed_nvlist_len) != 0) {

			dlog_free(packed_nvlist);
			DLOGTR0(PRIO_HIGH,
			    "Failed copying in Producer properties\n");
			return EFAULT; 
		}

		/* Check for an invalid topic name. */	
		if (!dl_topic_validate_name(desc.dltd_name))
			return EINVAL;

		if (dl_topic_hashmap_contains_key(topic_hashmap, desc.dltd_name))
			return EFAULT;

		/* Unpack the nvlist of properties used for configuring the
		 * DLog client instance.
		 */
		props = nvlist_unpack(packed_nvlist,
		    desc.dltd_conf.dlcc_packed_nvlist_len, 0); 
		dlog_free(packed_nvlist);
		if (props == NULL) {
			DLOGTR0(PRIO_HIGH,
			    "Failed creating Topic properties\n");
			return EFAULT;
		}
	
		/* Extract the log path from the properties */
		path = dnvlist_get_string(props,
	    		DL_CONF_LOG_PATH, DL_DEFAULT_LOG_PATH);

		/* Extract the maximum log segment size from the properties */
		max_seg_size = dnvlist_get_number(props,
	    		DL_CONF_MAX_SEGMENT_SIZE,
			DL_DEFAULT_MAX_SEGMENT_SIZE);
	
		/* Construct the new segment and add to the topic. */
		if (dl_kernel_segment_from_desc(&kseg,
		    path, desc.dltd_name, max_seg_size,
		    &desc.dltd_active_seg) == 0) {

			if (dl_topic_new(&topic, desc.dltd_name,
			    props, (struct dl_segment *) kseg) == 0) {

				if (dl_topic_hashmap_put_if_absent(
				    topic_hashmap, desc.dltd_name,
				    topic) == 0) {

					DLOGTR1(PRIO_LOW,
					    "Added new Topic/Partition: %s\n",
		    			    desc.dltd_name);
				} else {

					DLOGTR0(PRIO_HIGH,
					    "Failed adding topic to hashmap\n");
					dl_topic_delete(topic);
					dl_kernel_segment_delete(kseg);
					return EFAULT;
				}	
			} else {
				DLOGTR0(PRIO_HIGH,
				    "Failed creating topic instance\n");
				dl_kernel_segment_delete(kseg);
				/* Free the nvlist that stores the configuration properties */
				nvlist_destroy(props);
				return EFAULT;
			}
		} else {

			DLOGTR0(PRIO_HIGH, "Failed creating segment\n");
			/* Free the nvlist that stores the configuration properties */
			nvlist_destroy(props);
			return EFAULT;
		}

		return 0;
	}
	case DLOGIOC_DELTOPICPART: {
		struct dl_topic_desc **pdesc =
		    (struct dl_topic_desc **) addr;
		struct dl_topic_desc desc;	

		/* Copyin the description of the new topic. */
		if (copyin((void *) *pdesc, &desc, sizeof(desc)) != 0)
			return EFAULT; 
	
		/* Check for an invalid topic name. */	
		if (!dl_topic_validate_name(desc.dltd_name))
			return EINVAL;
	
		/* Delete the topic. */	
		if (dl_topic_hashmap_remove(topic_hashmap,
		    desc.dltd_name) == -1) {

			DLOGTR1(PRIO_NORMAL,
			    "Failed deleting Topic/Partition %s (not found)\n",
		    	    desc.dltd_name);
		} else {

			DLOGTR1(PRIO_LOW, "Deleted Topic/Partition: %s\n",
		    	    desc.dltd_name);
		}

		return 0;
	}
	case DLOGIOC_GETTOPICS: {
		struct dl_topics_desc **pdesc =
		    (struct dl_topics_desc **) addr;
		struct dl_topics_desc desc, *tmp_desc;
		struct dl_topic_desc *tmp;
		size_t ntopics, count = 0;

		/* Copyin the description of the new topic. */
		if (copyin((void *) *pdesc, &desc, sizeof(desc)) != 0)
			return EFAULT; 

		ntopics = desc.dltsd_ntopics;
		DLOGTR1(PRIO_LOW, "Getting %zu Topic(s)\n", ntopics);

		/* Return a topic description for each topic in the hashmap. */ 
		dl_topic_hashmap_foreach(topic_hashmap, dlog_topic_count,
		    &count);
			
		DLOGTR1(PRIO_LOW, "No. of Topic/Partitions = %zu\n", count);

		/* Allocate a temporary TopicsDesc instance capable of
		 * holding all descriptions of all of the topics.
		 */
		tmp_desc = (struct dl_topics_desc *) dlog_alloc(
		    sizeof(struct dl_topics_desc) +
		    (count * sizeof(struct dl_topic_desc)));
		DL_ASSERT(desc != NULL,
		    ("Failed to allocate temporary TopicsDesc instance"));

		/* Copy the description of each topic into the allocated
		 * TopicsDesc.
		 */
		tmp = tmp_desc->dltsd_topic_desc;
		dl_topic_hashmap_foreach(topic_hashmap, dlog_topic_to_desc,
		    &tmp);
		
		/* Return the smallest of the request number of topics and
		 * the actual number of topics.
		 */
		tmp_desc->dltsd_ntopics = count < ntopics ? count : ntopics;

		/* Copyout the description of the Topics. */
		if (copyout(tmp_desc, (void *) *pdesc,
		    sizeof(struct dl_topics_desc) +
		    (tmp_desc->dltsd_ntopics * sizeof(struct dl_topic_desc))) != 0) {

			dlog_free(tmp_desc);
			return EFAULT; 
		}

		dlog_free(tmp_desc);
		return 0;
	}
	case DLOGIOC_PRODUCER: {
		struct dl_client_config_desc desc;
		struct dl_client_config_desc **pdesc =
		    (struct dl_client_config_desc **) addr;
		struct dlog_handle *handle;
		nvlist_t *props;
		void *packed_nvlist;

		/* Copyin the description of the client configuration. */
		if (copyin((void *) *pdesc, &desc, sizeof(desc)) != 0)
			return EFAULT; 

		DLOGTR0(PRIO_LOW, "Configuring DLog producer.\n");

		packed_nvlist = dlog_alloc(desc.dlcc_packed_nvlist_len);
		DL_ASSERT(packed_nvlist != NULL,
		    ("Failed allocating memory for the nvlist.")); 

		if (copyin(desc.dlcc_packed_nvlist, packed_nvlist,
		    desc.dlcc_packed_nvlist_len) != 0) {

			dlog_free(packed_nvlist);
			DLOGTR0(PRIO_HIGH,
			    "Failed copying in Producer properties\n");
			return EFAULT; 
		}

		/* Unpack the nvlist of properties used for configuring the
		 * DLog client instance.
		 */
		props = nvlist_unpack(packed_nvlist,
		    desc.dlcc_packed_nvlist_len, 0); 
		dlog_free(packed_nvlist);
		if (props == NULL) {
			DLOGTR0(PRIO_HIGH,
			    "Failed creating Producer properties\n");
			return EFAULT;
		}

		/* Open the DLog client with the specified properties. */
		if (dlog_client_open(&handle, props) != 0) {

			DLOGTR0(PRIO_HIGH, "Error opening Dlog client.\n");
			return EFAULT;
		}

		/* Free the nvlist that stores the configuration properties */
		nvlist_destroy(props);

		/* Associate the the DLog client handle with the device file. */
		if (devfs_set_cdevpriv(handle, dl_client_close) != 0) {

			DLOGTR0(PRIO_HIGH,
			    "Error associating the DLog client handle.\n");
			dlog_client_close(handle);
			return EFAULT;
		}

		return 0;
	}
	default:
		return ENOTTY;
	}
}

static void
dl_client_close(void *arg)
{
	struct dlog_handle *handle = (struct dlog_handle *) arg;

	DLOGTR0(PRIO_LOW, "Closing DLog producer.\n");
	dlog_client_close(handle);
}


DEV_MODULE(dlog, dlog_event_handler, NULL);
MODULE_VERSION(dlog, 1);
