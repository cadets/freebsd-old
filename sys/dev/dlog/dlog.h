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

#ifndef _DLOG_H
#define _DLOG_H

#include <sys/types.h>
#include <sys/ioccom.h>

#define DL_MAX_TOPIC_NAME_LEN 249

struct dl_client_config_desc {
	void * dlcc_packed_nvlist;
	size_t dlcc_packed_nvlist_len;
};

struct dl_segment_desc {
	uint64_t dlsd_base_offset; /* Base offset of the segment. */
	uint32_t dlsd_offset; /* Offset within the segment. */
};

struct dl_topic_desc {
	struct dl_client_config_desc dltd_conf;
	struct dl_segment_desc dltd_active_seg;
	char dltd_name[DL_MAX_TOPIC_NAME_LEN]; /* Name of the topic. */
};

struct dl_topics_desc {
	size_t dltsd_ntopics;
	struct dl_topic_desc dltsd_topic_desc[1];
};

#define DLOGIOC_ADDTOPICPART _IOW('d', 1, struct dl_topic_desc *)
#define DLOGIOC_DELTOPICPART _IOW('d', 2, struct dl_topic_desc *)
#define DLOGIOC_GETTOPICS _IOWR('d', 3, struct dl_topics_desc *)
#define DLOGIOC_PRODUCER _IOW('d', 4, struct dl_client_config_desc *)

#endif
