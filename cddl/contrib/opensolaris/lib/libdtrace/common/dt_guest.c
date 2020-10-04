/*-
 * Copyright (c) 2020 (Mara Mihali)
 * All rights reserved.
 *
 * This software was developed by BAE Systems, the University of Cambridge
 * Computer Laboratory, and Memorial University under DARPA/AFRL contract
 * FA8650-15-C-7558 ("CADETS"), as part of the DARPA Transparent Computing
 * (TC) research program.
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
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/queue.h>

#include <dtrace.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <assert.h>
#ifdef illumos
#include <alloca.h>
#endif
#include <libgen.h>
#ifdef illumos
#include <libproc.h>
#endif
#ifdef __FreeBSD__
#include <spawn.h>
#endif

#include <libxo/xo.h>

#include <dt_impl.h>
#include <sys/time.h>

#define FRAGMENTSZ 32000

struct dtrace_guest_entry
{
    dtrace_bufdesc_t *desc;
    STAILQ_ENTRY(dtrace_guest_entry)
    entries;
} dtrace_guest_entry_t;

struct dtrace_guestq
{
    STAILQ_HEAD(, dtrace_guest_entry)
    head;
    pthread_mutex_t mtx;
};

extern int
dt_consume_cpu(dtrace_hdl_t *dtp, FILE *fp, int cpu,
               dtrace_bufdesc_t *buf, boolean_t just_one,
               dtrace_consumer_t *dc, void *arg);

static int dt_gtq_empty(struct dtrace_guestq *gtq)
{
	return (STAILQ_EMPTY(&gtq->head));
}

static void dt_gtq_enqueue(struct dtrace_guestq *gtq, struct dtrace_guest_entry *trc_entry)
{
	STAILQ_INSERT_TAIL(&gtq->head, trc_entry, entries);
}

static struct dtrace_guest_entry *dt_gtq_dequeue(struct dtrace_guestq *gtq)
{
	struct dtrace_guest_entry *trc_entry;
	trc_entry = STAILQ_FIRST(&gtq->head);
	if (trc_entry != NULL)
	{
		STAILQ_REMOVE_HEAD(&gtq->head, entries);
	}

	return (trc_entry);
}

static void *dt_send_script(void *file_path)
{

	FILE *fp, *writer_stream;
	char *d_script, *fifo;
	long file_size;
	int fd, sz;

	fifo = "/tmp/fifo";

	if ((fp = fopen((char *)file_path, "r")) == NULL)
	{
		printf("Error occudred while opening script file: %s\n", strerror(errno));
		exit(1);
	}

	if (fseek(fp, 0L, SEEK_END) == -1)
	{
		printf("Error occured in fseek: %s", strerror(errno));
		exit(1);
	}

	if ((file_size = ftell(fp)) == -1)
	{
		printf("Error occured in ftell: %s", strerror(errno));
		exit(1);
	}

	rewind(fp);

	d_script = malloc(file_size + 1);
	if ((fread(d_script, sizeof(char), file_size, fp)) != file_size)
	{
		printf("Error occured while reading script file: %s.\n", strerror(errno));
		exit(1);
	}
	fclose(fp);

	d_script[file_size] = '\0';
	if ((fd = open(fifo, O_WRONLY)) == -1)
	{
		printf("Error occured while opening fifo: %s\n", strerror(errno));
		exit(1);
	}

	if ((writer_stream = fdopen(fd, "w")) == NULL)
	{
		printf("Failed to open write stream: %s", strerror(errno));
		exit(1);
	}

	sz = fwrite(&file_size, sizeof(long), 1, writer_stream);
	if (sz <= 0)
	{
		printf("Failed to write size of script to the named pipe: %s", strerror(errno));
		exit(1);
	}

	if (fwrite(d_script, 1, file_size, writer_stream) != file_size)
	{
		if (ferror(writer_stream))
		{
			printf("Failed to write size of script to the named pipe: %s", strerror(errno));
			exit(1);
		}
	}

	fflush(writer_stream);

	free(d_script);
	close(fd);
	fclose(writer_stream);
}

static void dt_read_metadata(dtrace_hdl_t *dtp)
{
    	struct timeval ts1, ts2;
	dtrace_probedesc_t **pdescs;
	dtrace_eprobedesc_t **epdescs;
	dtrace_probedesc_t *probe;
	dtrace_eprobedesc_t *eprobe;
	FILE *fp;
	char *meta_fifo, *buf, *fmt, **formats;
	int fd, sz, nrecs = 0;
	size_t epbuf_sz = 0, fmt_len = 0;

	int maxformat, maxnpid, npdesc;

	meta_fifo = "/tmp/meta_fifo";
	int err = mkfifo(meta_fifo, 0666);
	if (err)
	{
		printf("Failed to mkfifo: %s", strerror(errno));
		exit(1);
	}

	if ((fd = open(meta_fifo, O_RDONLY)) == -1)
	{
		printf("Failed to open meta pipe for reading: %s. \n", strerror(errno));
		exit(1);
	}

	if ((fp = fdopen(fd, "r")) == NULL)
	{
		printf("Failed opening meta stream: %s. \n", strerror(errno));
		exit(1);
	}

	sz = fread(&maxformat, sizeof(int), 1, fp);
	assert(sz > 0);

	dtp->dt_maxformat = dtp->dt_maxstrdata = maxformat;

	if (maxformat > 0)
	{
		dtp->dt_formats = calloc(1, maxformat * sizeof(void *));
		assert(dtp->dt_formats != NULL);

		dtp->dt_strdata = calloc(1, maxformat * sizeof(char *));
		assert(dtp->dt_strdata != NULL);

		formats = calloc(1, maxformat * sizeof(char *));
		assert(formats != 0);

		for (int i = 0; i < maxformat; i++)
		{
			sz = fread(&fmt_len, sizeof(size_t), 1, fp);
			assert(sz > 0);
			fmt = calloc(1, sizeof(fmt_len + 1));
			sz = fread(fmt, 1, fmt_len, fp);
			assert(sz == fmt_len);
			formats[i] = fmt;
		}
	}

	sz = fread(&maxnpid, sizeof(int), 1, fp);
	assert(sz > 0);

	dtp->dt_maxprobe = maxnpid;
	dtp->dt_pdesc = calloc(1, maxnpid * sizeof(dtrace_probedesc_t *));
	assert(dtp->dt_pdesc != NULL);
	dtp->dt_edesc = calloc(1, maxnpid * sizeof(dtrace_eprobedesc_t *));
	assert(dtp->dt_edesc != NULL);

	sz = fread(&npdesc, sizeof(int), 1, fp);
	assert(sz > 0);
	printf("dtrace: script matched %d probes \n", npdesc);

	if (npdesc > 0)
	{

		for (int i = 0; i < npdesc; i++)
		{
			epbuf_sz = 0;
			probe = calloc(1, sizeof(dtrace_probedesc_t));
			assert(probe != NULL);

			sz = fread(probe, sizeof(dtrace_probedesc_t), 1, fp);
			assert(sz > 0);
			dtp->dt_pdesc[probe->dtpd_id] = probe;

			sz = fread(&epbuf_sz, sizeof(size_t), 1, fp);
			assert(sz > 0);

			eprobe = calloc(1, epbuf_sz);
			assert(eprobe != NULL);
			sz = fread(eprobe, 1, epbuf_sz, fp);
			assert(sz == epbuf_sz);
			dtp->dt_edesc[eprobe->dtepd_epid] = eprobe;

			if (maxformat > 0)
			{
				for (int i = 0; i < eprobe->dtepd_nrecs; i++)
				{
					dtrace_recdesc_t *rec = &eprobe->dtepd_rec[i];

					switch (rec->dtrd_action)
					{
					case DTRACEACT_DIFEXPR:
						dtp->dt_strdata[rec->dtrd_format - 1] =
							formats[rec->dtrd_format - 1];
						break;
					case DTRACEACT_PRINTA:
						dtp->dt_formats[rec->dtrd_format - 1] =
							dtrace_printa_create(dtp, formats[rec->dtrd_format - 1]);
						break;
					default:
						dtp->dt_formats[rec->dtrd_format - 1] = dtrace_printf_create(dtp, formats
																							  [rec->dtrd_format - 1]);
						break;
					}
				}
			}
		}
	}
	fclose(fp);
	close(fd);
}

static void dt_read_trace(void *xgtq)
{
    struct dtrace_guestq *gtq;
	struct dtrace_guest_entry *trc_entry;
	dtrace_bufdesc_t *buf;
	FILE *fp;
	char *trc_fifo;
	uint64_t size, chunk, sz;
	uintptr_t dest;

	int fd;

	trc_fifo = "/tmp/trace_fifo";
	gtq = (struct dtrace_guestq *)xgtq;

	int err = mkfifo(trc_fifo, 0666);
	if (err)
	{
		printf("Failed to mkfifo: %s", strerror(errno));
		exit(1);
	}

	if ((fd = open(trc_fifo, O_RDONLY)) == -1)
	{
		printf("Failed to open trace pipe for reading: %s. \n", strerror(errno));
		exit(1);
	}

	if ((fp = fdopen(fd, "r")) == NULL)
	{
		printf("Failed opening trace stream: %s. \n", strerror(errno));
		exit(1);
	}

	for (;;)
	{

		buf = calloc(1, sizeof(dtrace_bufdesc_t));
		assert(buf != NULL);
		trc_entry = calloc(1, sizeof(struct dtrace_guest_entry));
		assert(trc_entry != NULL);

		sz = fread(&buf->dtbd_size, sizeof(uint64_t), 1, fp);
		assert(sz > 0);

		sz = fread(&buf->dtbd_cpu, sizeof(uint32_t), 1, fp);
		assert(sz > 0);

		sz = fread(&buf->dtbd_errors, sizeof(uint32_t), 1, fp);
		assert(sz > 0);

		sz = fread(&buf->dtbd_drops, sizeof(uint64_t), 1, fp);
		assert(sz > 0);

		sz = fread(&buf->dtbd_oldest, sizeof(uint64_t), 1, fp);
		assert(sz > 0);

		sz = fread(&buf->dtbd_timestamp, sizeof(uint64_t), 1, fp);
		assert(sz > 0);

		buf->dtbd_data = calloc(1, buf->dtbd_size + 1);
		assert(buf->dtbd_data != NULL);

		dest = (uintptr_t)buf->dtbd_data;
		size = buf->dtbd_size;
		chunk = (size > FRAGMENTSZ) ? FRAGMENTSZ : size;
		while (size > 0)
		{
			size -= chunk;
			sz = fread(dest, 1, chunk, fp);
			assert(sz == chunk);
			dest += chunk;
			chunk = (size > FRAGMENTSZ) ? FRAGMENTSZ : size;
		}

		trc_entry->desc = buf;
		pthread_mutex_lock(&gtq->mtx);
		dt_gtq_enqueue(gtq, trc_entry);
		pthread_mutex_unlock(&gtq->mtx);
	}

	fclose(fp);
	close(fd);
}

static void dt_process_snapshot(struct dtrace_guestq *gtq, dtrace_hdl_t *dtp, dtrace_consumer_t con)
{
	dtrace_bufdesc_t *buf;
	struct dtrace_guest_entry *trc_entry;
	struct timeval timing;

	for (;;)
	{
		pthread_mutex_lock(&gtq->mtx);
		while (!dt_gtq_empty(gtq))
		{
			trc_entry = dt_gtq_dequeue(gtq);
			buf = trc_entry->desc;

			dt_consume_cpu(dtp, NULL, 0, buf, false, &con, NULL);

			free(trc_entry->desc->dtbd_data);
			free(trc_entry->desc);
			free(trc_entry);
		}
		pthread_mutex_unlock(&gtq->mtx);
	}
}

void dt_guest_start(char *script_file, dtrace_hdl_t *dtp, dtrace_consumer_t con)
{
	struct dtrace_guestq *gtq;
	pthread_t trace_reader;
	int err;

	gtq = calloc(1, sizeof(struct dtrace_guestq));
	assert(gtq != NULL);

	dt_write_script(script_file);
	STAILQ_INIT(&gtq->head);
	dt_read_metadata(dtp);
	pthread_create(&trace_reader, NULL, dt_read_trace, (void *)gtq);
	dt_process_snapshot(gtq, dtp, con);
}