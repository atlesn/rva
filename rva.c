/*
 * Copyright (c) 2025 Atle Solbakken <atle@goliathdns,no>
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "rvalib.h"

#include <assert.h>
#include <signal.h>
#include <pthread.h>
#include <unistd.h>

static const char *url = "rtsp://localhost:8554/test";
static const char *filename_prefix = "./test_out-";
static const char *filename_suffix = ".mp4";
static const char *filterdescr = "scale=1920:1080";
//#static const char *url = "rtsp://viewer:viewer!!!@192.168.1.108:554/cam/realmonitor?channel=1&subtype=0";

static volatile int stop_now = 0;
static volatile int flush_now = 0;
static volatile int thread_exited = 0;

enum ThreadIndex {
	THREAD_READER,
	THREAD_DECODER,
	THREAD_ENCODER,
	THREAD_COUNT
};

static void signal_handler(int sig) {
	switch (sig) {
		case SIGTERM:
			rva_info("Received SIGTERM\n");
			break;
		case SIGINT:
			rva_info("Received SIGINT\n");
			break;
		case SIGUSR1:
			rva_info("Received SIGUSR1\n");
			flush_now = 1;
			return;
		default:
			assert(0 && "Unknown signal");
			abort();
	};

	if (stop_now) {
		rva_error("Received second signal, quit now\n");
		exit(1);
	}

	stop_now = 1;
}

int main(int argc, const char **argv) {
	int err, ret = 0;

	(void)(argc);
	(void)(argv);

	RVASharedContext shctx = {0};
	RVAInputContext ictx = {
		.shctx = &shctx
	};
	void *res;
	RVAThreadContext threads[THREAD_COUNT];

	memset(threads, '\0', sizeof(threads));

	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		rva_error("Failed to bind signal handler");
		abort();
	}
	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		rva_error("Failed to bind signal handler");
		abort();
	}
	if (signal(SIGUSR1, signal_handler) == SIG_ERR) {
		rva_error("Failed to bind signal handler");
		abort();
	}

	err = rva_open_shared(&shctx);
	if (err)
		goto fail;

	err = rva_open_input(&ictx, url);
	if (err)
		goto fail;

	RVAReaderContext reader_ctx = {
		.shctx = &shctx,
		.ic = ictx.ic
	};

	threads[THREAD_READER].arg = &reader_ctx;
	threads[THREAD_READER].main = rva_reader_main;
	threads[THREAD_READER].name = "reader thread";
	threads[THREAD_READER].stop_now = &stop_now;
	threads[THREAD_READER].thread_exited = &thread_exited;

	RVADecoderContext decoder_ctx = {
		.shctx = &shctx,
		.avctx = ictx.avctx,
		.filterdescr = filterdescr
	};

	threads[THREAD_DECODER].arg = &decoder_ctx;
	threads[THREAD_DECODER].main = rva_decoder_main;
	threads[THREAD_DECODER].name = "decoder thread";
	threads[THREAD_DECODER].stop_now = &stop_now;
	threads[THREAD_DECODER].thread_exited = &thread_exited;

	RVAEncoderContext encoder_ctx = {
		.shctx = &shctx,
		.timebase = ictx.avctx->pkt_timebase,
		.shctx = &shctx,
		.filename_prefix = filename_prefix,
		.filename_suffix = filename_suffix,
		.flush_now = &flush_now
	};

	threads[THREAD_ENCODER].arg = &encoder_ctx;
	threads[THREAD_ENCODER].main = rva_encoder_main;
	threads[THREAD_ENCODER].name = "encoder thread";
	threads[THREAD_ENCODER].stop_now = &stop_now;
	threads[THREAD_ENCODER].thread_exited = &thread_exited;

	for (int i = 0; i < THREAD_COUNT; i++) {
		RVAThreadContext *thread = &threads[i];

		err = rva_start_thread(thread);
		if (err)
			goto fail;
	}

	for (;;) {
		for (int i = 0; i < THREAD_COUNT; i++) {
			RVAThreadContext *thread = &threads[i];
			if (rva_thread_check_heartbeat(thread)) {
				goto fail;
			}
		}
		if (stop_now || thread_exited) {
			break;
		}
		usleep(100 * 1000);
	}

	goto out;
	fail:
		ret = -1;
	out:
		rva_info("Main thread exiting\n");
		stop_now = 1;
		for (int i = 0; i < THREAD_COUNT; i++) {
			RVAThreadContext *thread = &threads[i];

			if (thread->running) {
				pthread_join(thread->thread, &res);
				rva_info("Joined with %s\n", thread->name);
				if ((intptr_t) res)
					ret = -1;
			}
		}
		rva_close_input(&ictx);
		rva_close_shared(&shctx);
		return ret;
}
