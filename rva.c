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
	int err, ret = EXIT_SUCCESS;

	RVASharedContext shctx = {0};
	RVAInputContext ictx = {0};
	RVAReaderContext reader_ctx = {0};
	RVADecoderContext decoder_ctx = {0};
	RVAGeneratorContext generator_ctx = {0};
	RVAEncoderContext encoder_ctx = {0};
	RVAThreadContext threads[THREAD_COUNT];

	memset(threads, '\0', sizeof(threads));

	if (argc != 2) {
		goto usage;
	}

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

	if (!strcmp(argv[1], "rtsp")) {
		err = rva_open_input(&ictx, url);
		if (err)
			goto fail;

		rva_init_reader(&reader_ctx, &threads[THREAD_READER], &stop_now, &thread_exited, &ictx, &shctx.packet_buf);
		rva_init_decoder(&decoder_ctx, &threads[THREAD_DECODER], &stop_now, &thread_exited, &ictx, filterdescr, &shctx.packet_buf, &shctx.frame_buf);
		rva_init_encoder(&encoder_ctx, &threads[THREAD_ENCODER], &stop_now, &thread_exited, filename_prefix, filename_suffix, &flush_now, &shctx.frame_buf, ictx.time_base);
	}
	else if (!strcmp(argv[1], "dummy")) {
		rva_init_generator(&generator_ctx, &threads[THREAD_DECODER], &stop_now, &thread_exited, filterdescr, &shctx.frame_buf);
		rva_init_encoder(&encoder_ctx, &threads[THREAD_ENCODER], &stop_now, &thread_exited, filename_prefix, filename_suffix, &flush_now, &shctx.frame_buf, ictx.time_base);
	}
	else {
		rva_error("Unknown mode '%s'\n", argv[1]);
		goto usage;
	}

	err = rva_run(threads, THREAD_COUNT, &stop_now, &thread_exited);
	if (err)
		goto fail;

	goto out;
	usage:
		rva_error("Usage: %s {rtsp|dummy}\n", argv[0]);
	fail:
		ret = EXIT_FAILURE;
	out:
		rva_close_input(&ictx);
		rva_close_shared(&shctx);
		return ret;
}
