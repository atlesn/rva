#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

static const char *url = "rtsp://localhost:8554/test";
//#static const char *url = "rtsp://viewer:viewer!!!@192.168.1.108:554/cam/realmonitor?channel=1&subtype=0";

static volatile int stop_now = 0;
static volatile int thread_exited = 0;

static void error(const char *format, ...) {
	va_list(args); 
	va_start(args, format);

	vfprintf(stderr, format, args);

	va_end(args);
}

static void info(const char *format, ...) {
	va_list(args); 
	va_start(args, format);

	vfprintf(stderr, format, args);

	va_end(args);
}

typedef struct InputContext {
	const AVInputFormat *file_iformat;
	AVFormatContext *ic;
	AVCodecContext *avctx;
} InputContext;

static int open_input(InputContext *ictx, const char *filename) {
	int err, ret = 0;

	AVFormatContext *ic = NULL;
	const AVInputFormat *file_iformat;
	AVCodecContext *avctx;

	file_iformat = av_find_input_format("rtsp");
	if (!file_iformat) {
		error("Could not find input format\n");
		goto out_fail;
	}

	ic = avformat_alloc_context();
	if (!ic) {
		error("Could not allocate input format context\n");
		goto out_fail;
	}

	ic->flags |= AVFMT_FLAG_NONBLOCK;

	err = avformat_open_input(&ic, filename, file_iformat, NULL);
	if (err < 0) {
		error("Error opening input: %s\n", av_err2str(err));
		assert(!ic);
		goto out_fail;
	}

	avctx = avcodec_alloc_context3(NULL);
	if (!avctx) {
		error("Could not allocate codec context\n");
		goto out_free_codec_ctx;
	}

	for (int i = 0; i < ic->nb_streams; i++) {
		AVStream *stream = ic->streams[i];
		info("stream[%d] codec id %d name %s tag %u\n",
			i, stream->codecpar->codec_id, avcodec_get_name(stream->codecpar->codec_id), stream->codecpar->codec_tag);
	}

	assert(ic->nb_streams > 0);

	av_dump_format(ic, 0, filename, 0);

	ictx->file_iformat = file_iformat;
	ictx->ic = ic;
	ictx->avctx = avctx;

	goto out;
	out_free_codec_ctx:
		avcodec_free_context(&avctx);
	out_fail:
		ret = -1;
	out:
		return ret;
}

static void close_input(InputContext *ictx) {
	avformat_close_input(&ictx->ic);
	assert(!ictx->ic);
	avcodec_free_context(&ictx->avctx);
}

#define BUFSIZE 16

typedef struct PacketBuffer {
	AVPacket *pkts[BUFSIZE];
	pthread_mutex_t mutex;
	int wpos;
	int rpos;
	int count;
} PacketBuffer;

typedef struct Heartbeat {
	time_t atomic_heartbeat;
} Heartbeat;

static void update_heartbeat(Heartbeat *hb) {
	__sync_lock_test_and_set(&hb->atomic_heartbeat, time(NULL));
}

static int check_heartbeat(Heartbeat *hb, const char *who) {
	time_t heartbeat = __sync_fetch_and_add(&hb->atomic_heartbeat, 0);
	if (time(NULL) - heartbeat > 5) {
		error("Heartbeat timeout for %s\n", who);
		return 1;
	}
	return 0;
}

static Heartbeat make_heartbeat(void) {
	Heartbeat hb = {
		.atomic_heartbeat = time(NULL)
	};
	return hb;
}

typedef struct ThreadContext {
	Heartbeat heartbeat;
	pthread_t thread;
	const char *name;
	void *(*entry)(void *);
	int running;
	void *arg;
} ThreadContext;

enum ThreadIndex {
	THREAD_READER,
	THREAD_DECODER,
	THREAD_COUNT
};

typedef struct DecoderContext {
	enum AVCodecID codec_id;
	PacketBuffer *buf;
	AVCodecContext *avctx;
} DecoderContext;

static void *decoder_main(void *arg) {
	int err, ret = 0;
	ThreadContext *thread = arg;
	DecoderContext *ctx = thread->arg;
	PacketBuffer *buf = ctx->buf;
	AVFrame *frame = NULL;
	AVPacket *packet = NULL;

	frame = av_frame_alloc();
	if (!frame) {
		error("Failed to allocate frame\n");
		goto fail;
	}

	for (;;) {
		if (stop_now)
			goto done;

		pthread_mutex_lock(&buf->mutex);
		if (buf->count == 0) {
			pthread_mutex_unlock(&buf->mutex);
			usleep(10 * 1000);
			continue;
		}

		packet = av_packet_alloc();
		if (!packet) {
			error("Failed to allocate packet\n");
			goto fail;
		}

		av_packet_ref(packet, buf->pkts[buf->rpos]);
		av_packet_unref(buf->pkts[buf->rpos]);
		buf->rpos = (buf->rpos + 1) % BUFSIZE;
		buf->count--;

		pthread_mutex_unlock(&buf->mutex);

		again:
		if (stop_now)
			goto done;

		update_heartbeat(&thread->heartbeat);

		err = avcodec_send_packet(ctx->avctx, packet);
		if (err == AVERROR(EAGAIN)) {
			error("avcodec_send_packet dropped packet\n");
			usleep(100 * 1000);
			goto again;
		}
		av_packet_free(&packet);

		for (;;) {
			err = avcodec_receive_frame(ctx->avctx, frame);
			if (err == AVERROR(EAGAIN)) {
				// No frames
				break;
			}
			else if (err >= 0) {
				info("Got a frame\n");
				av_frame_unref(frame);
			}
			else {
				error("avcodec_receive_frame failed: %s\n", av_err2str(err));
				goto fail;
			}
		}
	}

	goto done;
	fail:
		ret = 1;
	done:
		info("Decoder thread exiting\n");
		av_packet_free(&packet);
		av_frame_free(&frame);
		thread_exited = 1;
		return (void *) (intptr_t) ret;
}

typedef struct ReaderContext {
	AVFormatContext *ic;
	PacketBuffer *buf;
} ReaderContext;

static void *reader_main(void *arg) {
	int err, ret = 0;
	ThreadContext *thread = arg;
	ReaderContext *ctx = thread->arg;
	PacketBuffer *buf = ctx->buf;
	AVPacket *packet = NULL;

	packet = av_packet_alloc();
	if (!packet) {
		error("Failed to allocate packet\n");
		goto fail;
	}

	for (;;) {
		for (;;) {
			err = av_read_frame(ctx->ic, packet);
			if (err < 0) {
				if (err == AVERROR(EAGAIN))
					break;
				error("Failed to read frame: %s\n", av_err2str(err));
				goto fail;
			}
			else {
				retry:
				if (stop_now)
					goto done;

				update_heartbeat(&thread->heartbeat);

				pthread_mutex_lock(&buf->mutex);

				if (buf->count == BUFSIZE) {
					error("Packet buffer full\n");
					pthread_mutex_unlock(&buf->mutex);
					usleep(100 * 1000);
					goto retry;
				}
				av_packet_move_ref(buf->pkts[buf->wpos], packet);
				buf->wpos = (buf->wpos + 1) % BUFSIZE;
				buf->count++;

				info("Read pkt size %d wpos %d rpos %d count %d\n", buf->pkts[buf->wpos]->size, buf->wpos, buf->rpos, buf->count);

				pthread_mutex_unlock(&buf->mutex);
			}
		}
	}

	goto done;
	fail:
		ret = 1;
	done:
		info("Reader thread exiting\n");
		av_packet_free(&packet);
		thread_exited = 1;
		return (void *) (intptr_t) ret;
}

static void signal_handler(int sig) {
	switch (sig) {
		case SIGTERM:
			info("Received SIGTERM\n");
			break;
		case SIGINT:
			info("Received SIGINT\n");
			break;
		default:
			assert(0 && "Unknown signal");
			abort();
	};

	if (stop_now) {
		error("Received second signal, quit now\n");
		exit(1);
	}

	stop_now = 1;
}

int main(int argc, const char **argv) {
	int err, ret = 0;

	InputContext ictx = {0};
	const AVCodec *codec;
	AVStream *stream;
	void *res;
	PacketBuffer buf = {0};
	ThreadContext threads[THREAD_COUNT];

	memset(threads, '\0', sizeof(threads));

	if (signal(SIGTERM, signal_handler) == SIG_ERR) {
		error("Failed to bind signal handler");
		abort();
	}
	if (signal(SIGINT, signal_handler) == SIG_ERR) {
		error("Failed to bind signal handler");
		abort();
	}

	err = pthread_mutex_init(&buf.mutex, NULL);
	if (err) {
		error("Failed to initialize mutex");
		abort();
	}

	err = open_input(&ictx, url);
	if (err < 0)
		goto fail;

	for (int i = 0; i < BUFSIZE; i++) {
		buf.pkts[i] = av_packet_alloc();
		if (!buf.pkts[i]) {
			error("Failed to allocate packet\n");
			goto fail;
		}
	}

	stream = ictx.ic->streams[0];

	err = avcodec_parameters_to_context(ictx.avctx, stream->codecpar);
	if (err) {
		error("Failed to set codec parameters: %s\n", av_err2str(err));
		goto fail;
	}

	ictx.avctx->pkt_timebase = stream->time_base;

	codec = avcodec_find_decoder(ictx.avctx->codec_id);
	if (!codec) {
		error("Codec not found\n");
		goto fail;
	}

	ictx.avctx->codec_id = codec->id;

	if (ictx.avctx->codec_type != AVMEDIA_TYPE_VIDEO) {
		error("Codec type was not video");
		goto fail;
	}

	err = avcodec_open2(ictx.avctx, codec, NULL);
	if (err < 0)
		goto fail;

	ReaderContext reader_ctx = {
		.ic = ictx.ic,
		.buf = &buf
	};

	threads[THREAD_READER].arg = &reader_ctx;
	threads[THREAD_READER].entry = reader_main;
	threads[THREAD_READER].name = "reader thread";

	DecoderContext decoder_ctx = {
		.avctx = ictx.avctx,
		.buf = &buf
	};

	threads[THREAD_DECODER].arg = &decoder_ctx;
	threads[THREAD_DECODER].entry = decoder_main;
	threads[THREAD_DECODER].name = "decoder thread";

	for (int i = 0; i < THREAD_COUNT; i++) {
		ThreadContext *thread = &threads[i];

		info("Starting %s\n", thread->name);

		thread->heartbeat = make_heartbeat();

		err = pthread_create(&thread->thread, NULL, thread->entry, thread);
		if (err) {
			error("Failed to start %s\n", thread->name);
			goto fail;
		}

		thread->running = 1;
	}

	for (;;) {
		for (int i = 0; i < THREAD_COUNT; i++) {
			ThreadContext *thread = &threads[i];

			if (check_heartbeat(&thread->heartbeat, thread->name)) {
				pthread_cancel(thread->thread);
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
		info("Main thread exiting\n");
		stop_now = 1;
		for (int i = 0; i < THREAD_COUNT; i++) {
			ThreadContext *thread = &threads[i];

			if (thread->running) {
				pthread_join(thread->thread, &res);
				info("Joined with %s\n", thread->name);
				if ((intptr_t) res)
					ret = -1;
			}
		}
		pthread_mutex_lock(&buf.mutex);
		for (int i = 0; i < BUFSIZE; i++)
			av_packet_free(&buf.pkts[i]);
		pthread_mutex_unlock(&buf.mutex);
		close_input(&ictx);
		pthread_mutex_destroy(&buf.mutex);
		return ret;
}
