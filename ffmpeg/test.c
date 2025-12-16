#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/frame.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

static const char *url = "rtsp://localhost:8554/test";
static const char *filename = "./test_out.mp4";
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

typedef struct SharedContext {
	AVRational time_base;
	int encoder_flushed;
} SharedContext;

typedef struct InputContext {
	const AVInputFormat *file_iformat;
	AVFormatContext *ic;
	AVCodecContext *avctx;
	SharedContext *shctx;
} InputContext;

static int open_input(InputContext *ictx, const char *filename) {
	int err, ret = 0;

	AVFormatContext *ic = NULL;
	const AVInputFormat *file_iformat;
	AVCodecContext *avctx;
	AVStream *stream;
	const AVCodec *codec;

	file_iformat = av_find_input_format("rtsp");
	if (!file_iformat) {
		error("Could not find input format\n");
		goto out_fail;
	}

	ic = avformat_alloc_context();
	if (!ic) {
		error("Could not allocate input format context\n");
		goto out_free_format_ctx;
	}

	err = avformat_open_input(&ic, filename, file_iformat, NULL);
	if (err < 0) {
		error("Error opening input: %s\n", av_err2str(err));
		assert(!ic);
		goto out_free_format_ctx;
	}

	avctx = avcodec_alloc_context3(NULL);
	if (!avctx) {
		error("Could not allocate codec context\n");
		goto out_free_format_ctx;
	}

	for (unsigned int i = 0; i < ic->nb_streams; i++) {
		AVStream *stream = ic->streams[i];
		info("stream[%d] codec id %d name %s tag %u\n",
			i, stream->codecpar->codec_id, avcodec_get_name(stream->codecpar->codec_id), stream->codecpar->codec_tag);
	}

	assert(ic->nb_streams > 0);

	av_dump_format(ic, 0, filename, 0);

	stream = ic->streams[0];

	err = avcodec_parameters_to_context(avctx, stream->codecpar);
	if (err) {
		error("Failed to set codec parameters: %s\n", av_err2str(err));
		goto out_free_codec_ctx;
	}

	avctx->pkt_timebase = stream->time_base;

	codec = avcodec_find_decoder(avctx->codec_id);
	if (!codec) {
		error("Input codec not found\n");
		goto out_free_codec_ctx;
	}

	avctx->codec_id = codec->id;

	if (avctx->codec_type != AVMEDIA_TYPE_VIDEO) {
		error("Codec type was not video");
		goto out_free_codec_ctx;
	}

	err = avcodec_open2(avctx, codec, NULL);
	if (err < 0)
		goto out_free_codec_ctx;

	ictx->file_iformat = file_iformat;
	ictx->ic = ic;
	ictx->avctx = avctx;
	ictx->shctx->time_base = stream->time_base;

	goto out;
	out_free_codec_ctx:
		avcodec_free_context(&avctx);
	out_free_format_ctx:
		avformat_free_context(ic);
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

typedef struct EncoderPrivateContext {
	const AVOutputFormat *file_oformat;
	AVFormatContext *oc;
	AVCodecContext *avctx;
} EncoderPrivateContext;

static int open_encoder(
		EncoderPrivateContext *octx,
		const char *filename,
		const SharedContext *shctx,
		enum AVPixelFormat pixel_format,
		int width,
		int height
) {
	int err, ret = 0;

	const AVOutputFormat *file_oformat;
	AVFormatContext *oc = NULL;
	AVCodecContext *avctx;
	const AVCodec *codec;
	char cwd[PATH_MAX] = {0};
	AVStream *stream;

	getcwd(cwd, sizeof(cwd));
	info("CWD: %s\n", cwd);

	info("Open output timebase %i/%i format %i\n", shctx->time_base.num, shctx->time_base.den, pixel_format);

	err = unlink(filename);
	if (!err || (err && errno == ENOENT)) {
		// OK
	}
	else {
		error("Failed to unlink %s: %s\n", filename, strerror(errno));
		goto out_fail;
	}

	file_oformat = av_guess_format("mp4", NULL, NULL);
	if (!file_oformat) {
		error("Failed to get output format\n");
		goto out_fail;
	}

	err = avformat_alloc_output_context2(&oc, file_oformat, "mp4", filename);
	if (err) {
		error("Could not allocate output format context\n");
		goto out_fail;
	}

	codec = avcodec_find_encoder_by_name("libx264");
	if (!codec) {
		error("Output codec not found\n");
		goto out_free_format_ctx;
	}

	stream = avformat_new_stream(oc, NULL);
	if (!stream) {
		error("Failed to create output stream\n");
		goto out_free_format_ctx;
	}

	avctx = avcodec_alloc_context3(codec);
	if (!avctx) {
		error("Could not allocate output codec context\n");
		goto out_free_format_ctx;
	}
	
	avctx->codec_id = codec->id;
	avctx->time_base = shctx->time_base;
	avctx->pix_fmt = pixel_format;
	avctx->width = width;
	avctx->height = height;
	avctx->qmin = 12;
	avctx->qmax = 16;
	avctx->max_qdiff = 2;
	avctx->qcompress = 0.1;
	avctx->bit_rate = 4 * 1000 * 1000;

	err = avcodec_parameters_from_context(stream->codecpar, avctx);
	if (err) {
		error("Failed to set parameters on stream\n");
		goto out_free_format_ctx;
	}

	err = avcodec_open2(avctx, codec, NULL);
	if (err) {
		error("Failed to open output codec\n");
		goto out_free_format_ctx;
	}

	stream->time_base = avctx->time_base;

	av_dump_format(oc, 0, filename, 1);

	err = avio_open(&oc->pb, filename, AVIO_FLAG_WRITE);
	if (err) {
		error("Failed to open output file '%s': %s\n", filename, av_err2str(err));
		goto out_free_codec_ctx;
	}

	// err = av_dict_set(&dict, "preset", "fast", 0);
	// if (!dict) {
	//	error("Failed to create dictionary\n");
	//	goto out_free_codec_ctx;
	// }

	err = avformat_write_header(oc, NULL);
	if (err) {
		error("Failed to write file header: %s\n", av_err2str(err));
		goto out_close_avio;
	}

	octx->file_oformat = file_oformat;
	octx->oc = oc;
	octx->avctx = avctx;

	goto out;
	out_close_avio:
		avio_closep(&oc->pb);
	out_free_codec_ctx:
		avcodec_free_context(&avctx);
	out_free_format_ctx:
		avformat_free_context(oc);
	out_fail:
		ret = -1;
	out:
		return ret;
}

static void close_encoder(EncoderPrivateContext *octx) {
	if (octx->oc) {
		avio_closep(&octx->oc->pb);
		avformat_free_context(octx->oc);
		octx->oc = NULL;
	}
	avcodec_free_context(&octx->avctx);
}

#define BUFSIZE 16

#define BUFMEMBERS(type)          \
	type *entries[BUFSIZE];   \
	pthread_mutex_t mutex;    \
	int wpos;                 \
	int rpos;                 \
	int count;

#define BUF_WRITE_BEGIN(buf, type) do {         \
	type *entry = buf->entries[buf->wpos];

#define BUF_WRITE_END(buf)                      \
	buf->wpos = (buf->wpos + 1) % BUFSIZE;  \
	buf->count++; } while(0)

#define BUF_READ_BEGIN(buf, type) do {          \
	type *entry = buf->entries[buf->rpos]

#define BUF_READ_END(buf)                       \
	buf->rpos = (buf->rpos + 1) % BUFSIZE;  \
	buf->count--; } while(0)

#define BUF_FULL(buf) \
	buf->count == BUFSIZE

#define BUF_EMPTY(buf) \
	buf->count == 0

#define BUF_ALLOC(buf, alloc)                         \
	err = pthread_mutex_init(&buf.mutex, NULL);   \
	if (err) {                                    \
		error("Failed to initialize mutex");  \
		abort();                              \
	}                                             \
	for (int i = 0; i < BUFSIZE; i++) {           \
	  buf.entries[i] = alloc();                   \
	    if (!buf.entries[i]) {                    \
	      error("Failed to allocate entry\n");    \
	      goto fail;                              \
	    }                                         \
	}

#define BUF_FREE(buf, type, free)             \
	pthread_mutex_lock(&buf.mutex);      \
	for (int i = 0; i < BUFSIZE; i++) {   \
	  free(&buf.entries[i]);              \
	}                                     \
	pthread_mutex_unlock(&buf.mutex);     \
	pthread_mutex_destroy(&buf.mutex)

typedef struct PacketBuffer {
	BUFMEMBERS(AVPacket)
} PacketBuffer;

typedef struct FrameBuffer {
	BUFMEMBERS(AVFrame)
} FrameBuffer;

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

typedef struct ThreadContext ThreadContext;

typedef int (*ThreadMain)(ThreadContext *, void *arg);

typedef struct ThreadContext {
	Heartbeat heartbeat;
	pthread_t thread;
	const char *name;
	ThreadMain main;
	int running;
	void *arg;
} ThreadContext;

static void thread_heartbeat(ThreadContext *ctx) {
	update_heartbeat(&ctx->heartbeat);
}

static void *thread_entry(void *arg) {
	ThreadContext *ctx = arg;

	int ret = ctx->main(ctx, ctx->arg);

	return (void *)(intptr_t) ret;
}

enum ThreadIndex {
	THREAD_READER,
	THREAD_DECODER,
	THREAD_ENCODER,
	THREAD_COUNT
};

#define PASTE(a,b) a ## b

#define QUOTE(a) #a

#define THREAD_WITH_BUF_WRITE(thread, buf, type, task) \
	PASTE(type,retry):                      \
	if (stop_now) goto done;                \
	thread_heartbeat(thread);               \
	pthread_mutex_lock(&buf->mutex);        \
	if (BUF_FULL(buf)) {                    \
	  error("Buffer for " QUOTE(type) " full\n"); \
	  pthread_mutex_unlock(&buf->mutex);    \
	  usleep(100 * 1000);                   \
	  goto PASTE(type,retry);               \
	}                                       \
	BUF_WRITE_BEGIN(buf, type);             \
	task                                    \
	BUF_WRITE_END(buf);                     \
	pthread_mutex_unlock(&buf->mutex);

#define THREAD_WITH_BUF_READ(thread, buf, type, task) \
	retry:                                  \
	if (stop_now) goto done;                \
	thread_heartbeat(thread);               \
	pthread_mutex_lock(&buf->mutex);        \
	if (BUF_EMPTY(buf)) {                   \
	  pthread_mutex_unlock(&buf->mutex);    \
	  usleep(100 * 1000);                   \
	  goto retry;                           \
	}                                       \
	BUF_READ_BEGIN(buf, type);              \
	task                                    \
	BUF_READ_END(buf);                      \
	pthread_mutex_unlock(&buf->mutex);

typedef struct EncoderContext {
	FrameBuffer *frame_buf;
	AVRational timebase;
	SharedContext *shctx;
} EncoderContext;

static int encoder_main(ThreadContext *thread, void *arg) {
	int err, ret = 0;
	EncoderPrivateContext octx = {0};
	EncoderContext *ctx = arg;
	FrameBuffer *buf = ctx->frame_buf;
	AVFrame *frame = NULL;
	AVPacket *packet = NULL;
	int64_t packet_count = 0;
	unsigned int stream_index = 0;

	frame = av_frame_alloc();
	if (!frame) {
		error("Failed to allocate frame\n");
		goto fail;
	}

	packet = av_packet_alloc();
	if (!packet) {
		error("Failed to allocate packet\n");
		goto fail;
	}

	for (;;) {
		info("Write packet count %" PRIi64 "\n", packet_count);

		THREAD_WITH_BUF_READ(thread, buf, AVFrame,
			av_frame_move_ref(frame, entry);
			av_frame_unref(entry);
			info("Read frame to decoder wpos %d rpos %d count %d\n", buf->wpos, buf->rpos, buf->count);
		);

		if (!octx.oc) {
			err = open_encoder(&octx, filename, ctx->shctx, frame->format, frame->width, frame->height);
			if (err < 0)
				goto fail;
		}

		frame->pict_type = AV_PICTURE_TYPE_NONE;

		err = avcodec_send_frame(octx.avctx, frame);
		if (err) {
			error("avcodec_send_frame failed: %s\n", av_err2str(err));
			goto fail;
		}

		av_frame_unref(frame);

		for (;;) {
			err = avcodec_receive_packet(octx.avctx, packet);
			if (err == AVERROR(EAGAIN)) {
				break;
			}
			else if (err) {
				error("avcodec_receive_packet failed: %s\n", av_err2str(err));
				goto fail;
			}

			info("Read packet from encoder pts %lli dts %lli\n", (long long int) packet->pts, (long long int) packet->dts);

			err = av_interleaved_write_frame(octx.oc, packet);
			if (err) {
				error("Failed to write packet: %s\n", strerror(errno));
				goto fail;
			}

			packet_count++;

			av_packet_unref(packet);
		}
	}

	done:

	info("Finalizing output after %" PRIi64 " packets\n", packet_count);

	err = avcodec_send_frame(octx.avctx, NULL);
	if (err) {
		error("avcodec_send_frame failed when flushing: %s\n", av_err2str(err));
		goto fail;
	}

	for (;;) {
		err = avcodec_receive_packet(octx.avctx, packet);
		if (err == AVERROR_EOF) {
			break;
		}
		else if (err) {
			error("avcodec_receive_packet failed when flushing: %s\n", av_err2str(err));
			goto fail;
		}

		packet->stream_index = stream_index;
		av_packet_rescale_ts(packet, octx.avctx->time_base, octx.oc->streams[stream_index]->time_base);

		err = av_interleaved_write_frame(octx.oc, packet);
		if (err) {
			error("Failed to write packet while flushing: %s\n", strerror(errno));
			goto fail;
		}

		packet_count++;

		av_packet_unref(packet);
	}

	info("Packet count after finalizing: %" PRIi64 " packets\n", packet_count);

	err = av_write_trailer(octx.oc);
	if (err) {
		error("Failed to write trailer\n");
		goto fail;
	}

	ctx->shctx->encoder_flushed = 1;

	goto out;
	fail:
		ret = 1;
	out:
		info("Encoder thread exiting\n");
		close_encoder(&octx);
		av_frame_free(&frame);
		av_packet_free(&packet);
		thread_exited = 1;
		return ret;
}

typedef struct DecoderContext {
	enum AVCodecID codec_id;
	PacketBuffer *packet_buf;
	FrameBuffer *frame_buf;
	AVCodecContext *avctx;
} DecoderContext;

static int decoder_main(ThreadContext *thread, void *arg) {
	int err, ret = 0;
	DecoderContext *ctx = arg;
	AVFrame *frame = NULL;
	AVPacket *packet = NULL;

	frame = av_frame_alloc();
	if (!frame) {
		error("Failed to allocate frame\n");
		goto fail;
	}

	for (;;) {
		THREAD_WITH_BUF_READ(thread, ctx->packet_buf, AVPacket,
			packet = av_packet_alloc();
			if (!packet) {
				error("Failed to allocate packet\n");
				goto fail;
			}
			av_packet_ref(packet, entry);
			av_packet_unref(entry);
		);

		err = avcodec_send_packet(ctx->avctx, packet);
		if (err) {
			error("avcodec_send_packet dropped failed\n");
			goto fail;
		}
		av_packet_free(&packet);

		for (;;) {
			err = avcodec_receive_frame(ctx->avctx, frame);
			if (err == AVERROR(EAGAIN)) {
				// No frames
				break;
			}
			else if (err >= 0) {
				THREAD_WITH_BUF_WRITE(thread, ctx->frame_buf, AVFrame,
					av_frame_move_ref(entry, frame);
				);
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
		return ret;
}

typedef struct ReaderContext {
	AVFormatContext *ic;
	PacketBuffer *buf;
} ReaderContext;

static int reader_main(ThreadContext *thread, void *arg) {
	int err, ret = 0;
	ReaderContext *ctx = arg;
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
				THREAD_WITH_BUF_WRITE(thread, buf, AVPacket,
					av_packet_move_ref(entry, packet);
					info("Read pkt size %d wpos %d rpos %d count %d\n", entry->size, buf->wpos, buf->rpos, buf->count);
				);
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
		return ret;
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

	(void)(argc);
	(void)(argv);

	SharedContext shctx = {0};
	InputContext ictx = {
		.shctx = &shctx
	};
	void *res;
	PacketBuffer input_packet_buf = {0};
	FrameBuffer frame_buf = {0};
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

	err = open_input(&ictx, url);
	if (err < 0)
		goto fail;

	BUF_ALLOC(input_packet_buf, av_packet_alloc);
	BUF_ALLOC(frame_buf, av_frame_alloc);

	ReaderContext reader_ctx = {
		.ic = ictx.ic,
		.buf = &input_packet_buf
	};

	threads[THREAD_READER].arg = &reader_ctx;
	threads[THREAD_READER].main = reader_main;
	threads[THREAD_READER].name = "reader thread";

	DecoderContext decoder_ctx = {
		.avctx = ictx.avctx,
		.packet_buf = &input_packet_buf,
		.frame_buf = &frame_buf
	};

	threads[THREAD_DECODER].arg = &decoder_ctx;
	threads[THREAD_DECODER].main = decoder_main;
	threads[THREAD_DECODER].name = "decoder thread";

	EncoderContext encoder_ctx = {
		.frame_buf = &frame_buf,
		.timebase = ictx.avctx->pkt_timebase,
		.shctx = &shctx
	};

	threads[THREAD_ENCODER].arg = &encoder_ctx;
	threads[THREAD_ENCODER].main = encoder_main;
	threads[THREAD_ENCODER].name = "encoder thread";

	for (int i = 0; i < THREAD_COUNT; i++) {
		ThreadContext *thread = &threads[i];

		info("Starting %s\n", thread->name);

		thread->heartbeat = make_heartbeat();

		err = pthread_create(&thread->thread, NULL, thread_entry, thread);
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
		BUF_FREE(frame_buf, AVFrame, av_frame_free);
		BUF_FREE(input_packet_buf, AVPacket, av_packet_free);
		close_input(&ictx);
		return ret;
}
