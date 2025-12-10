#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <assert.h>

static const char *url = "rtsp://viewer:viewer!!!@192.168.1.108:554/cam/realmonitor?channel=1&subtype=0";

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

// TODO : Must read in a thread, the frame reading seems to always block
#define BUFSIZE 1

int main(int argc, const char **argv) {
	int err, ret = 0;

	InputContext ictx;
	const AVCodec *codec;
	AVPacket *pkts[BUFSIZE] = {0};
	AVFrame *frame = NULL;
	AVStream *stream;
	int pkt_wpos = 0, pkt_rpos = 0, pkt_count = 0;

	err = open_input(&ictx, url);
	if (err < 0)
		goto fail;

	for (int i = 0; i < BUFSIZE; i++) {
		pkts[i] = av_packet_alloc();
		if (!pkts[i]) {
			error("Failed to allocate packet\n");
			goto fail;
		}
	}

	frame = av_frame_alloc();
	if (!frame) {
		error("Failed to allocate frame\n");
		goto fail;
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

	int max = 10;
	for (;;) {
		if (--max == 0)
			break;

		for (;;) {
			if (pkt_count == BUFSIZE) {
				error("Packet buffer full\n");
				break;
			}

			err = av_read_frame(ictx.ic, pkts[pkt_wpos]);
			if (err < 0) {
				if (err == AVERROR(EAGAIN))
					break;
				error("Failed to read frame: %s\n", av_err2str(err));
				goto fail;
			}
			else {
				info("Read pkt size %d wpos %d rpos %d count %d\n", pkts[pkt_wpos]->size, pkt_wpos, pkt_rpos, pkt_count);
				pkt_wpos = (pkt_wpos + 1) % BUFSIZE;
				pkt_count++;
			}
		}

		for (;;) {
			if (pkt_count == 0) {
				error("Packet buffer empty\n");
				break;
			}

			err = avcodec_send_packet(ictx.avctx, pkts[pkt_rpos]);
			if (err == AVERROR(EAGAIN)) {
				error("avcodec_send_packet dropped packet\n");
				goto fail;
			}
			av_packet_unref(pkts[pkt_rpos]);

			pkt_rpos = (pkt_rpos + 1) % BUFSIZE;
			pkt_count--;

			for (;;) {
				err = avcodec_receive_frame(ictx.avctx, frame);
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
	}

	goto out;
	fail:
		ret = -1;
	out:
		av_frame_free(&frame);
		for (int i = 0; i < BUFSIZE; i++)
			av_packet_free(&pkts[i]);
		close_input(&ictx);
		return ret;
}
