#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <stddef.h>
#include <stdio.h>

static const char *filename = "rtsp://viewer:viewer!!!@192.168.1.108:554/cam/realmonitor?channel=1&subtype=0";

int main(int argc, const char **argv) {
	AVFormatContext *ic = NULL;
	const AVInputFormat *file_iformat;
	const AVCodec *codec;
	AVStream *stream;
	AVCodecContext *avctx;
	AVPacket *pkt = NULL;
	AVFrame *frame = NULL;
	int err;

	file_iformat = av_find_input_format("rtsp");

	ic = avformat_alloc_context();
	if (!ic)
		goto fail;

	avctx = avcodec_alloc_context3(NULL);
	if (!avctx)
		goto fail_ic;

	pkt = av_packet_alloc();
	if (!pkt)
		goto fail_avctx;

	frame = av_frame_alloc();
	if (!pkt)
		goto fail_avctx;

	err = avformat_open_input(&ic, filename, file_iformat, NULL);
	if (err < 0) {
		if (err != AVERROR_EXIT)
			fprintf(stderr, "Error opening input: %s\n", av_err2str(err));
		goto fail_ic;
	}

	for (int i = 0; i < ic->nb_streams; i++) {
		AVStream *stream = ic->streams[i];
		printf("stream[%d] codec id %d name %s tag %u\n",
			i, stream->codecpar->codec_id, avcodec_get_name(stream->codecpar->codec_id), stream->codecpar->codec_tag);
		printf("stream[%d] width %d height %d\n",
			i, stream->codecpar->width, stream->codecpar->height);
	}

	stream = ic->streams[0];

	av_dump_format(ic, 0, filename, 0);

	err = avcodec_parameters_to_context(avctx, stream->codecpar);
	if (err)
		goto fail_avctx;
	avctx->pkt_timebase = stream->time_base;

	codec = avcodec_find_decoder(avctx->codec_id);
	if (!codec) {
		fprintf(stderr, "Codec not found\n");
		goto fail_avctx;
	}

	avctx->codec_id = codec->id;

	if (avctx->codec_type != AVMEDIA_TYPE_VIDEO) {
		fprintf(stderr, "Codec type was not video");
		goto fail_avctx;
	}

	err = avcodec_open2(avctx, codec, NULL);
	if (err < 0)
		goto fail;

	for (;;) {
		err = av_read_frame(ic, pkt);
		if (err < 0) {
			if (ic->pb && ic->pb->error)
				break;
			continue;
		}
		else {
			// Not eof
		}

		printf("Read pkt size %d\n", pkt->size);

		err = avcodec_send_packet(avctx, pkt);
		if (err == AVERROR(EAGAIN)) {
			fprintf(stderr, "avcodec_send_packet dropped packet\n");
			goto fail_avctx;
		}

		for (;;) {
			err = avcodec_receive_frame(avctx, frame);
			if (err == AVERROR(EAGAIN)) {
				// No frames
				break;
			}
			else if (err >= 0) {
				printf("Got a frame\n");
				av_frame_unref(frame);
			}
			else {
				fprintf(stderr, "avcodec_receive_frame failed\n");
				goto fail_avctx;
			}
		}

		av_packet_unref(pkt);
	}

	av_frame_free(&frame);
	av_packet_free(&pkt);
	avcodec_free_context(&avctx);
	avformat_free_context(ic);

	return 0;

	fail_avctx:
		av_frame_free(&frame);
		av_packet_free(&pkt);
		avcodec_free_context(&avctx);
	fail_ic:
		avformat_free_context(ic);
	fail:
		return -1;
}
