#!/bin/sh
ffmpeg -re -stream_loop -1 -i testvideo.mp4 -c copy -f rtsp rtsp://localhost:8554/test
