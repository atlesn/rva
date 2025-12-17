#!/bin/sh
ffmpeg -f lavfi \
	-i "color=c=green:s=1280x720:d=1[green]; color=c=red:s=1280x720:d=1[red]; color=c=blue:s=1280x720:d=1[blue]; [green][red][blue]concat=n=3:v=1:a=0" \
	-vf "drawtext=text='%{eif\:mod(n\,10)\:d}':x=10:y=10:fontsize=24:fontcolor=white" \
	-t 10 -pix_fmt yuv420p testvideo.mp4
