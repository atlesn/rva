rva_SOURCES=rva.c rvalib.c
rva_CFLAGS = ${AM_CFLAGS} ${FFMPEG_CFLAGS}
rva_LDADD = ${AM_LIBS} ${FFMPEG_LIBS}

make_testvideo_SOURCES=make_testvideo.c rvalib.c
make_testvideo_CFLAGS = ${AM_CFLAGS} ${FFMPEG_CFLAGS}
make_testvideo_LDADD = ${AM_LIBS} ${FFMPEG_LIBS}

bin_PROGRAMS=rva make_testvideo
