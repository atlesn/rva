AC_INIT([rtsp-video-archiver],[0.1])

AM_INIT_AUTOMAKE([subdir-objects no-dependencies])
LI_INIT
AC_PROG_CC
AC_PROG_INSTALL
AM_SILENT_RULES([yes])

AC_MSG_CHECKING([for ffmpeg header flags])
cflags=`pkg-config --cflags libavcodec libavfilter libavformat libavutil`
if test $? -ne 0; then
	AC_MSG_ERROR([Failed to get flags for ffmpeg headers])
else
	FFMPEG_CFLAGS=${cflags}
	AC_SUBST([FFMPEG_CFLAGS])
fi

AC_MSG_CHECKING([for ffmpeg libraries])
libs=`pkg-config --libs libavcodec libavfilter libavformat libavutil`
if test $? -ne 0; then
	AC_MSG_ERROR([Failed to get ffmpeg libraries])
else
	FFMPEG_LIBS=${libs}
	AC_SUBST([FFMPEG_LIBS])
fi

AC_CHECK_HEADERS([pthread.h])

AC_CONFIG_FILES(Makefile)

AC_OUTPUT
