CFLAGS = -g -O0
AM_CPPFLAGS = -DSYSCONFDIR='"@sysconfdir@"'
EXTRA_DIST = $(wildcard *.h)
bin_PROGRAMS = hadm_main hadmctl
hadm_main_SOURCES = common.h hadm_main.c \
					list.h \
					conf.c conf.h \
					ip.c ip.h \
					connection.c connection.h \
					daemon.c daemon.h \
					device.c device.h \
					device_worker.c device_worker.h \
					io.c io.h \
					node.c node.h \
					node_worker.c node_worker.h \
					packet.c packet.h \
					queue.c queue.h \
					sock.c sock.h \
					thread.c thread.h \
					timer.c timer.h \
					utils.c utils.h \
					log.c log.h

hadmctl_SOURCES = common.h hadmctl.c \
				  hadmcmd.c hadmcmd.h \
				  conf.c conf.h \
				  packet.c packet.h \
				  utils.c utils.h \
				  sock.c sock.h \
				  io.c io.h \
				  log.c log.h

hadm_main_CPPFLAGS = $(AM_CPPFLAGS)
hadm_main_CPPFLAGS += -I$(top_srcdir)/include
hadm_main_CPPFLAGS += -pthread
hadm_main_CPPFLAGS += -I/usr/include/libxml2
hadm_main_CPPFLAGS += -I$(top_srcdir)/libs/zlog-master/src
hadm_main_CPPFLAGS += -I$(top_srcdir)/libs/libevent-2.0.21-stable/include

hadm_main_LDFLAGS = -L$(top_builddir)/libs/zlog-master/src
hadm_main_LDFLAGS += -L$(top_builddir)/libs/libevent-2.0.21-stable

hadm_main_LDADD = -lpthread
hadm_main_LDADD += -levent_pthreads
hadm_main_LDADD += -levent
hadm_main_LDADD += -lxml2
hadm_main_LDADD += -lrt
hadm_main_LDADD += -lz
hadm_main_LDADD += -lzlog

hadmctl_CPPFLAGS = $(AM_CPPFLAGS)
hadmctl_CPPFLAGS += -I$(top_srcdir)/include
hadmctl_CPPFLAGS += -I/usr/include/libxml2
hadmctl_CPPFLAGS += -I$(top_srcdir)/libs/zlog-master/src
hadmctl_CPPFLAGS += -I$(top_srcdir)/libs/libevent-2.0.21-stable/include

hadmctl_LDFLAGS = -L$(top_builddir)/libs/zlog-master/src
hadmctl_LDFLAGS += '-Wl,-rpath,$$ORIGIN/../lib'

hadmctl_LDADD = -lxml2
hadmctl_LDADD += -lrt
hadmctl_LDADD += -lz
hadmctl_LDADD += -lzlog
