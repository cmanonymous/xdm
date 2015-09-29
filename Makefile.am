ACLOCAL_AMFLAGS = -I m4

export AM_CPPFLAGS = -DSYSCONFDIR='"$(sysconfdir)"'
export PREFIX = $(prefix)

EXTRA_DIST = conf include

SUBDIRS = libs src kmod

uninstall-hook:
	rmdir $(prefix)/* 1>/dev/null 2>&1

install-exec-hook:
	if ! test -d $(prefix)/log; then \
		mkdir $(prefix)/log; \
	fi
