ACLOCAL_AMFLAGS = -I m4

PREFIX = @prefix@
RPMBUILD = @RPMBUILD@

EXTRA_DIST = conf include autogen.sh build.sh .git

SUBDIRS = libs src  kmod 


# default for KDIR/KVER
KVER := `uname -r`
KDIR := /lib/modules/$(KVER)/build

.PHONY: rpm km-rpm 
specs/hadm.spec: specs/hadm.spec.in 
specs/hadm-km.spec: specs/hadm-km.spec.in 
#$(top_builddir)/config.status

rpm: dist specs/hadm.spec
	cp $(distdir).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb $(RPMOPT) specs/hadm.spec

km-rpm: dist specs/hadm-km.spec
	cp $(distdir).tar.gz `rpm -E "%_sourcedir"`
	$(RPMBUILD) -bb $(RPMOPT) specs/hadm-km.spec
	    	
uninstall-hook:
	rmdir $(PREFIX)/* 1>/dev/null 2>&1

install-exec-hook:
	mkdir -p $(DESTDIR)/$(PREFIX)/etc 
	cp conf/hadm_log.conf $(DESTDIR)/$(PREFIX)/etc/hadm_log.conf.example 
	cp conf/hadm_conf.xml $(DESTDIR)/$(PREFIX)/etc/hadm_conf.xml.example 
