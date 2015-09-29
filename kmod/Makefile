PREFIX := /opt/hadm
KMOD_DIR := $(PREFIX)/kmod
HADM_KMOD := hadm_kmod
KDIR := /lib/modules/$(shell uname -r)/build
DISTFILES = $(wildcard *.c) $(wildcard *.h) Makefile Kbuild compat

all: modules

modules:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install: modules
	[ ! -d $(KMOD_DIR) ] && mkdir $(KMOD_DIR); \
		cp -p $(HADM_KMOD).ko $(KMOD_DIR)

uninstall:
	rm -rf $(KMOD_DIR)

distdir: $(DISTFILES)
	cp -a $(DISTFILES) $(distdir)

