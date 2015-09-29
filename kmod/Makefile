HADM_KMOD = hadm_kmod.ko
# HADM_TRACE = hadm_trace.ko

KMOD_DIR = $(PREFIX)/kmod

KDIR := /lib/modules/$(shell uname -r)/build
ccflags-y += -g

obj-m := hadm_kmod.o

hadm_kmod-objs := main.o

hadm_kmod-objs += hadm_struct.o
hadm_kmod-objs += hadm_config.o
hadm_kmod-objs += hadm_packet.o
hadm_kmod-objs += hadm_socket.o
hadm_kmod-objs += hadm_device.o
hadm_kmod-objs += hadm_node.o
hadm_kmod-objs += hadm_site.o
hadm_kmod-objs += hadm_thread.o
hadm_kmod-objs += hadm_queue.o
hadm_kmod-objs += hadm_bio.o
hadm_kmod-objs += primary_info.o
hadm_kmod-objs += bio_helper.o
hadm_kmod-objs += buffer.o

hadm_kmod-objs += bwr.o
hadm_kmod-objs += bwr_data.o
hadm_kmod-objs += dbm.o
hadm_kmod-objs += fullsync.o

hadm_kmod-objs += cmd_worker.o

hadm_kmod-objs += bio_handler.o
hadm_kmod-objs += node_syncer.o
hadm_kmod-objs += p_data.o

hadm_kmod-objs += packet_handler.o
hadm_kmod-objs += p_worker.o
hadm_kmod-objs += node_worker.o

hadm_kmod-objs += utils.o
hadm_kmod-objs += hadm_proc.o
hadm_kmod-objs += hadm_proc_show.o

# obj-m += hadm_trace.o
# hadm_trace-objs := hadm_tracing.o

all: modules

modules:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

install: modules
	[ ! -d $(KMOD_DIR) ] && mkdir $(KMOD_DIR); \
		cp -p $(HADM_KMOD) $(KMOD_DIR); \
		# cp -p $(HADM_TRACE) $(KMOD_DIR)

uninstall:
	rm -rf $(KMOD_DIR)
