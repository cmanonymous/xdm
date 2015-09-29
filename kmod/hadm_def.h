#ifndef HADM_DEF_H
#define HADM_DEF_H

#include <linux/module.h>

#include "../include/common.inc"
#include "../include/packet.inc"
#include "../include/bwr.inc"
#include "../include/errcode.h"

#undef USE_CONFIG_H

#ifdef USE_CONFIG_H
#  include "../config.h"
#else
#  define PREFIX "/opt/hadm"
#endif

#define HADM_CONF_PATH PREFIX "/etc/hadm_conf.xml"

#define MAX_NODES 32
#define MAX_DEVICES 255

#define BITS_PER_BYTE 8
#define BYTE_SHIFT 3

#define BYTES_PER_DBM 4096
#define DBM_SHIFT 12
#define DBM_DELTA_SYNC 1
#define DBM_FULLSYNC 2

#define BIO_MAX_BYTES 4096

#define BIO_NOT_BEGIN 0
#define BIO_IS_WRITING 1
#define BIO_LOCAL_DONE 2
#define BIO_BWR_DONE BIO_LOCAL_DONE
#define BIO_DONT_WRITE 4
#define BIO_FAIL 5

#define PACKET_LEN 4096

#define DATA_PORT 9998
#define MAX_IP_SIZE 16
#define MAX_PATH_SIZE 128
#define MAX_BIO_QUEUE_SIZE (1<<3)

#define DEFAULT_CMD_RECV_PORT 9997
#define RECEIVER_TIMEOUT 3000	/* millisecond */

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0)
#define COMPAT_HAVE_VOID_MAKE_REQUEST
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,37)
#define COMPAT_HAVE_BLKDEV_GET_BY_PATH
#endif

#ifndef round_up
#define __round_mask(x,y) ((__typeof__(x))((y)-1))
#define round_up(x,y) ((((x)-1) | __round_mask(x,y))+1)
#define round_down(x,y) ((x) & ~__round_mask(x,y))
#endif

#ifndef div_round_up
#define div_round_up(x, y) (((x) - 1) / (y) + 1)
#endif

#ifndef pr_warn
#define pr_warn	pr_warning
#endif

#ifdef DEBUG_IO
#define IO_DEBUG(...) \
	do { printk(__VA_ARGS__); } while (0)
#else
#define IO_DEBUG(...)
#endif

#include "hadm_wrapper.h"

#endif	/* HADM_DEF_H */
