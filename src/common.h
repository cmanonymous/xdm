#ifndef __COMMON_H__
#define __COMMON_H__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <string.h>
#include <netdb.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <libgen.h>
#include <event2/event.h>
#include <event2/thread.h>
#include <event2/event_struct.h>
#include <libxml/xpath.h>
#include <zlib.h>
#include <zlog.h>
#include <linux/fs.h>
#include <sys/statvfs.h>
#include <ifaddrs.h>

#define MODULE_FILE "/proc/modules"
#define MODULE_NAME "hadm_kmod"
#define MODULE_PATH "/opt/hadm/kmod/hadm_kmod.ko"

#define HADM_LOG_CONF SYSCONFDIR "/hadm_log.conf"
#define HADM_SERVER_LOG_CAT "hadm_server_cat"
#define HADM_CLI_LOG_CAT "hadm_cli_cat"

#define MAX_DEVICES 255
#define SELECT_MAX_FDS 256
#define CONNECT_TIMER_TIMEOUT 5
#define LOCALHOST "localhost"

#define set_bit(nr, data) (data) |= (1U << (nr))
#define clear_bit(nr, data) (data) &= ~(1U << (nr))
#define test_bit(nr, var) (!!((var) & (1U << (nr))))

#define BLK_SHIFT  12
#define BLK_SIZE   (1U << BLK_SHIFT)
#define BLK_MASK   (~(BLK_SIZE - 1))

#define SECTOR_SIZE_BIT 9
#define SECTOR_SIZE (1U << SECTOR_SIZE_BIT)

typedef void (*event_handler)(evutil_socket_t fd, short event, void *args);

enum {
	NODE_DFD_DISCONNECTED,
	NODE_DFD_CONNECTED,
	NODE_MFD_DISCONNECTED,
	NODE_MFD_CONNECTED
};

static char *connect_state[] = {
	[NODE_DFD_DISCONNECTED] = "disconnect",
	[NODE_DFD_CONNECTED] = "connect",
	[NODE_MFD_DISCONNECTED] = "disconnect",
	[NODE_MFD_CONNECTED] = "connect",
};

enum {
	DATA_HANDSHAKE,
	DATA_HANDSHAKE_ACK,
	META_HANDSHAKE,
	META_HANDSHAKE_ACK
};

#include "common.inc"
#include "packet.inc"
#include "common_string.h"
#include "config.h"
#include "errcode.h"

#include "log.h"
#include "queue.h"
#include "conf.h"
#include "packet.h"
#include "daemon.h"
#include "device.h"
#include "io.h"
#include "node_worker.h"
#include "device_worker.h"
#include "node.h"
#include "sock.h"
#include "connection.h"
#include "thread.h"
#include "timer.h"
#include "utils.h"
#include "hadmcmd.h"
#include "hadmctl.h"
#include "ip.h"

#endif // __COMMON_H__
