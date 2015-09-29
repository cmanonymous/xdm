#ifndef __COMMON_INC__
#define __COMMON_INC__

#define CONFIG_FILE SYSCONFDIR "/hadm_conf.xml"
#define MAX_NAME_LEN 256
#define MAX_HOSTNAME_LEN 256
#define MAX_IPADDR_LEN 32
#define MAX_PORT_LEN 8
#define PACKET_HDR_LEN 128
#define NODE_STATE_HDR_LEN 64
#define MAGIC 0x3e953ac16a4227b9
#define BWR_UNINIT_MAGIC 0x3e953ac16a4227cc
#define MAX_NODES 32
#define INVALID_ID 255
#define MAX_NODE_ID 254
#define INVALID_SECTOR ((uint64_t)(int64_t)~0)

#define XCHG_DBM_END 0x100
#define FULLSYNC_DATA_REQ 0x101

/*
 * NOTE: 现在的 data_state(DATA_xxx) 和 c_state(C_xxx) 的状态是从以前的 c_state
 * 中划分出来的，以前的 c_state 表示传输状态。
 *
 * 参考链接： http://wiki.cloudbility.com:8888/pages/viewpage.action?pageId=23855142
 */

enum {
	DATA_UPTODATE,
	DATA_CONSISTENT,
	DATA_DBM,
	DATA_SPLITBRAIN,
	DATA_CORRUPT,
};

enum {
	C_STOPPED,
	C_SYNC,
	C_DELTA_SYNC_DBM,
	C_DELTA_SYNC_BWR,
	C_CMSYNC_DBM,
	C_NEED_FULLSYNC,
	C_CONFIG,
	C_UP,
	C_DOWN,
	C_NEG,
	C_READY,
	C_REPSTOP,
	C_REPSTART,
	C_DBM,
	C_DELTA_SYNC,
	C_FULLSYNC,
	C_SPLITBRAIN,
};

enum {
	N_DISCONNECT,
	N_CONNECT,
};

enum {
	HS_SUCCESS,
	HS_FAIL,
};

enum {
	D_CONSISTENT,
	D_INCONSISTENT,
	D_FAIL,
};

enum {
	R_SECONDARY,
	R_PRIMARY,
};

enum {
	DEV_DOWN,
	DEV_UP,
};

enum {
	PROTO_ASYNC,
	PROTO_SYNC,
};

enum {
	MODE_SHARE,
	MODE_UNSHARE,
};

enum node_type {
	LOCAL_NODE = 0,
	SITE_NODE = 1,
};

#endif // __COMMON_INC__
