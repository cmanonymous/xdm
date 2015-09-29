#ifndef __ERRCODE_H__
#define __ERRCODE_H__

enum {
	ESPLITBRAIN = 1,
	ECOLLISION = 2,
};

enum {
	/* cmd: 0~31 */
	ECMD_OK = 0,
	ECMD_COMMON = 1,
	ECMD_CONFIG_FAIL = 2,
	ECMD_WRONG_USAGE = 3,
	ECMD_NET_ERROR = 4,
	ECMD_KMOD_EXIST = 5,
	ECMD_NO_RESOURCE = 6,
	ECMD_GET_BWRINFO = 7,
	ECMD_NO_PATH = 8,
	ECMD_OPEN_FAIL = 9,
	ECMD_IO_ERR = 10,
	ECMD_NOMEM = 11,
	ECMD_EXIST_PRIMARY = 11,
	ECMD_RES_NOT_UP = 12,
	ECMD_INCONSISTENCE = 14,
	ECMD_SPLITBRAIN = 15,
	ECMD_CHECK_STATE_FAIL = 16,
	ECMD_NO_NODE = 17,
	ECMD_NO_STATE = 18,

	/* kmod: 32~63 */
	EKMOD_ALREADY_CONFIG = 32,
	EKMOD_ALREADY_UP = 33,
	EKMOD_ALREADY_DOWN = 34,
	EKMOD_NODEV = 35,
	EKMOD_NOTASK = 36,
	EKMOD_NONODE = 37,
	EKMOD_PACKET_WRONG = 38,
	EKMOD_DUAL_PRIMARY = 39,
	EKMOD_PEER_BWR_NOT_EMPTY = 40,
	EKMOD_PEER_BM_NOT_EMPTY = 41,
	EKMOD_INUSE = 42,
	EKMOD_SEND_FAIL = 43,
	EKMOD_LOCAL_ROLE = 44,
	EKMOD_REMOTE_ROLE = 45,
	EKMOD_NOT_SUPPORT = 46,
	EKMOD_DELTA_SYNC_EXIT = 47,
	EKMOD_CSTATE = 48,
	EKMOD_BAD_CSTATE = 49,
	EKMOD_BAD_DSTATE = 50,
	EKMOD_NOT_PRIMARY = 51,
	EKMOD_MASTER_EXIST = 51,

	/* net: 64~95 */
	ENET_NEED_FULLSYNC = 64,

	EKMOD_UNKNOWN_STATE,
};

#ifdef USE_HADM_STR_ERRNO
static const char *hadm_str_errno[] = {
	[0] = "no error",
	[EKMOD_ALREADY_CONFIG] = "resource already configure",
	[EKMOD_ALREADY_UP] = "resource already up",
	[EKMOD_ALREADY_DOWN] = "resource already down",
	[EKMOD_NODEV] = "no such device",
	[EKMOD_NOTASK] = "kmod create thread failed",
	[EKMOD_NONODE] = "no such node",
	[EKMOD_PACKET_WRONG] = "wrong packet",
	[EKMOD_DUAL_PRIMARY] = "already exist a primary node",
	[EKMOD_PEER_BWR_NOT_EMPTY] = "peer secondary BWR is not empty",
	[EKMOD_PEER_BM_NOT_EMPTY] = "peer secondary dbm is not empty",
	[EKMOD_INUSE] = "resource busy",
	[EKMOD_SEND_FAIL] = "kmod send packet failed",
	[EKMOD_LOCAL_ROLE] = "local role is not right",
	[EKMOD_REMOTE_ROLE] = "remote role is not right",
	[EKMOD_NOT_SUPPORT] = "not support",
	[EKMOD_NOT_PRIMARY] = "expect primary",
	[EKMOD_BAD_DSTATE] = "disk state is inconsistent",

	[ENET_NEED_FULLSYNC] = "remote need fullsync",
	[EKMOD_UNKNOWN_STATE] = "unknow state",
};
#endif

#endif	/* __ERRCODE_H__ */
