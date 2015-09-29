#ifndef __PACKET_INC__
#define __PACKET_INC__

enum {
	P_CTRL_TYPE,
	P_DATA_TYPE,
	P_CMD_TYPE,
	P_TYPE_NUM = 3,
};


enum {
	P_CTRL_START,
	P_HANDSHAKE,
	P_HANDSHAKE_ACK,
	P_NODE_STATE,
	P_NODE_STATE_ACK,
	P_META_PING,
	P_META_PING_ACK,
	P_KMOD_DISCONN,
	P_NODE_CONN_STATE,
	P_DEV_DOWN_NOTIFY,
	P_DEV_DOWN_NOTIFY_ACK,
	P_STARTREP,
	P_PRIMARY_PROBE,
	P_PRIMARY_PROBE_ACK,
	P_CTRL_END,

	P_DATA_START,
	P_DATA,
	P_DATA_ACK,
	P_RS_DATA,
	P_RS_DATA_ACK,
	P_DATA_NET_ACK,
	P_DELTA_SYNC_REQ,
	P_FULLSYNC_REQ,
	P_FULLSYNC_REP,
	P_FULLSYNC_MD5,
	P_FULLSYNC_DATA_REQ,
	P_DBM_REQ,
	P_DBM_REP,
	P_DATA_END,

	P_LOCAL_START,
	P_SECONDARY,
	P_FORCEPRIMARY,
	P_FORCESECONDARY,
	P_CONFIG,
	P_INIT,
	P_UP,
	P_DOWN,
	P_PRIMARY,
	P_DELTA_SYNC,
	P_DELTA_SYNC_DONE,
	P_FULLSYNC,
	P_STATUS,
	P_STATUS_ACK,
	P_CMSYNC,
	P_KERN_HANDSHAKE_D,
	P_KERN_HANDSHAKE_D_ACK,
	P_KERN_HANDSHAKE_M,
	P_KERN_HANDSHAKE_M_ACK,
	P_LOCAL_END,

	P_UNKNOWN,
	P_TYPE_MAX,
};
struct node_state_packet {
	union {
		struct {
			int id;
			int role;
			int kmod_id;
			int dev_state;
                        int data_state;
			uint8_t disk_state;
			int c_state;
			int n_state;
			unsigned protocol;
			uint64_t snd_head;
			uint64_t snd_ack_head;
			uint64_t node_head;
			uint64_t tail;
			uint64_t bwr_disk_size;
			uint64_t bwr_size;
			uint64_t dbm_set;
			uint64_t rbwr_size[MAX_NODES];
			uint64_t rdbm_set[MAX_NODES];
		}__attribute__((packed));

		char __pack[NODE_STATE_HDR_LEN];
	};

	char data[0];
};

struct packet {
	union {
		struct {
			uint64_t magic;
			uint32_t len;
			uint8_t type;
			uint8_t dev_id;
			uint64_t uuid;
			uint64_t bwr_seq;
			uint32_t node_from;
			uint32_t node_to;
			uint32_t kmod_from;
			uint32_t kmod_to;
			uint64_t dev_sector;
			uint64_t bwr_sector;
			uint32_t node_state_num;
			int16_t errcode;
			uint8_t md5[16];
		}__attribute__((packed));

		char __pack[PACKET_HDR_LEN];
	};

	char data[0];
};

struct conf_packet {
	union {
		struct {
			char kmodport[MAX_PORT_LEN];
			int ping;
			int pingtimeout;
			int server_num;
			int res_num;
			int node_num;
			int local_node_id;
			int local_server_id;
			uint32_t len;
		}__attribute__((packed));
	};

	char data[0];
};

struct server_conf_packet {
	union {
		struct {
			int id;
			char localipaddr[MAX_IPADDR_LEN];
			char localport[MAX_PORT_LEN];
			char remoteipaddr[MAX_IPADDR_LEN];
			char remoteport[MAX_PORT_LEN];
		};
	};

	char data[0];
};

struct node_conf_packet {
	union {
		struct {
			int id;
			int server_id;
			char hostname[MAX_HOSTNAME_LEN];
		}__attribute__((packed));
	};

	char data[0];
};

struct res_conf_packet {
	union {
		struct {
			int id;
			char name[MAX_NAME_LEN];
			int runnode_num;
			uint64_t data_len;
			uint64_t meta_offset;
			uint64_t dbm_offset;
			uint64_t dbm_size;
			uint64_t bwr_disk_size;
			uint64_t bwr_offset;
		}__attribute__((packed));
	};

	char data[0];
};

struct runnode_conf_packet {
	union {
		struct {
			int id;
			int proto;
			char disk[MAX_NAME_LEN];
			char bwr_disk[MAX_NAME_LEN];
		}__attribute__((packed));
	};

	char data[0];
};

#endif // __PACKET_INC__
