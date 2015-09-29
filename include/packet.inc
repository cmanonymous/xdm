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

	P_SC_START,
	P_SC_HS = P_SC_START,
	P_SC_HS_ACK,
	P_SC_STATE,
	P_SC_STATE_ACK,
	P_SC_PING,
	P_SC_PING_ACK,
	P_SC_CONN_STATE,
	P_SC_DEVDOWN,
	P_SC_DEVDOWN_ACK,
	P_SC_STARTREP,
	P_SC_PRI_PRO,
	P_SC_PRI_PRO_ACK,
	P_SC_END = P_SC_PRI_PRO_ACK,

	P_NC_START,
	P_NC_CONN_STATE,
	P_NC_PING,
	P_NC_PING_ACK,
	P_NC_MASTER,
	P_NC_STATE_REQ,
	P_NC_STATE,
	P_NC_END,

	P_CTRL_END,

	P_DATA_START,

	P_SD_START,
	P_SD_DATA = P_SD_START,
	P_SD_NET_ACK,
	P_SD_DATA_ACK,
	P_SD_RSDATA,
	P_SD_RSDATA_ACK,
	P_SD_DSYNC_REQ,
	P_SD_FSYNC_REQ,
	P_SD_FSYNC_REP,
	P_SD_FSYNC_MD5,
	P_SD_FSYNC_DATA,
	P_SD_DBM_REQ,
	P_SD_DBM_REP,
	P_SD_END = P_SD_DBM_REP,

	P_ND_START,
	P_ND_SBIO,
	P_ND_SBIO_ACK,
	P_ND_END,

	P_DATA_END,

	P_CMD_START,
	P_SECONDARY,
	P_FORCEPRIMARY,
	P_FORCESECONDARY,
	P_CONFIG,
	P_INIT,
	P_UP,
	P_DOWN,
	P_PRIMARY,
	P_MASTER,
	P_SLAVER,
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
	P_CMD_END,

	P_UNKNOWN,
	P_TYPE_MAX,
//
//	P_META_PING = 5,
//	P_META_PING_ACK,
//	P_NODE_CONN_STATE,
//	P_DEV_DOWN_NOTIFY,
//	P_DEV_DOWN_NOTIFY_ACK,
//	P_STARTREP = 10,
//	P_PRIMARY_PROBE,
//	P_PRIMARY_PROBE_ACK,
//	P_CTRL_END,
//
//	P_DATA_START,
//	P_DATA = 15,
//	P_DATA_ACK,
//	P_RS_DATA,
//	P_RS_DATA_ACK,
//	P_DATA_NET_ACK,
//	P_DELTA_SYNC_REQ = 20,
//	P_FULLSYNC_REQ,
//	P_FULLSYNC_REP,
//	P_FULLSYNC_MD5,
//	P_FULLSYNC_DATA_REQ,
//	P_DBM_REQ = 25,
//	P_DBM_REP,
//	P_DATA_END,
//	P_LOCAL_START,
//	P_SECONDARY,
//	P_FORCEPRIMARY = 30,
//	P_FORCESECONDARY,
//	P_CONFIG,
//	P_INIT,
//	P_UP,
//	P_DOWN = 35,
//	P_PRIMARY,
//	P_DELTA_SYNC,
//	P_DELTA_SYNC_DONE,
//	P_FULLSYNC,
//	P_STATUS = 40,
//	P_STATUS_ACK,
//	P_CMSYNC,
//	P_KERN_HANDSHAKE_D,
//	P_KERN_HANDSHAKE_D_ACK,
//	P_KERN_HANDSHAKE_M = 45,
//	P_KERN_HANDSHAKE_M_ACK,
//	P_LOCAL_END,
//
};

struct node_state_packet {
	union {
		struct {
			uint8_t primary;
			uint8_t master;
		};

		char __pack[NODE_STATE_HDR_LEN];
	};
};

struct site_state_packet {
	union {
		struct {
			int id;
			int role;
			int dev_state;
                        int data_state;
			uint8_t disk_state;
			int c_state;
			int n_state;
			unsigned protocol;
			uint64_t snd_head;
			uint64_t snd_ack_head;
			uint64_t site_head;
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
			uint8_t node_type;
			uint8_t dev_id;
			uint64_t uuid;
			uint64_t bwr_seq;
			uint32_t node_from;
			uint32_t node_to;
			uint64_t dev_sector;
			uint64_t bwr_sector;
			int16_t errcode;
			uint8_t md5[16];
			/* packet specific data */
			union {
				/* state packet */
				uint32_t site_state_num;

				/* node state packet */
				struct {
					uint8_t primary;
					uint8_t master;
					uint8_t open;
				};

				/* sbio packet */
				struct {
					uint32_t bi_size;
					uint64_t bi_flags;
					uint64_t bi_rw;
				};
			};
		//}__attribute__((packed));
		};

		char __pack[PACKET_HDR_LEN];
	};

	char data[0];
};

struct conf_packet {
	union {
		struct {
			char serverip[MAX_IPADDR_LEN];
			char serverport[MAX_PORT_LEN];
			char kmodport[MAX_PORT_LEN];
			int maxpingcount;
			int pingtimeout;
			int res_num;
			int site_num;
			int node_num;
			int local_site_id;
			int local_node_id;
			uint32_t len;
		}__attribute__((packed));
	};

	char data[0];
};

struct site_conf_packet {
	union {
		struct {
			int id;
			int mode;
			int node_num;
			char sitename[MAX_HOSTNAME_LEN];
		}__attribute__((packed));
	};

	char data[0];
};

struct node_conf_packet {
	union {
		struct {
			int id;
			char hostname[MAX_HOSTNAME_LEN];
			char ipaddr[MAX_IPADDR_LEN];
			char port[MAX_PORT_LEN];
		}__attribute__((packed));
	};

	char data[0];
};

struct res_conf_packet {
	union {
		struct {
			int id;
			char name[MAX_NAME_LEN];
			int runsite_num;
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

struct runsite_conf_packet {
	union {
		struct {
			int id;
			int proto;
			int runnode_num;
			char ipaddr[MAX_IPADDR_LEN];
			char port[MAX_PORT_LEN];
			char disk[MAX_NAME_LEN];
			char bwr_disk[MAX_NAME_LEN];
		}__attribute__((packed));
	};

	char data[0];
};

#endif // __PACKET_INC__
