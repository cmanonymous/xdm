#ifndef HADM_CONFIG_H
#define HADM_CONFIG_H

#include <linux/module.h>

#include "hadm_def.h"

struct server_config {
	int id;
	char localipaddr[MAX_IPADDR_LEN];
	char localport[MAX_PORT_LEN];
	char remoteipaddr[MAX_IPADDR_LEN];
	char remoteport[MAX_PORT_LEN];
};

struct node_config {
	int id;
	int server_id;
	char hostname[MAX_HOSTNAME_LEN];
};

struct runnode_config {
	int id;
	int proto;
	char disk[MAX_NAME_LEN];
	char bwr_disk[MAX_NAME_LEN];
};

struct res_config {
	int id;
	char name[MAX_NAME_LEN];
	int runnode_num;
	uint64_t data_len;
	uint64_t meta_offset;
	uint64_t dbm_offset;
	uint64_t dbm_size;
	uint64_t bwr_offset;
	uint64_t bwr_disk_size;
	struct runnode_config *runnodes;
};

struct config {
	/* gobal */
	char kmodport[MAX_PORT_LEN];
	int ping;
	int pingtimeout;

	/* server */
	int local_server_id;
	int server_num;
	struct server_config *servers;

	/* kmod node */
	int local_node_id;
	int node_num;
	struct node_config *nodes;

	/* resource */
	int res_num;
	struct res_config *res;
};

struct hadmdev;

struct config *alloc_config(void);
void free_config(struct config *cfg);
struct config *unpack_config(struct conf_packet *conf_pkt);

extern int get_node_id(void);
extern uint32_t get_connected_nodes(struct hadmdev *dev);
extern uint32_t get_ready_nodes(struct hadmdev *dev);
extern int is_primary(struct hadmdev *dev, int node_id);
extern void dump_config(const char *msg, struct config *cfg);

#endif	/* HADM_CONFIG_H */
