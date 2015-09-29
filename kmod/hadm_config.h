#ifndef HADM_CONFIG_H
#define HADM_CONFIG_H

#include <linux/module.h>

#include "hadm_def.h"

struct site_config {
	int id;
	int mode;
	char name[MAX_HOSTNAME_LEN];
	char ipaddr[MAX_IPADDR_LEN];
	char port[MAX_PORT_LEN];
	int node_num;
	struct node_config *nodes;
};

struct node_config {
	int id;
	char hostname[MAX_HOSTNAME_LEN];
	char ipaddr[MAX_IPADDR_LEN];
	char port[MAX_PORT_LEN];
};

struct runsite_config {
	int id;
	int proto;
	char ipaddr[MAX_IPADDR_LEN];
	char port[MAX_PORT_LEN];
	char disk[MAX_NAME_LEN];
	char bwr_disk[MAX_NAME_LEN];
	int runnode_num;
	struct node_config *runnodes;
};

struct res_config {
	int id;
	char name[MAX_NAME_LEN];
	uint64_t data_len;
	uint64_t meta_offset;
	uint64_t dbm_offset;
	uint64_t dbm_size;
	uint64_t bwr_offset;
	uint64_t bwr_disk_size;
	int runsite_num;
	struct runsite_config *runsites;
};

struct config {
	char serverip[MAX_IPADDR_LEN];
	char serverport[MAX_PORT_LEN];
	char kmodport[MAX_PORT_LEN];
	int maxpingcount;
	int pingtimeout;
	int node_num;
	int site_num;
	struct site_config *sites;
	int res_num;
	struct res_config *res;
	int local_node_id;
	int local_site_id;
};

struct hadmdev;

struct config *alloc_config(void);
void free_config(struct config *cfg);

void unpack_runsite(struct runsite_config *runsite_cfg, struct runsite_conf_packet *runsite_conf_pkt);

void unpack_res(struct res_config *res_cfg, struct res_conf_packet *res_conf_pkt);

void unpack_site(struct site_config *site_cfg, struct site_conf_packet *site_conf_pkt);

struct config *unpack_config(struct conf_packet *conf_pkt);

struct res_config *find_resource(struct config *cfg, int id);
struct site_config *find_site(struct config *cfg, int id);
extern int get_site_id(void);
extern int get_node_id(void);
extern uint32_t get_connected_sites(struct hadmdev *dev);
extern int is_primary(struct hadmdev *dev, int site_id);

extern void pr_config(struct config *cfg);
extern void pr_global_config(struct config *cfg);
extern void pr_site_config(struct site_config *site);
extern void pr_node_config(struct node_config *node);
extern void pr_res_config(struct res_config *res_config);
extern void pr_runsite_config(struct runsite_config *runsite_config);
extern void pr_runnode_config(struct node_config *node);

#endif	/* HADM_CONFIG_H */
