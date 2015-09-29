#ifndef __CONF_H__
#define __CONF_H__

struct site_config {
	int id;
	int mode;
	char sitename[MAX_HOSTNAME_LEN];
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
	char name[MAX_NAME_LEN];  //with the find_res_by_name function, name must unique in local
	uint64_t data_len;
	uint64_t meta_offset;
	uint64_t dbm_offset;
	uint64_t dbm_size;
	int runsite_num;
	struct runsite_config *runsites;
};

struct config {
	char serverip[MAX_IPADDR_LEN];
	char serverport[MAX_PORT_LEN];
	char kmodport[MAX_PORT_LEN];
	int pingtimeout;
	int maxpingcount;
	int site_num;
	int node_num;
	struct site_config *sites;
	int res_num;
	struct res_config *res;
	int local_site_id;
	int local_node_id;
};

char *trim(const char *str);

struct config *alloc_config();

void free_config(struct config *cfg);

struct config *load_config(const char *filename);

xmlXPathObjectPtr exec_xpath_expr(xmlXPathContextPtr ctx, const char *expr);

char *get_content(xmlXPathContextPtr ctx, const char *expr);

int get_global(xmlXPathContextPtr ctx, struct config *cfg);

int get_serverip(xmlXPathContextPtr ctx, struct config *cfg);

int get_serverport(xmlXPathContextPtr ctx, struct config *cfg);

int get_kmodport(xmlXPathContextPtr ctx, struct config *cfg);

int get_ping(xmlXPathContextPtr ctx, struct config *cfg);

int get_pingtimeout(xmlXPathContextPtr ctx, struct config *cfg);

int get_node(xmlXPathContextPtr ctx, struct config *cfg, int site_idx, int idx);

int get_nodes(xmlXPathContextPtr ctx, struct config *cfg);

int get_runsite(xmlXPathContextPtr ctx, struct config *cfg, int res_index, int runsite_index);

int get_runsites(xmlXPathContextPtr ctx, struct config *cfg, int index);

int get_res(xmlXPathContextPtr ctx, struct config *cfg, int index);

int get_resources(xmlXPathContextPtr ctx, struct config *cfg);

int align_packet_size(int size);

int get_conf_packet_size(struct config *cfg);

struct conf_packet *alloc_conf_packet(struct config *cfg);

void free_conf_packet(struct conf_packet *conf_pkt);

void pack_runsite(struct runsite_conf_packet *runsite_conf_pkt, struct runsite_config *runsite_cfg);

void pack_res(struct res_conf_packet *res_conf_pkt, struct res_config *res_cfg);

void pack_node(struct node_conf_packet *node_conf_pkt, struct node_config *node_cfg);

struct conf_packet *pack_config(struct config *cfg);

int get_local_node_id(struct config *cfg, int *node_idp);

struct res_config *find_res_by_name(const char *res_name, struct config *cfg);

#endif // __CONF_H__
