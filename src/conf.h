#ifndef __CONF_H__
#define __CONF_H__

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

struct res_config {
	int id;
	char name[MAX_NAME_LEN];  //with the find_res_by_name function, name must unique in local
	uint64_t data_len;
	uint64_t meta_offset;
	uint64_t dbm_offset;
	uint64_t dbm_size;
	int runnode_num;
	struct runnode_config *runnodes;
};

struct runnode_config {
	int id;
	int proto;
	char disk[MAX_NAME_LEN];
	char bwr_disk[MAX_NAME_LEN];
};

struct config {
	/* gobal */
	char kmodport[MAX_PORT_LEN];
	int ping;
	int pingtimeout;

	/* server */
	int local_server_idx;	//NOTE: servers[]下标
	int server_num;
	struct server_config *servers;

	/* kmod node */
	int local_node_id;	//NOTE：是local node在nodes[]数组里的下标，不是node->id
	int node_num;
	struct node_config *nodes;

	/* resource */
	int res_num;
	struct res_config *res;
};

char *trim(const char *str);

struct config *alloc_config();

void free_config(struct config *cfg);

struct config *load_config(const char *filename);

int align_packet_size(int size);

int get_conf_packet_size(struct config *cfg);

struct conf_packet *alloc_conf_packet(struct config *cfg);

void free_conf_packet(struct conf_packet *conf_pkt);

struct conf_packet *pack_config(struct config *cfg);

struct conf_packet *pack_config_for_res(struct config *cfg,
		struct res_config *res);

struct node_config *get_local_node(struct config *cfg);

struct node_config *find_node(struct config *cfg, char *argv[]);

struct node_config *find_node_by_id(struct config *cfg, int id);

struct server_config *find_server_by_id(struct config *cfg, int id);

char *get_server_ip(struct config *cfg, int id);

struct res_config *find_res_by_name(const char *res_name, struct config *cfg);

char *get_node_ip(struct config *cfg, int node_id);

int get_res_node_proto(struct res_config *res, int node_id);

char *get_node_name(struct config *cfg, int node_id);

void pr_global_config(struct config *c);
void pr_server_config(struct server_config *s);
void pr_runnode_config(struct runnode_config *r);
void pr_res_config(struct res_config *r);
void pr_config(struct config *c);

#endif // __CONF_H__
