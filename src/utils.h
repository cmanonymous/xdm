#ifndef __UTILS_H__
#define __UTILS_H__

#define MD5_FORMAT \
	"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define MD5_ARGS(md5_hash) \
	md5_hash[0],  md5_hash[1],  md5_hash[2],  md5_hash[3], \
	md5_hash[4],  md5_hash[5],  md5_hash[6],  md5_hash[7], \
	md5_hash[8],  md5_hash[9],  md5_hash[10], md5_hash[11],\
	md5_hash[12], md5_hash[13], md5_hash[14], md5_hash[15]

int make_timespec(long msec, struct timespec *ts);

int check_root();

int check_module();

int check_kmod(const char *kmod_name);

int check_local_resource(struct res_config *res, struct config *cfg);

int get_bwr_info(struct res_config *res, struct config *cfg, uint64_t *data_len,
                 uint64_t *meta_offset, uint64_t *dbm_offset, uint64_t *dbm_size,
                 uint64_t *bwr_offset, uint64_t *bwr_disk_size);

int pack_fill_bwr(struct conf_packet *conf_pkt, struct config *cfg);

int get_res_path(struct res_config *res, struct config *cfg, int node_idx,
                char *dev_name, char *bwr_name);

int show_packet(struct config *cfg, struct res_config *res, struct packet *pkt);

char *get_node_name(struct config *cfg, int node_id);
char *get_node_ip(struct config *cfg, int node_id);
int get_res_node_proto(struct res_config *res, int node_id);
int get_disk_size(char *name, unsigned long *size);
int get_res_disk_size(struct res_config *res, struct config *cfg,
                unsigned long *disk_size, unsigned long *bwr_disk_size);
uint64_t get_bwr_size(uint64_t sectors);
int get_primary_id(struct packet *pkt);
struct node_state_packet *get_node_state(struct packet *pkt, int id);

struct node_config *find_node(struct config *cfg, char *argv[]);

char *md5_print(char *out, uint8_t *in);
int node_belong_res(struct node_config *node, struct res_config * res);
int server_belong_res(struct config *cfg, struct server_config *server, struct res_config *res);
int check_splitbrain(struct packet *pkt);
int check_response(int fd);
void pr_meta_info(char *addr);
void pr_bwr_meta_info(char *addr);
void pr_dbm_cnt(void *start, uint64_t size);

void daemonize();
void pr_config(struct config *cfg);

#endif // __UTILS_H__
