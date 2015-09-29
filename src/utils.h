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
int trim_nonlocal_res(struct config *cfg);

int pack_fill_bwr(struct conf_packet *conf_pkt, struct config *cfg);

int get_res_path(struct res_config *res, int site_idx,
                char *dev_name, char *bwr_name);

int show_packet(struct config *cfg, struct res_config *res, struct packet *pkt);

char *get_site_name(struct config *cfg, int site_id);
char *get_site_ip(struct config *cfg, int site_id);
int get_res_node_proto(struct res_config *res, int site_id);
int get_disk_size(char *name, unsigned long *size);
int get_res_disk_size(struct res_config *res, struct config *cfg,
                unsigned long *disk_size, unsigned long *bwr_disk_size);
int get_primary_id(struct packet *pkt);
struct site_state_packet *get_site_state(struct packet *pkt, int id);

struct site_config *find_site(struct config *cfg, char *argv[]);
struct site_config *find_site_by_id(struct config *cfg, int id);
struct site_config *find_site_by_name(struct config *cfg, char *hostname);
struct site_config *find_site_by_ip(struct config *cfg, char *ip);

char *md5_print(char *out, uint8_t *in);
int node_belong_res(struct node_config *node, struct res_config * res);
int check_response(int fd);
void pr_meta_info(char *addr);

void daemonize();
void pr_config(struct config *cfg);
void pr_global_config(struct config *cfg);
void pr_site_config(struct site_config *site);
void pr_res_config(struct res_config *res_config);
void pr_runsite_config(struct runsite_config *runsite_config);
void pr_node_config(struct node_config *node);
void pr_runnode_config(struct node_config *node);

#endif // __UTILS_H__
