#define USE_HADM_STR_ERRNO
#include "common.h"
#include "common_string.h"
#include "../include/bwr.inc"

#ifdef HADM_DEBUG
#define HADM_DEBUG_SET 1
#else
#define HADM_DEBUG_SET 0
#endif

#define debug_print(fmt, ...)\
        do { if(HADM_DEBUG_SET) fprintf(stdout, (fmt), __VA_ARGS__); } while (0)

#define NO_LESS_SUB(x, y) (x > y ? x - y : 0)

#define DATA_ALIGN 9
#define META_DATA_SIZE_BIT 20
#define META_DATA_SIZE (1U << META_DATA_SIZE_BIT)
#define SECON_STATE_FMT "\t%-*s: %s\n" /* host name */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: %s(%s)\n"/* replication mode */\
        "\t%-*s: %s\n"/* disk status */\
        "\t%-*s: %s\n"/* data status */\
        "\t%-*s: %s\n"/* replication status */\
        "\t%-*s: %lu\n"/* replication speed */\
        "\t%-*s: %s\n"/* network status */\
        "\t%-*s: %lu\n"/* bwr behind */\
        "\t%-*s: %lu\n"/* dbm size */\
        "\t%-*s: %lu\n"/* time distance */

#define PRI_STATE_FMT "\t%-*s: %s\n" /* host name */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: /dev/%s\n"/*dev path */\
        "\t%-*s: %lu\n"/* uuid */\
        "\t%-*s: %lu\n"/* seq_id */\
        "\t%-*s: %s\n"/* disk state */\
        "\t%-*s: %s\n"/* data state */\
        "\t%-*s: %s\n"/* device state */\
        "\t%-*s: %lu\n"/* IO stat */\
        "\t%-*s: %s\n"/* disk device */\
        "\t%-*s: %lu\n"/* disk size */\
        "\t%-*s: %s\n"/* bwr device */\
        "\t%-*s: %lu\n"/* bwr disk size */\
        "\t%-*s: %u\n"/* secondary num# */

#define NODE_STATE_FMT_LEN 20
#define NODE_STATE_FMT "\t%s%-*s: %d%s\n"/* node id */\
        "\t%-*s: %s\n"/* node role */\
        "\t%-*s: %s\n"/* host name */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: %s\n"/* resource name */\
        "\t%-*s: %s\n"/* disk device */\
        "\t%-*s: %lu\n"/* disk size */\
        "\t%-*s: %s\n"/* bwr device */\
        "\t%-*s: %lu\n"/* bwr disk size */\
        "\t%-*s: %s\n"/* device state */\
        "\t%-*s: %s\n"/* cstate */\
        "\t%-*s: %s\n"/* dstate */
#define NONLOCAL_STATE_FMT "\t%-*s: %s\n" /* nstate */
#define EXTER_STATE_FMT ""\
        "\t%-*s: %lu\n"/* bwr sizee */\
        "\t%-*s: %lu\n"/* dbm_size */
#define DOWN_STATE_FMT "\t%-*s: %s\n" /* nstate */

int make_timespec(long msec, struct timespec *ts)
{
        int ret;
        long sec;
        long nsec;

        sec = msec / 1000;
        nsec = (msec % 1000) * 1000 * 1000;

        ret = clock_gettime(CLOCK_REALTIME, ts);
        if(ret < 0) {
                return ret;
        }

        ts->tv_sec += sec;
        ts->tv_nsec += nsec;

        return ret;
}

int check_root()
{
        return getuid() == 0;
}

int check_module()
{
        return check_kmod(MODULE_NAME);
}

int check_kmod(const char *kmod_name)
{
        FILE *file;
        char line[BUFSIZ];
        int ret = 0;
        char *tmp;

        file = fopen(MODULE_FILE, "r");
        if(file == NULL) {
                log_error("error: can not open module file.");
                return -1;
        }

        while(!feof(file)) {
                memset(line, 0, sizeof(line));
                tmp = fgets(line, sizeof(line), file);

                if(!strncmp(kmod_name, line, strlen(kmod_name))) {
                        ret = 1;
                        break;
                }
        }

        fclose(file);

        return ret;
}

int check_local_resource(struct res_config *res, struct config *cfg)
{
        int ret = 0;
        int idx;
        struct runsite_config *res_iter;

        for (idx = 0; idx < res->runsite_num; idx++) {
                res_iter = &res->runsites[idx];
                if (cfg->local_site_id == res_iter->id){
                        ret = 1;
                        break;
                }
        }

        return ret;
}

void daemonize()
{
	daemon(0, 0);
}

int get_bwr_info(struct res_config *res, struct config *cfg, uint64_t *data_len,
                 uint64_t *meta_offset, uint64_t *dbm_offset, uint64_t *dbm_size,
                 uint64_t *bwr_offset, uint64_t *bwr_disk_size)
{
        int fd;
        int idx;
        int local_id;
        int ret;
        char res_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};
        uint64_t data_beg_sector, data_end_sector;
        uint64_t total_dbm_sectors;
        uint64_t num_blocks = 0;

        if (get_res_path(res, cfg->local_site_id, res_name, bwr_name) == -1) {
                log_error("error: can't get resource path in config file.");
                return -1;
        }

        fd = open(res_name, O_RDONLY);
        if (fd == -1) {
                log_error("error: can't open resource device: %s.", strerror(errno));
                return -1;
        }
        ret = ioctl(fd, BLKGETSIZE, &num_blocks);
        if (ret == -1) {
                log_error("error: ioctl resource device : %s.", strerror(errno));
                return -1;
        }
	num_blocks = (num_blocks >> 15) <<15 ;
        total_dbm_sectors = MAX_NODES * num_blocks / (BLK_SIZE * 8);
        close(fd);

        fd = open(bwr_name, O_RDONLY);
        if (fd == -1) {
                log_error("error: open bwr device  : %s", strerror(errno));
                return -1;
        }
        ret = ioctl(fd, BLKGETSIZE, &num_blocks);
        if (ret == -1) {
                log_error("error: ioctl bwr device : %s", strerror(errno));
                return -1;
        }
	close(fd);

        *meta_offset = 0;
        *dbm_offset = META_DATA_SIZE / SECTOR_SIZE; /* 1M */
        *dbm_size = total_dbm_sectors / MAX_NODES;
        data_beg_sector = ((((META_DATA_SIZE / SECTOR_SIZE) + total_dbm_sectors) + DATA_ALIGN - 1) / DATA_ALIGN) * DATA_ALIGN;
        data_end_sector = (num_blocks / DATA_ALIGN) * DATA_ALIGN;
        *bwr_offset = data_beg_sector;
        *data_len = data_end_sector - data_beg_sector;
        *bwr_disk_size = num_blocks << SECTOR_SIZE_BIT; /* bytes */

        return 0;
}

int trim_nonlocal_res(struct config *cfg)
{
        int ridx, nidx, non_locals;
        struct res_config *res, *res_iter;
        struct runsite_config *site;
		int i = 0;

        non_locals = 0;
        res = malloc(sizeof(struct res_config) * cfg->res_num);
        if (res == NULL) {
                log_error("error: not enough memory!");
                return -1;
        }
        memset(res, 0, sizeof(struct res_config) * cfg->res_num);

        for (ridx = 0; ridx < cfg->res_num; ridx++) {
                res_iter = &cfg->res[ridx];
                for (nidx = 0; nidx < res_iter->runsite_num; nidx++) {
                        site = &res_iter->runsites[nidx];
                        if (site->id == cfg->local_site_id)
                                break;
                }

                if (nidx < res_iter->runsite_num) {
                        memcpy(&res[i++], res_iter, sizeof(struct res_config));
                }
                else {
                        non_locals++;
                }
        }

        free(cfg->res);
        cfg->res = res;
        cfg->res_num -= non_locals;
        return 0;
}

struct res_conf_packet *res_start(struct conf_packet *pkt)
{
	struct site_conf_packet *site;
	char *ptr;
	int i;

	ptr = pkt->data;	/* res start */
	for (i = 0; i < pkt->site_num; i++) {
		site = (struct site_conf_packet *)ptr;
		ptr = site->data;
		ptr += site->node_num * sizeof(struct node_conf_packet);
	}

	return (struct res_conf_packet *)ptr;
}

struct res_conf_packet *res_entry(struct conf_packet *cfg_pkt, int id)
{
	struct res_conf_packet *res;
	struct runsite_conf_packet *runsite;
	char *ptr;
	int i, j;

	res = res_start(cfg_pkt);
	for (i = 0; i < id; i++) {
		ptr = (char *)res->data; /* runsite start */
		for (j = 0; j < res->runsite_num; j++) {
			runsite = (struct runsite_conf_packet *)ptr;
			ptr = runsite->data; /* runnode start */
			ptr += runsite->runnode_num * sizeof(struct node_conf_packet);
		}
		res = (struct res_conf_packet *)ptr;
	}

	return res;
}

int pack_fill_bwr(struct conf_packet *conf_pkt, struct config *cfg)
{
	int idx;
	int ret;
	uint64_t data_len;
	uint64_t meta_offset;
	uint64_t dbm_offset;
	uint64_t dbm_size;
	uint64_t bwr_offset;
	uint64_t bwr_disk_size;
	struct res_conf_packet *res_pkt;
	struct res_config *res;

	for (idx = 0; idx < conf_pkt->res_num; idx++) {
		res_pkt = res_entry(conf_pkt, idx);
		res = find_res_by_name(res_pkt->name, cfg);
		if (!res) {
			log_error("error: can not find resource %s", res_pkt->name);
			return -ECMD_NO_RESOURCE;
		}

		ret = get_bwr_info(res, cfg,
				   &data_len, &meta_offset, &dbm_offset, &dbm_size,
				   &bwr_offset, &bwr_disk_size);
		if (ret < 0)
			return -ECMD_GET_BWRINFO;

		res_pkt->data_len = data_len;
		res_pkt->meta_offset = meta_offset;
		res_pkt->dbm_offset = dbm_offset;
		res_pkt->dbm_size = dbm_size;
		res_pkt->bwr_offset = bwr_offset;
		res_pkt->bwr_disk_size = bwr_disk_size;
	}

	return 0;
}

int get_res_path(struct res_config *res, int site_idx, char *dev_name, char *bwr_name)
{
        int idx;
        struct runsite_config *runsite;

        for (idx = 0; idx <= res->runsite_num; idx++)
        {
                runsite = &res->runsites[idx];
                if (site_idx == runsite->id)
                {
                        strncpy(dev_name, runsite->disk, strlen(runsite->disk));
                        strncpy(bwr_name, runsite->bwr_disk, strlen(runsite->bwr_disk));
                        return 0;
                }
        }
        return -1;
}

char *get_site_name(struct config *cfg, int site_id)
{
        int idx;
        struct site_config *site;

        for (idx = 0; idx < cfg->site_num; idx++) {
                site = &cfg->sites[idx];
                if (site_id == site->id)
                        return site->sitename;
        }
        return NULL;
}

int get_res_site_proto(struct res_config *res, int site_id)
{
        int idx;
        struct runsite_config *site;

        for (idx = 0; idx < res->runsite_num; idx++) {
                site = &res->runsites[idx];
                if (site_id == site->id)
			return site->proto;
        }
        return -1;
}

char *get_site_ip(struct config *cfg, int site_id)
{
        int idx;
        struct site_config *site;

        for (idx = 0; idx < cfg->site_num; idx++) {
                site = &cfg->sites[idx];
                if (site_id == site->id)
                        return site->ipaddr;
        }
        return NULL;
}

int get_res_disk_size(struct res_config *res, struct config *cfg,
                unsigned long *disk_size, unsigned long *bwr_disk_size)
{
        int ret;
        int fd;
        long long num_blocks = 0;
        char dev_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};

        ret = get_res_path(res, cfg->local_site_id, dev_name, bwr_name);
        if (ret < 0) {
                log_error("error: can not find the resource path.");
                return -ECMD_NO_PATH;
        }

        ret = get_disk_size(dev_name, disk_size);
        if (ret < 0) {
                log_error("error: can not get disk size.");
                return -ECMD_IO_ERR;
        }
	*disk_size = (*disk_size >> 24) << 24;

        ret = get_disk_size(bwr_name, bwr_disk_size);
        if (ret == -1) {
                log_error("error: can not get bwr disk size.");
                return -ECMD_IO_ERR;
        }

        return ret;
}

int get_disk_size(char *name, unsigned long *size)
{
        int fd, ret;
        unsigned long num_blocks;

        fd = open(name, O_RDONLY);
        if (fd == -1) {
                log_error("error: open disk: %s", strerror(errno));
                return -1;
        }

        ret = ioctl(fd, BLKGETSIZE, &num_blocks);
        if (ret == -1) {
                log_error("error: ioctl disk: %s", strerror(errno));
                return -1;
        }

        *size = num_blocks * SECTOR_SIZE;

        return ret;
}

int get_primary_id(struct packet *pkt)
{
        int idx;
        struct site_state_packet *site_state_pkt, *iter;

        site_state_pkt = (struct site_state_packet *)(pkt->data);
        for (idx = 0; idx < pkt->site_state_num; idx++) {
                iter = &site_state_pkt[idx];
                if (iter->role == R_PRIMARY) {
                        return iter->id;
                        break;
                }
        }

        return -1;
}

struct site_state_packet *get_site_state(struct packet *pkt, int id)
{
        int idx;
        struct site_state_packet *site_state_pkt;

        site_state_pkt = (struct site_state_packet *)(pkt->data);
        for (idx = 0; idx < pkt->site_state_num; idx++) {
                if (site_state_pkt[idx].id == id) {
                        return &site_state_pkt[idx];
                }
        }

        return NULL;
}

struct site_config *find_site(struct config *cfg, char *argv[])
{
        int type;

        type = argv[1] ? atoi(argv[1]) : 0;

        switch(type) {
                case 0:
                        return find_site_by_id(cfg, atoi(argv[0]));
                case 1:
                        return find_site_by_name(cfg, argv[0]);
                case 2:
                        return find_site_by_ip(cfg, argv[0]);
                default:
                        return NULL;
        }
}

struct site_config *find_site_by_id(struct config *cfg, int id)
{
        int idx;

        for (idx = 0; idx < cfg->site_num; idx++) {
                if (cfg->sites[idx].id == id)
                        return &cfg->sites[idx];
        }

        return NULL;
}

/* Right now, site have no name in config file. */
struct site_config *find_site_by_name(struct config *cfg, char *sitename)
{
        return NULL;
}

struct site_config *find_site_by_ip(struct config *cfg, char *ip)
{
        int idx;

        for (idx = 0; idx < cfg->site_num; idx++) {
                if (strncmp(cfg->sites[idx].ipaddr, ip, strlen(cfg->sites[idx].ipaddr)) == 0)
                        return &cfg->sites[idx];
        }

        return NULL;
}

int site_belong_res(struct site_config *node, struct res_config * res)
{
        int idx;

        for (idx = 0; idx < res->runsite_num; idx++) {
                if (res->runsites[idx].id == node->id)
                        return 1;
        }

        return 0;
}

int check_device_up(struct  packet *pkt, struct config *cfg)
{
        struct site_state_packet *state_pkt;

        state_pkt = get_site_state(pkt, cfg->local_site_id);
        if (!state_pkt) {
                return 0;
        }
        return state_pkt->dev_state == DEV_UP;
}

int check_response(int fd)
{
        int ret, err;
        struct packet *pkt;

        pkt = packet_recv(fd);
        if (pkt == NULL) {
                log_error("error: receive response packet failed.");
                ret = -1;
                goto out;
        }
        else if (pkt->errcode != 0) {
                err = -pkt->errcode;

                log_error("error: %s",
                                hadm_str_errno[err]);
                ret = pkt->errcode;
                goto out;
        }

        ret = 0;
out:
        free(pkt);
        return ret;
}

#define BITS_HASH_SIZE 1 << 8

int numb_bits(int numb)
{
        int nr = numb ? 1 : 0;

        while (numb &= (numb - 1))
                nr++;
        return nr;
}

int bits(void *addr, uint64_t size)
{
        int i, nr = 0;
        unsigned char *iter;
        static unsigned char BITS_HASH[BITS_HASH_SIZE] = {0};

        if (!BITS_HASH[1])
                for (i=0; i < BITS_HASH_SIZE; i++)
                        BITS_HASH[i] = numb_bits(i);

        for (iter = addr; size--; iter++)
                nr += BITS_HASH[*iter];
        return nr;
}

void pr_meta_info(char *addr)
{
        int i;
        struct bwr_meta *meta;
        char md5[33];

        meta = (struct bwr_meta *)addr;
        printf("magic: %llx, dev_id: %d, disk_size: %llu, bwr_disk_size: %llu, "
               "meta_start: %llu, dbm_start: %llu, bwr_start: %llu\n",
               meta->magic, meta->dev_id, meta->disk_size, meta->bwr_disk_size,
               meta->meta_start, meta->dbm_start, meta->bwr_start);

        printf("\nhead: ");
        for (i = 0; i < MAX_NODES; i++) {
                printf("%lld ", meta->head[i]);
        }
        printf("\n");
        printf("tail: %llu, disk_state: %d\n", meta->tail, meta->disk_state);
        printf("\n");

        printf("last_primary: id=%d, uuid=%lld, bwr_seq=%lld\n\tlast_page_sector:%llu, last_page_damaged:%d, last_page_md5:%s\n",
               meta->last_primary.id, meta->last_primary.uuid, meta->last_primary.bwr_seq,
               meta->last_primary.last_page, meta->last_primary.last_page_damaged,
	       md5_print(md5, meta->last_primary.last_page_md5));
        printf("local_primary: id=%d, uuid=%lld, bwr_seq=%lld\n\n",
               meta->local_primary.id, meta->local_primary.uuid, meta->local_primary.bwr_seq);
}

int show_packet(struct config *cfg, struct res_config *res, struct packet *pkt)
{
        int i, idx;
        int ret;
        int primary_idx = -1;
	uint64_t uuid;
	uint64_t bwr_seq;
	uint64_t tail, node_head, snd_head;
        uint64_t disk_size, bwr_disk_size;
        struct site_state_packet *site_state_pkt;
        struct site_state_packet *iter;
        char dev_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};
        char node_name[MAX_NAME_LEN] = {0};

        ret = get_res_disk_size(res, cfg, &disk_size, &bwr_disk_size);
        if (ret < 0) {
                log_error("error: can not get resource disk/bwr size.");
                return ret;
        }

	uuid = pkt->uuid;
	bwr_seq = pkt->bwr_seq;
        site_state_pkt = (struct site_state_packet *)(pkt->data);
        printf("HA Disk Mirroring Device: %s\n", res->name);
        for (idx = 0; idx < pkt->site_state_num; idx++) {
                iter = &site_state_pkt[idx];
                if (primary_idx < 0) {
			if (iter->role == R_PRIMARY) {
				primary_idx = idx;
				idx = -1;
			} else if (idx == pkt->site_state_num - 1 && !idx) {
				primary_idx = pkt->site_state_num;
				idx = -1;
			}
			continue;
		}
                iter = &site_state_pkt[(idx + primary_idx) % pkt->site_state_num];
		ret = get_res_path(res, iter->id, dev_name, bwr_name);
		tail = iter->tail;

		if (!idx) {
			if (primary_idx == pkt->site_state_num) {
				if (iter->id != cfg->local_site_id) {
					log_error("error: Not local status packet(no primary).");
					return -ECMD_NO_STATE;
				}
				printf("Secondary:\n");
			} else
				printf("Primary:\n");
			printf(PRI_STATE_FMT,
					NODE_STATE_FMT_LEN, "Host Name", get_site_name(cfg, iter->id),
					NODE_STATE_FMT_LEN, "Host IP", get_site_ip(cfg, iter->id),
					NODE_STATE_FMT_LEN, "Dev Name", res->name,
					NODE_STATE_FMT_LEN, "UUID", uuid,
					NODE_STATE_FMT_LEN, "Seq ID", bwr_seq,
					NODE_STATE_FMT_LEN, "Disk Status", dstate_name[iter->disk_state],
					NODE_STATE_FMT_LEN, "Data Status", datastate_name[iter->data_state],
					NODE_STATE_FMT_LEN, "Dev Status", dev_state_name[iter->dev_state],
					NODE_STATE_FMT_LEN, "IO Stat", 0LLU,
					NODE_STATE_FMT_LEN, "Backend Dev", dev_name,
					NODE_STATE_FMT_LEN, "Bdev Size", disk_size,
					NODE_STATE_FMT_LEN, "BWR Dev", bwr_name,
					NODE_STATE_FMT_LEN, "BWR Size", bwr_disk_size,
					NODE_STATE_FMT_LEN, "Total Secondary", pkt->site_state_num - 1);
			continue;
		}

		printf("Secondary:\n");
                printf(SECON_STATE_FMT,
                                NODE_STATE_FMT_LEN, "Host Name", get_site_name(cfg, iter->id),
                                NODE_STATE_FMT_LEN, "Host IP", get_site_ip(cfg, iter->id),
				NODE_STATE_FMT_LEN, "Replication Mode",
				proto_name[iter->protocol],proto_name[get_res_site_proto(res, iter->id)],
                                NODE_STATE_FMT_LEN, "Disk Status", dstate_name[iter->data_state != DATA_CONSISTENT],
                                NODE_STATE_FMT_LEN, "Data Status", datastate_name[iter->data_state],
                                NODE_STATE_FMT_LEN, "Replication Status", cstate_name[iter->c_state],
                                NODE_STATE_FMT_LEN, "Replication Speed", 0LLU,
				NODE_STATE_FMT_LEN, "Network Status", nstate_name[iter->n_state],
				NODE_STATE_FMT_LEN, "BWR Behind", (unsigned long long)NO_LESS_SUB(tail, iter->site_head),
				NODE_STATE_FMT_LEN, "Dbm", iter->dbm_set,
				NODE_STATE_FMT_LEN, "Time Distance", 0LLU);

                memset(dev_name, 0, sizeof(dev_name));
                memset(bwr_name, 0, sizeof(bwr_name));
        }
        return 0;
}

char *md5_print(char *out, uint8_t *in)
{
	snprintf(out, 33, MD5_FORMAT, MD5_ARGS(in));
	return out;
}

void pr_config(struct config *cfg)
{
	int i;

	pr_global_config(cfg);

	printf("\n");
	printf("Total sites: %d\n", cfg->site_num);
	for (i = 0; i < cfg->site_num; i++)
		pr_site_config(&cfg->sites[i]);
	printf("\tlocal_site_id: %d\n", cfg->local_site_id);

	printf("\n");
	printf("Total resources: %d\n", cfg->res_num);
	for (i = 0; i < cfg->res_num; i++)
		pr_res_config(&cfg->res[i]);
}

void pr_global_config(struct config *cfg)
{
	printf("server ip: %s\n", cfg->serverip);
	printf("server port: %s\n", cfg->serverport);
	printf("kmodport: %s\n", cfg->kmodport);
	printf("server maxpingcount: %d\n", cfg->maxpingcount);
	printf("server pingtimeout: %d\n", cfg->pingtimeout);
}

void pr_site_config(struct site_config *site)
{
	int i;

	printf("\tid: %d\n", site->id);
	printf("\tname: %s\n", site->sitename);
	printf("\tmode: %d\n", site->mode);
	printf("\tip: %s\n", site->ipaddr);
	printf("\tport: %s\n", site->port);

	printf("\tTotal %d nodes in site:\n", site->node_num);
	for (i = 0; i < site->node_num; i++) {
		pr_node_config(&site->nodes[i]);
		printf("\n");
	}
}

void pr_node_config(struct node_config *node)
{
	printf("\t\tid: %d\n", node->id);
	printf("\t\thostname: %s\n", node->hostname);
	printf("\t\tip: %s\n", node->ipaddr);
	printf("\t\tport: %s\n", node->port);
}

void pr_res_config(struct res_config *res_config)
{
	int i;

	printf("\tid: %d\n", res_config->id);
	printf("\tname: %s\n", res_config->name);
	printf("\tdatalen: %lu\n", res_config->data_len);
	printf("\tdbm_offset: %lu\n", res_config->dbm_offset);
	printf("\tdbm_size: %lu\n", res_config->dbm_size);

	printf("\tTotal runsite%s: %d\n", res_config->runsite_num > 0 ? "s" : "", res_config->runsite_num);
	for (i = 0; i < res_config->runsite_num; i++)
		pr_runsite_config(&res_config->runsites[i]);
}

void pr_runsite_config(struct runsite_config *runsite_config)
{
	int i;

	printf("\t\tid: %d\n", runsite_config->id);
	printf("\t\tproto: %s\n", runsite_config->proto ? "ASYNC" : "SYNC");
	printf("\t\tipaddr: %s\n", runsite_config->ipaddr);
	printf("\t\tport: %s\n", runsite_config->port);
	printf("\t\tdisk: %s\n", runsite_config->disk);
	printf("\t\tbwr_disk: %s\n", runsite_config->bwr_disk);
	printf("\t\trunnode_num: %d\n", runsite_config->runnode_num);

	for (i = 0; i < runsite_config->runnode_num; i++) {
		pr_runnode_config(&runsite_config->runnodes[i]);
		printf("\n");
	}
}

void pr_runnode_config(struct node_config *node)
{
	printf("\t\t\tid: %d\n", node->id);
	printf("\t\t\thostname: %s\n", node->hostname);
	printf("\t\t\tip: %s\n", node->ipaddr);
	printf("\t\t\tport: %s\n", node->port);
}
