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
	"\t%-*s: %d\n"/* node id */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: %s(%s)\n"/* replication mode */\
        "\t%-*s: %s\n"/* disk status */\
        "\t%-*s: %s\n"/* data status */\
        "\t%-*s: %s\n"/* replication status */\
        "\t%-*s: %llu\n"/* replication speed */\
        "\t%-*s: %s\n"/* network status */\
        "\t%-*s: %llu\n"/* bwr behind */\
        "\t%-*s: %llu\n"/* dbm size */\
        "\t%-*s: %llu\n"/* time distance */

#define PRI_STATE_FMT "\t%-*s: %s\n" /* host name */\
	"\t%-*s: %d\n"/* node id */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: /dev/%s\n"/*dev path */\
        "\t%-*s: %llu\n"/* uuid */\
        "\t%-*s: %llu\n"/* seq_id */\
        "\t%-*s: %s\n"/* disk state */\
        "\t%-*s: %s\n"/* data state */\
        "\t%-*s: %s\n"/* device state */\
        "\t%-*s: %llu\n"/* IO stat */\
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
#define RBWR_STATE_NODE_FMT "\t%-*s: %lu\n" /* rbwr size */
#define RBWR_STATE_NODE_FMT_LEN 8

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

                if(!strcmp(kmod_name, line)) {
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
        struct runnode_config *res_iter;

        for (idx = 0; idx < res->runnode_num; idx++) {
                res_iter = &res->runnodes[idx];
                if (cfg->local_node_id == res_iter->id){
                        ret = 1;
                        break;
                }
        }

        return ret;
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

        if (get_res_path(res, cfg, cfg->local_node_id, res_name, bwr_name) == -1)
        {
                log_error("error: can't get resource path in config file.");
                return -1;
        }

        fd = open(res_name, O_RDONLY);
        if (fd == -1){
                log_error("error: can't open resource device %s: %s.",
				res_name, strerror(errno));
                return -1;
        }
        ret = ioctl(fd, BLKGETSIZE, &num_blocks);
        if (ret == -1){
                log_error("error: ioctl resource device %s: %s.",
				res_name, strerror(errno));
                return -1;
        }
        //num_blocks = ((num_blocks + 32767) / 32768) * 32768;
	num_blocks = (num_blocks >> 15) <<15 ;
        total_dbm_sectors = MAX_NODES * num_blocks / (BLK_SIZE * 8);
        close(fd);

        fd = open(bwr_name, O_RDWR);
        if (fd == -1)
        {
                log_error("error: open bwr device  : %s", strerror(errno));
                return -1;
        }
        ret = ioctl(fd, BLKGETSIZE, &num_blocks);
        if ( ret == -1)
        {
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

int pack_fill_bwr(struct conf_packet *conf_pkt, struct config * cfg)
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

        res_pkt = (struct res_conf_packet *)(conf_pkt->data
			+ (sizeof(struct node_conf_packet) * conf_pkt->node_num)
			+ (sizeof(struct server_conf_packet) * conf_pkt->server_num));
        res = find_res_by_name(res_pkt->name, cfg);
        if (res == NULL) {
                log_error("error: can not find the resource");
                return -ECMD_NO_RESOURCE;
        }
        for (idx = 0; idx < conf_pkt->res_num; idx++){
                ret = get_bwr_info(res, cfg,
                                   &data_len, &meta_offset, &dbm_offset, &dbm_size,
                                   &bwr_offset, &bwr_disk_size);
                if (ret < 0) {
			return -ECMD_GET_BWRINFO;
		}
		res_pkt->data_len = data_len;
		res_pkt->meta_offset = meta_offset;
		res_pkt->dbm_offset = dbm_offset;
		res_pkt->dbm_size = dbm_size;
		res_pkt->bwr_offset = bwr_offset;
		res_pkt->bwr_disk_size = bwr_disk_size;

                res_pkt = (struct res_conf_packet *)(res_pkt->data + res_pkt->runnode_num * sizeof(struct runnode_conf_packet));
                res = find_res_by_name(res_pkt->name, cfg);
        }

        return 0;
}

int get_res_path(struct res_config *res, struct config *cfg, int node_idx, char *dev_name, char *bwr_name)
{
        int idx;
        struct runnode_config *runnode;

        for (idx = 0; idx <= res->runnode_num; idx++)
        {
                runnode = &res->runnodes[idx];
                if (node_idx == runnode->id)
                {
                        strncpy(dev_name, runnode->disk, strlen(runnode->disk));
                        strncpy(bwr_name, runnode->bwr_disk, strlen(runnode->bwr_disk));
                        return 0;
                }
        }
        return -1;
}

uint64_t get_bwr_size(uint64_t sectors)
{
        return sectors * SECTOR_SIZE * (DATA_ALIGN - 1) / DATA_ALIGN;
}

int get_res_disk_size(struct res_config *res, struct config *cfg,
                unsigned long *disk_size, unsigned long *bwr_disk_size)
{
        int ret;
        int fd;
        long long num_blocks = 0;
        char dev_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};

        ret = get_res_path(res, cfg, cfg->local_node_id, dev_name, bwr_name);
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

int trim_nonlocal_res(struct config *cfg)
{
	int ridx, nidx, non_locals;
	struct res_config *res, *res_iter;
	struct runnode_config *node;
	int i = 0;
	int local_id;

	non_locals = 0;
	res = malloc(sizeof(struct res_config) * cfg->res_num);
	if (res == NULL) {
		log_error("error: not enough memory!");
		return -1;
	}
	memset(res, 0, sizeof(struct res_config) * cfg->res_num);

	local_id = cfg->nodes[cfg->local_node_id].id;
	for (ridx = 0; ridx < cfg->res_num; ridx++) {
		res_iter = &cfg->res[ridx];
		for (nidx = 0; nidx < res_iter->runnode_num; nidx++) {
			node = &res_iter->runnodes[nidx];
			if (node->id == cfg->local_node_id)
				break;
		}

		if (nidx < res_iter->runnode_num) {
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

int get_primary_id(struct packet *pkt)
{
        int idx;
        struct node_state_packet *node_state_pkt, *iter;

        node_state_pkt = (struct node_state_packet *)(pkt->data);
        for (idx = 0; idx < pkt->node_state_num; idx++) {
                iter = &node_state_pkt[idx];
                if (iter->role == R_PRIMARY) {
                        return iter->id;
                        break;
                }
        }

        return -1;
}

struct node_state_packet *get_node_state(struct packet *pkt, int id)
{
        int idx;
        struct node_state_packet *node_state_pkt;

        node_state_pkt = (struct node_state_packet *)(pkt->data);
        for (idx = 0; idx < pkt->node_state_num; idx++) {
                if (node_state_pkt[idx].id == id) {
                        return &node_state_pkt[idx];
                }
        }

        return NULL;
}

int node_belong_res(struct node_config *node, struct res_config * res)
{
        int idx;

        for (idx = 0; idx < res->runnode_num; idx++) {
                if (res->runnodes[idx].id == node->id)
                        return 1;
        }

        return 0;
}

int server_belong_res(struct config *cfg, struct server_config *server, struct res_config *res)
{
	int idx;
	struct node_config *node;
	for (idx = 0; idx < res->runnode_num; idx++) {
		node = find_node_by_id(cfg, res->runnodes[idx].id);
		if(node && node->server_id == server->id) {
			return 1;
		}

        }
	return 0;



}

int check_splitbrain(struct packet *pkt)
{
        int idx;
        struct node_state_packet *node_state_pkt, *iter;

        node_state_pkt = (struct node_state_packet *)(pkt->data);
        for (idx = 0; idx < pkt->node_state_num; idx++) {
                iter = &node_state_pkt[idx];
                if (iter->c_state == C_SPLITBRAIN) {
                        return 1;
                        break;
                }
        }

        return 0;
}

int check_device_up(struct  packet *pkt, struct config *cfg)
{
        struct node_state_packet *state_pkt;

        state_pkt = get_node_state(pkt, cfg->local_server_idx);
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

void pr_dbm_cnt(void *start, uint64_t size)
{
        printf(" %d ", bits(start, size));
}

void pr_bwr_meta_info(char *addr)
{
        int i;
        struct bwr_data_meta *meta;
        char md5[33];

        meta = (struct bwr_data_meta *)addr;
	printf("%-*s:%lu\n"
			"%-*s:%lu\n"
			"%-*s:%lu\n"
			"%-*s:%lu\n"
			"%-*s:%lu\n",
			12, "uuid",meta->uuid,
			12, "bwr_seq",meta->bwr_seq,
			12, "bwr_sector",meta->bwr_sector,
			12, "dev_sector",meta->dev_sector,
			12, "checksum",meta->checksum);

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
        struct node_state_packet *node_state_pkt;
        struct node_state_packet *iter;
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
        node_state_pkt = (struct node_state_packet *)(pkt->data);
        printf("HA Disk Mirroring Device: %s\n", res->name);
        for (idx = 0; idx < pkt->node_state_num; idx++) {
                iter = &node_state_pkt[idx];
                if (primary_idx < 0) {
			if (iter->role == R_PRIMARY) {
				primary_idx = idx;
				idx = -1;
			} else if (idx == pkt->node_state_num - 1 && !idx) {
				primary_idx = pkt->node_state_num;
				idx = -1;
			}
			continue;
		}
                iter = &node_state_pkt[(idx + primary_idx) % pkt->node_state_num];
		ret = get_res_path(res, cfg, iter->kmod_id, dev_name, bwr_name);
		tail = iter->tail;

		if (!idx) {
			if (primary_idx == pkt->node_state_num) {
				if (iter->id != cfg->local_server_idx) {
					log_error("error: Not local status packet(no primary).");
					return -ECMD_NO_STATE;
				}
				printf("Secondary:\n");
			} else
				printf("Primary:\n");
			printf(PRI_STATE_FMT,
					NODE_STATE_FMT_LEN, "Host Name", get_node_name(cfg, iter->kmod_id),
					NODE_STATE_FMT_LEN, "Node ID", iter->id,
					NODE_STATE_FMT_LEN, "Host IP", get_server_ip(cfg, iter->id),
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
					NODE_STATE_FMT_LEN, "Total Secondary", pkt->node_state_num - 1);
			continue;
		}

		printf("Secondary:\n");
                printf(SECON_STATE_FMT,
                                NODE_STATE_FMT_LEN, "Host Name", get_node_name(cfg, iter->kmod_id),
				NODE_STATE_FMT_LEN, "Node ID", iter->id,
                                NODE_STATE_FMT_LEN, "Host IP", get_server_ip(cfg, iter->id),
				NODE_STATE_FMT_LEN, "Replication Mode",
				proto_name[iter->protocol],proto_name[get_res_node_proto(res, iter->id)],
                                NODE_STATE_FMT_LEN, "Disk Status", dstate_name[iter->data_state != DATA_CONSISTENT],
                                NODE_STATE_FMT_LEN, "Data Status", datastate_name[iter->data_state],
                                NODE_STATE_FMT_LEN, "Replication Status", cstate_name[iter->c_state],
                                NODE_STATE_FMT_LEN, "Replication Speed", 0LLU,
				NODE_STATE_FMT_LEN, "Network Status", nstate_name[iter->n_state],
				NODE_STATE_FMT_LEN, "BWR Behind", (unsigned long long)NO_LESS_SUB(tail, iter->node_head),
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

void daemonize()
{
	daemon(0, 0);
}
