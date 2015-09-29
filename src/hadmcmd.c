#define USE_HADM_STR_ERRNO
#define _GNU_SOURCE

#include "common.h"
#include "../include/bwr.inc"
#include <getopt.h>

extern char *progname;

static struct option init_options[] = {
	{"local-id", 1, 0, 0},
	{"local-uuid", 1, 0, 0},
	{"local-bwrseq", 1, 0, 0},
	{"local-md5", 1, 0, 0},
	{"local-md5-sector", 1, 0, 0},

	{"last-id", 1, 0, 0},
	{"last-uuid", 1, 0, 0},
	{"last-bwrseq", 1, 0, 0},
	{"last-md5", 1, 0, 0},
	{"last-md5-sector", 1, 0, 0},

	{0, 0, 0, 0}
};

static void __get_resname_from_cmdline(int argc, char *argv[], char *resname, int reslen)
{
        int c, option_index;

        /* rescan anyway */
        optind = 1;
        for (;;) {
                c = getopt_long(argc, argv, "", init_options, &option_index);
                if (c == -1)
                        break;
        }

        if (optind < argc) {
                memcpy(resname, argv[optind], reslen);
        }
}

static int __fill_meta(int argc, char *argv[], struct bwr_meta *meta)
{
        int c, option_index;
        const char *name = "no-name-for-debug";

        if (meta == NULL)
                return -1;

        /* rescan anyway */
        optind = 1;
        for (;;) {
                c = getopt_long(argc, argv, "", init_options, &option_index);
                if (c == -1)
                        break;
                name = init_options[option_index].name;
                switch (c) {
                case 0:
                        if (memcmp(name, "local-id", strlen(name)) == 0) {
                                meta->local_primary.id = atoi(optarg);
                        } else if (memcmp(name, "local-uuid", strlen(name)) == 0) {
                                meta->local_primary.uuid = atol(optarg);
                        } else if (memcmp(name, "local-bwrseq", strlen(name)) == 0) {
                                meta->local_primary.bwr_seq = atol(optarg);
                        } else if (memcmp(name, "local-md5", strlen(name)) == 0) {
                                memcpy(meta->local_primary.last_page_md5, optarg, 16);
                        } else if (memcmp(name, "local-md5-sector", strlen(name)) == 0) {
                                meta->local_primary.last_page = atol(optarg);
                        } else if (memcmp(name, "last-id", strlen(name)) == 0) {
                                meta->last_primary.id = atoi(optarg);
                        } else if (memcmp(name, "last-uuid", strlen(name)) == 0) {
                                meta->last_primary.uuid = atol(optarg);
                        } else if (memcmp(name, "last-bwrseq", strlen(name)) == 0) {
                                meta->last_primary.bwr_seq = atol(optarg);
                        } else if (memcmp(name, "last-md5", strlen(name)) == 0) {
                                memcpy(meta->last_primary.last_page_md5, name, 16);
                        } else if (memcmp(name, "last-md5-sector", strlen(name)) == 0) {
                                meta->last_primary.last_page = atol(optarg);
                        } else {
                        }
                        break;
                case '?':
                        break;
                default:
                        break;
                }
        }

        return 0;
}

int do_init(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        int res_fd;
        int n;
        long long fill_zero_len;
        char *content;
        char dev_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};
        char res_name[MAX_NAME_LEN] = {0};
        uint64_t data_max;
        uint64_t meta_offset;
        uint64_t dbm_offset;
        uint64_t dbm_size;
        uint64_t bwr_offset;
        uint64_t bwr_disk_size;
        int64_t remain;
        struct res_config *res;
        int init_argv_len = argc + 2; /* 2 for init and NULL */
        char *init_argv[init_argv_len];

        if (check_module()) {
                log_error("error: kmod exist.");
                return -ECMD_KMOD_EXIST;
        }

        init_argv[0] = "init";
        for (n = 1; n < init_argv_len - 1; n++)
                init_argv[n] = argv[n-1];
        init_argv[n] = NULL;

        __get_resname_from_cmdline(init_argv_len - 1, init_argv, res_name, MAX_NAME_LEN);
        res = find_res_by_name(res_name, cfg);
        if (res == NULL) {
                log_error("error: can not find this resource.");
                return -ECMD_NO_RESOURCE;
        }

        ret = get_bwr_info(res, cfg, &data_max, &meta_offset, &dbm_offset,
                           &dbm_size, &bwr_offset, &bwr_disk_size);
        if (ret < 0) {
                log_error("error: can not get bwr device meta info.");
                return -ECMD_GET_BWRINFO;
        }

        ret = get_res_path(res, cfg->local_site_id, dev_name, bwr_name);
        if (ret < 0) {
                log_error("error: can not find the resource path.");
                return -ECMD_NO_PATH;
        }
        res_fd = open(bwr_name, O_RDWR | O_SYNC);
        if (res_fd < 0) {
                log_error("error: open device error: %s.", strerror(errno));
                return -ECMD_OPEN_FAIL;
        }

        content = malloc(BUFSIZ);
        if (content == NULL) {
                log_error("error: initial bwr device error. Not enough memory.");
                ret = -ECMD_NOMEM;
                goto out;
        }
        memset(content, 0, BUFSIZ);

        struct bwr_meta *bwr_meta;
        bwr_meta = (struct bwr_meta *)content;
        bwr_meta->magic = MAGIC;
        bwr_meta->dev_id = res->id;
        ret = get_res_disk_size(res, cfg, &bwr_meta->disk_size, &bwr_meta->bwr_disk_size);
        if (ret < 0) {
                log_error("error: can not get resource disk/bwr size.");
                goto fmem;
        }
        bwr_meta->meta_start = 0;
        bwr_meta->bwr_start = bwr_offset;
        bwr_meta->dbm_start = dbm_offset;
        int i;
        for (i = 0; i < MAX_NODES; i++) {
            bwr_meta->head[i] = INVALID_SECTOR;
        }
        for (i = 0; i < res->runsite_num; i++) {
            struct runsite_config *runsite;
            runsite = &res->runsites[i];
            bwr_meta->head[runsite->id] = bwr_offset;
        }
        bwr_meta->tail = bwr_offset;
        bwr_meta->disk_state = D_CONSISTENT;
        bwr_meta->last_primary.id = INVALID_ID;
        bwr_meta->last_primary.uuid = 0;
        bwr_meta->last_primary.bwr_seq = 0;
        bwr_meta->local_primary.id = INVALID_ID;
        bwr_meta->local_primary.uuid = 0;
        bwr_meta->local_primary.bwr_seq = 0;
        __fill_meta(argc, init_argv, bwr_meta);

        write_n(res_fd, content, BUFSIZ);

        memset(content, 0, BUFSIZ);
        remain = bwr_offset * SECTOR_SIZE;
        while (remain > 0) {
                n = write(res_fd, content, BUFSIZ);
                if (n < 0) {
                        log_error("error: write to bwr device error: %s.", strerror(errno));
                        ret = -ECMD_IO_ERR;
                        goto fmem;
                }
                if (n == 0)
                        break;
                remain -= n;
        }

fmem:
        free(content);
out:
        close(res_fd);
        return ret;
}

void do_init_usage()
{
        log_error("usage: hadmctl init <res_name>");
}

int __do_config(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct conf_packet *conf_pkt;

        if(argc != 0) {
                log_error("error: command need no arguement.");
                return -ECMD_WRONG_USAGE;
        }

        conf_pkt = pack_config(cfg);
        if(conf_pkt == NULL) {
                log_error("error: can not config the resource.");
                return -ECMD_NO_RESOURCE;
        }

        pkt = alloc_packet(conf_pkt->len);
        if(pkt == NULL) {
                log_error("error: allocate packet error.");
                ret = -ECMD_NOMEM;
                goto conf_packet_err;
        }

        pkt->type = subcmd->type;

        ret = pack_fill_bwr(conf_pkt, cfg);
        if (ret < 0){
                log_error("error: fill the bwr info in packet failed.");
                goto packet_err;
        }
        memcpy(pkt->data, conf_pkt, conf_pkt->len);

        ret = packet_send(fd, pkt);
        if (ret < 0) {
                log_error("error: send packet to kernel error.");
                ret = -ECMD_NET_ERROR;
                goto packet_err;
        }

        ret = check_response(fd);

packet_err:
        free_packet(pkt);
conf_packet_err:
        free_conf_packet(conf_pkt);
        return ret;
}

void __do_config_usage()
{
        log_error("usage: hadmctl config");
}

int common_device_up(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct res_config *res;
        struct packet *pkt;

        if(argc != 1) {
                log_error("error: command need a arguement.");
                return -ECMD_WRONG_USAGE;
        }

        res = find_res_by_name(argv[0], cfg);
        if(res == NULL) {
                log_error("error: can not find the resource.");
                return -ECMD_NO_RESOURCE;
        }

        pkt = alloc_packet0();
        if(pkt == NULL) {
                log_error("error: allocate packet error.");
                return -ECMD_NOMEM;
        }

        pkt->type = subcmd->type;
        pkt->dev_id = res->id;

        ret = packet_send(fd, pkt);
        if (ret < 0) {
                log_error("error: send packet to kernel error.");
                ret = -ECMD_NET_ERROR;
                goto out;
        }

        ret = check_response(fd);

out:
        close(fd);
        free_packet(pkt);
        return ret;
}

int __do_up(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_up_usage()
{
        log_error("usage: hadmctl up <res_name>");
}

int do_down(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_down_usage()
{
        log_error("usage: hadmctl down <res_name>");
}

int do_status(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct res_config *res;

        if (argc != 1) {
                log_error("error: command need a arguement.");
                return -ECMD_WRONG_USAGE;
        }

        res = find_res_by_name(argv[0], cfg);
        if (res == NULL) {
                log_error("error: can not find the resource.");
                return -ECMD_NO_RESOURCE;
        }

        ret = get_status(fd, cfg, res, &pkt);
        if (ret < 0) {
                return ret;
        }

        if (pkt->errcode != 0) {
                ret = pkt->errcode;
                log_error("error: %s", hadm_str_errno[-ret]);
                goto out;
        }

        ret = show_packet(cfg, res, pkt);
        if (ret < 0) {
                goto out;
        }
out:
        free(pkt);
        return ret;
}

void do_status_usage()
{
        log_error("usage: hadmctl status <res_name>");
}

int do_primary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct res_config *res;
        struct packet *pkt;
        struct site_state_packet *state_pkt;

        if (argc != 1) {
                log_error("error: command need a parameter.");
                do_primary_usage();
                return -ECMD_WRONG_USAGE;
        }

        res = find_res_by_name(argv[0], cfg);
        if (res == NULL) {
                log_error("error: can not find the resource.");
                return -ECMD_NO_RESOURCE;
        }

        ret = get_status(-1, cfg, res, &pkt);
        if (ret < 0) {
                return ret;
        }

        if (pkt->errcode != 0) {
                ret = pkt->errcode;
                log_error("error: %s",
                                hadm_str_errno[-ret]);
                goto err;
        }

        ret = get_primary_id(pkt);
        if (ret != -1) {
                log_error("error: exist a primary node.");
                ret = -ECMD_EXIST_PRIMARY;
                goto err;
        }

        state_pkt = get_site_state(pkt, cfg->local_site_id);
        if (!state_pkt) {
                ret = -ECMD_COMMON;
                goto err;
        }
        if (state_pkt->dev_state != DEV_UP) {
                log_error("error: device not up.");
                ret = -ECMD_RES_NOT_UP;
                goto err;
        }
        if (state_pkt->dbm_set != 0) {
                log_error("error: inconsistence state, dbm size:%llu", state_pkt->dbm_set);
                ret = -ECMD_INCONSISTENCE;
                goto err;
        }

        return common_device_up(fd, argc, argv, cfg, subcmd);
err:
        free(pkt);
        return ret;
}

void do_primary_usage()
{
        log_error("usage: hadmctl primary <res_name>");
}

int do_secondary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int idx, ret;
        int primary_id;
        struct packet *pkt;
        struct site_state_packet *site_state_pkt, *iter;
        struct res_config *res;

        if (argc != 1) {
                log_error("error: command need a arguement.");
                return -ECMD_WRONG_USAGE;
        }

        res = find_res_by_name(argv[0], cfg);
        if (res == NULL) {
                log_error("error: can not find this resource.");
                return -ECMD_NO_RESOURCE;
        }

        ret = get_status(-1, cfg, res, &pkt);
        if (ret < 0) {
                return ret;
        }
        if (pkt->errcode != 0) {
                ret = pkt->errcode;
                log_error("error: %s",
                                hadm_str_errno[-ret]);
                goto err;
        }

        if (!check_device_up(pkt, cfg)) {
                log_error("error: device not up.");
                ret = -ECMD_RES_NOT_UP;
                goto err;
        }

        free(pkt);
        return common_device_up(fd, argc, argv, cfg, subcmd);
err:
        free(pkt);
        return ret;
}

void do_secondary_usage()
{
        log_error("usage: hadmctl secondary <res_name>");
}

int do_help(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        struct command *help_entry;
        if (argc == 0) {
                usage(progname);
                return 0;
        }

        if (argc > 1) {
                do_help_usage();
                return -ECMD_WRONG_USAGE;
        }

        help_entry = find_subcmd_by_name(argv[0]);

        if(subcmd == NULL) {
                log_error("hadmctl: no manual entry for command %s.", argv[0]);
                return -ECMD_WRONG_USAGE;
        }
        else {
                help_entry->usage();
        }

        return 0;
}

void do_help_usage()
{
        log_error("usage: hadmctl help [command].");
}

int common_sync(int fd, struct command *subcmd, struct res_config *res, struct site_state_packet *node)
{
        int ret;
        struct packet *pkt;

        pkt = alloc_packet0();
        if (pkt == NULL) {
                log_error("error: can not allocate packet. Not enough memory.");
                return -ECMD_NOMEM;
        }

        pkt->type = subcmd->type;
        pkt->dev_id = res->id;
        pkt->node_to = node->id;

        ret = packet_send(fd, pkt);
        if (ret < 0) {
                log_error("error: failed send packet to kernel.");
                ret = -ECMD_NET_ERROR;
                goto out;
        }

        ret = check_response(fd);

out:
        close(fd);
        free_packet(pkt);
        return ret;
}

int common_sync_check(int argc, char *argv[], struct config *cfg,
                struct res_config **res, struct site_state_packet **site_state)
{
        int ret;
        struct packet *pkt;
        struct site_config *site;

        if (argc != 2 && argc != 3) {
                log_error("error: command need a resource followed by a host id.");
                return -ECMD_WRONG_USAGE;
        }

        *res = find_res_by_name(argv[0], cfg);
        if (*res == NULL) {
                log_error("error: can not find the resource.");
                return -ECMD_NO_RESOURCE;
        }

        site = find_site(cfg, ++argv);
        if (site == NULL || !site_belong_res(site, *res)) {
                log_error("error: can not find the site.");
                return -ECMD_NO_NODE;
        }

        ret = get_status(-1, cfg, *res, &pkt);
        if (ret < 0) {
                return ret;
        }
        if (pkt->errcode != 0) {
                ret = pkt->errcode;
                log_error("error: %s",
                                hadm_str_errno[-ret]);
                return ret;
        }

        if (!check_device_up(pkt, cfg)) {
                log_error("error: device not up.");
                return -ECMD_RES_NOT_UP;
        }

        *site_state = get_site_state(pkt, site->id);
        if (*site_state == NULL) {
                log_error("error: can not get the node state.");
                return -ECMD_NO_STATE;
        }

        return 0;
}

int do_fullsync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct res_config *res;
        struct site_config *site;
        struct site_state_packet *site_state;

        ret = common_sync_check(argc, argv, cfg, &res, &site_state);
        if (ret < 0) {
                return ret;
        }
#if 0
        if (site_state->n_state == N_DISCONNECT ||
            site_state->c_state == C_DELTA_SYNC_DBM ||
            site_state->c_state == C_DELTA_SYNC_BWR ||
            site_state->c_state == C_CMSYNC_DBM) {
                if (site_state->n_state == N_DISCONNECT)
                        log_error("error: network disconnect.");
                else
                        log_error("error: conflict cstate.");
                return -ECMD_CHECK_STATE_FAIL;
        }
#endif
        return common_sync(fd, subcmd, res, site_state);
}

int do_delta_sync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct res_config *res;
        struct site_config *site;
        struct site_state_packet *site_state;

        ret = common_sync_check(argc, argv, cfg, &res, &site_state);
        /* if (ret < 0) { */
        /*         return ret; */
        /* } */

        /* if (site_state->n_state == N_DISCONNECT || site_state->c_state != C_DBM || */
        /*                 site_state->bwr_size != 0 || site_state->dbm_set == 0) { */
        /*         if (site_state->n_state == N_DISCONNECT) */
        /*                 log_error("error: networt disconnect."); */
        /*         else if (site_state->c_state != C_DBM) */
        /*                 log_error("error: need in dbm state."); */
        /*         else if (site_state->bwr_size != 0) */
        /*                 log_error("error: bwr size not empty."); */
        /*         else */
        /*                 log_error("error: no dbm generated."); */
        /*         return -ECMD_CHECK_STATE_FAIL; */
        /* } */

        return common_sync(fd, subcmd, res, site_state);
}

int do_cmsync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct res_config *res;
        struct site_config *site;
        struct site_state_packet *site_state;

        ret = common_sync_check(argc, argv, cfg, &res, &site_state);
        if (ret < 0) {
                return ret;
        }

		return common_sync(fd, subcmd, res, site_state);

        if (site_state->n_state == N_CONNECT && site_state->c_state == C_SPLITBRAIN) {
                return common_sync(fd, subcmd, res, site_state);
        }
        else {
                if (site_state->n_state != N_CONNECT)
                        log_error("error: network disconnet");
                else
                        log_error("error: not in splitbrain state.");

                return -ECMD_CHECK_STATE_FAIL;
        }
}

void do_cmsync_usage()
{
}

void do_fullsync_usage()
{
}

void do_delta_sync_usage()
{
}

int do_version(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        if (argc > 0) {
                do_version_usage();
                return -ECMD_WRONG_USAGE;
        }

        printf("%s version %s\ngit commit %s\n", progname, VERSION, GIT_COMMIT);
        return 0;
}

void do_version_usage()
{
        log_error("usage: hadmctl version");
}

int do_forceprimary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_forceprimary_usage()
{
}

int do_forcesecondary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_forcesecondary_usage()
{
}

int do_up(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int ret;
        struct packet *pkt;
        struct conf_packet *conf_pkt;
	struct res_config *res;

        if(argc != 1) {
                log_error("error: command need a argument.");
                return -ECMD_WRONG_USAGE;
        }
	res = find_res_by_name(argv[0],cfg);
	if(res == NULL) {
		return -ECMD_NO_RESOURCE;
	}

        conf_pkt = pack_config(cfg);
        if(conf_pkt == NULL) {
                log_error("error: can not config the resource.");
                return -ECMD_NO_RESOURCE;
        }

        pkt = alloc_packet(conf_pkt->len);
        if(pkt == NULL) {
                log_error("error: allocate packet error.");
                ret = -ECMD_NOMEM;
                goto conf_packet_err;
        }

        pkt->type = P_UP;
	pkt->dev_id = res->id;

        ret = pack_fill_bwr(conf_pkt, cfg);
        if (ret < 0) {
                log_error("error: fill the bwr info in packet failed.");
                goto packet_err;
        }
        memcpy(pkt->data, conf_pkt, conf_pkt->len);

        ret = packet_send(fd, pkt);
        if (ret < 0) {
                log_error("error: send packet to kernel error.");
                ret = -ECMD_NET_ERROR;
                goto packet_err;
        }

        pkt = packet_recv(fd);
        if (pkt == NULL) {
                log_error("error: receive response packet failed.");
                ret = -ECMD_NET_ERROR;
                goto packet_err;
        }

        if (pkt->errcode !=0 && pkt->errcode != -EKMOD_ALREADY_UP) {
                ret = pkt->errcode;
                log_error("error: %s", hadm_str_errno[-ret]);
                goto packet_err;
        }

packet_err:
        free_packet(pkt);
conf_packet_err:
        free_conf_packet(conf_pkt);
        close(fd);
        return ret;
}

int do_dump(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        int idx, bwr_fd, ret;
        struct runsite_config *runsite;
        struct res_config *res;

        char *content;
        char *meta_data;
        char *dbm_data;
        char dev_name[MAX_NAME_LEN] = {0};
        char bwr_name[MAX_NAME_LEN] = {0};
        uint64_t content_size;
        uint64_t data_max;
        uint64_t meta_offset;
        uint64_t dbm_offset;
        uint64_t dbm_size;
        uint64_t bwr_offset;
        uint64_t bwr_disk_size;

        if (argc != 1) {
                log_error("error: command need a arguement.");
                return -ECMD_WRONG_USAGE;
        }

        res = find_res_by_name(argv[0], cfg);
        if (res == NULL) {
                log_error("error: can not find this resource.");
                return -ECMD_NO_RESOURCE;
        }

        ret = get_bwr_info(res, cfg, &data_max, &meta_offset, &dbm_offset,
                           &dbm_size, &bwr_offset, &bwr_disk_size);
        if (ret == -1) {
                log_error("error: can not get bwr device meta info.");
                return -ECMD_GET_BWRINFO;
        }

        ret = get_res_path(res, cfg->local_site_id, dev_name, bwr_name);
        if (ret == -1) {
                log_error("error: can not find the resource path.");
                return -ECMD_NO_PATH;
        }

        bwr_fd = open(bwr_name, O_RDONLY | O_DIRECT);
        if (fd < 0) {
                log_error("error: open device error: %s.", strerror(errno));
                return -ECMD_OPEN_FAIL;
        }

        ret = lseek64(bwr_fd, meta_offset << SECTOR_SIZE_BIT, SEEK_SET);
        if (ret < 0) {
                log_error("error: lseek bwr device error: %s.", strerror(errno));
                ret = -ECMD_IO_ERR;
                goto f_free;
        }

        content_size = (dbm_offset - meta_offset + dbm_size * MAX_NODES) << SECTOR_SIZE_BIT;
        ret = posix_memalign((void **)&content, BUFSIZ, content_size);
        if (ret < 0) {
                log_error("error: alloc mem failed. %s.", strerror(errno));
                ret = -ECMD_NOMEM;
                goto f_free;
        }
        memset(content, 0, content_size);

        ret  = read(bwr_fd, content, content_size);
        if (ret != content_size) {
                perror("read data error:");
                ret = -ECMD_IO_ERR;
                goto m_free;
        }

        pr_meta_info(content);
        runsite = res->runsites;
        dbm_data = content + ((dbm_offset - meta_offset) << SECTOR_SIZE_BIT);
        printf("dbm_cnt:");
        for (idx = 0; idx < res->runsite_num; idx++) {
                printf(" %d ", bits(dbm_data + ((dbm_size * runsite[idx].id) << SECTOR_SIZE_BIT)
                                , dbm_size << SECTOR_SIZE_BIT));
        }
        printf("\n");

        ret = 0;
m_free:
        free(content);
f_free:
        close(bwr_fd);
        return ret;
}

void do_dump_usage()
{
        log_error("usage: hadmctl dump <res_name>");
}

int do_master(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_master_usage()
{
	log_error("usage: hadmctl master <res_name>");
}

int do_slaver(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd)
{
        return common_device_up(fd, argc, argv, cfg, subcmd);
}

void do_slaver_usage()
{
	log_error("usage: hadmctl slaver <res_name>");
}
