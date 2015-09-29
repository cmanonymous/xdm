#include "common.h"


enum CMD_TYPE {
        P_HELP = P_TYPE_MAX + 1,
        P_VERSION,
        P__UP,
        P_DUMP,
        P_DUMPBWR,
        P_STARTKMOD,
};

#define MAX_LINE_LEN 4096
#define USAGE_FMT "usage: %s <command> [<args>]\n\n"\
        "The most commonly used commands are:\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"\
        "  %-10s: %s\n"

const char *progname;

struct command subcommand[] = {
        [P__UP] = {P_UP, "__up", __do_up, do_up_usage},
        [P_HELP] = {P_HELP, "help", do_help, do_help_usage},
        [P_VERSION] = {P_VERSION, "version", do_version, do_version_usage},
        [P_PRIMARY] = {P_PRIMARY, "primary", do_primary, do_primary_usage},
        [P_SECONDARY] = {P_SECONDARY, "secondary", do_secondary, do_secondary_usage},
        [P_UP] = {P_UP, "up", do_up, do_up_usage},
        [P_DOWN] = {P_DOWN, "down", do_down, do_down_usage},
        [P_CONFIG] = {P_CONFIG, "__config", __do_config, __do_config_usage},
        [P_INIT] = {P_INIT, "init", do_init, do_init_usage},
        [P_STATUS] = {P_STATUS, "status", do_status, do_status_usage},
        [P_DELTA_SYNC] = {P_DELTA_SYNC, "delta_sync", do_delta_sync, do_delta_sync_usage},
        [P_FULLSYNC] = {P_FULLSYNC, "fullsync", do_fullsync, do_fullsync_usage},
        [P_CMSYNC] = {P_CMSYNC, "cmsync", do_cmsync, do_cmsync_usage},
        [P_FORCEPRIMARY] = {P_FORCEPRIMARY, "forceprimary", do_forceprimary, do_forceprimary_usage},
        [P_FORCESECONDARY] = {P_FORCESECONDARY, "forcesecondary", do_forcesecondary, do_forcesecondary_usage},
        [P_DUMP] = {P_DUMP, "dump", do_dump, do_dump_usage},
        [P_DUMPBWR] = {P_DUMPBWR, "dumpbwr", do_dumpbwr, do_dumpbwr_usage},
        [P_STARTKMOD] = {P_STARTKMOD, "startkmod", do_startkmod, do_startkmod_usage},
};

int main(int argc, char *argv[])
{
        struct config *cfg;
        int fd;
        int ret;

        if(!check_root()) {
                fprintf(stderr, "Not root user.\n");
                exit(1);
        }

        ret = log_init(HADM_LOG_CONF, HADM_CLI_LOG_CAT);
        if(ret < 0) {
                fprintf(stderr, "can not init zlog.\n");
                return -ECMD_CONFIG_FAIL;
        }

        progname = basename(argv[0]);

        if(--argc <= 0) {
                usage(progname);
                return -ECMD_WRONG_USAGE;
        }

        cfg = load_config(CONFIG_FILE);
        if(cfg == NULL) {
                log_error("error: can not load config.");
                return -ECMD_CONFIG_FAIL;
        }

        if (strncmp(argv[1], "version", sizeof(argv[1])) &&
            strncmp(argv[1], "dump", sizeof(argv[1])) &&
            strncmp(argv[1], "dumpbwr", sizeof(argv[1])) &&
            strncmp(argv[1], "startkmod", sizeof(argv[1])) &&
            strncmp(argv[1], "help", sizeof(argv[1]))) {
                fd = connect_to_kern(cfg);
                if(fd < 0) {
			if (strncmp(argv[1], "init", sizeof(argv[1]))) {
				log_error("error: connect the kernel failed.");
				return -ECMD_NET_ERROR;
			}
                }
        }

        ret = do_command(fd, argc, ++argv, cfg);

        free_config(cfg);

        return ret;
}

struct command *find_subcmd_by_name(const char *cmd)
{
        return find_cmd_by_name(cmd, subcommand, sizeof(subcommand) / sizeof(struct command));
}

struct command *find_subcmd_by_type(int type)
{
        return find_cmd_by_type(type, subcommand);
}

struct command *find_cmd_by_name(const char *cmd, struct command *subcmd, int num)
{
        int idx;

        for(idx = 0; idx < num; idx++) {
                if(subcmd[idx].cmd == NULL) {
                        continue;
                }

                if(!strcmp(cmd, subcmd[idx].cmd)){
                        return &subcmd[idx];
                }
        }

        return NULL;
}

struct command *find_cmd_by_type(int type, struct command *subcmd)
{
        if(subcmd[type].cmd == NULL) {
                return NULL;
        }

        return &subcmd[type];
}

void usage(const char *progname)
{
        log_error(USAGE_FMT, progname,
                        "init", "initial the running environment",
                        "config", "load the config file",
                        "up", "activate the resource",
                        "down", "shutdown the resource",
                        "primary", "make the resource be the primary replication",
                        "secondary", "make the resource be the secondary replication",
                        "status", "show the resource status on all running node",
                        "delta_sync", "in dbm state, delta_sync dbm data to target node",
                        "cmsync", "in splitbrain state, full mode dbm delta_sync",
                        "fullsync", "disk block delta_sync",
                        "version", "show hadmctl program version",
                        "help", "show manual info");
}

int connect_to_kern(struct config *cfg)
{
        int fd;
        struct sockaddr addr;
        int ret;

        memset(&addr, 0, sizeof(struct sockaddr));

        fd = sock_create();
        if(fd < 0) {
                log_error("error: create socket failed.");
                return -1;
        }

        ret = sock_get_addr(LOCALHOST, cfg->kmodport, &addr);
        if(ret < 0) {
                log_error("error: get local addr failed.");
                goto err;
        }

        ret = sock_connect(fd, &addr);
        if(ret < 0) {
                goto err;
        }

        return fd;

err:
        sock_close(fd);

        return -1;
}

int do_command(int fd, int argc, char *argv[], struct config *cfg)
{
        struct command *subcmd;
        int i, ret;
        char cmdline[MAX_LINE_LEN] = {0};

        subcmd = find_subcmd_by_name(argv[0]);

        if(subcmd == NULL) {
                log_error("error: %s is not a hadmctl command.", argv[0]);
                usage(progname);
                return -1;
        }

        for (i=0; i < argc; i++) {
                strcat(cmdline, argv[i]);
                strcat(cmdline, " ");
        }

        if(--argc < 0) {
                subcmd->usage();
                return -1;
        }

        log_debug("%s %s", progname, cmdline);
        ret = subcmd->do_command(fd, argc, ++argv, cfg, subcmd);

        return ret;
}

int get_status(struct config *cfg, struct res_config *res, struct packet **pkt)
{
        int ret;
        int fd;
        struct packet *temp_pkt;

        temp_pkt = alloc_packet0();
        if (temp_pkt == NULL) {
                log_error("error: not enough memory!");
                return -ECMD_NOMEM;
        }

        temp_pkt->dev_id = res->id;
        temp_pkt->type = P_STATUS;

        fd = connect_to_kern(cfg);
        if(fd < 0) {
                log_error("error: connect the kernel failed.");
                free(temp_pkt);
                return -ECMD_NET_ERROR;
        }

        ret = packet_send(fd, temp_pkt);
        if (ret == -1) {
                log_error("error: send packet failed.");
                free(temp_pkt);
                close(fd);
                return -ECMD_NET_ERROR;
        }
        free(temp_pkt);

        temp_pkt = packet_recv(fd);
        if (temp_pkt == NULL) {
                log_error("error: receive packet failed.");
                close(fd);
                return -ECMD_NET_ERROR;

        }

        *pkt = temp_pkt;
        close(fd);
        return 0;

}
