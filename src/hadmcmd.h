#ifndef __HADMCMD_H__
#define __HADMCMD_H__

struct command;

typedef int (*cmd_function)(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);
typedef void (*cmd_usage)();

struct command {
	int type;
	const char *cmd;
	cmd_function do_command;
	cmd_usage usage;
};

int __do_config(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void __do_config_usage();

int do_up(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_up_usage();

int do_down(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_down_usage();

int do_init(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_init_usage();

int do_status(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_status_usage();

int do_primary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_primary_usage();

int do_secondary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_secondary_usage();

int do_help(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_help_usage();

int common_sync_check(int argc, char *argv[], struct config *cfg, struct res_config **res, struct site_state_packet **site_state);

int common_sync(int fd, struct command *subcmd, struct res_config *res, struct site_state_packet *node);

int do_fullsync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

int do_delta_sync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

int do_cmsync(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_cmsync_usage();

void do_fullsync_usage();

void do_delta_sync_usage();

int do_version(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_version_usage();

int do_forcesecondary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_forcesecondary_usage();

int do_forceprimary(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_forceprimary_usage();

int __do_up(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

int do_dump(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);

void do_dump_usage();

int do_master(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);
void do_master_usage();
int do_slaver(int fd, int argc, char *argv[], struct config *cfg, struct command *subcmd);
void do_slaver_usage();
#endif // __HADMCMD_H__
