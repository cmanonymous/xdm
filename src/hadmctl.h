#ifndef __HADMCTL_H__
#define __HADMCTL_H__

struct command *find_subcmd_by_name(const char *cmd);

struct command *find_subcmd_by_type(int type);

struct command *find_cmd_by_name(const char *cmd, struct command *subcmd, int num);

struct command *find_cmd_by_type(int type, struct command *subcmd);

void usage(const char *prog);

int connect_to_kern(struct config *cfg);

int do_command(int fd, int argc, char *argv[], struct config *cfg);

int get_status(int conn_fd, struct config *cfg, struct res_config *res, struct packet **pkt);

#endif // __HADMCTL_H__
