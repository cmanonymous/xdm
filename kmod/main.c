#include <linux/module.h>

#include <linux/init.h>
#include <linux/sched.h>

#include "hadm_def.h"
#include "hadm_struct.h"

static int hadm_local_id = INVALID_LOCAL_ID;
module_param(hadm_local_id, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_local_id, "HADM local kmod node id");

static char *hadm_server_ipaddr = DEFAULT_SERVER_IPADDR;
module_param(hadm_server_ipaddr, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_server_ipaddr, "HADM server IP address");

static int hadm_server_port = DEFAULT_SERVER_PORT;
module_param(hadm_server_port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_server_port, "HADM server listen port");

static int hadm_cmd_port = DEFAULT_CMD_RECV_PORT;
module_param(hadm_cmd_port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_cmd_port, "HADM command server port");

extern struct hadm_struct *g_hadm;

int hadm_module_init(void)
{
	if (hadm_local_id < 0) {
		pr_err("HADM: invalid hadm_local_id: %d\n", hadm_local_id);
		return -EINVAL;
	}

	g_hadm = hadm_alloc(hadm_server_ipaddr, hadm_server_port, GFP_KERNEL);
	if (IS_ERR(g_hadm))
		return PTR_ERR(g_hadm);

	return hadm_init(g_hadm, hadm_local_id, hadm_cmd_port, GFP_KERNEL);
}

void hadm_module_exit(void)
{
	hadm_put(g_hadm);
}

module_init(hadm_module_init);
module_exit(hadm_module_exit);
MODULE_LICENSE("GPL");
