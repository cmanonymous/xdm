#include <linux/module.h>

#include <linux/init.h>
#include <linux/sched.h>

#include "hadm_def.h"		/* HADM_CONF_PATH */
#include "hadm_struct.h"

static char *hadm_config_path = HADM_CONF_PATH;
module_param(hadm_config_path, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_config_path, "HADM configuration path");

static int hadm_cmd_port = DEFAULT_CMD_RECV_PORT;
module_param(hadm_cmd_port, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(hadm_cmd_port, "HADM command server port");

extern struct hadm_struct *g_hadm;

int hadm_module_init(void)
{
	int ret;

	g_hadm = hadm_alloc(GFP_KERNEL);
	if (IS_ERR(g_hadm))
		return PTR_ERR(g_hadm);
	ret = hadm_init(g_hadm, hadm_config_path, hadm_cmd_port, GFP_KERNEL);
	if (ret)
		return ret;


	return 0;
}

void hadm_module_exit(void)
{
	hadm_put(g_hadm);
}

module_init(hadm_module_init);
module_exit(hadm_module_exit);
MODULE_LICENSE("GPL");
