#include <linux/module.h>
#include <linux/list.h>
#include <linux/seq_file.h>
#include <linux/proc_fs.h>
#include "../include/common.inc"
#include "../config.h"
#include "../include/packet.inc"
#include "hadm_node.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "utils.h"
#include "hadm_proc_show.h"

#define ACCT_FMT "%-8s:\t%llu\n"	/* R_BIO */\
		 "%-8s:\t%llu\n"	/* R_WRAPPER */\
		 "%-8s:\t%llu\n"	/* R_SM_WRAP */\
		 "%-8s:\t%llu\n"	/* R_SUBBIO */\
		 "%-8s:\t%llu\n"	/* R_SUBB_F*/\
		 "%-8s:\t%llu\n"	/* R_BIO_F */\
		 "%-8s:\t%llu\n"	/* W_BIO */\
		 "%-8s:\t%llu\n"	/* W_BIO_SET */\
		 "%-8s:\t%llu\n"	/* W_WRAPPER */\
		 "%-8s:\t%llu\n"	/* W_SM_WRAP */\
		 "%-8s:\t%llu\n"	/* W_SUBBIO */\
		 "%-8s:\t%llu\n"	/* W_SUBB_F */\
		 "%-8s:\t%llu\n"	/* W_BIO_F */

#define ACCT_VALUE_FMT	"%-8llu\t"	/* R_BIO */\
			"%-8llu\t"	/* R_WRAPPER */\
			"%-8llu\t"	/* R_SM_WRAP */\
			"%-8llu\t"	/* R_SUBBIO */\
			"%-8llu\t"	/* R_SUBB_F*/\
			"%-8llu\t"	/* R_BIO_F */\
			"%-8llu\t"	/* W_BIO */\
			"%-8llu\t"	/* W_BIO_SET */\
			"%-8llu\t"	/* W_WRAPPER */\
			"%-8llu\t"	/* W_SM_WRAP */\
			"%-8llu\t"	/* W_SUBBIO */\
			"%-8llu\t"	/* W_SUBB_F */\
			"%-8llu\t\n"	/* W_BIO_F */

static int hadm_proc_open(struct inode *inode, struct file *file);
static int hadm_proc_release(struct inode *inode, struct file *file);

extern struct hadm_show_func proc_show_funs[];

const struct file_operations hadm_proc_fops = {
	.owner      = THIS_MODULE,
	.read       = seq_read,
	.llseek     = seq_lseek,
	.open       = hadm_proc_open,
	.release    = hadm_proc_release,
};

typedef int (*show_func)(struct seq_file *, void *);

static show_func find_show_func(const char *file_name)
{
	struct hadm_show_func *p_show = proc_show_funs;
	while(p_show->file_name != NULL) {
//		pr_info("strcmp %p:%s,%p:%s\n",p_show,p_show->file_name,
//				file_name,file_name);
		if(!strcmp(file_name, p_show->file_name)) {
			return p_show->show;
		}
		p_show++;
	}

	return NULL;
}

static int hadm_proc_open(struct inode *inode, struct file *file)
{
	const unsigned char *file_name = file->f_path.dentry->d_name.name;

	show_func show = find_show_func(file_name);

	if (try_module_get(THIS_MODULE)) {
		if(show != NULL) {
			return single_open(file, show, PDE_DATA(inode));
		}
	}

	return -ENODEV;
}

static int hadm_proc_release(struct inode *inode, struct file *file)
{
	module_put(THIS_MODULE);
	return single_release(inode, file);
}

static void hadm_create_proc_file(const char *file_name, struct hadm_struct *hadm)
{
	proc_create_data(file_name, S_IFREG | S_IRUGO, hadm->proc_dir, &hadm_proc_fops, NULL);
}

static void hadm_remove_proc_file(const char *file_name, struct hadm_struct *hadm)
{
	remove_proc_entry(file_name, hadm->proc_dir);
}

void hadm_create_proc(struct hadm_struct *hadm)
{
	struct hadm_show_func *p_show = proc_show_funs;

	hadm->proc_dir = proc_mkdir(HADMDEV_NAME, NULL);

	while(p_show->file_name != NULL) {
		hadm_create_proc_file(p_show->file_name, hadm);
		p_show++;
	}
}

void hadm_remove_proc(struct hadm_struct *hadm)
{
	struct hadm_show_func *p_show = proc_show_funs;

	while(p_show->file_name != NULL) {
		hadm_remove_proc_file(p_show->file_name, hadm);
		p_show++;
	}
	remove_proc_entry(HADMDEV_NAME, NULL);
}
