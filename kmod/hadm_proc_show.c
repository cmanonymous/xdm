#include <linux/seq_file.h>

#include "../include/common.inc"
#include "../config.h"
#include "../include/packet.inc"

#include "hadm_site.h"
#include "hadm_node.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "utils.h"
#include "bwr.h"

#include "hadm_proc_show.h"

#define HADM_PROC       "hadm"
#define BWR_ANCHOR_PROC "bwr_anchor"

struct hadm_show_func proc_show_funs[] = {
	{HADM_PROC, hadm_proc_show},
	{BWR_ANCHOR_PROC, bwr_anchor_show},
	{"site_status", site_status_show},
	{"node_status", node_status_show},
	{NULL, NULL},
};

#include "../include/common_string.h"

#define NODE_STATE_FMT_LEN 20
#define NODE_STATE_FMT "\t%-*s: %d\n"/* node id */\
        "\t%-*s: %s\n"/* node role */\
        "\t%-*s: %s\n"/* host name */\
        "\t%-*s: %s\n"/* host ip */\
        "\t%-*s: %s\n"/* resource name */\
        "\t%-*s: /dev/%s\n"/*dev path */\
        "\t%-*s: %s\n"/* disk device */\
        "\t%-*s: %lu\n"/* disk size */\
        "\t%-*s: %s\n"/* bwr device */\
        "\t%-*s: %lu\n"/* bwr device size*/\
        "\t%-*s: %s\n"/* node state*/
#define NONLOCAL_STATE_FMT "\t%-*s: %s\n" /* nstate */
#define EXTER_STATE_FMT ""\
        "\t%-*s: %s\n"/* dev state */\
        "\t%-*s: %lu\n"/* bwr sizee */\
        "\t%-*s: %lu\n"/* dbm_size */
#define DOWN_STATE_FMT "\t%-*s: %s\n"

int hadm_proc_show(struct seq_file *seq, void *v)
{
	int n_primary;
	struct hadmdev *dev;
	struct hadm_site *runsite;
	struct hadm_site_state *site_state;

	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		seq_printf(seq, "%s version %s\ngit commit %s\n", "hadm", VERSION, GIT_COMMIT);
		seq_printf(seq, "resource: %s\n\n", dev->name);

		n_primary = get_nr_primary(dev);

		list_for_each_entry(runsite, &dev->hadm_site_list, site) {

			site_state = &runsite->s_state;
			seq_printf(seq, NODE_STATE_FMT,
					NODE_STATE_FMT_LEN, "Node ID", runsite->id,
					NODE_STATE_FMT_LEN, "Node role", role_name[site_state->role],
					NODE_STATE_FMT_LEN, "Host name", runsite->conf.name,
					NODE_STATE_FMT_LEN, "Host IP", runsite->conf.ipaddr,
					NODE_STATE_FMT_LEN, "Dev name", dev->name,
					NODE_STATE_FMT_LEN, "Dev path", dev->name,
					NODE_STATE_FMT_LEN, "Disk device", runsite->conf.disk,
					NODE_STATE_FMT_LEN, "Disk size", (unsigned long)runsite->hadmdev->bdev_disk_size,
					NODE_STATE_FMT_LEN, "Bwr device", runsite->conf.bwr_disk,
					NODE_STATE_FMT_LEN, "Bwr device size", (unsigned long)runsite->s_state.bwr_size,
					NODE_STATE_FMT_LEN, "node dstate", dstate_name[site_state->dbm_set > 0]);

			if (runsite != dev->local_site) {
				seq_printf(seq, NONLOCAL_STATE_FMT,
						NODE_STATE_FMT_LEN, "Node n_state", nstate_name[site_state->n_state]);
			}

			if (site_state->c_state != C_DOWN) {
				seq_printf(seq, DOWN_STATE_FMT,
						NODE_STATE_FMT_LEN, "Node cstate", cstate_name[site_state->c_state]);


				if ((n_primary > 0 && site_state->role != R_PRIMARY) || (n_primary == 0 && runsite != dev->local_site)) {
					seq_printf(seq, EXTER_STATE_FMT,
							NODE_STATE_FMT_LEN, "device state", dev_state_name[site_state->dev_state],
							NODE_STATE_FMT_LEN, "bwr_size", (unsigned long)site_state->bwr_size,
							NODE_STATE_FMT_LEN, "Node dbm_set", (unsigned long)site_state->dbm_set);
				}
			}
			seq_printf(seq, "\n");
		}
	}

	return 0;
}

int bwr_anchor_show(struct seq_file *seq, void *v)
{
	struct hadmdev *dev;
	struct hadm_site *runsite;
	int local_node_id,primary_id;
	seq_printf(seq, "%s version %s\ngit commit %s\n", "hadm", VERSION, GIT_COMMIT);
	local_node_id=get_site_id();
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		primary_id=hadmdev_get_primary_id(dev);
		if(local_node_id!=primary_id) {
			continue;
		}
		seq_printf(seq, "resource: %s,local_site id:%d,primary id:%d\n", dev->name,local_node_id,primary_id);
		seq_printf(seq,"bwr tail:%llu,uuid:%llu,seq id:%llu\n",
				(unsigned long long)(dev->bwr->mem_meta.tail),
				(unsigned long long)(dev->bwr->mem_meta.local_primary.uuid),
				(unsigned long long)(dev->bwr->mem_meta.local_primary.bwr_seq));
		seq_printf(seq,"id\t\thead\tsnd head\tsnd ack head\n");
		list_for_each_entry(runsite, &dev->hadm_site_list, site) {
			if(runsite->id==local_node_id) {
				seq_printf(seq,"%d(local_site)\t%llu\n",
						local_node_id,(unsigned long long)dev->bwr->mem_meta.head[local_node_id]);
			}else {
				seq_printf(seq,"%d\t\t%llu\t%llu\t\t%llu\n",
						runsite->id,
						(unsigned long long)dev->bwr->mem_meta.head[runsite->id],
						(unsigned long long)runsite->s_state.snd_head,
						(unsigned long long)runsite->s_state.snd_ack_head
						);

			}
		}
		seq_printf(seq,"\n");
	}

	return 0;
}

int site_status_show(struct seq_file *seq, void *v)
{
	return 0;
}

int node_status_show(struct seq_file *seq, void *v)
{
	int local_id;
	struct hadmdev *dev;
	struct hadm_node *runnode, *master;

	seq_printf(seq, "%s version %s\ngit commit %s\n", "hadm", VERSION, GIT_COMMIT);
	local_id = get_node_id();
	list_for_each_entry(dev, &g_hadm->dev_list, node) {
		master = hadmdev_get_master(dev);
		seq_printf(seq, "resource: %s, master: %d\n", dev->name,
				master ? master->id : -1);
		list_for_each_entry(runnode, &dev->hadm_node_list, node) {
			if (runnode->id == local_id) {
				seq_printf(seq, "[%d] %s %s (local node) %s\n", runnode->id,
						runnode->name,
						runnode->ipaddr,
						atomic_read(&dev->openers) ? "open" : "close");
			} else {
				seq_printf(seq,"[%d] %s %s %s %s\n", runnode->id,
						runnode->name,
						runnode->ipaddr,
						hadm_node_connect(runnode) ? "connect" : "disconnect",
						hadm_node_open(runnode) ? "open" : "close");
			}
		}
		seq_printf(seq,"\n");
	}

	return 0;
}
