#include <linux/module.h>

#include <linux/slab.h>

#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"

struct config *alloc_config(void)
{
	struct config *cfg;

	cfg = kzalloc(sizeof(struct config), GFP_KERNEL);
	if(cfg == NULL) {
		return NULL;
	}

	memset(cfg, 0, sizeof(struct config));

	return cfg;
}

void free_config(struct config *cfg)
{
	int i, j;
	struct site_config *site;
	struct res_config *res;
	struct runsite_config *runsite;

	if (cfg->sites != NULL) {
		for (i = 0; i < cfg->site_num; i++) {
			site = &cfg->sites[i];
			if (site->nodes != NULL) {
				kfree(site->nodes);
			}
		}
		kfree(cfg->sites);
	}

	if(cfg->res != NULL) {
		for(i = 0; i < cfg->res_num; i++) {
			res = &cfg->res[i];
			if(res->runsites != NULL) {
				for (j = 0; j < res->runsite_num; j++) {
					runsite = &res->runsites[j];
					if (runsite->runnodes)
						kfree(runsite->runnodes);
				}
				kfree(res->runsites);
			}
		}

		kfree(cfg->res);
	}

	if (cfg)
		kfree(cfg);
}

void unpack_runsite(struct runsite_config *runsite_cfg, struct runsite_conf_packet *runsite_conf_pkt)
{
	runsite_cfg->id = runsite_conf_pkt->id;
	runsite_cfg->proto = runsite_conf_pkt->proto;
	runsite_cfg->runnode_num = runsite_conf_pkt->runnode_num;
	strncpy(runsite_cfg->ipaddr, runsite_conf_pkt->ipaddr, strlen(runsite_conf_pkt->ipaddr));
	strncpy(runsite_cfg->port, runsite_conf_pkt->port, strlen(runsite_conf_pkt->port));
	strncpy(runsite_cfg->disk, runsite_conf_pkt->disk, strlen(runsite_conf_pkt->disk));
	strncpy(runsite_cfg->bwr_disk, runsite_conf_pkt->bwr_disk, strlen(runsite_conf_pkt->bwr_disk));
}

void unpack_res(struct res_config *res_cfg, struct res_conf_packet *res_conf_pkt)
{
	pr_info("%s: res: id:%d runsite_num:%d name:%s data_len:%llu.\n",
			__func__, res_conf_pkt->id, res_conf_pkt->runsite_num, res_conf_pkt->name, res_cfg->data_len);
	res_cfg->id = res_conf_pkt->id;
	res_cfg->runsite_num = res_conf_pkt->runsite_num;
	strncpy(res_cfg->name, res_conf_pkt->name, strlen(res_conf_pkt->name));
	res_cfg->data_len = res_conf_pkt->data_len;
	res_cfg->meta_offset = res_conf_pkt->meta_offset;
	res_cfg->dbm_offset = res_conf_pkt->dbm_offset;
	res_cfg->dbm_size = res_conf_pkt->dbm_size;
	res_cfg->bwr_offset = res_conf_pkt->bwr_offset;
	res_cfg->bwr_disk_size = res_conf_pkt->bwr_disk_size;
}

void unpack_site(struct site_config *site_cfg, struct site_conf_packet *site_conf_pkt)
{
	site_cfg->id = site_conf_pkt->id;
	site_cfg->mode = site_conf_pkt->mode;
	site_cfg->node_num = site_conf_pkt->node_num;
}

void unpack_node(struct node_config *node_cfg, struct node_conf_packet *node_conf_pkt)
{
	node_cfg->id = node_conf_pkt->id;
	strncpy(node_cfg->hostname, node_conf_pkt->hostname, strlen(node_conf_pkt->hostname));
	strncpy(node_cfg->ipaddr, node_conf_pkt->ipaddr, strlen(node_conf_pkt->ipaddr));
	strncpy(node_cfg->port, node_conf_pkt->port, strlen(node_conf_pkt->port));
}

struct config *unpack_config(struct conf_packet *conf_pkt)
{
	struct config *cfg;
	struct res_config *res;
	struct site_config *site;
	struct node_config *node;
	struct site_conf_packet *site_conf_pkt;
	struct node_conf_packet *node_conf_pkt;
	struct res_conf_packet *res_conf_pkt;
	struct runsite_conf_packet *runsite_conf_pkt;
	struct node_conf_packet *runnode_conf_pkt;
	int i;
	int j;
	int k;

	cfg = alloc_config();
	if(cfg == NULL) {
		return NULL;
	}

	strncpy(cfg->serverip, conf_pkt->serverip, strlen(conf_pkt->serverip));
	strncpy(cfg->serverport, conf_pkt->serverport, strlen(conf_pkt->serverport));
	strncpy(cfg->kmodport, conf_pkt->kmodport, strlen(conf_pkt->kmodport));
	cfg->maxpingcount = conf_pkt->maxpingcount;
	cfg->pingtimeout = conf_pkt->pingtimeout;
	cfg->site_num = conf_pkt->site_num;
	cfg->node_num = conf_pkt->node_num;
	cfg->res_num = conf_pkt->res_num;
	cfg->local_site_id = conf_pkt->local_site_id;
	cfg->local_node_id = conf_pkt->local_node_id;

	cfg->sites = kzalloc(cfg->site_num * sizeof(struct site_config), GFP_KERNEL);
	if(cfg->sites == NULL) {
		goto err;
	}
	memset(cfg->sites, 0, cfg->site_num * sizeof(struct site_config));

	site_conf_pkt = (struct site_conf_packet *)conf_pkt->data;
	for(i = 0; i < cfg->site_num; i++) {
		site = &cfg->sites[i];
		unpack_site(site, site_conf_pkt);

		site->nodes = kzalloc(site->node_num * sizeof(struct node_config), GFP_KERNEL);
		if (site->nodes == NULL)
			goto err;
		memset(site->nodes, 0, site->node_num * sizeof(struct node_config));
		node_conf_pkt = (struct node_conf_packet *)site_conf_pkt->data;
		for (j = 0; j < site_conf_pkt->node_num; j++) {
			node = &site->nodes[j];
			unpack_node(node, node_conf_pkt);

			node_conf_pkt++;
		}

                site_conf_pkt = (struct site_conf_packet *)node_conf_pkt;
	}

	cfg->res = kzalloc(cfg->res_num * sizeof(struct res_config), GFP_KERNEL);
	if(cfg->res == NULL) {
		goto err;
	}
	memset(cfg->res, 0, cfg->res_num * sizeof(struct res_config));

	res_conf_pkt = (struct res_conf_packet *)site_conf_pkt;
	for(i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];
		unpack_res(res, res_conf_pkt);

		res->runsites = kzalloc(res->runsite_num * sizeof(struct runsite_config), GFP_KERNEL);
		if(res->runsites == NULL) {
			goto err;
		}
		memset(res->runsites, 0, res->runsite_num * sizeof(struct runsite_config));

		runsite_conf_pkt = (struct runsite_conf_packet *)res_conf_pkt->data;
		for(j = 0; j < res->runsite_num; j++) {
			struct runsite_config *runsite_cfg;

			runsite_cfg = &res->runsites[j];
			unpack_runsite(runsite_cfg, runsite_conf_pkt);

			runnode_conf_pkt = (struct node_conf_packet *)runsite_conf_pkt->data;
			runsite_cfg->runnodes = kzalloc(runsite_cfg->runnode_num * sizeof(*runsite_cfg->runnodes), GFP_KERNEL);
			if (!runsite_cfg->runnodes)
				goto err;
			for (k = 0; k < runsite_cfg->runnode_num; k++) {
				struct node_config *runnode_cfg;

				runnode_cfg = &runsite_cfg->runnodes[k];
				unpack_node(runnode_cfg, runnode_conf_pkt);
				runnode_conf_pkt++;
			}

			runsite_conf_pkt = (struct runsite_conf_packet *)runnode_conf_pkt;
		}

		res_conf_pkt = (struct res_conf_packet *)runsite_conf_pkt;
	}

	return cfg;
err:
	free_config(cfg);
	return NULL;
}

struct res_config *find_resource(struct config *cfg, int id)
{
	int i;
	struct res_config *res = NULL;

	for (i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];
		if (id == res->id)
			break;
	}

	return res;
}

struct site_config *find_site(struct config *cfg, int id)
{
	int i;
	struct site_config *site = NULL;

	for (i = 0; i < cfg->site_num; i++) {
		site = &cfg->sites[i];
		if (site->id == id)
			break;
	}

	return site;
}

struct site_config *find_runsite(int id, struct config *cfg)
{
        int idx;
	struct site_config *site;

        for (idx = 0; idx < cfg->site_num; idx++) {
		site = &cfg->sites[idx];
                if (site->id == id)
                        return site;
	}

        return NULL;
}

int get_site_id(void)
{
	return g_hadm->local_site_id;
}

int get_node_id(void)
{
	return g_hadm->local_node_id;
}

uint32_t get_connected_sites(struct hadmdev *dev)
{
	struct hadm_site *hadm_site;
	unsigned long site_to;
	unsigned long flags;
	int nstate;

	site_to = 0;
	list_for_each_entry(hadm_site, &dev->hadm_site_list, site) {
		spin_lock_irqsave(&hadm_site->s_state.lock, flags);
		nstate = hadm_site->s_state.n_state;
		spin_unlock_irqrestore(&hadm_site->s_state.lock, flags);
		if (hadm_site->id != g_hadm->local_site_id &&
		    nstate == N_CONNECT)
			set_bit(hadm_site->id, &site_to);
	}

	return site_to;
}

int is_primary(struct hadmdev *dev, int node_id)
{
	int role;
	struct hadm_site *node;

	node = find_hadm_site_by_id(dev, node_id);
	if (node == NULL || IS_ERR(node)) {
		pr_err("is_primary: no node %d\n", node_id);
		return 0;
	}
	role = hadm_site_get(node, SECONDARY_STATE, S_ROLE);

	return role == R_PRIMARY;
}

void pr_config(struct config *cfg)
{
	int i;

	pr_global_config(cfg);

	pr_info("\n");
	pr_info("Total sites: %d\n", cfg->site_num);
	for (i = 0; i < cfg->site_num; i++)
		pr_site_config(&cfg->sites[i]);
	pr_info("\tlocal_site_id: %d\n", cfg->local_site_id);

	pr_info("\n");
	pr_info("Total resources: %d\n", cfg->res_num);
	for (i = 0; i < cfg->res_num; i++)
		pr_res_config(&cfg->res[i]);
}

void pr_global_config(struct config *cfg)
{
	pr_info("server ip: %s\n", cfg->serverip);
	pr_info("server port: %s\n", cfg->serverport);
	pr_info("kmodport: %s\n", cfg->kmodport);
	pr_info("server maxpingcount: %d\n", cfg->maxpingcount);
	pr_info("server pingtimeout: %d\n", cfg->pingtimeout);
}

void pr_site_config(struct site_config *site)
{
	int i;

	pr_info("\tid: %d\n", site->id);
	pr_info("\tmode: %d\n", site->mode);
	pr_info("\tip: %s\n", site->ipaddr);
	pr_info("\tport: %s\n", site->port);

	pr_info("\tTotal %d nodes in site:\n", site->node_num);
	for (i = 0; i < site->node_num; i++) {
		pr_node_config(&site->nodes[i]);
		pr_info("\n");
	}
}

void pr_node_config(struct node_config *node)
{
	pr_info("\t\tid: %d\n", node->id);
	pr_info("\t\thostname: %s\n", node->hostname);
	pr_info("\t\tip: %s\n", node->ipaddr);
	pr_info("\t\tport: %s\n", node->port);
}

void pr_res_config(struct res_config *res_config)
{
	int i;

	pr_info("\tid: %d\n", res_config->id);
	pr_info("\tname: %s\n", res_config->name);
	pr_info("\tdatalen: %llu\n", res_config->data_len);
	pr_info("\tdbm_offset: %llu\n", res_config->dbm_offset);
	pr_info("\tdbm_size: %llu\n", res_config->dbm_size);

	pr_info("\tTotal runsite%s: %d\n", res_config->runsite_num > 0 ? "s" : "", res_config->runsite_num);
	for (i = 0; i < res_config->runsite_num; i++)
		pr_runsite_config(&res_config->runsites[i]);
}

void pr_runsite_config(struct runsite_config *runsite_config)
{
	int i;

	pr_info("\t\tid: %d\n", runsite_config->id);
	pr_info("\t\tproto: %s\n", runsite_config->proto ? "ASYNC" : "SYNC");
	pr_info("\t\tipaddr: %s\n", runsite_config->ipaddr);
	pr_info("\t\tport: %s\n", runsite_config->port);
	pr_info("\t\tdisk: %s\n", runsite_config->disk);
	pr_info("\t\tbwr_disk: %s\n", runsite_config->bwr_disk);
	pr_info("\t\trunnode_num: %d\n", runsite_config->runnode_num);

	for (i = 0; i < runsite_config->runnode_num; i++) {
		pr_runnode_config(&runsite_config->runnodes[i]);
		pr_info("\n");
	}
}

void pr_runnode_config(struct node_config *node)
{
	pr_info("\t\t\tid: %d\n", node->id);
	pr_info("\t\t\thostname: %s\n", node->hostname);
	pr_info("\t\t\tip: %s\n", node->ipaddr);
	pr_info("\t\t\tport: %s\n", node->port);
}

/* ----------deprecate functions -------------*/
