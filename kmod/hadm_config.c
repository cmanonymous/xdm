#include <linux/module.h>

#include <linux/slab.h>

#include "hadm_config.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_node.h"

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
	int i;
	struct res_config *res;

	if(cfg->nodes != NULL) {
		kfree(cfg->nodes);
	}

	if(cfg->res != NULL) {
		for(i = 0; i < cfg->res_num; i++) {
			res = &cfg->res[i];
			if(res->runnodes != NULL) {
				kfree(res->runnodes);
			}
		}

		kfree(cfg->res);
	}
}

static void unpack_runnode(struct runnode_config *runnode_cfg, struct runnode_conf_packet *runnode_conf_pkt)
{
	runnode_cfg->id = runnode_conf_pkt->id;
	runnode_cfg->proto = runnode_conf_pkt->proto;
	strncpy(runnode_cfg->disk, runnode_conf_pkt->disk, strlen(runnode_conf_pkt->disk));
	strncpy(runnode_cfg->bwr_disk, runnode_conf_pkt->bwr_disk, strlen(runnode_conf_pkt->bwr_disk));
}

static void unpack_res(struct res_config *res_cfg, struct res_conf_packet *res_conf_pkt)
{
	res_cfg->id = res_conf_pkt->id;
	res_cfg->runnode_num = res_conf_pkt->runnode_num;
	strncpy(res_cfg->name, res_conf_pkt->name, strlen(res_conf_pkt->name));
	res_cfg->data_len = res_conf_pkt->data_len;
	res_cfg->meta_offset = res_conf_pkt->meta_offset;
	res_cfg->dbm_offset = res_conf_pkt->dbm_offset;
	res_cfg->dbm_size = res_conf_pkt->dbm_size;
	res_cfg->bwr_offset = res_conf_pkt->bwr_offset;
	res_cfg->bwr_disk_size = res_conf_pkt->bwr_disk_size;
}

static void unpack_node(struct node_config *node_cfg, struct node_conf_packet *node_conf_pkt)
{
	node_cfg->id = node_conf_pkt->id;
	node_cfg->server_id = node_conf_pkt->server_id;
	strncpy(node_cfg->hostname, node_conf_pkt->hostname, strlen(node_conf_pkt->hostname));
}

static void unpack_server(struct server_config *server_cfg, struct server_conf_packet *server_conf_pkt)
{
	server_cfg->id = server_conf_pkt->id;
	strncpy(server_cfg->localipaddr, server_conf_pkt->localipaddr, strlen(server_conf_pkt->localipaddr));
	strncpy(server_cfg->localport, server_conf_pkt->localport, strlen(server_conf_pkt->localport));
	strncpy(server_cfg->remoteipaddr, server_conf_pkt->remoteipaddr, strlen(server_conf_pkt->remoteipaddr));
	strncpy(server_cfg->remoteport, server_conf_pkt->remoteport, strlen(server_conf_pkt->remoteport));
}

struct config *unpack_config(struct conf_packet *conf_pkt)
{
	struct config *cfg;
	struct server_conf_packet *server_conf_pkt;
	struct node_conf_packet *node_conf_pkt;
	struct res_conf_packet *res_conf_pkt;
	struct runnode_conf_packet *runnode_conf_pkt;
	struct res_config *res_cfg;
	int i;
	int j;

	cfg = alloc_config();
	if(cfg == NULL) {
		return NULL;
	}

	strncpy(cfg->kmodport, conf_pkt->kmodport, strlen(conf_pkt->kmodport));
	cfg->ping = conf_pkt->ping;
	cfg->pingtimeout = conf_pkt->pingtimeout;
	cfg->node_num = conf_pkt->node_num;
	cfg->res_num = conf_pkt->res_num;
	cfg->server_num = conf_pkt->server_num;
	cfg->local_node_id = conf_pkt->local_node_id;
	cfg->local_server_id = conf_pkt->local_server_id;

	/* unpack servres */
	cfg->servers = kzalloc(cfg->server_num * sizeof(struct server_config), GFP_KERNEL);
	if (!cfg->servers)
		goto err;
	server_conf_pkt = (struct server_conf_packet *)conf_pkt->data;
	for (i = 0; i < cfg->server_num; i++) {
		unpack_server(&cfg->servers[i], server_conf_pkt);
		server_conf_pkt++;
	}

	/* unpack kmod nodes */
	cfg->nodes = kzalloc(cfg->node_num * sizeof(struct node_config), GFP_KERNEL);
	if (!cfg->nodes)
		goto err;
	node_conf_pkt = (struct node_conf_packet *)server_conf_pkt;
	for(i = 0; i < cfg->node_num; i++) {
		unpack_node(&cfg->nodes[i], node_conf_pkt);
		node_conf_pkt++;
	}

	/* unpack resources */
	cfg->res = kzalloc(cfg->res_num * sizeof(struct res_config), GFP_KERNEL);
	if (!cfg->res)
		goto err;
	res_conf_pkt = (struct res_conf_packet *)node_conf_pkt;
	for(i = 0; i < cfg->res_num; i++) {
		res_cfg = &cfg->res[i];
		unpack_res(res_cfg, res_conf_pkt);
		res_cfg->runnodes = kzalloc(res_cfg->runnode_num * sizeof(struct runnode_config), GFP_KERNEL);
		if(res_cfg->runnodes == NULL) {
			goto err;
		}
		memset(res_cfg->runnodes, 0, res_cfg->runnode_num * sizeof(struct runnode_config));

		runnode_conf_pkt = (struct runnode_conf_packet *)res_conf_pkt->data;
		for(j = 0; j < res_cfg->runnode_num; j++) {
			unpack_runnode(&res_cfg->runnodes[j], runnode_conf_pkt);
			runnode_conf_pkt++;
		}

		res_conf_pkt = (struct res_conf_packet *)runnode_conf_pkt;
	}

	return cfg;

err:
	free_config(cfg);
	return NULL;
}

int get_node_id(void)
{
	return g_hadm->local_node_id;
}

uint32_t get_connected_nodes(struct hadmdev *dev)
{
	struct hadm_node *hadm_node;
	unsigned long node_to;
	unsigned long flags;
	int nstate;

	node_to = 0;
	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		spin_lock_irqsave(&hadm_node->s_state.lock, flags);
		nstate = hadm_node->s_state.n_state;
		spin_unlock_irqrestore(&hadm_node->s_state.lock, flags);
		if (hadm_node->id != g_hadm->local_node_id &&
		    nstate == N_CONNECT)
			set_bit(hadm_node->id, &node_to);
	}

	return node_to;
}

uint32_t get_ready_nodes(struct hadmdev *dev)
{
	struct hadm_node *runnode;
	unsigned long node_to;
	int cstate;

	node_to = 0;
	list_for_each_entry(runnode, &dev->hadm_node_list, node) {
		cstate = hadm_node_get(runnode, SECONDARY_STATE, S_CSTATE);
		if (runnode->id != g_hadm->local_node_id &&
		    cstate == C_SYNC)
			set_bit(runnode->id, &node_to);
	}

	return node_to;
}

int is_primary(struct hadmdev *dev, int node_id)
{
	int role;
	struct hadm_node *node;

	node = find_hadm_node_by_id(dev, node_id);
	if (node == NULL || IS_ERR(node)) {
		pr_err("is_primary: no node %d\n", node_id);
		return 0;
	}
	role = hadm_node_get(node, SECONDARY_STATE, S_ROLE);

	return role == R_PRIMARY;
}

static void dump_server(const char *msg, struct server_config *server)
{
	pr_info("%s: id:%d|l_ip:%s|l_port:%s|r_ip:%s|r_port:%s.\n",
			msg, server->id, server->localipaddr, server->localport,
			server->remoteipaddr, server->remoteport);
}

static void dump_node(const char *msg, struct node_config *node)
{
	pr_info("%s: id:%d|server_id:%d|hostname:%s.\n", msg,
			node->id, node->server_id, node->hostname);
}

static void dump_runnode(const char *msg, struct runnode_config *runnode)
{
	pr_info("%s: id:%d|proto:%d|disk:%s|bwr:%s.\n", msg, runnode->id,
			runnode->proto, runnode->disk, runnode->bwr_disk);
}

static void dump_resource(const char *msg, struct res_config *res)
{
	int idx;
	struct runnode_config *runnode;

	pr_info("%s: id:%d|name:%s|data_len:%llu|meta_offset:%llu|"
			"dbm_offset:%llu|dbm_size:%llu|bwr_offset:%llu"
			"bwr_disk_size:%llu.\n", msg,
			res->id, res->name, res->data_len, res->meta_offset,
			res->dbm_offset, res->dbm_size, res->bwr_offset,
			res->bwr_disk_size);

	for (idx = 0; idx < res->runnode_num; idx++) {
		runnode = &res->runnodes[idx];
		dump_runnode("\t\t", runnode);
	}
}

void dump_config(const char *msg, struct config *cfg)
{
	int idx;
	struct server_config *server;
	struct node_config *node;
	struct res_config *res;

	pr_info("%s: kmodport:%s|ping:%d|pingtimeout:%d|local_server:%d"
			"|local_node:%d.\n", msg, cfg->kmodport,
			cfg->ping, cfg->pingtimeout,
			cfg->local_server_id, cfg->local_node_id);
	for (idx = 0; idx < cfg->server_num; idx++) {
		server = &cfg->servers[idx];
		dump_server("\t", server);
	}

	for (idx = 0; idx < cfg->node_num; idx++) {
		node = &cfg->nodes[idx];
		dump_node("\t", node);
	}

	for (idx = 0; idx < cfg->res_num; idx++) {
		res = &cfg->res[idx];
		dump_resource("\t", res);
	}
}
