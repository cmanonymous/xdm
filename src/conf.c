#include "common.h"

#define MAX_EXPR_LEN 1024

#define SERVERIP "/hadm/global/serverip"
#define SERVERPORT "/hadm/global/serverport"
#define KMODPORT "/hadm/global/kmodport"
#define MAXPINGCOUNT "/hadm/global/maxpingcount"
#define PINGTIMEOUT "/hadm/global/pingtimeout"

#define SITE "/hadm/sites/site"
#define SITE_ID "/hadm/sites/site[%d]/id"
#define SITE_MODE "/hadm/sites/site[%d]/mode"

#define NODE "/hadm/sites/site[%d]/nodes/node"
#define NODE_ID "/hadm/sites/site[%d]/nodes/node[%d]/id"
#define NODE_HOSTNAME "/hadm/sites/site[%d]/nodes/node[%d]/hostname"
#define NODE_IPADDR "/hadm/sites/site[%d]/nodes/node[%d]/ipaddr"
#define NODE_PORT "/hadm/sites/site[%d]/nodes/node[%d]/port"

#define RESOURCE "/hadm/resources/resource"
#define RESOURCE_ID "/hadm/resources/resource[%d]/id"
#define RESOURCE_NAME "/hadm/resources/resource[%d]/name"

#define RUNSITE "/hadm/resources/resource[%d]/runsites/runsite"
#define RUNSITE_ID "/hadm/resources/resource[%d]/runsites/runsite[%d]/id"
#define RUNSITE_PROTO "/hadm/resources/resource[%d]/runsites/runsite[%d]/protocol"
#define RUNSITE_DISK "/hadm/resources/resource[%d]/runsites/runsite[%d]/disk"
#define RUNSITE_BWR_DISK "/hadm/resources/resource[%d]/runsites/runsite[%d]/bwr_disk"
#define RUNSITE_IPADDR "/hadm/resources/resource[%d]/runsites/runsite[%d]/ip"
#define RUNSITE_PORT "/hadm/resources/resource[%d]/runsites/runsite[%d]/port"

#define RUNNODE "/hadm/resources/resource[%d]/runsites/runsite[%d]/runnodes/id"
#define RUNNODE_ID "/hadm/resources/resource[%d]/runsites/runsite[%d]/runnodes/id[%d]"

#define ASYNC "async"
#define SYNC "sync"

#define SHARE "share"
#define UNSHARE "stand along"

char *trim(const char *str)
{
	char *res;
	int len;
	int i;
	int j;

	len = strlen(str);
	res = malloc(len + 1);
	if(res == NULL) {
		return NULL;
	}
	memset(res, 0, len + 1);

	for(i = 0, j = 0; i < len; i++) {
		if(!isspace(str[i])) {
			res[j++] = str[i];
		}
	}

	return res;
}

struct config *alloc_config()
{
	struct config *cfg;

	cfg = malloc(sizeof(struct config));
	if(cfg == NULL) {
		return NULL;
	}

	memset(cfg, 0, sizeof(struct config));

	return cfg;
}

void free_config(struct config *cfg)
{
	int i;
	struct site_config *site;
	struct res_config *res;

	if(cfg->sites != NULL) {
		for(i = 0; i < cfg->site_num; i++) {
			site = &cfg->sites[i];
			if(site->nodes != NULL)
				free(site->nodes);
		}

		free(cfg->sites);
	}

	if(cfg->res != NULL) {
		for(i = 0; i < cfg->res_num; i++) {
			res = &cfg->res[i];
			if(res->runsites != NULL) {
				free(res->runsites);
			}
		}

		free(cfg->res);
	}
}

struct config *load_config(const char *filename)
{
	xmlDocPtr doc;
	xmlXPathContextPtr ctx;
	struct config *cfg;
	int local_site_id;
	int local_node_id;

	doc = xmlParseFile(filename);
	if(doc == NULL) {
		return NULL;
	}

	ctx = xmlXPathNewContext(doc);
	if(ctx == NULL) {
		xmlFreeDoc(doc);
		return NULL;
	}

	cfg = alloc_config();
	if(cfg == NULL) {
		goto err;
	}

	if(get_global(ctx, cfg) < 0) {
		goto err_config;
	}

	if(get_sites(ctx, cfg) < 0) {
		goto err_config;
	}

	if(get_resources(ctx, cfg) < 0) {
		goto err_config;
	}

	local_site_id = get_local_site_id(cfg, &local_node_id);
	if(local_site_id < 0) {
		log_error("cannot find local node id");
		goto err_config;
	}


	cfg->local_site_id = local_site_id;
	cfg->local_node_id = local_node_id;

        if (trim_nonlocal_res(cfg) < 0) {
                goto err_config;
        }

	xmlXPathFreeContext(ctx);
	xmlFreeDoc(doc);

	return cfg;

err_config:
	free_config(cfg);

err:
	xmlXPathFreeContext(ctx);
	xmlFreeDoc(doc);

	return NULL;
}

xmlXPathObjectPtr exec_xpath_expr(xmlXPathContextPtr ctx, const char *expr)
{
	xmlXPathObjectPtr obj;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if(obj == NULL) {
		return NULL;
	}

	return obj;
}

char *get_content(xmlXPathContextPtr ctx, const char *expr)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	xmlNodePtr pnode;

	obj = exec_xpath_expr(ctx, expr);
	if(obj == NULL){
		return NULL;
	}

	pnodes = obj->nodesetval;
	if(pnodes->nodeNr != 1) {
		goto err;
	}

	pnode = pnodes->nodeTab[0];
	if(pnode->children->type != XML_TEXT_NODE) {
		goto err;
	}

	xmlXPathFreeObject(obj);
	return trim((const char *)pnode->children->content);

err:
	xmlXPathFreeObject(obj);
	return NULL;
}

int get_global(xmlXPathContextPtr ctx, struct config *cfg)
{
	if(get_serverip(ctx, cfg) < 0) {
		return -1;
	}

	if(get_serverport(ctx, cfg) < 0) {
		return -1;
	}

	if(get_kmodport(ctx, cfg) < 0) {
		return -1;
	}

	if(get_pingtimeout(ctx, cfg) < 0) {
		return -1;
	}

	if(get_maxpingcount(ctx, cfg) < 0) {
		return -1;
	}

	return 0;
}

int get_serverip(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;

	content = get_content(ctx, SERVERIP);
	if(content == NULL) {
		return -1;
	}

	strncpy(cfg->serverip, content, strlen(content));

	free(content);
	return 0;
}

int get_serverport(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;

	content = get_content(ctx, SERVERPORT);
	if(content == NULL) {
		return -1;
	}

	strncpy(cfg->serverport, content, strlen(content));

	free(content);
	return 0;
}

int get_kmodport(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;

	content = get_content(ctx, KMODPORT);
	if(content == NULL) {
		return -1;
	}

	strncpy(cfg->kmodport, content, strlen(content));

	free(content);
	return 0;
}

int get_pingtimeout(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;

	content = get_content(ctx, PINGTIMEOUT);
	if(content == NULL) {
		return -1;
	}

	cfg->pingtimeout = atoi(content);

	free(content);
	return 0;
}

int get_maxpingcount(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;

	content = get_content(ctx, MAXPINGCOUNT);
	if(content == NULL) {
		return -1;
	}

	cfg->maxpingcount = atoi(content);

	free(content);
	return 0;
}

int get_node(xmlXPathContextPtr ctx, struct config *cfg, int site_idx, int idx)
{
	char expr[MAX_EXPR_LEN];
	struct site_config *site;
	struct node_config *node;
	char *content;

	site = &cfg->sites[site_idx];
	node = &site->nodes[idx];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_ID, site_idx + 1, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}
	node->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_HOSTNAME, site_idx + 1, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}
	strncpy(node->hostname, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_IPADDR, site_idx + 1, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}
	strncpy(node->ipaddr, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_PORT, site_idx + 1, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}
	strncpy(node->port, content, strlen(content));
	free(content);

	return 0;
}

int get_runnode(xmlXPathContextPtr ctx, struct config *cfg, int res_idx, int runsite_idx, int idx)
{
	struct res_config *res;
	struct runsite_config *runsite;
	struct node_config *node;
	struct site_config *site;
	struct node_config *raw_node;
	char expr[MAX_EXPR_LEN];
	char *content;
	int id;

	res = &cfg->res[res_idx];
	runsite = &res->runsites[runsite_idx];
	node = &runsite->runnodes[idx];

	/* id */
	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE_ID, res_idx + 1, runsite_idx + 1, idx + 1);
	content = get_content(ctx, expr);
	if (!content)
		return -1;
	id = atoi(content);
	free(content);

	site = &cfg->sites[runsite->id];
	raw_node = &site->nodes[id];
	*node = *raw_node;

	return 0;
}

int get_site(xmlXPathContextPtr ctx, struct config *cfg, int idx)
{
	char expr[MAX_EXPR_LEN];
	struct site_config *site = &cfg->sites[idx];
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	char *content;
	int i;

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SITE_ID, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}
	site->id = atoi(content);
	free(content);

	/* NOTE: configure site name in hadm_config.xml ? */
	snprintf(site->sitename, MAX_HOSTNAME_LEN, "site[%d]", site->id);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SITE_MODE, idx + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	if (!strncmp(content, SHARE, strlen(SHARE)))
		site->mode = MODE_SHARE;
	else if (!strncmp(content, UNSHARE, strlen(UNSHARE)))
		site->mode = MODE_UNSHARE;
	else {
		free(content);
		return -1;
	}
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE, idx + 1);
	obj = exec_xpath_expr(ctx, expr);
	if(obj == NULL){
		return -1;
	}

	pnodes = obj->nodesetval;
	if(pnodes->nodeNr <= 0) {
		goto err;
	}

	site->node_num = pnodes->nodeNr;
	site->nodes = malloc(site->node_num * sizeof(struct node_config));
	memset(site->nodes, 0, site->node_num * sizeof(struct node_config));

	for(i = 0; i < site->node_num; i++) {
		if (get_node(ctx, cfg, idx, i) < 0)
			goto err_node;
	}

	xmlXPathFreeObject(obj);
	return 0;

err_node:
	if (site->nodes) {
		free(site->nodes);
		site->nodes = NULL;
	}
err:
	xmlXPathFreeObject(obj);
	return -1;
}


int get_sites(xmlXPathContextPtr ctx, struct config *cfg)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr psites;
	int i;

	obj = exec_xpath_expr(ctx, SITE);
	if(obj == NULL){
		return -1;
	}

	psites = obj->nodesetval;
	if(psites->nodeNr <= 0) {
		goto err;
	}

	cfg->site_num = psites->nodeNr;
	cfg->sites = malloc(cfg->site_num * sizeof(struct site_config));
	memset(cfg->sites, 0, cfg->site_num * sizeof(struct site_config));

	for(i = 0; i < cfg->site_num; i++) {
		if (get_site(ctx, cfg, i) < 0)
			goto err_site;
		cfg->node_num += cfg->sites[i].node_num;
	}

	xmlXPathFreeObject(obj);
	return 0;

err_site:
	if(cfg->sites) {
		free(cfg->sites);
		cfg->sites = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

int get_runsite(xmlXPathContextPtr ctx, struct config *cfg, int res_index, int runsite_index)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	char expr[MAX_EXPR_LEN];
	struct res_config *res;
	struct runsite_config *runsite;
	char *content;
	int i;

	res = &cfg->res[res_index];
	runsite = &res->runsites[runsite_index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_ID, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	runsite->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_PROTO, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	if(!strncmp(content, ASYNC, strlen(ASYNC))) {
		runsite->proto = PROTO_ASYNC;
	} else if(!strncmp(content, SYNC, strlen(SYNC))) {
		runsite->proto = PROTO_SYNC;
	} else {
		free(content);
		return -1;
	}

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_DISK, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(runsite->disk, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_BWR_DISK, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(runsite->bwr_disk, content, strlen(content));
	free(content);

	/* runsite ip */
	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_IPADDR, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if (content == NULL)
		return -1;
	strncpy(runsite->ipaddr, content, strlen(content));
	free(content);

	/* runsite port */
	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE_PORT, res_index + 1, runsite_index + 1);
	content = get_content(ctx, expr);
	if (content == NULL)
		return -1;
	strncpy(runsite->port, content, strlen(content));
	free(content);

	/* runnodes */
	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE, res_index + 1, runsite_index + 1);
	obj = exec_xpath_expr(ctx, expr);
	if (obj == NULL)
		return -1;
	pnodes = obj->nodesetval;
	if (pnodes->nodeNr <= 0)
		goto err_free_xml_obj;
	runsite->runnode_num = pnodes->nodeNr;
	runsite->runnodes = calloc(runsite->runnode_num, sizeof(struct node_config));
	if (runsite->runnodes == NULL)
		goto err_free_xml_obj;
	for (i = 0; i < runsite->runnode_num; i++) {
		if (get_runnode(ctx, cfg, res_index, runsite_index, i) < 0)
			goto err_free_runnodes;
	}

	return 0;

err_free_runnodes:
	free(runsite->runnodes);
err_free_xml_obj:
	xmlXPathFreeObject(obj);
	return -1;
}

int get_runsites(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	char expr[MAX_EXPR_LEN];
	struct res_config *res;
	int i;

	res = &cfg->res[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNSITE, index + 1);
	obj = exec_xpath_expr(ctx, expr);
	if(obj == NULL){
		return -1;
	}

	pnodes = obj->nodesetval;
	if(pnodes->nodeNr <= 0) {
		goto err;
	}

	res->runsite_num = pnodes->nodeNr;
	res->runsites = malloc(res->runsite_num * sizeof(struct runsite_config));
	if(res->runsites == NULL) {
		goto err;
	}
	memset(res->runsites, 0, res->runsite_num * sizeof(struct runsite_config));

	for(i = 0; i < res->runsite_num; i++) {
		if(get_runsite(ctx, cfg, index, i) < 0) {
			goto err_runsite;
		}
	}

	xmlXPathFreeObject(obj);
	return 0;

err_runsite:
	if(res->runsites != NULL) {
		free(res->runsites);
		res->runsites = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

int get_res(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	struct res_config *res;
	char *content;
	char expr[MAX_EXPR_LEN];

	res = &cfg->res[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RESOURCE_ID, index + 1);

	content = get_content(ctx, expr);
	if(content == NULL) {
		goto err;
	}
	res->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RESOURCE_NAME, index + 1);

	content = get_content(ctx, expr);
	if(content == NULL) {
		goto err;
	}
	strncpy(res->name, content, strlen(content));
	free(content);

	if(get_runsites(ctx, cfg, index) < 0) {
		goto err;
	}

	return 0;

err:
	return -1;
}

int get_resources(xmlXPathContextPtr ctx, struct config *cfg)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	int i;

	obj = exec_xpath_expr(ctx, RESOURCE);
	if(obj == NULL){
		return -1;
	}

	pnodes = obj->nodesetval;

	if(pnodes->nodeNr <= 0) {
		goto err;
	}

	cfg->res_num = pnodes->nodeNr;
	cfg->res = malloc(cfg->res_num * sizeof(struct res_config));
	if(cfg->res == NULL) {
		goto err;
	}
	memset(cfg->res, 0, cfg->res_num * sizeof(struct res_config));

	for(i = 0; i < cfg->res_num; i++) {
		if(get_res(ctx, cfg, i) < 0) {
			goto err_res;
		}
	}

	xmlXPathFreeObject(obj);
	return 0;

err_res:
	if(cfg->res != NULL) {
		free(cfg->res);
		cfg->res = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

int align_packet_size(int size)
{
	if(size & ~BLK_MASK) {
		size = (size & BLK_MASK) + BLK_SIZE;
	}

	return size;
}

int get_conf_packet_size(struct config *cfg)
{
	struct site_config *site;
	struct res_config *res;
	int size;
	int i, j;

	size = sizeof(struct conf_packet);
	size += cfg->site_num * sizeof(struct site_conf_packet);
	size += cfg->res_num * sizeof(struct res_conf_packet);

	for(i = 0; i < cfg->site_num; i++) {
		site = &cfg->sites[i];
		size += site->node_num * sizeof(struct node_conf_packet);
	}

	for(i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];
		size += res->runsite_num * sizeof(struct runsite_conf_packet);
		for (j = 0; j < res->runsite_num; j++) {
			struct runsite_config *runsite;

			runsite = &res->runsites[j];
			size += runsite->runnode_num * sizeof(struct node_conf_packet);
		}
	}

	return align_packet_size(size);
}

struct conf_packet *alloc_conf_packet(struct config *cfg)
{
	struct conf_packet *conf_pkt;
	int len;

	len = get_conf_packet_size(cfg);

	conf_pkt = malloc(len);
	if(conf_pkt == NULL) {
		return NULL;
	}

	memset(conf_pkt, 0, len);
	conf_pkt->len = len;

	return conf_pkt;
}

void free_conf_packet(struct conf_packet *conf_pkt)
{
	free(conf_pkt);
}

void pack_site(struct site_conf_packet *site_conf_pkt, struct site_config *site_cfg)
{
	site_conf_pkt->id = site_cfg->id;
	memcpy(site_conf_pkt->sitename, site_cfg->sitename, MAX_HOSTNAME_LEN);
	site_conf_pkt->mode = site_cfg->mode;
	site_conf_pkt->node_num = site_cfg->node_num;
}

void pack_runsite(struct runsite_conf_packet *runsite_conf_pkt, struct runsite_config *runsite_cfg)
{
	runsite_conf_pkt->id = runsite_cfg->id;
	runsite_conf_pkt->proto = runsite_cfg->proto;
	runsite_conf_pkt->runnode_num = runsite_cfg->runnode_num;
	strncpy(runsite_conf_pkt->ipaddr, runsite_cfg->ipaddr, strlen(runsite_cfg->ipaddr));
	strncpy(runsite_conf_pkt->port, runsite_cfg->port, strlen(runsite_cfg->port));
	strncpy(runsite_conf_pkt->disk, runsite_cfg->disk, strlen(runsite_cfg->disk));
	strncpy(runsite_conf_pkt->bwr_disk, runsite_cfg->bwr_disk, strlen(runsite_cfg->bwr_disk));
}

void pack_res(struct res_conf_packet *res_conf_pkt, struct res_config *res)
{
	res_conf_pkt->id = res->id;
	res_conf_pkt->runsite_num = res->runsite_num;
	res_conf_pkt->data_len = res->data_len;
	res_conf_pkt->meta_offset = res->meta_offset;
	res_conf_pkt->dbm_offset = res->dbm_offset;
	res_conf_pkt->dbm_size = res->dbm_size;
	strncpy(res_conf_pkt->name, res->name, strlen(res->name));
}

void pack_node(struct node_conf_packet *node_conf_pkt, struct node_config *node_cfg)
{
	node_conf_pkt->id = node_cfg->id;
	strncpy(node_conf_pkt->hostname, node_cfg->hostname, strlen(node_cfg->hostname));
	strncpy(node_conf_pkt->ipaddr, node_cfg->ipaddr, strlen(node_cfg->ipaddr));
	strncpy(node_conf_pkt->port, node_cfg->port, strlen(node_cfg->port));
}

/*
 * 打包结构的按照配置文件的结构进行打包
 *
 * 1. global
 * 2. sites
 * 3. resources
 *
 * 其中，sites 和 resources 里面嵌入了其他的内容。site 下面有 node，resource 下
 * 面有 runsites,runsite 下面有 runnode。
 *
 * 一个包的平坦结构如下：
 *
 * serverip: 127.0.0.1
 * serverport: 9999
 * kmodport: 13527
 * pingtimeout: 10
 * maxpingcount: 10
 * site_num: 2
 * node_num: 2
 * res_num: 2
 * local_site_id: 0
 * local_node_id: 0
 *
 * 接下来，是 sites 的内容
 *
 * id: 0
 * mode: SYNC
 * sitename: site[0]
 * node_num: 2
 *
 * 接下来，是 site0 里面的 2 个节点的内容：
 *
 * id: 0
 * hostname: u154
 * ipaddr: 192.168.10.154
 * port: 8811
 *
 * id: 1
 * hostname: u155
 * ipaddr: 192.168.10.155
 * port: 8811
 *
 * 然后，重复是 site 的内容，打包完 site 的内容之后，接着是 resource 的内容：
 *
 * id: 0
 * name: hadm0
 * data_len: 44327843275
 * meta_offset: 1234987
 * dbm_offset: 4234
 * dbm_size: 4312
 *
 * 接下来，是 resource 里面的 runsite 内容：
 *
 * id: 0
 * proto: SYNC
 * ipaddr: 192.168.10.10
 * port: 8811
 * disk: /dev/hadm/bdev0
 * bwr_disk: /dev/hadm/bwr0
 * runnode_num: 2
 *
 * 接下来，是 runsite 里面 runnode 的内容：
 *
 * id: 0
 * hostname: u154
 * ipaddr: 192.168.10.154
 * port: 8811
 *
 * id: 1
 * hostname: u155
 * ipaddr: 192.168.10.155
 * port: 8811
 *
 * 接下来，是另外一个 runsite 的内容：
 *
 * id: 1
 * proto: SYNC
 * ipaddr: 192.168.10.20
 * port: 8811
 * disk: /dev/hadm/bdev0
 * bwr_disk: /dev/hadm/bwr0
 * runnode_num:2
 *
 * 接下来，是这个 runsite 里面 runnode 的内容：
 *
 * id: 0
 * hostname: u156
 * ipaddr: 192.168.10.156
 * port: 8811
 *
 * 接下来，重复 resource 的内容。
 *
 * 整个打包就结束了。
 */
struct conf_packet *pack_config(struct config *cfg)
{
	struct site_config *site_cfg;
	struct node_config *node_cfg;
	struct res_config *res;
	struct runsite_config *runsite_cfg;
	struct conf_packet *conf_pkt;
	struct site_conf_packet *site_conf_pkt;
	struct node_conf_packet *node_conf_pkt;
	struct res_conf_packet *res_conf_pkt;
	struct runsite_conf_packet *runsite_conf_pkt;
	struct node_conf_packet *runnode_conf_pkt;
	int i, j, k;

	conf_pkt = alloc_conf_packet(cfg);
	if(conf_pkt == NULL) {
		return NULL;
	}

	strncpy(conf_pkt->serverip, cfg->serverip, strlen(cfg->serverip));
	strncpy(conf_pkt->serverport, cfg->serverport, strlen(cfg->serverport));
	strncpy(conf_pkt->kmodport, cfg->kmodport, strlen(cfg->kmodport));
	conf_pkt->maxpingcount = cfg->maxpingcount;
	conf_pkt->pingtimeout = cfg->pingtimeout;
	conf_pkt->site_num = cfg->site_num;
	conf_pkt->node_num = cfg->node_num;
	conf_pkt->res_num = cfg->res_num;
	conf_pkt->local_site_id = cfg->local_site_id;
	conf_pkt->local_node_id = cfg->local_node_id;

	site_conf_pkt = (struct site_conf_packet *)conf_pkt->data;

	for(i = 0; i < cfg->site_num; i++) {
		site_cfg = &cfg->sites[i];

		pack_site(site_conf_pkt, site_cfg);

		node_conf_pkt = (struct node_conf_packet *)site_conf_pkt->data;
		for (j = 0; j < site_cfg->node_num; j++) {
			node_cfg = &site_cfg->nodes[j];

			pack_node(node_conf_pkt, node_cfg);
			node_conf_pkt++;
		}

		site_conf_pkt = (struct site_conf_packet *)node_conf_pkt;
	}

	res_conf_pkt = (struct res_conf_packet *)site_conf_pkt;

	for(i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];

		pack_res(res_conf_pkt, res);

		runsite_conf_pkt = (struct runsite_conf_packet *)res_conf_pkt->data;
		for(j = 0; j < res->runsite_num; j++) {
			runsite_cfg = &res->runsites[j];

			pack_runsite(runsite_conf_pkt, runsite_cfg);

			runnode_conf_pkt = (struct node_conf_packet *)runsite_conf_pkt->data;
			for (k = 0; k < runsite_cfg->runnode_num; k++) {
				struct node_config *runnode_cfg;

				runnode_cfg = &runsite_cfg->runnodes[k];
				pack_node(runnode_conf_pkt, runnode_cfg);
				runnode_conf_pkt++;
			}

			runsite_conf_pkt = (struct runsite_conf_packet *)runnode_conf_pkt;
		}

		res_conf_pkt = (struct res_conf_packet *)runsite_conf_pkt;
	}

	return conf_pkt;
}

int get_local_site_id(struct config *cfg, int *node_idp)
{
	struct site_config *site_cfg;
	struct node_config *node_cfg;
	char hostname[MAX_HOSTNAME_LEN];
	int site_idx;
	int node_idx;
	int ret;

	memset(hostname, 0, sizeof(hostname));

	ret = gethostname(hostname, sizeof(hostname));
	if(ret < 0) {
		return -1;
	}

	for (site_idx = 0; site_idx < cfg->site_num; site_idx++) {
		site_cfg = &cfg->sites[site_idx];
		for(node_idx = 0; node_idx < site_cfg->node_num; node_idx++) {
			node_cfg = &site_cfg->nodes[node_idx];

			if(!strncmp(hostname, node_cfg->hostname,
						strlen(hostname))) {
				goto found;
			}
		}
	}

	return -1;
found:
	if (node_idp)
		*node_idp = node_cfg->id;
	return site_cfg->id;
}

struct res_config *find_res_by_name(const char *res_name, struct config *cfg)
{
	struct res_config *res;
	int idx;

	for(idx = 0; idx < cfg->res_num; idx++) {
		res = &cfg->res[idx];

		if(!strncmp(res_name, res->name, strlen(res->name))) {
			return res;
		}
	}

	return NULL;
}
