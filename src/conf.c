#include "common.h"

#define MAX_EXPR_LEN 1024

#define KMODPORT "/hadm/global/kmodport"
#define PING "/hadm/global/ping"
#define PINGTIMEOUT "/hadm/global/pingtimeout"

#define SERVER "/hadm/servers/server"
#define SERVER_ID "/hadm/servers/server[%d]/id"
#define SERVER_LOCALIPADDR "/hadm/servers/server[%d]/localipaddr"
#define SERVER_LOCALPORT "/hadm/servers/server[%d]/localport"
#define SERVER_REMOTEIPADDR "/hadm/servers/server[%d]/remoteipaddr"
#define SERVER_REMOTEPORT "/hadm/servers/server[%d]/remoteport"

#define NODE "/hadm/nodes/node"
#define NODE_ID "/hadm/nodes/node[%d]/id"
#define NODE_SERVERID "/hadm/nodes/node[%d]/serverid"
#define NODE_HOSTNAME "/hadm/nodes/node[%d]/hostname"

#define RESOURCE "/hadm/resources/resource"
#define RESOURCE_ID "/hadm/resources/resource[%d]/id"
#define RESOURCE_NAME "/hadm/resources/resource[%d]/name"

#define RUNNODE "/hadm/resources/resource[%d]//runnode"
#define RUNNODE_ID "/hadm/resources/resource[%d]/runnodes/runnode[%d]/id"
#define RUNNODE_PROTO "/hadm/resources/resource[%d]/runnodes/runnode[%d]/protocol"
#define RUNNODE_DISK "/hadm/resources/resource[%d]/runnodes/runnode[%d]/disk"
#define RUNNODE_BWR_DISK "/hadm/resources/resource[%d]/runnodes/runnode[%d]/bwr_disk"

#define ASYNC "async"
#define SYNC "sync"

static xmlXPathObjectPtr exec_xpath_expr(xmlXPathContextPtr ctx, const char *expr)
{
	xmlXPathObjectPtr obj;

	obj = xmlXPathEvalExpression(BAD_CAST expr, ctx);
	if(obj == NULL) {
		return NULL;
	}

	return obj;
}

static char *get_content(xmlXPathContextPtr ctx, const char *expr)
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

static int get_kmodport(xmlXPathContextPtr ctx, struct config *cfg)
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

static int get_ping(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;
	int ping;

	content = get_content(ctx, PING);
	if(content == NULL) {
		return -1;
	}

	ping = atoi(content);
	cfg->ping = ping;

	free(content);
	return 0;
}

static int get_pingtimeout(xmlXPathContextPtr ctx, struct config *cfg)
{
	char *content;
	int pingtimeout;

	content = get_content(ctx, PINGTIMEOUT);
	if(content == NULL) {
		return -1;
	}

	pingtimeout = atoi(content);
	cfg->pingtimeout = pingtimeout;

	free(content);
	return 0;
}

static int get_global(xmlXPathContextPtr ctx, struct config *cfg)
{
	if(get_kmodport(ctx, cfg) < 0) {
		return -1;
	}

	if(get_ping(ctx, cfg) < 0) {
		return -1;
	}

	if(get_pingtimeout(ctx, cfg) < 0) {
		return -1;
	}

	return 0;
}

static int get_server(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	char expr[MAX_EXPR_LEN];
	struct server_config *server;
	char *content;

	server = &cfg->servers[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SERVER_ID, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	server->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SERVER_LOCALIPADDR, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(server->localipaddr, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SERVER_LOCALPORT, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(server->localport, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SERVER_REMOTEIPADDR, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(server->remoteipaddr, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), SERVER_REMOTEPORT, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		return -1;
	}

	strncpy(server->remoteport, content, strlen(content));
	free(content);

	return 0;
}

static int get_servers(xmlXPathContextPtr ctx, struct config *cfg)
{
	int i;
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;

	obj = exec_xpath_expr(ctx, SERVER);
	if(obj == NULL){
		return -1;
	}

	pnodes = obj->nodesetval;

	if(pnodes->nodeNr <= 0) {
		goto err;
	}

	cfg->server_num = pnodes->nodeNr;
	cfg->servers = malloc(cfg->server_num * sizeof(struct server_config));
	if(cfg->servers == NULL) {
		goto err;
	}
	memset(cfg->servers, 0, cfg->server_num * sizeof(struct server_config));

	for(i = 0; i < cfg->server_num; i++) {
		if(get_server(ctx, cfg, i) < 0) {
			goto err_server;
		}
	}

	xmlXPathFreeObject(obj);
	return 0;

err_server:
	if(cfg->servers != NULL) {
		free(cfg->servers);
		cfg->servers = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

static int get_node(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	char expr[MAX_EXPR_LEN];
	struct node_config *node;
	char *content;

	node = &cfg->nodes[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_ID, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing node id in config file.");
		return -1;
	}

	node->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_SERVERID, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing node ip for node %d in config file.",
				node->id);
		return -1;
	}

	node->server_id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), NODE_HOSTNAME, index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing node port for node %d in config file.",
				node->id);
		return -1;
	}

	strncpy(node->hostname, content, strlen(content));
	free(content);

	return 0;
}

static int get_nodes(xmlXPathContextPtr ctx, struct config *cfg)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	int i;

	obj = exec_xpath_expr(ctx, NODE);
	if(obj == NULL){
		return -1;
	}

	pnodes = obj->nodesetval;
	if(pnodes->nodeNr <= 0) {
		goto err;
	}

	cfg->node_num = pnodes->nodeNr;
	cfg->nodes = malloc(cfg->node_num * sizeof(struct node_config));
	if(cfg->nodes == NULL) {
		goto err;
	}
	memset(cfg->nodes, 0, cfg->node_num * sizeof(struct node_config));

	for(i = 0; i < cfg->node_num; i++) {
		if(get_node(ctx, cfg, i) < 0) {
			goto err_node;
		}
	}

	xmlXPathFreeObject(obj);
	return 0;

err_node:
	if(cfg->nodes) {
		free(cfg->nodes);
		cfg->nodes = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

static int get_runnode(xmlXPathContextPtr ctx, struct config *cfg, int res_index, int runnode_index)
{
	char expr[MAX_EXPR_LEN];
	struct res_config *res;
	struct runnode_config *runnode;
	char *content;

	res = &cfg->res[res_index];
	runnode = &res->runnodes[runnode_index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE_ID, res_index + 1, runnode_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing runnode id(res: %d).",
				res->id);
		return -1;
	}

	runnode->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE_PROTO, res_index + 1, runnode_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing runnode proto(res: %d).",
				res->id);
		return -1;
	}

	if(!strcmp(content, ASYNC)) {
		runnode->proto = PROTO_ASYNC;
	} else if(!strcmp(content, SYNC)) {
		runnode->proto = PROTO_SYNC;
	} else {
		log_error("wrong proto for runnode %d(res: %d).",
				runnode->id, res->id);
		free(content);
		return -1;
	}
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE_DISK, res_index + 1, runnode_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing disk name for runnode %d(res: %d).",
				runnode->id, res->id);
		return -1;
	}

	strncpy(runnode->disk, content, strlen(content));
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE_BWR_DISK, res_index + 1, runnode_index + 1);
	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing bwr name for runnode %d(res: %d).",
				runnode->id, res->id);
		return -1;
	}

	strncpy(runnode->bwr_disk, content, strlen(content));
	free(content);

	return 0;
}

static int get_runnodes(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	xmlXPathObjectPtr obj;
	xmlNodeSetPtr pnodes;
	char expr[MAX_EXPR_LEN];
	struct res_config *res;
	int i;

	res = &cfg->res[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RUNNODE, index + 1);
	obj = exec_xpath_expr(ctx, expr);
	if(obj == NULL){
		log_error("missing runnodes for resource %d in config file.",
				res->id);
		return -1;
	}

	pnodes = obj->nodesetval;
	if(pnodes->nodeNr <= 0) {
		log_error("runnode numbers must larger than 0 (res: %d)",
				res->id);
		goto err;
	}

	res->runnode_num = pnodes->nodeNr;
	res->runnodes = malloc(res->runnode_num * sizeof(struct runnode_config));
	if(res->runnodes == NULL) {
		goto err;
	}
	memset(res->runnodes, 0, res->runnode_num * sizeof(struct runnode_config));

	for(i = 0; i < res->runnode_num; i++) {
		if(get_runnode(ctx, cfg, index, i) < 0) {
			goto err_runnode;
		}
	}

	xmlXPathFreeObject(obj);
	return 0;

err_runnode:
	if(res->runnodes != NULL) {
		free(res->runnodes);
		res->runnodes = NULL;
	}

err:
	xmlXPathFreeObject(obj);
	return -1;
}

static int get_res(xmlXPathContextPtr ctx, struct config *cfg, int index)
{
	struct res_config *res;
	char *content;
	char expr[MAX_EXPR_LEN];

	res = &cfg->res[index];

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RESOURCE_ID, index + 1);

	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing resource id in config file.");
		goto err;
	}
	res->id = atoi(content);
	free(content);

	memset(expr, 0, sizeof(expr));
	snprintf(expr, sizeof(expr), RESOURCE_NAME, index + 1);

	content = get_content(ctx, expr);
	if(content == NULL) {
		log_error("missing resource name for resource %d in config file.",
				res->id);
		goto err;
	}
	strncpy(res->name, content, strlen(content));
	free(content);

	if(get_runnodes(ctx, cfg, index) < 0) {
		goto err;
	}

	return 0;

err:
	return -1;
}

static int get_resources(xmlXPathContextPtr ctx, struct config *cfg)
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

static int trim_nonlocal_res(struct config *cfg)
{
        int ridx, nidx, non_locals;
        struct res_config *res, *res_iter;
        struct runnode_config *node;
		int i = 0;

        non_locals = 0;
        res = malloc(sizeof(struct res_config) * cfg->res_num);
        if (res == NULL) {
                log_error("error: not enough memory!");
                return -1;
        }
        memset(res, 0, sizeof(struct res_config) * cfg->res_num);

        for (ridx = 0; ridx < cfg->res_num; ridx++) {
                res_iter = &cfg->res[ridx];
                for (nidx = 0; nidx < res_iter->runnode_num; nidx++) {
                        node = &res_iter->runnodes[nidx];
                        if (node->id == cfg->local_node_id)
                                break;
                }

                if (nidx < res_iter->runnode_num) {
                        memcpy(&res[i++], res_iter, sizeof(struct res_config));
                }
                else {
                        non_locals++;
                }
        }

        free(cfg->res);
        cfg->res = res;
        cfg->res_num -= non_locals;
        return 0;
}

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
	struct res_config *res;

	if(cfg->nodes != NULL) {
		free(cfg->nodes);
	}

	if(cfg->res != NULL) {
		for(i = 0; i < cfg->res_num; i++) {
			res = &cfg->res[i];
			if(res->runnodes != NULL) {
				free(res->runnodes);
			}
		}

		free(cfg->res);
	}
}

static int get_local_node_id(struct config *cfg)
{
	struct node_config *node_cfg;
	char hostname[MAX_HOSTNAME_LEN];
	int idx;
	int ret;

	memset(hostname, 0, sizeof(hostname));

	ret = gethostname(hostname, sizeof(hostname));
	if(ret < 0) {
		return -1;
	}

	for(idx = 0; idx < cfg->node_num; idx++) {
		node_cfg = &cfg->nodes[idx];

		if(!strcmp(hostname, node_cfg->hostname)) {
			return idx;
		}
	}

	return -1;
}

/* IFF cfg->local_node_id valid */
static int get_local_server_idx(struct config *cfg)
{
	int idx;
	struct node_config *local_node;
	struct server_config *scfg;

	local_node = &cfg->nodes[cfg->local_node_id];
	for (idx = 0; idx < cfg->server_num; idx++) {
		scfg = &cfg->servers[idx];
		if (scfg->id == local_node->server_id)
			return idx;
	}

	return -1;
}

struct config *load_config(const char *filename)
{
	xmlDocPtr doc;
	xmlXPathContextPtr ctx;
	struct config *cfg;
	int local_node_id;
	int local_server_idx;

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

	if (get_servers(ctx, cfg) < 0) {
		goto err_config;
	}

	if(get_nodes(ctx, cfg) < 0) {
		goto err_config;
	}

	if(get_resources(ctx, cfg) < 0) {
		goto err_config;
	}

	local_node_id = get_local_node_id(cfg);
	if(local_node_id < 0) {
		log_error("cannot find local node id");
		goto err_config;
	}
	cfg->local_node_id = local_node_id;

	local_server_idx = get_local_server_idx(cfg);
	if (local_server_idx < 0) {
		log_error("cannot find local server id");
		goto err_config;
	}
	cfg->local_server_idx = local_server_idx;

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

int align_packet_size(int size)
{
	if(size & ~BLK_MASK) {
		size = (size & BLK_MASK) + BLK_SIZE;
	}

	return size;
}

int get_conf_packet_size(struct config *cfg)
{
	struct res_config *res;
	int size;
	int i;

	size = sizeof(struct conf_packet);
	size += cfg->node_num * sizeof(struct node_conf_packet);
	size += cfg->server_num * sizeof(struct server_config);
	size += cfg->res_num * sizeof(struct res_conf_packet);

	for(i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];
		size += res->runnode_num * sizeof(struct runnode_conf_packet);
	}

	return align_packet_size(size);
}

struct conf_packet *alloc_conf_packet_for_res(struct config *cfg,
		struct res_config *res)
{
	struct conf_packet *conf_pkt;
	int len;

	len = sizeof(struct conf_packet);
	len += cfg->node_num * sizeof(struct node_conf_packet);
	len += cfg->server_num * sizeof(struct server_config);
	len += sizeof(struct res_conf_packet);
	len += res->runnode_num * sizeof(struct runnode_conf_packet);

	len = align_packet_size(len);

	conf_pkt = malloc(len);
	if(conf_pkt == NULL) {
		return NULL;
	}

	memset(conf_pkt, 0, len);
	conf_pkt->len = len;

	return conf_pkt;
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

static void pack_runnode(struct runnode_conf_packet *runnode_conf_pkt,
			 struct runnode_config *runnode_cfg)
{
	runnode_conf_pkt->id = runnode_cfg->id;
	runnode_conf_pkt->proto = runnode_cfg->proto;
	strncpy(runnode_conf_pkt->disk, runnode_cfg->disk, strlen(runnode_cfg->disk));
	strncpy(runnode_conf_pkt->bwr_disk, runnode_cfg->bwr_disk, strlen(runnode_cfg->bwr_disk));
}

static void pack_res(struct res_conf_packet *res_conf_pkt, struct res_config *res)
{
	res_conf_pkt->id = res->id;
	res_conf_pkt->runnode_num = res->runnode_num;
	res_conf_pkt->data_len = res->data_len;
	res_conf_pkt->meta_offset = res->meta_offset;
	res_conf_pkt->dbm_offset = res->dbm_offset;
	res_conf_pkt->dbm_size = res->dbm_size;
	strncpy(res_conf_pkt->name, res->name, strlen(res->name));
}

static void pack_node(struct node_conf_packet *node_conf_pkt,
		      struct node_config *node_cfg)
{
	node_conf_pkt->id = node_cfg->id;
	node_conf_pkt->server_id = node_cfg->server_id;
	strncpy(node_conf_pkt->hostname, node_cfg->hostname, strlen(node_cfg->hostname));
}

static void pack_server(struct server_conf_packet *server_conf_pkt,
		      struct server_config *server_cfg)
{
	server_conf_pkt->id = server_cfg->id;
	strncpy(server_conf_pkt->localipaddr, server_cfg->localipaddr, MAX_IPADDR_LEN);
	strncpy(server_conf_pkt->remoteipaddr, server_cfg->remoteipaddr, MAX_IPADDR_LEN);
	strncpy(server_conf_pkt->localport, server_cfg->localport, MAX_PORT_LEN);
	strncpy(server_conf_pkt->remoteport, server_cfg->remoteport, MAX_PORT_LEN);
}

struct conf_packet *pack_config_for_res(struct config *cfg, struct res_config *res)
{
	struct conf_packet *conf_pkt;
	struct node_config *node_cfg;
	struct server_config *server_cfg;
	struct runnode_config *runnode_cfg;
	struct node_conf_packet *node_conf_pkt;
	struct server_conf_packet *server_conf_pkt;
	struct res_conf_packet *res_conf_pkt;
	struct runnode_conf_packet *runnode_conf_pkt;
	int i;

	conf_pkt = alloc_conf_packet_for_res(cfg, res);
	if(conf_pkt == NULL) {
		return NULL;
	}

	strncpy(conf_pkt->kmodport, cfg->kmodport, strlen(cfg->kmodport));
	conf_pkt->ping = cfg->ping;
	conf_pkt->pingtimeout = cfg->pingtimeout;
	conf_pkt->node_num = cfg->node_num;
	conf_pkt->server_num = cfg->server_num;
	conf_pkt->res_num = 1;
	conf_pkt->local_server_id = cfg->servers[cfg->local_server_idx].id;
	conf_pkt->local_node_id = cfg->nodes[cfg->local_node_id].id;

	/* servers */
	server_conf_pkt = (struct server_conf_packet *)conf_pkt->data;
	for (i = 0; i < cfg->server_num; i++) {
		server_cfg = &cfg->servers[i];
		pack_server(server_conf_pkt, server_cfg);
		server_conf_pkt++;
	}

	/* kmod nodes */
	node_conf_pkt = (struct node_conf_packet *)server_conf_pkt;
	for (i = 0; i < cfg->node_num; i++) {
		node_cfg = &cfg->nodes[i];
		pack_node(node_conf_pkt, node_cfg);
		node_conf_pkt++;
	}

	res_conf_pkt = (struct res_conf_packet *)node_conf_pkt;
	pack_res(res_conf_pkt, res);

	runnode_conf_pkt = (struct runnode_conf_packet *)res_conf_pkt->data;
	for(i = 0; i < res->runnode_num; i++) {
		runnode_cfg = &res->runnodes[i];

		pack_runnode(runnode_conf_pkt, runnode_cfg);
		runnode_conf_pkt++;
	}

	return conf_pkt;
}

struct conf_packet *pack_config(struct config *cfg)
{
	struct conf_packet *conf_pkt;
	struct server_conf_packet *server_conf_pkt;
	struct server_config *server_cfg;
	struct node_config *node_cfg;
	struct res_config *res;
	struct runnode_config *runnode_cfg;
	struct node_conf_packet *node_conf_pkt;
	struct res_conf_packet *res_conf_pkt;
	struct runnode_conf_packet *runnode_conf_pkt;
	int i;
	int j;

	conf_pkt = alloc_conf_packet(cfg);
	if(conf_pkt == NULL) {
		return NULL;
	}

	/* global */
	strncpy(conf_pkt->kmodport, cfg->kmodport, strlen(cfg->kmodport));
	conf_pkt->ping = cfg->ping;
	conf_pkt->pingtimeout = cfg->pingtimeout;
	conf_pkt->server_num = cfg->server_num;
	conf_pkt->node_num = cfg->node_num;
	conf_pkt->res_num = cfg->res_num;
	conf_pkt->local_server_id = cfg->servers[cfg->local_server_idx].id;
	conf_pkt->local_node_id = cfg->nodes[cfg->local_node_id].id;

	/* servers */
	server_conf_pkt = (struct server_conf_packet *)conf_pkt->data;
	for (i = 0; i < cfg->server_num; i++) {
		server_cfg = &cfg->servers[i];
		pack_server(server_conf_pkt, server_cfg);
		server_conf_pkt++;
	}

	/* kmod nodes */
	node_conf_pkt = (struct node_conf_packet *)server_conf_pkt;
	for (i = 0; i < cfg->node_num; i++) {
		node_cfg = &cfg->nodes[i];
		pack_node(node_conf_pkt, node_cfg);
		node_conf_pkt++;
	}

	/* resources */
	res_conf_pkt = (struct res_conf_packet *)node_conf_pkt;
	for(i = 0; i < cfg->res_num; i++) {
		res = &cfg->res[i];
		pack_res(res_conf_pkt, res);

		/* runnodes */
		runnode_conf_pkt = (struct runnode_conf_packet *)res_conf_pkt->data;
		for(j = 0; j < res->runnode_num; j++) {
			runnode_cfg = &res->runnodes[j];
			pack_runnode(runnode_conf_pkt, runnode_cfg);
                        runnode_conf_pkt++;
		}

		res_conf_pkt = (struct res_conf_packet *)runnode_conf_pkt;
	}

	return conf_pkt;
}

struct res_config *find_res_by_name(const char *res_name, struct config *cfg)
{
	struct res_config *res;
	int idx;

	for(idx = 0; idx < cfg->res_num; idx++) {
		res = &cfg->res[idx];

		if(!strcmp(res_name, res->name)) {
			return res;
		}
	}

	return NULL;
}

struct node_config *find_node_by_id(struct config *cfg, int id)
{
        int idx;

        for (idx = 0; idx < cfg->node_num; idx++) {
                if (cfg->nodes[idx].id == id)
                        return &cfg->nodes[idx];
        }

        return NULL;
}

static struct node_config *find_node_by_name(struct config *cfg, char *hostname)
{
        int idx;

        for (idx = 0; idx < cfg->node_num; idx++) {
                if (!strcmp(cfg->nodes[idx].hostname, hostname)){
                        return &cfg->nodes[idx];
		}
        }

        return NULL;
}

struct node_config *find_node(struct config *cfg, char *argv[])
{
        int type;

        type = argv[1] ? atoi(argv[1]) : 0;

        switch(type) {
                case 0:
                        return find_node_by_id(cfg, atoi(argv[0]));
                case 1:
                        return find_node_by_name(cfg, argv[0]);
                default:
                        return NULL;
        }
}

struct server_config *find_server_by_id(struct config *cfg, int id)
{
	int idx;
	struct server_config *server_cfg;
	if(id < 0){
		return NULL;
	}

	for (idx = 0; idx < cfg->server_num; idx++) {
		server_cfg = &cfg->servers[idx];
		if (server_cfg->id == id)
			return server_cfg;
	}

	return NULL;
}

struct node_config *get_local_node(struct config *cfg)
{
	int idx;
        struct node_config *node;

        for (idx = 0; idx < cfg->node_num; idx++) {
                node = &cfg->nodes[idx];
                if (cfg->local_node_id == node->id)
                        return node;
        }

        return NULL;
}

char *get_node_ip(struct config *cfg, int node_id)
{
        return NULL;
}

char *get_server_ip(struct config *cfg, int id)
{
	int idx;
	struct server_config *server;

	for (idx = 0; idx < cfg->server_num; idx++) {
		server = &cfg->servers[idx];
		if (server->id == id)
			return server->remoteipaddr;
	}

	return NULL;
}

int get_res_node_proto(struct res_config *res, int node_id)
{
        int idx;
        struct runnode_config *node;

        for (idx = 0; idx < res->runnode_num; idx++) {
                node = &res->runnodes[idx];
                if (node_id == node->id)
			return node->proto;
        }
        return -1;
}

char *get_node_name(struct config *cfg, int node_id)
{
        int idx;
        struct node_config *node;

        for (idx = 0; idx < cfg->node_num; idx++) {
                node = &cfg->nodes[idx];
                if (node_id == node->id)
                        return node->hostname;
        }
        return NULL;
}

void pr_global_config(struct config *c)
{
	printf("kmodport: %s\n", c->kmodport);;
	printf("ping: %d\n", c->ping);
	printf("pingtimeout: %d\n", c->pingtimeout);
}

void pr_server_config(struct server_config *s)
{
	printf("\tid: %d\n", s->id);
	printf("\tlocalipaddr: %s\n", s->localipaddr);
	printf("\tlocalport: %s\n", s->localport);
	printf("\tremoteipaddr: %s\n", s->remoteipaddr);
	printf("\tremoteport: %s\n", s->remoteport);
}

void pr_node_config(struct node_config *n)
{
	printf("\tid: %d\n", n->id);
	printf("\tserver_id: %d\n", n->server_id);
	printf("\thostname: %s\n", n->hostname);
}

void pr_runnode_config(struct runnode_config *r)
{
	printf("\t\tid: %d\n", r->id);
	printf("\t\tproto: %s\n", r->proto == PROTO_SYNC ? "SYNC" : "ASYNC");
	printf("\t\tdisk: %s\n", r->disk);
	printf("\t\tbwr_disk: %s\n", r->bwr_disk);
}

void pr_res_config(struct res_config *r)
{
	int i;

	printf("\tid: %d\n", r->id);
	printf("\tname: %s\n", r->name);

	printf("\trunnodes:\n");
	for (i = 0; i < r->runnode_num; i++) {
		struct runnode_config *runnode;

		runnode = &r->runnodes[i];
		pr_runnode_config(runnode);
		printf("\n");
	}
}

void pr_config(struct config *c)
{
        int i;

        pr_global_config(c);
	printf("\n");

	/* servers */
	printf("servers:\n");
	for (i = 0; i < c->server_num; i++) {
		struct server_config *s;

		s = &c->servers[i];
		pr_server_config(s);
		printf("\n");
	}
	printf("\n");

	/* kmod nodes */
	printf("kmod nodes:\n");
	for (i = 0; i < c->node_num; i++) {
		struct node_config *n;

		n = &c->nodes[i];
		pr_node_config(n);
		printf("\n");
	}
	printf("\n");

	/* resources */
	printf("resources:\n");
	for (i = 0; i < c->res_num; i++) {
		struct res_config *r;

		r = &c->res[i];
		pr_res_config(r);
		printf("\n");
	}
}
