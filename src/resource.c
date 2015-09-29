#include "common.h"

void free_resource(struct resource *resource)
{
	if (resource && resource->runsites.sites)
		free(resource->runsites.sites);
	free(resource);
}

static void init_local_ip_in_resource(struct resource *res)
{
	int i;
	struct node *site;
	struct node *local_site;

	local_site = res->local_site;

	for (i = 0; i < res->runsites.nr; i++) {
		site = &res->runsites.sites[i];
		snprintf(site->local_ip, MAX_IPADDR_LEN, "%s", local_site->remote_ip);
		snprintf(site->local_port, MAX_PORT_LEN, "%s", local_site->remote_port);
	}
}

/* 假设每个 site 的浮动 ip 都是不同的 */
struct resource *make_resource(struct daemon *daemon,
		struct config *cfg, struct res_config *res_config)
{
	struct resource *resource;
	int ret;
	int i;

	resource = malloc(sizeof(*resource));
	if (resource == NULL)
		return NULL;
	resource->attr.id = res_config->id;
	snprintf(resource->attr.name, MAX_NAME_LEN, "%s", res_config->name);

	resource->runsites.nr = res_config->runsite_num;
	resource->runsites.sites = calloc(res_config->runsite_num, sizeof(struct node));
	if (resource->runsites.sites == NULL)
		goto err_free_resource;
	for (i = 0; i < res_config->runsite_num; i++) {
		struct site_config *site_config;
		struct runsite_config *runsite_config;
		struct node *runsite;

		runsite_config = &res_config->runsites[i];
		runsite = &resource->runsites.sites[i];
		site_config = find_site_by_id(cfg, runsite_config->id);
		if (!site_config)
			goto err_free_runsites;

		ret = init_node(runsite, SITE_NODE, runsite_config->id, site_config->sitename,
				runsite_config->ipaddr, runsite_config->ipaddr,
				runsite_config->port, runsite_config->port,
				cfg->pingtimeout, cfg->maxpingcount);
		if (ret < 0)
			goto err_free_runsites;

		node_set_daemon(runsite, daemon);

		if (runsite->id == cfg->local_site_id)
			resource->local_site = runsite;
	}

	init_local_ip_in_resource(resource);

	return resource;

err_free_runsites:
	free(resource->runsites.sites);
err_free_resource:
	free(resource);
	return NULL;
}

void resource_set_daemon(struct resource *r, struct daemon *d)
{
	r->daemon = d;
}

struct resource_list *create_resource_list(int max)
{
	struct resource_list *reslist;

	reslist = malloc(sizeof(*reslist));
	if (reslist) {
		reslist->resources = calloc(max, sizeof(struct resource *));
		if (reslist->resources == NULL)
			goto err_free_resource_list;
		reslist->max = max;
		reslist->nr = 0;
	}

	return reslist;

err_free_resource_list:
	free(reslist);
	return NULL;
}

void free_resource_list(struct resource_list *list)
{
	if (list) {
		if (list->resources)
			free(list->resources);
		free(list);
	}
}

int resource_list_resize(struct resource_list *list)
{
	struct resource **resources;
	struct resource **tmp;
	int size;

	size = list->max + (list->max * 3) / 2;
	resources = calloc(size, sizeof(*resources));
	if (!resources)
		return -1;
	list->max = size;

	tmp = list->resources;
	memcpy(resources, tmp, list->nr * sizeof(*resources));

	list->resources = resources;
	free(tmp);

	return 0;
}

int resource_list_put(struct resource_list *list, struct resource *res)
{
	list->resources[list->nr] = res;
	list->nr += 1;

	return (list->nr == list->max) ? resource_list_resize(list) : 0;
}

struct resource_list *init_resource_list(struct daemon *daemon, struct config *cfg)
{
	struct resource_list *reslist;
	int i;

	reslist = create_resource_list(1);
	if (!reslist)
		return NULL;

	for (i = 0; i < cfg->res_num; i++) {
		struct resource *resource;
		struct res_config *res_config;
		int ret;

		res_config = &cfg->res[i];
		ret = check_local_resource(res_config, cfg);
		if (!ret)
			continue;

		resource = make_resource(daemon, cfg, res_config);
		if (resource == NULL)
			goto err_free_resource_list;
		resource_set_daemon(resource, daemon);

		ret = resource_list_put(reslist, resource);
		if (ret < 0)
			goto err_free_resource_list;
	}

	return reslist;

err_free_resource_list:
	free_resource_list(reslist);
	return NULL;
}

/*
 * 从 resource_list 中过滤出需要连接的 node_list 列表
 *
 * 在遍历 resource_list 之前，不知道有多少个 site 节点需要连接。可以先创建一个
 * node_list，动态地增加这个列表，在完成之后，就能够确定有多少个 site 节点需要连
 * 接了，最后再创建一个有准确数目的 node_list。
 *
 * 这里的实现简单地遍历 resource_list 两次：一次确定有没有 log_owner，确定
 * log_owner 之后，第二次遍历将不是本地的 site 节点加入到 node_list 中。
 *
 * 因为这里的 resource_list 的数目不多，所以性能应该不是问题。
 */
struct node_list *filter_from(struct resource_list *rlist)
{
	struct node_list *nlist;
	struct resource *resource;
	int i, j;

	nlist = create_node_list(2);
	if (nlist == NULL)
		return NULL;

	/* node_list_do_connect() 需要一个本地 site 节点 */
	resource = rlist->resources[0];
	nlist->local_node_id = 0;
	nlist->nodes[0] = resource->local_site;
	nlist->node_num = 1;

	for (i = 0; i < rlist->nr; i++) {
		resource = rlist->resources[i];
		if (!node_logowner(resource))
			continue;

		for (j = 0; j < resource->runsites.nr; j++) {
			struct node *site;
			int ret;

			site = &resource->runsites.sites[j];
			if (site == resource->local_site)
				continue;
			ret = node_list_put(nlist, site);
			if (ret < 0)
				goto free_node_list;
		}
	}

	return nlist;

free_node_list:
	free(nlist);
	return NULL;
}

void send_connect_info(struct device *dev, struct resource *resource)
{
	struct packet *pkt;
	int idx;

	/* yes, it is log owner, sent packet to other log owner */
	pkt = alloc_packet0();
	pkt->type = P_SC_CONN_STATE;
	pkt->node_type = SITE_NODE;
	pkt->node_from = resource->local_site->id;

	for (idx = 0; idx < resource->runsites.nr; idx++) {
		struct node *site;

		site = &resource->runsites.sites[idx];
		if (resource->local_site == site)
			continue;

		if (site->data_conn_state == NODE_DFD_CONNECTED &&
			site->meta_conn_state == NODE_MFD_CONNECTED)
		{
			packet_set_node_to(site->id, pkt);
		}
	}

	pkt->dev_id = resource->attr.id;
	dev_put_meta_packet(dev, pkt);
}

void notify_all(struct device *dev, struct resource_list *list)
{
	int idx;

	for (idx = 0; idx < list->nr; idx++) {
		struct resource *resource;

		resource = list->resources[idx];
		send_connect_info(dev, resource);
	}
}

struct resource *find_resource_by_id(struct resource_list *list, int id)
{
	int i;
	struct resource *resource;
	struct resource *tmp;

	resource = NULL;
	for (i = 0; i < list->nr; i++) {
		tmp = list->resources[i];
		if (tmp && tmp->attr.id == id) {
			resource = tmp;
			break;
		}
	}

	return resource;
}

void pr_resource(struct resource *resource)
{
	int i;

	printf("resource:\n");
	printf("\tid: %d\n", resource->attr.id);
	printf("\tname: %s\n", resource->attr.name);
	printf("\tnodes:\n");
	for (i = 0; i < resource->runsites.nr; i++) {
		struct node *node;

		node = &resource->runsites.sites[i];
		printf("\t\tid: %d\n", node->id);
		printf("\t\tremote_ip: %s, remote_port: %s\n", node->remote_ip, node->remote_port);
	}
	printf("\tlocal_site: %d\n", resource->local_site->id);
}

void pr_resource_list(struct resource_list *list)
{
	int i;

	for (i = 0; i < list->nr; i++) {
		struct resource *res;

		res = list->resources[i];
		pr_resource(res);
	}
}
