#ifndef __RESOURCE_H__
#define __RESOURCE_H__

enum {
	LOCAL_NODE_LIST,
	REMOTE_NODE_LIST,
	NR_LIST,
};

struct resource_attribute {
	int id;
	char name[MAX_NAME_LEN];
};

struct site_vec {
	int nr;
	struct node *sites;
};

struct resource {
	struct resource_attribute attr;
	struct site_vec runsites;
	struct node *local_site;
	struct daemon *daemon;		/* point back */
};

/*
 * resource_list 只保存能在本 site 运行的 resource
 */
struct resource_list {
	int max;
	int nr;
	struct resource **resources;
};

struct resource_list *init_resource_list(struct daemon *daemon, struct config *cfg);
struct resource_list *create_resource_list(int max);

struct resource *make_resource(struct daemon *daemon, struct config *cfg, struct res_config *res_config);
struct node_list *filter_from(struct resource_list *rlist);

struct resource *find_resource_by_id(struct resource_list *list, int id);

#endif	/* __RESOURCE_H__ */
