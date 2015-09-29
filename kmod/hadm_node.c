#include "hadm_node.h"


struct hadm_node *hadm_node_alloc(gfp_t flag)
{
	struct hadm_node *node;

	node = kmalloc(sizeof(struct hadm_node), flag);
	if (!node)
		return NULL;
	INIT_LIST_HEAD(&node->node);

	return node;
}

struct hadm_node *hadm_node_create(int id, char *name, char *ipaddr)
{
	struct hadm_node *node;

	node = kzalloc(sizeof(struct hadm_node), GFP_KERNEL);
	if (!node)
		return NULL;

	INIT_LIST_HEAD(&node->node);
	node->id = id;
	strncpy(node->name, name, sizeof(node->name));
	strncpy(node->ipaddr, ipaddr, sizeof(node->ipaddr));

	return node;
}

void hadm_node_disconnect(struct hadm_node *node)
{
	if (!hadm_node_connect(node))
		return;
	pr_info("%s disconnect from node(%s) %d.\n", __FUNCTION__,
			node->name, node->id);
	clear_hadm_node_connect(node);
}
