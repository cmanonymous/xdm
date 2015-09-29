#ifndef HADM_NODE_H
#define HADM_NODE_H

#include "hadm_def.h"


enum hadm_node_flags {
	__hn_connect,
	__hn_open,
	__hn_ready,
};

struct hadm_node {
	struct list_head node;
	uint32_t id;
	unsigned long flags;
	struct hadmdev *hadmdev;
	char name[MAX_NAME_LEN];
	char ipaddr[MAX_IPADDR_LEN];
};

#define HADM_NODE_FNS(name)					\
static inline void set_hadm_node_##name(struct hadm_node *node)	\
{								\
       set_bit(__hn_##name, &(node)->flags);                    \
}								\
static inline void clear_hadm_node_##name(struct hadm_node *node) \
{								\
       clear_bit(__hn_##name, &(node)->flags);			\
}								\
static inline int hadm_node_##name(struct hadm_node *node)	\
{								\
       return test_bit(__hn_##name, &(node)->flags);            \
}

HADM_NODE_FNS(connect)
HADM_NODE_FNS(open)
HADM_NODE_FNS(ready)

struct hadm_node *hadm_node_alloc(gfp_t flag);
struct hadm_node *hadm_node_create(int id, char *name, char *ipaddr);

void hadm_node_disconnect(struct hadm_node *node);

#endif  // HAMD_NODE_H
