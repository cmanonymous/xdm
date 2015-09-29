#ifndef __IP_H__
#define __IP_H__

struct ip {
	char addr[MAX_IPADDR_LEN];
};

struct ip_list {
	int max;
	int inuse;
	struct ip *ips;
};

void init_ip_list(struct ip_list *list);
struct ip_list *create_ip_list(int max);
void free_ip_list(struct ip_list *list);
void pr_ip_list(struct ip_list *list);

#endif	/* __IP_H__ */
