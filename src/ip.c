#include "common.h"

struct ip_list *create_ip_list(int max)
{
	struct ip_list *list;

	list = malloc(sizeof(*list));
	if (list == NULL)
		return NULL;

	list->ips = calloc(max, sizeof(struct ip));
	if (list->ips == NULL)
		goto err_free_ip_list;
	list->max = max;
	list->inuse = 0;

	return list;

err_free_ip_list:
	free(list);
	return NULL;
}

void free_ip_list(struct ip_list *list)
{
	if (list) {
		if (list->ips)
			free(list->ips);
		free(list);
	}
}

int ip_list_resize(struct ip_list *list)
{
	struct ip *ips;
	struct ip *tmp;
	int size;

	size = list->max + (list->max * 3) / 2;
	ips = calloc(size, sizeof(*ips));
	if (!ips)
		return -1;
	list->max = size;

	tmp = list->ips;
	memcpy(ips, tmp, list->inuse * sizeof(*ips));

	list->ips = ips;
	free(tmp);

	return 0;
}

/* taken from http://stackoverflow.com/questions/212528/get-the-ip-address-of-the-machine
 * modified by huruiqin@skybility.com
 */
void init_ip_list(struct ip_list *list)
{
	int ret;
	struct ifaddrs *ifp;
	struct ifaddrs *tmp;
	struct ip *ip;

	ret = getifaddrs(&ifp);
	if (ret < 0) {
		log_error("failed to get ip address");
		return;
	}

	ip = list->ips;
	for (tmp = ifp; tmp != NULL; tmp = tmp->ifa_next) {
		int family;
		void *addr;

		if (!tmp->ifa_addr)
			continue;

		family = tmp->ifa_addr->sa_family;
		if (family == AF_INET) {
			struct sockaddr_in *ipv4 = (struct sockaddr_in *)tmp->ifa_addr;
			addr = &ipv4->sin_addr;
			inet_ntop(AF_INET, addr, ip->addr, MAX_IPADDR_LEN);
			list->inuse += 1;
			ip += 1;
		} else if (family == AF_INET6) {
			struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)tmp->ifa_addr;
			addr = &ipv6->sin6_addr;
			inet_ntop(AF_INET6, addr, ip->addr, MAX_IPADDR_LEN);
			list->inuse += 1;
			ip += 1;
		}

		if (list->inuse == list->max) {
			ret = ip_list_resize(list);
			if (ret < 0)
				break;
			ip = &list->ips[list->inuse];
		}
	}

	if (ifp != NULL)
		freeifaddrs(ifp);
}

void pr_ip_list(struct ip_list *list)
{
	int i;

	for (i = 0; i < list->inuse; i++) {
		struct ip *ip;

		ip = &list->ips[i];
		printf("%s\n", ip->addr);
	}
}
