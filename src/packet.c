#include "common.h"

struct sock_packet *alloc_sock_packet(int node_type)
{
	struct sock_packet *pkt;
	size_t size;

	size = sizeof(*pkt);
	if (node_type == SITE_NODE)
		size += MAX_IPADDR_LEN;

	pkt = malloc(size);
	if(pkt == NULL) {
		return NULL;
	}

	memset(pkt, 0, size);

	return pkt;
}

void log_sock_packet(struct sock_packet *pkt)
{
	log_debug("%s_HANDSHAKE from %s %d, ipaddr=%s",
		  pkt->type == DATA_HANDSHAKE ? "DATA" : "META",
		  node_type_name[pkt->node_type], pkt->node_id, pkt->ipaddr);
}

struct sock_packet *create_sock_packet(int type, int node_id, int node_type, char *ipaddr)
{
	struct sock_packet *pkt;

	pkt = alloc_sock_packet(node_type);
	if(pkt == NULL) {
		return NULL;
	}

	pkt->type = type;
	pkt->node_id = node_id;
	pkt->node_type = node_type;
	snprintf(pkt->ipaddr, MAX_IPADDR_LEN, "%s", ipaddr);

	log_sock_packet(pkt);

	return pkt;
}

void free_sock_packet(struct sock_packet *pkt)
{
	free(pkt);
}

int sock_packet_send(int fd, struct sock_packet *pkt)
{
	int ret;

	ret = sock_write(fd, pkt, sizeof(struct sock_packet));
	if(ret != sizeof(struct sock_packet)) {
		return -1;
	}

	return ret;
}

int sock_packet_recv(int fd, struct sock_packet *pkt)
{
	int ret;

	ret = sock_read(fd, pkt, sizeof(struct sock_packet));
	if(ret != sizeof(struct sock_packet)) {
		return -1;
	}

	return ret;
}

struct packet *alloc_packet(uint32_t len)
{
	int total_len;
	struct packet *pkt;

	total_len = sizeof(struct packet) + len;

	pkt = malloc(total_len);
	if(pkt == NULL) {
		return NULL;
	}

	memset(pkt, 0, total_len);

	pkt->magic = MAGIC;
	pkt->len = len;

	return pkt;
}

struct packet *alloc_packet0()
{
	return alloc_packet(0);
}

void free_packet(struct packet *pkt)
{
	free(pkt);
}

int packet_send(int fd, struct packet *pkt)
{
	int total_len;
	int ret;

	if(fd < 0) {
		return -1;
	}

	total_len = sizeof(struct packet) + pkt->len;

	ret = sock_write(fd, pkt, total_len);
	if(ret != total_len) {
		return -1;
	}

	return ret;
}

struct packet *packet_recv_header(int fd)
{
	struct packet *hdr;
	int ret;

	hdr = alloc_packet0();
	if(hdr == NULL) {
		return NULL;
	}

	ret = sock_read(fd, hdr, sizeof(struct packet));
	if(ret != sizeof(struct packet)) {
		free_packet(hdr);
		return NULL;
	}

	return hdr;
}

struct packet *packet_recv(int fd)
{
	struct packet *hdr;
	struct packet *pkt;
	int ret;

	hdr = packet_recv_header(fd);
	if(hdr == NULL) {
		return NULL;
	}

	pkt = alloc_packet(hdr->len);
	if(pkt == NULL) {
		goto err_hdr;
	}

	memcpy(pkt, hdr, sizeof(struct packet));

	ret = sock_read(fd, pkt->data, pkt->len);
	if(ret != pkt->len) {
		goto err_pkt;
	}

	free_packet(hdr);
	return pkt;

err_pkt:
	free_packet(pkt);

err_hdr:
	free_packet(hdr);

	return NULL;
}

int packet_set_node_to(int nr, struct packet *packet)
{
	return set_bit(nr, packet->node_to);
}

int packet_test_node_to(int nr, struct packet *packet)
{
	return test_bit(nr, packet->node_to);
}

int get_packet_node_type(struct packet *packet)
{
	int p_type = packet->type;

	if ((p_type >= P_SC_START && p_type <= P_SC_END) ||
			(p_type >= P_SD_START && p_type <= P_SD_END))
		return SITE_NODE;

	if ((p_type >= P_NC_START && p_type <= P_NC_END) ||
			(p_type >= P_ND_START && p_type <= P_ND_END))
		return LOCAL_NODE;
	return -1;
}

struct packet *create_config_packet(struct config *cfg)
{
	struct packet *pkt;
	struct conf_packet *conf_pkt;

	conf_pkt = pack_config(cfg);
	if(conf_pkt == NULL) {
		return NULL;
	}

	pkt = alloc_packet(conf_pkt->len);
	if(pkt == NULL) {
		goto err_pkt;
	}

	pkt->type = P_CONFIG;
	memcpy(pkt->data, conf_pkt, conf_pkt->len);

	free_conf_packet(conf_pkt);
	return pkt;

err_pkt:
	free_conf_packet(conf_pkt);

	return NULL;
}

struct packet *packet_clone(struct packet *orig_pkt)
{
	struct packet *pkt;

	pkt = alloc_packet(orig_pkt->len);
	if(pkt == NULL) {
		return NULL;
	}

	memcpy(pkt, orig_pkt, sizeof(struct packet) + orig_pkt->len);

	return pkt;
}

struct z_packet *alloc_z_packet(uint32_t len)
{
	struct z_packet *z_pkt;
	int total_len;

	total_len = sizeof(struct z_packet) + len;

	z_pkt = malloc(total_len);
	if(z_pkt == NULL) {
		return NULL;
	}

	memset(z_pkt, 0, total_len);
	z_pkt->len = len;

	return z_pkt;
}

struct z_packet *alloc_z_packet0()
{
	return alloc_z_packet(0);
}

void free_z_packet(struct z_packet *z_pkt)
{
	free(z_pkt);
}

struct z_packet *pack_z_packet(struct packet *pkt)
{
	struct z_packet *z_pkt;
	unsigned char *out;
	unsigned long outlen;
	unsigned long total_len;
	int ret;

	total_len = sizeof(struct packet) + pkt->len;
	out = malloc(total_len);
	if(out == NULL) {
		return NULL;
	}

	memset(out, 0, total_len);
	ret = compress(out, &outlen, (unsigned char *)pkt, total_len);
	if(ret != Z_OK) {
		free(out);
		return NULL;
	}

	z_pkt = alloc_z_packet(outlen);
	z_pkt->data_len = pkt->len;

	memcpy(z_pkt->data, out, outlen);

	return z_pkt;
}

struct packet *unpack_z_packet(struct z_packet *z_pkt)
{
	struct packet *pkt;
	unsigned char *out;
	unsigned long outlen;
	unsigned long total_len;
	int ret;

	total_len = sizeof(struct packet) + z_pkt->data_len;

	pkt = alloc_packet(z_pkt->data_len);
	if(pkt == NULL) {
		return NULL;
	}

	ret = uncompress((unsigned char *)pkt, &outlen, z_pkt->data, total_len);
	if(ret != Z_OK) {
		free_packet(pkt);
		return NULL;
	}

	return pkt;
}

struct z_packet *z_packet_recv_header(int fd)
{
	struct z_packet *hdr;
	int ret;

	hdr = alloc_z_packet0();
	if(hdr == NULL) {
		return NULL;
	}

	ret = sock_read(fd, hdr, sizeof(struct z_packet));
	if(ret != sizeof(struct z_packet)) {
		free_z_packet(hdr);
		return NULL;
	}

	return hdr;
}

struct z_packet *z_packet_recv(int fd)
{
	struct z_packet *hdr;
	struct z_packet *pkt;
	int ret;

	hdr = z_packet_recv_header(fd);
	if(hdr == NULL) {
		return NULL;
	}

	pkt = alloc_z_packet(hdr->len);
	if(pkt == NULL) {
		goto err_hdr;
	}

	memcpy(pkt, hdr, sizeof(struct z_packet));

	ret = sock_read(fd, pkt->data, pkt->len);
	if(ret != pkt->len) {
		goto err_pkt;
	}

	free_z_packet(hdr);
	return pkt;

err_pkt:
	free_z_packet(pkt);

err_hdr:
	free_z_packet(hdr);

	return NULL;
}

int z_packet_send(int fd, struct z_packet *pkt)
{
	int total_len;
	int ret;

	total_len = sizeof(struct z_packet) + pkt->len;

	ret = sock_write(fd, pkt, total_len);
	if(ret != total_len) {
		return -1;
	}

	return ret;
}

void log_packet_header(struct packet *pkt)
{
	int idx;
	int max_node = 0;
	int node_num = 0;
	char nfmt[8];
	char node_to_str[128];

	memset(node_to_str, 0, sizeof(node_to_str));
	for(idx = 0; idx < MAX_NODES; idx++) {
		if(packet_test_node_to(idx, pkt)) {
			node_num++;
			max_node = idx;
		}
	}

	for(idx = 0; idx < max_node && node_num > 0; idx++) {
		if(packet_test_node_to(idx, pkt)) {
			memset(nfmt, 0, sizeof(nfmt));
			snprintf(nfmt, sizeof(nfmt), "%d,", idx);
			strncat(node_to_str, nfmt, sizeof(node_to_str));
		}
	}

	if(node_num > 0) {
		memset(nfmt, 0, sizeof(nfmt));
		snprintf(nfmt, sizeof(nfmt), "%d", max_node);
		strncat(node_to_str, nfmt, sizeof(node_to_str));
	} else {
		snprintf(node_to_str, sizeof(node_to_str), "NaN");
	}

	log_debug("|magic:%#lx|len:%u|type:%s|dev_id:%d|"
			"node_from:%u|node_to:%s|"
			"dev_sector:%lu|bwr_sector:%lu|"
			"site_state_num:%d|errcode:%d|",
			pkt->magic, pkt->len, packet_name[pkt->type], pkt->dev_id,
			pkt->node_from, node_to_str,
			pkt->dev_sector, pkt->bwr_sector,
			pkt->site_state_num, pkt->errcode);

}
