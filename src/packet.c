#include "common.h"

struct sock_packet *alloc_sock_packet()
{
	struct sock_packet *pkt;

	pkt = malloc(sizeof(struct sock_packet));
	if(pkt == NULL) {
		return NULL;
	}

	memset(pkt, 0, sizeof(struct sock_packet));

	return pkt;
}

struct sock_packet *create_sock_packet(int node_id, int type)
{
	struct sock_packet *pkt;

	pkt = alloc_sock_packet();
	if(pkt == NULL) {
		return NULL;
	}

	pkt->node_id = node_id;
	pkt->type = type;

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
		log_error("Error: %s failed", __func__);
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
		log_error("%s: alloc packet failed.\n", __func__);
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
		log_error("Error: %s wrong fd:%d", __func__, fd);
		return -1;
	}

	total_len = sizeof(struct packet) + pkt->len;

	ret = sock_write(fd, pkt, total_len);
	if(ret != total_len) {
		log_error("Error: %s write:(%d:%d)", __func__, total_len, ret);
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
		log_error("Error: recv packet header failed(%u:%d)",
				sizeof(struct packet), ret);
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
		log_error("Error: %s recv head failed", __func__);
		return NULL;
	}

	pkt = alloc_packet(hdr->len);
	if(pkt == NULL) {
		log_error("Error: %s alloc packet failed", __func__);
		goto err_hdr;
	}

	memcpy(pkt, hdr, sizeof(struct packet));

	ret = sock_read(fd, pkt->data, pkt->len);
	if(ret != pkt->len) {
		log_error("Error: %s read data failed", __func__);
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

void packet_log_debug(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str)
{
	log_debug("|magic:%#lx|len:%u|type:%s|dev_id:%d|"
			"node_from:%u|node_to:%s|"
			"kmod_from:%x|kmod_to:%s|"
			"dev_sector:%lu|bwr_sector:%lu|bwr_seq:%lu|"
			"node_state_num:%d|errcode:%d|",
			pkt->magic, pkt->len, packet_name[pkt->type], pkt->dev_id,
			pkt->node_from, node_to_str,
			pkt->kmod_from, kmod_to_str,
			pkt->dev_sector, pkt->bwr_sector, pkt->bwr_seq,
			pkt->node_state_num, pkt->errcode);
}

void packet_log_info(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str)
{
	log_info("|magic:%#lx|len:%u|type:%s|dev_id:%d|"
			"node_from:%u|node_to:%s|"
			"kmod_from:%x|kmod_to:%s|"
			"dev_sector:%lu|bwr_sector:%lu|bwr_seq:%lu|"
			"node_state_num:%d|errcode:%d|",
			pkt->magic, pkt->len, packet_name[pkt->type], pkt->dev_id,
			pkt->node_from, node_to_str,
			pkt->kmod_from, kmod_to_str,
			pkt->dev_sector, pkt->bwr_sector, pkt->bwr_seq,
			pkt->node_state_num, pkt->errcode);
}

void packet_log_warn(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str)
{
	log_warn("|magic:%#lx|len:%u|type:%s|dev_id:%d|"
			"node_from:%u|node_to:%s|"
			"kmod_from:%x|kmod_to:%s|"
			"dev_sector:%lu|bwr_sector:%lu|bwr_seq:%lu|"
			"node_state_num:%d|errcode:%d|",
			pkt->magic, pkt->len, packet_name[pkt->type], pkt->dev_id,
			pkt->node_from, node_to_str,
			pkt->kmod_from, kmod_to_str,
			pkt->dev_sector, pkt->bwr_sector, pkt->bwr_seq,
			pkt->node_state_num, pkt->errcode);
}

void packet_log_error(struct packet *pkt,
		      const char *node_to_str, const char *kmod_to_str)
{
	log_error("|magic:%#lx|len:%u|type:%s|dev_id:%d|"
			"node_from:%u|node_to:%s|"
			"kmod_from:%x|kmod_to:%s|"
			"dev_sector:%lu|bwr_sector:%lu|bwr_seq:%lu|"
			"node_state_num:%d|errcode:%d|",
			pkt->magic, pkt->len, packet_name[pkt->type], pkt->dev_id,
			pkt->node_from, node_to_str,
			pkt->kmod_from, kmod_to_str,
			pkt->dev_sector, pkt->bwr_sector, pkt->bwr_seq,
			pkt->node_state_num, pkt->errcode);
}

void bit_index_to_str(int bit, char *str, int len)
{
	int idx;
	int max_node = 0;
	int node_num = 0;
	char nfmt[8];

	memset(str, 0, len);
	for (idx = 0; idx < MAX_NODES; idx++) {
		if (test_bit(idx, bit)) {
			node_num += 1;
			max_node = idx;
		}
	}

	for (idx = 0; idx < max_node && node_num > 0; idx++) {
		if (test_bit(idx, bit)) {
			memset(nfmt, 0, sizeof(nfmt));
			snprintf(nfmt, sizeof(nfmt), "%d,", idx);
			strncat(str, nfmt, len);
		}
	}

	if (node_num > 0) {
		memset(nfmt, 0, sizeof(nfmt));
		snprintf(nfmt, sizeof(nfmt), "%d", max_node);
		strncat(str, nfmt, len);
	} else {
		snprintf(str, len, "NaN");
	}
}

void log_packet_header(struct packet *pkt,
		       void (*pkt_log_fn)(struct packet *, const char *, const char *))
{
	char node_to_str[128];
	char kmod_to_str[128];

	bit_index_to_str(pkt->node_to, node_to_str, sizeof(node_to_str));
	bit_index_to_str(pkt->kmod_to, kmod_to_str, sizeof(kmod_to_str));

	pkt_log_fn(pkt, node_to_str, kmod_to_str);
}
