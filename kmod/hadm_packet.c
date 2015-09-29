#define pr_fmt(fmt) "hadm_packet: " fmt

#include <linux/module.h>

#include "hadm_packet.h"
#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "bwr.h"
#include "utils.h"
#include "hadm_struct.h"
#include "p_worker.h"
#include "hadm_socket.h"
#include "hadm_bio.h"
#include "fullsync.h"

#define NOT_USE_CSTATE_NAME
#define NOT_USE_DSTATE_NAME
#define NOT_USE_NSTATE_NAME
#define NOT_USE_ROLE_NAME
#define NOT_USE_DEV_STATE_NAME
#define NOT_USE_PROTO_NAME
#include "../include/common_string.h"

void dump_packet(const char *msg, struct packet *pack)
{
	char md5_str[33];

	md5_print(md5_str, pack->md5);
	printk(KERN_INFO "%s: magic=0x%llx|md5=%s|type=%s|uuid=%llu|bwr_seq=%llu|len=%u|dev_id=%d|"
	       "from=%u|to=0x%x|dev_sector=%llu|bwr_sector=%llu|bwr_seq=%llu|"
	       "node_state_num=%u|errcode=%d\n",
	       msg,
	       (unsigned long long)pack->magic,
	       md5_str,
	       packet_name[pack->type],
	       (unsigned long long)pack->uuid,
	       (unsigned long long)pack->bwr_seq,
	       pack->len,
	       pack->dev_id,
	       pack->node_from,
	       pack->node_to,
	       (unsigned long long)pack->dev_sector,
	       (unsigned long long)pack->bwr_sector,
	       (unsigned long long)pack->bwr_seq,
	       pack->node_state_num,
	       pack->errcode);
}

void packet_free(struct packet *pack)
{
	if (pack != NULL && !IS_ERR(pack))
		kfree(pack);
}

struct packet *packet_alloc(size_t len, int gfp_mask)
{
	struct packet *pack;

	pack = kzalloc(PACKET_HDR_LEN + len, gfp_mask);
	if (!pack || IS_ERR(pack))
		return NULL;

	pack->magic = MAGIC;
	pack->type = P_UNKNOWN;
	pack->len = len;
	pack->node_from = get_node_id();
	pack->kmod_from = get_kmod_id();
	pack->errcode = 0;

	return pack;
}

struct packet *packet_alloc_for_node(size_t len, int gfp_mask,
		struct hadm_node *node)
{
	struct packet *pack;

	pack = packet_alloc(len, gfp_mask);
	if (!pack)
		return NULL;

	pack->node_to = (1 << node->id);
	pack->kmod_to = (1 << node->kmod_id);

	return pack;
}

void packet_init(struct packet *pack, uint8_t type, uint8_t dev_id,
		 uint32_t node_to, uint64_t dev_sector, uint64_t bwr_sector, uint64_t bwr_seq,
		 uint32_t nr_node_state, int16_t errcode)
{
	pack->type = type;
	pack->dev_id = dev_id;
	pack->node_to = node_to;
	pack->dev_sector = dev_sector;
	pack->bwr_sector = bwr_sector;
	pack->bwr_seq = bwr_seq;
	pack->node_state_num = nr_node_state;
	pack->errcode = errcode;
}

struct packet *packet_alloc_node_state_packet(struct hadmdev *hadmdev)
{
	struct packet *state_pack;
	struct hadm_node *hadm_node;
	struct node_state_packet *ns_pack;
	size_t datalen;
	int nr_nodes, local_node_id;

	local_node_id = get_node_id();
	nr_nodes = atomic_read(&hadmdev->hadm_node_list_len);
	datalen = nr_nodes * sizeof(struct node_state_packet);

	state_pack = packet_alloc(datalen, GFP_KERNEL);
	if (!state_pack)
		return NULL;

	state_pack->type = P_NODE_STATE;
	state_pack->dev_id = hadmdev->minor;
	state_pack->node_to = get_hs_nodes(hadmdev);
	state_pack->kmod_to = -1;
	state_pack->node_state_num = nr_nodes;
	state_pack->uuid = hadmdev->bwr->mem_meta.local_primary.uuid;
	state_pack->bwr_seq = bwr_seq(hadmdev->bwr);

	ns_pack = (struct node_state_packet *)state_pack->data;
	list_for_each_entry(hadm_node, &hadmdev->hadm_node_list, node) {
		hadm_node_state_pack(ns_pack, &hadm_node->s_state);
		ns_pack += 1;
	}

	return state_pack;
}

/* NOTE: packet_send 没有处理队列被禁用的情况，因为没有搞清楚如何释放队列节点 */
int packet_send(struct packet *snd_pack)
{
	struct hadm_pack_node *node;
	struct hadmdev *hadmdev = NULL;
	hadmdev = find_hadmdev_by_minor(snd_pack->dev_id);
	if(hadmdev == NULL) {
		return -ENODEV;
	}

	if (snd_pack->type >= P_TYPE_MAX)
		return -ECMD_NO_STATE;

	if(P_CTRL_START<snd_pack->type && snd_pack->type < P_CTRL_END) {
		node=hadm_pack_node_create(snd_pack,g_hadm->ctrl_net->sock);
		if (node == NULL || IS_ERR(node))
			return -ENOMEM;
		hadm_queue_push(hadmdev->p_sender_queue[P_CTRL_TYPE] , &node->q_node);
		atomic_inc(&g_hadm->sender_queue_size[P_CTRL_TYPE]);
	}
	else if (P_DATA_START < snd_pack->type && snd_pack->type < P_DATA_END) {
		node=hadm_pack_node_create(snd_pack,g_hadm->data_net->sock);
		if (node == NULL || IS_ERR(node))
			return -ENOMEM;
		hadm_queue_push(hadmdev->p_sender_queue[P_DATA_TYPE] , &node->q_node);
		atomic_inc(&g_hadm->sender_queue_size[P_DATA_TYPE]);
	}
	else {
		pr_err("%s: wrong packet\n", __FUNCTION__);
		dump_packet("packet_send", snd_pack);
	}
	wake_up(&g_hadm->queue_event);

	return 0;
}

int packet_node_send(struct hadm_pack_node *node, int block)
{
	struct packet *snd_pack = node->pack;
	struct hadmdev *hadmdev = NULL;
	int ret;
	int p_type = P_TYPE_MAX;
	hadmdev = find_hadmdev_by_minor(snd_pack->dev_id);
	if(hadmdev == NULL) {
		return -ENODEV;
	}

	if (snd_pack->type >= P_TYPE_MAX)
		return -ECMD_NO_STATE;

	if(P_CTRL_START < snd_pack->type && snd_pack->type < P_CTRL_END) {
		p_type = P_CTRL_TYPE;
	}
	else if (P_DATA_START < snd_pack->type && snd_pack->type < P_DATA_END) {
		p_type = P_DATA_TYPE;
	}
	else {
		pr_err("%s: wrong packet\n", __FUNCTION__);
		dump_packet("packet_send", snd_pack);
		return -EINVAL;
	}
	if(block)
		ret = hadm_queue_push(hadmdev->p_sender_queue[p_type] , &node->q_node);
	else
		ret = hadm_queue_push_nowait(hadmdev->p_sender_queue[p_type] , &node->q_node);
	if(ret){
		pr_err("%s: push to queue %s failed, queue length = %u\n", 
				__FUNCTION__,
				hadmdev->p_sender_queue[p_type]->name, 
				hadm_queue_len(hadmdev->p_sender_queue[p_type]));
		return ret;
	}

	atomic_inc(&g_hadm->sender_queue_size[p_type]);
	wake_up(&g_hadm->queue_event);
	return 0;


}

int send_uptodate_packet(struct hadm_node *hadm_node, uint64_t bwr_seq)
{
	struct packet *packet;
	struct hadmdev *hadmdev = hadm_node->hadmdev;
	packet = packet_alloc_for_node(0, GFP_KERNEL, hadm_node);
	if (!packet) {
		pr_err("%s: alloc packet failed.\n", __func__);
		return -ENOMEM;
	}

	packet->type = P_DATA;
	packet->uuid = hadmdev->bwr->mem_meta.local_primary.uuid;
	packet->bwr_seq = bwr_seq;
	packet->dev_id = hadmdev->minor;

	pr_info("send p_data(0len) packet: bwr_seq:%lld, uuid:%llu.\n",
			packet->bwr_seq, packet->uuid);
	return packet_send(packet);
}

int sync_node_bwrdata(struct hadm_node *node, struct bwr_data *data,
		int sync_type)
{
	int ret;
	struct packet *pack;

	pack = packet_alloc_for_node(PAGE_SIZE, GFP_KERNEL, node);
	if (!pack)
		return -ENOMEM;
	pack->type = sync_type;
	//pack->bwr_seq = sync_type == P_DATA ? data->meta.bwr_seq : 0;
	pack->bwr_seq = data->meta.bwr_seq;
	pack->dev_id = node->hadmdev->minor;
	pack->dev_sector = data->meta.dev_sector;
	pack->bwr_sector = data->meta.bwr_sector;
	pack->uuid = bwr_get_uuid(node->hadmdev->bwr);

	memcpy(pack->data, page_address(data->data_page), PAGE_SIZE);
	fullsync_md5_hash(pack->data, PAGE_SIZE, pack->md5);

	ret = packet_send(pack);
	if (ret < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		packet_free(pack);
	}
	return ret;
}

int rssync_node_sector(struct hadm_node *node, sector_t dev_sector)
{
	int ret;
	struct packet *pack;
	struct page *page;
	struct hadm_io hadm_io_vec[1];
	struct hadmdev *hadmdev = node->hadmdev;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s alloc page faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	hadm_io_vec[0].page = page;
	hadm_io_vec[0].start = 0;
	hadm_io_vec[0].len = PAGE_SIZE;
	ret = hadm_io_rw_sync(hadmdev->bdev, dev_sector, READ, hadm_io_vec, 1);
	if (ret < 0) {
		pr_err("%s write faild.(%d)\n", __FUNCTION__, ret);
		goto free_page;
	}

	/* 2. 发送数据 */
	ret = -ENOMEM;
	pack = packet_alloc_for_node(PAGE_SIZE, GFP_KERNEL, node);
	if (!pack) {
		pr_err("%s alloc packet faild.\n", __FUNCTION__);
		goto free_page;
	}
	pack->type = P_RS_DATA;
	pack->dev_id = hadmdev->minor;
	pack->uuid = bwr_get_uuid(hadmdev->bwr);
	pack->dev_sector = dev_sector;

	memcpy(pack->data, page_address(page), PAGE_SIZE);

	/* for debug */
	fullsync_md5_hash(pack->data, PAGE_SIZE, pack->md5);

	/* sender will free packet */
	ret = packet_send(pack);
	if (ret < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		packet_free(pack);
	}

free_page:
	__free_page(page);
	return ret;
}
