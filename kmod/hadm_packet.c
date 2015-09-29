#define pr_fmt(fmt) "hadm_packet: " fmt

#include <linux/module.h>

#include "hadm_packet.h"
#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_site.h"
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


/* ---------- helper function ------------*/
static void hvec_to_kvec(struct hadm_io *hv, struct kvec *kv, uint32_t cnt)
{
	if (!cnt)
		return;
	while (cnt--) {
		kv[cnt].iov_base = page_address(hv[cnt].page) + hv[cnt].start;
		kv[cnt].iov_len = hv[cnt].len;
	}
}

/* TODO */
static int hadm_data_type(int type)
{
	switch (type) {
	case P_ND_SBIO:
	case P_ND_SBIO_ACK:
	case P_SD_DATA:
	case P_SD_RSDATA:
		return HADM_DATA_PAGE;
	default:
		return HADM_DATA_NORMAL;
	}
}

/* ----------- hapack_data ------------------*/

void dump_hdpack_data(const char *str, struct hdpack_data *data)
{
	if (!data)
		return;
	pr_info("%s: type:%d|count:%d|len:%u|vcnt:%u|max_vcnt:%u|\n",
			str, data->type, atomic_read(&data->count),
			data->len, data->vcnt, data->max_vcnt);
	if (data->type == HADM_DATA_PAGE)
		dump_hadm_io_vec(data->hv, data->vcnt);
	else
		pr_info("buff:%p.\n", data->buff);

}
/* @flags: mem alloc flag(GFP_KERNEL...)
 * @size:  data len for HADM_DATA_NORMAL, data max_vcnt for HADM_DATA_PAGE
 * @type:  data type: HADM_DATA_NORMAL/HADM_DATA_PAGE
 */
struct hdpack_data *hdpack_data_alloc(gfp_t flags, uint32_t size,
		int type)
{
	uint32_t vcnt;
	struct hdpack_data *data;
	struct hadm_io *hv;
	char *buf;

	data = kzalloc(sizeof(struct hdpack_data), flags);
	if (!data)
		return NULL;
	if (size) {
		if (type == HADM_DATA_PAGE) {
			vcnt = size;
			hv = kzalloc(sizeof(struct hadm_io) * vcnt, flags);
			if (!hv) {
				pr_err("%s: page hv (%u) alloc faild.", __func__, vcnt);
				goto data_fail;
			}
			data->max_vcnt = vcnt;
			data->hv = hv;
		} else if (type == HADM_DATA_NORMAL) {
			buf = kzalloc(size, flags);
			if (!buf) {
				pr_err("%s: buf alloc faild.", __FUNCTION__);
				goto data_fail;
			}
			data->buff = buf;

			/* 为防止加入HADM_DATA_NORMAL的数据时 忘记设置值，
			 * 在这里予以赋值*/
			data->len = size;
		} else {
			pr_err("%s: wrong type %d.", __FUNCTION__, type);
			goto data_fail;
		}
	}

	data->type = type;
	atomic_set(&data->count, 1);

	return data;

data_fail:
	kfree(data);
	return NULL;
}

void hdpack_data_clear_buff(struct hdpack_data *data)
{
	if (!data)
		return;
	if (data->len)
		kfree(data->buff);
	data->len = 0;
}

void hdpack_data_clear_page(struct hdpack_data *data)
{
	struct hadm_io *hv;

	if (!data)
		return;
	if (data->len) {
		while (data->vcnt--) {
			hv = &data->hv[data->vcnt];
			__free_page(hv->page);
		}
	}
	data->len = 0;
}

void hdpack_data_clear_content(struct hdpack_data *data)
{
	if (data->type == HADM_DATA_NORMAL)
		hdpack_data_clear_buff(data);
	else if (data->type == HADM_DATA_PAGE)
		hdpack_data_clear_page(data);
	else
		pr_err("%s: unsupport type %d.\n", __func__, data->type);
}

void hdpack_data_free(struct hdpack_data *data)
{
	int idx;

	if (atomic_dec_and_test(&data->count)) {
		if (data->len) {
			if (data->type == HADM_DATA_PAGE) {
				for (idx = 0; idx < data->vcnt; idx++)
					__free_page(data->hv[idx].page);
				kfree(data->hv);
			} else
				kfree(data->buff);
		}
		kfree(data);
	}
}

void hdpack_data_get(struct hdpack_data *data)
{
	atomic_inc(&data->count);
}

/* pack->head->len duplicate with data->len, so be carefull
 * NOTE: now, only support HADM_DATA_PAGE type data add page
 */
int hdpack_data_add_page(struct hdpack_data *data, struct page *page,
		int start, int len)
{
	struct hadm_io *hv;

	BUG_ON(data->type != HADM_DATA_PAGE);

	if (data->vcnt >= data->max_vcnt)
		return -1;

	hv = &data->hv[data->vcnt];
	hv->page = page;
	hv->start = start;
	hv->len = len;

	data->vcnt++;
	data->len += len;

	return 0;
}

int hdpack_data_alloc_pages(struct hdpack_data *data, uint32_t len)
{
	return 0;
}

/* -------------- hdpacket ----------------------*/
/* @flags: mem alloc flags
 * @data_len: packet data len
 * @data_type: HADM_DATA_NORMAL or HADM_DATA_PAGE
 *
 * 为了防止遗忘导致错误，这里引入了一个不一致的地方：
 * data->len/head.len 应该是数据的长度，在加入数据的时候设置，但在操作normal
 * 类型的数据时，容易忘记设置加入数据的长度，导致错误.
 * 因此：
 *	对于normal型数据，在alloc的时候设置数据的长度.(隐含了一个假设：即包在
 *	发送时，必定有填充所有数据)
 *
 *	对于page型数据，在alloc的时候没有设置数据长度，调用add_page接口增加.
 *
 * 总的来说，目前的接口不需要调用者在其它地方做设置数据长度的操作.
 */
struct hdpacket *hdpacket_alloc(gfp_t flags, uint32_t size, int data_type)
{
	struct packet *head;
	struct hdpacket *pack;
	struct hdpack_data *data;

	pack = kzalloc(sizeof(struct hdpacket), flags);
	if (!pack)
		return NULL;

	data = hdpack_data_alloc(flags, size, data_type);
	if (!data) {
		pr_err("%s: alloc data faild.", __FUNCTION__);
		kfree(pack);
		return NULL;
	}
	pack->data = data;

	head = &pack->head;
	head->magic = MAGIC;
	head->type = P_UNKNOWN;

	/* 参考data->len */
	if (data_type == HADM_DATA_NORMAL)
		head->len = size;

	INIT_LIST_HEAD(&pack->list);

	return pack;
}

struct hdpacket *site_hdpacket_alloc(gfp_t flags, uint32_t len, int type)
{
	struct hdpacket *pack;

	pack = hdpacket_alloc(flags, len, type);
	if (!pack)
		return NULL;
	pack->head.node_from = get_site_id();

	return pack;
}

struct hdpacket *node_hdpacket_alloc(gfp_t flags, uint32_t len, int type)
{
	struct hdpacket *pack;

	pack = hdpacket_alloc(flags, len, type);
	if (!pack)
		return NULL;
	pack->head.node_from = get_node_id();

	return pack;
}

void hdpacket_clear_data(struct hdpacket *pack)
{
	if (pack->head.len)
		hdpack_data_clear_content(pack->data);

	pack->head.len = 0;
}

void hdpacket_free(struct hdpacket *pack)
{
	BUG_ON(!pack);

	hdpack_data_free(pack->data);
	kfree(pack);
}

void hdpacket_queue_clean(struct hadm_queue *q)
{
	unsigned long flags;
	struct list_head del_list;
	struct hdpacket *iter, *tmp;

	INIT_LIST_HEAD(&del_list);
	spin_lock_irqsave(&q->lock, flags);
	list_cut_position(&del_list, &q->head, q->head.prev);
	q->len = 0;
	if (waitqueue_active(&q->push_waitqueue))
		wake_up(&q->push_waitqueue);
	spin_unlock_irqrestore(&q->lock, flags);

	list_for_each_entry_safe(iter, tmp, &del_list, list) {
		list_del(&iter->list);
		hdpacket_free(iter);
	}
}

void hdpacket_queue_clean_careful(struct hadm_queue *q)
{
	unsigned long flags;
	struct hdpacket *iter, *tmp;

	spin_lock_irqsave(&q->lock, flags);
	list_for_each_entry_safe(iter, tmp, &q->head, list) {
		list_del(&iter->list);
		hdpacket_free(iter);
	}
	q->len = 0;
	if (waitqueue_active(&q->push_waitqueue))
		wake_up(&q->push_waitqueue);
	spin_unlock_irqrestore(&q->lock, flags);
}

void hdpacket_queue_free(struct hadm_queue *q)
{
	hdpacket_queue_clean(q);
	hadm_queue_free(q);
}

int hdpacket_add_page(struct hdpacket *pack, struct page *page,
		int start, int len)
{
	int ret;

	ret = hdpack_data_add_page(pack->data, page, start, len);
	if (ret < 0) {
		pr_err("%s: data add page failed.", __FUNCTION__);
		return ret;
	}

	pack->head.len += len;
	return 0;
}

struct hdpacket *hdpacket_clone(struct hdpacket *pack)
{
	struct hdpacket *clone_pack;

	clone_pack = hdpacket_alloc(GFP_KERNEL, 0, pack->data->type);
	if (!clone_pack)
		return NULL;
	memcpy(&clone_pack->head, &pack->head, sizeof(struct packet));

	if (pack->data)
		hdpack_data_get(pack->data);
	clone_pack->data = pack->data;

	return clone_pack;
}

int hdpacket_send(struct socket *sock, struct hdpacket *pack)
{
	int ret;
	int len;
	int vcnt;
	struct kvec *kv;

	/* we need send the pack->head */
	vcnt = 1;

	if (pack->data->len) {
		if (pack->data->type == HADM_DATA_PAGE)
			vcnt += pack->data->vcnt;
		else
			vcnt++;
	}
	kv = kzalloc(sizeof(struct kvec) * vcnt, GFP_KERNEL);
	if (!kv)
		return -ENOMEM;
	kv[0].iov_base = &pack->head;
	kv[0].iov_len = sizeof(struct packet);

	if (pack->data->len) {
		if (pack->data->type == HADM_DATA_PAGE)
			hvec_to_kvec(pack->data->hv, &kv[1], vcnt - 1);
		else {
			kv[1].iov_base = pack->data->buff;
			kv[1].iov_len = pack->data->len;
		}
	}

	len = pack->data->len + sizeof(struct packet);
	ret = hadm_socket_sendv(sock, kv, vcnt, len);
	if (ret != len) {
		dump_packet(__func__, &pack->head);
		dump_hdpack_data(__func__, pack->data);
		pr_err("%s: sendv faild.ret:%d len:%d.\n", __FUNCTION__, ret, len);
		BUG_ON(ret > 0);
	} else
		ret = 0;

	kfree(kv);
	return ret;
}

struct hdpacket *__do_hdpacket_page_recv(struct socket *sock)
{
	int ret;
	int vcnt;
	int len, remain;
	struct kvec *kv;
	struct hdpacket *pack;
	struct packet *head;
	struct hdpack_data *data;
	struct page *page;

	pack = hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_PAGE);
	if (!pack) {
		pr_err("%s: hdpacket alloc faild.", __FUNCTION__);
		return NULL;
	}
	head = &pack->head;

	ret = hadm_socket_receive(sock, (char *)head, PACKET_HDR_LEN);
	if (ret != PACKET_HDR_LEN) {
		pr_err("%s: recevice error %d.", __FUNCTION__, ret);
		goto fail;
	}

	if (unlikely(head->magic != MAGIC)) {
		pr_err("%s: wrong packet", __FUNCTION__);
		//dump_packet("receive_node", pack);
		goto fail;
	}

	if (head->len) {
		vcnt = div_round_up(head->len, PAGE_SIZE);
		data = hdpack_data_alloc(GFP_KERNEL, vcnt, HADM_DATA_PAGE);
		if (!data) {
			pr_err("%s: hdpack_data alloc failed.", __FUNCTION__);
			goto fail;
		}
		pack->data = data;

		remain = head->len;
		while (remain > 0) {
			page = alloc_page(GFP_KERNEL);
			if (!page) {
				pr_err("%s: alloc page faild.", __FUNCTION__);
				goto fail;
			}
			len = min(remain, (int)PAGE_SIZE);
			ret = hdpacket_add_page(pack, page, 0, len);
			if (ret < 0) {
				pr_err("%s: add page faild.", __FUNCTION__);
				__free_page(page);
				goto fail;
			}
			remain -= len;
		}

		kv = kzalloc(sizeof(struct kvec) * data->vcnt, GFP_KERNEL);
		if (!kv) {
			pr_err("%s: alloc kv faild.", __FUNCTION__);
			goto fail;
		}
		hvec_to_kvec(data->hv, kv, data->vcnt);

		ret = hadm_socket_recvv(sock, kv, data->vcnt, head->len);
		kfree(kv);
		if (ret != head->len) {
			pr_err("%s: recvv faild.", __FUNCTION__);
			goto fail;
		}
	}

	return pack;

fail:
	hdpacket_free(pack);
	return NULL;
}

struct hdpacket *__do_hdpacket_normal_recv(struct socket *sock)
{
	int ret;
	struct hdpacket *pack;
	struct packet *head;
	struct hdpack_data *data;

	pack = hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack) {
		pr_err("%s: hdpacket alloc faild.", __FUNCTION__);
		return NULL;
	}
	head = &pack->head;

	ret = hadm_socket_receive(sock, (char *)head, PACKET_HDR_LEN);
	if (ret != PACKET_HDR_LEN) {
		pr_err("%s: recevice error %d.", __FUNCTION__, ret);
		goto fail;
	}

	if (unlikely(head->magic != MAGIC)) {
		pr_err("%s: wrong packet", __FUNCTION__);
		//dump_packet("receive_node", pack);
		goto fail;
	}

	if (head->len) {
		data = hdpack_data_alloc(GFP_KERNEL, head->len, HADM_DATA_NORMAL);
		if (!data) {
			pr_err("%s: hdpack_data alloc failed.", __FUNCTION__);
			goto fail;
		}
		pack->data = data;

		ret = hadm_socket_receive(sock, pack->data->buff, head->len);
		if (ret != head->len) {
			pr_err("%s: recvv faild.", __FUNCTION__);
			goto fail;
		}
		data->len = head->len;
	}

	return pack;

fail:
	hdpacket_free(pack);
	return NULL;
}

/* alloc page for @pack to recv data from @sock
 * we need manual add/replace data for pack
 */
int hdpacket_page_recv(struct hdpacket *pack, struct socket *sock)
{
	int ret;
	int vcnt;
	int len, remain;
	struct kvec *kv;
	struct page *page;
	struct hdpack_data *data;
	struct packet *head = &pack->head;

	if (!head->len)
		return 0;

	//dump_packet(__func__, head);
	vcnt = div_round_up(head->len, PAGE_SIZE);
	if (head->len & (PAGE_SIZE - 1)) {
		/* we have seen, read super block may 1024 bytes */
		pr_err("%s: warning, recv unsupport size %u.\n",
				__func__, head->len);
		dump_packet(__func__, head);
		//return -EKMOD_NOT_SUPPORT;
	}

	data = hdpack_data_alloc(GFP_KERNEL, vcnt, HADM_DATA_PAGE);
	if (!data) {
		pr_err("%s: hdpack_data alloc failed.", __FUNCTION__);
		return -ENOMEM;
	}

	remain = head->len;
	while (remain > 0) {
		page = alloc_page(GFP_KERNEL);
		if (!page) {
			pr_err("%s: alloc page faild.", __FUNCTION__);
			ret = -ENOMEM;
			goto fail;
		}
		len = min(remain, (int)PAGE_SIZE);
		ret = hdpack_data_add_page(data, page, 0, len);
		if (ret < 0) {
			pr_err("%s: add page faild.", __FUNCTION__);
			__free_page(page);
			goto fail;
		}
		remain -= len;
	}

	kv = kzalloc(sizeof(struct kvec) * data->vcnt, GFP_KERNEL);
	if (!kv) {
		pr_err("%s: alloc kv faild.", __FUNCTION__);
		ret = -ENOMEM;
		goto fail;
	}
	hvec_to_kvec(data->hv, kv, data->vcnt);

	ret = hadm_socket_recvv(sock, kv, data->vcnt, head->len);
	kfree(kv);
	if (ret != head->len) {
		pr_err("%s: recvv faild recv %d want(%d).",
				__func__, ret, head->len);
		dump_hdpack_data(__func__, data);
		if (ret >= 0)
			ret = -1;
		goto fail;
	}

	/* manual replace data */
	hdpack_data_free(pack->data);
	pack->data = data;

	//dump_hdpack_data(__func__, pack->data);
	return 0;
fail:
	hdpack_data_free(data);
	return ret;
}

/* alloc buffer for @pack to recv data from @sock */
int hdpacket_normal_recv(struct hdpacket *pack, struct socket *sock)
{
	int ret;
	struct hdpack_data *data;
	struct packet *head = &pack->head;

	if (!head->len)
		return 0;

	data = hdpack_data_alloc(GFP_KERNEL, head->len, HADM_DATA_NORMAL);
	if (!data) {
		pr_err("%s: hdpack_data alloc failed.", __FUNCTION__);
		return -ENOMEM;
	}

	ret = hadm_socket_receive(sock, data->buff, data->len);
	if (ret < 0) {
		pr_err("%s: recvv faild. %d", __FUNCTION__, ret);
		hdpack_data_free(data);
		return ret;
	}
	BUG_ON(ret != head->len);
	hdpack_data_free(pack->data);
	pack->data = data;

	return 0;
}

struct hdpacket *hdpacket_recv(struct socket *sock)
{
	int ret;
	int type;
	struct hdpacket *pack;
	struct packet *head;

	pack = hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack) {
		pr_err("%s: hdpacket alloc faild.", __FUNCTION__);
		return NULL;
	}
	head = &pack->head;

	/* we have replace the packet head, so we also need handle the other stuff manual
	 * eg: data, len
	 */
	ret = hadm_socket_receive(sock, (char *)head, PACKET_HDR_LEN);
	if (ret != PACKET_HDR_LEN) {
		pr_err("%s: recevice error %d.", __FUNCTION__, ret);
		goto fail;
	}

	if (unlikely(head->magic != MAGIC)) {
		pr_err("%s: wrong packet", __FUNCTION__);
		//dump_packet("receive_node", pack);
		goto fail;
	}

	if (head->len) {
		type = hadm_data_type(head->type);
		if (type == HADM_DATA_PAGE) {
			ret = hdpacket_page_recv(pack, sock);
		}
		else if (type == HADM_DATA_NORMAL)
			ret = hdpacket_normal_recv(pack, sock);
		else {
			pr_err("%s: wrong type:%d.", __FUNCTION__, type);
			goto fail;
		}

		if (ret < 0) {
			pr_err("%s: hdpacket recv data failed.", __FUNCTION__);
			goto fail;
		}
	}

	return pack;
fail:
	hdpacket_free(pack);
	return NULL;
}

/* ------- packet -----------------*/

void dump_packet(const char *msg, struct packet *pack)
{
	char md5_str[33];

	md5_print(md5_str, pack->md5);
	printk(KERN_INFO "%s: magic=0x%llx|md5=%s|type=%s|uuid=%llu|bwr_seq=%llu|len=%u|dev_id=%d|"
	       "from=%u|to=0x%x|dev_sector=%llu|bwr_sector=%llu|"
	       "site_state_num=%u|errcode=%d\n",
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
	       pack->site_state_num,
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
	if (pack != NULL && !IS_ERR(pack)) {
		pack->magic = MAGIC;
		pack->type = P_UNKNOWN;
		pack->len = len;
		//pack->node_from = get_site_id();
		pack->errcode = 0;
	}

	return pack;
}

void packet_init(struct packet *pack, uint8_t type, uint8_t dev_id,
		 uint32_t site_to, uint64_t dev_sector, uint64_t bwr_sector,
		 uint32_t nr_site_state, int16_t errcode)
{
	pack->type = type;
	pack->dev_id = dev_id;
	pack->node_to = site_to;
	pack->dev_sector = dev_sector;
	pack->bwr_sector = bwr_sector;
	pack->site_state_num = nr_site_state;
	pack->errcode = errcode;
}


/* -------------- use hdpacket ----------------- */


int send_uptodate_packet(struct hadm_site *hadm_site, uint64_t bwr_seq)
{
	struct hdpacket *pack;
	struct packet *head;
	struct hadmdev *hadmdev = hadm_site->hadmdev;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	pack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack)
		return -ENOMEM;

	head = &pack->head;
	head->type = P_SD_DATA;
	head->node_to = (1 << hadm_site->id);
	head->uuid = bwr_uuid(hadm_site->hadmdev->bwr);
	head->bwr_seq = bwr_seq;
	head->dev_id = hadmdev->minor;

	pr_info("send p_data(0len) packet: bwr_seq:%lld, uuid:%llu.\n",
			head->bwr_seq, head->uuid);
	if (hadm_queue_push(q, &pack->list) < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		hdpacket_free(pack);
	}

	return 0;
}

int sync_site_bwrdata(struct hadm_site *site, struct bwr_data *data,
		int sync_type)
{
	int ret;
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	pack = site_hdpacket_alloc(GFP_KERNEL, 1, HADM_DATA_PAGE);
	if (!pack)
		return -ENOMEM;

	head = &pack->head;
	head->type = sync_type;
	head->bwr_seq = data->meta.bwr_seq;
	head->dev_id = site->hadmdev->minor;
	head->dev_sector = data->meta.dev_sector;
	head->bwr_sector = data->meta.bwr_sector;
	head->uuid = bwr_uuid(site->hadmdev->bwr);
	head->node_to = (1 << site->id);

	get_page(data->data_page);
	ret = hdpacket_add_page(pack, data->data_page, 0, PAGE_SIZE);
	if (ret < 0) {
		pr_err("%s: add page faild.", __FUNCTION__);
		goto free_page;
	}

	fullsync_md5_hash(page_address(data->data_page), PAGE_SIZE, head->md5);

	ret = hadm_queue_push(q, &pack->list);
	if (ret < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		goto free_pack;
	}

	return 0;

free_page:
	put_page(data->data_page);
free_pack:
	hdpacket_free(pack);
	return ret;
}

int rssync_site_sector(struct hadm_site *site, sector_t dev_sector)
{
	int ret;
	struct hdpacket *pack;
	struct packet *head;
	struct page *page;
	struct hadm_io hadm_io_vec[1];
	struct hadmdev *hadmdev = site->hadmdev;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

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
	pack = site_hdpacket_alloc(GFP_KERNEL, 1, HADM_DATA_PAGE);
	if (!pack) {
		pr_err("%s alloc packet faild.\n", __FUNCTION__);
		goto free_page;
	}

	head = &pack->head;
	head->type = P_SD_RSDATA;
	head->dev_id = hadmdev->minor;
	head->uuid = bwr_uuid(hadmdev->bwr);
	head->dev_sector = dev_sector;
	head->node_to = (1 << site->id);

	ret = hdpacket_add_page(pack, page, 0, PAGE_SIZE);
	if (ret < 0) {
		pr_err("%s: add page faild.", __FUNCTION__);
		goto free_pack;
	}

	/* for debug */
	fullsync_md5_hash(page_address(page), PAGE_SIZE, head->md5);

	/* sender will free packet */
	ret = hadm_queue_push(q, &pack->list);
	if (ret < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		get_page(page);		//double free
		goto free_pack;
	}

	return 0;

free_pack:
	hdpacket_free(pack);
free_page:
	__free_page(page);
	return ret;
}

int send_master_notify(int node_to)
{
	int ret;
	struct hdpacket *pack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_CTRL_TYPE];

	pr_info("%s: send to node %d.\n", __FUNCTION__, node_to);

	pack = node_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!pack) {
		pr_err("%s alloc mem faild.\n", __FUNCTION__);
		return -ENOMEM;
	}

	head = &pack->head;
	head->type = P_NC_MASTER;
	head->node_to = 1 << node_to;

	ret = hadm_queue_push(q, &pack->list);
	if (ret < 0) {
		pr_err("%s: packet send faild.\n", __FUNCTION__);
		goto free_pack;
	}

	return 0;

free_pack:
	hdpacket_free(pack);
	return ret;
}
