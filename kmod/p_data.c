#define pr_fmt(fmt) "p_data: " fmt

#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_device.h"
#include "hadm_struct.h"
#include "hadm_site.h"
#include "bio_handler.h"
#include "hadm_bio.h"
#include "bwr.h"
#include "hadm_packet.h"
#include "dbm.h"
#include "utils.h"
#include "fullsync.h"
#include "hadm_thread.h"
#include "p_worker.h"
#include "../include/common_string.h"
#include "../include/errcode.h"

int p_data_send_net_ack(void *arg, int errcode)
{
	struct hdpacket *ack;
	struct packet *head;
	struct hdpacket *pack = arg;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (ack == NULL)
		return -ENOMEM;

	head = &ack->head;
	head->type = P_SD_NET_ACK;
	head->dev_id = pack->head.dev_id;
	head->dev_sector = pack->head.dev_sector;
	head->bwr_sector = pack->head.bwr_sector;
	head->node_to = (1 << pack->head.node_from);
	head->errcode = errcode;

	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __p_data_net_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *hadm_site;
	int errcode;

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("__p_data_ack: no site %d\n", head->node_from);
		return -EINVAL;
	}
	hadm_site_net_head_inc(hadm_site);
	errcode = head->errcode;
	if(errcode) {
		hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_STOPPED);
		hadm_site_set(hadm_site, SECONDARY_STATE, S_DSTATE, D_FAIL);
	}

	return 0;
}

/*
 * why this?
 *
 * 增加这个函数是为了解决 remote_sync 和 dbm_sync 之间的竞争。假设收到一个
 * P_SD_DATA_ACK，这个时候 dbm 满了，在 P_SD_DATA_ACK 的处理函数中，在检查完状态后，
 * 开始增加节点 site_head 的值。
 *
 * 在增加节点的 site_head 之前，如果 BWR 满了，将会产生 dbm，那么在
 * dbm_sync 线程中将会设置 dbm 的状态。那么这个时候在 P_SD_DATA_ACK 处理函数
 * 中，就不应该增加 site_head 的值。
 *
 * 假如这个时候增加了 site_head 的值，而 snd_head 还是保持不变，那么 site_head
 * 将会领先 snd_head 一个位置。这样就会使 dbm_sync 在产生 dbm 的过程中，导
 * 致 tail-1 的那个位置不能产生 dbm。
 */
static int __site_handle_data_ack(struct hdpacket *pack, struct hadm_site *site,
				  struct bwr *bwr)
{
	struct packet *head = &pack->head;
	unsigned long flags1, flags2;
	int cstate, ret = 0;
	sector_t site_head;

	/* require two lock:
	 * site->s_state.lock
	 *	bwl->lock
	 */
	spin_lock_irqsave(&site->s_state.lock, flags1);
	write_lock_irqsave(&bwr->lock, flags2);

	cstate = __hadm_site_get(&site->s_state, S_CSTATE);
	if (cstate != C_SYNC) {
		//pr_err("%s: give up(dev=%llu, bwr=%llu)\n", __FUNCTION__,
		       //(unsigned long long)head->dev_sector,
		       //(unsigned long long)head->bwr_sector);
		goto done;
	}

	site_head = __bwr_site_head(bwr, site->id);
	if (head->bwr_sector != site_head) {
		pr_info("unexpect P_SD_DATA packet(dev=%llu, bwr=%llu), head:%lu\n",
				(unsigned long long)head->dev_sector,
				(unsigned long long)head->bwr_sector,
				site_head);
		//__hadm_site_set(&site->s_state, S_CSTATE, C_STOPPED);
		//__hadm_site_reset_send_head(site);
		ret = -1;
		goto done;
	}

	if (site->conf.real_protocol != site->conf.protocol &&
			bwr_next_sector(bwr, site_head) == bwr->mem_meta.tail) {
		pr_info("site %d translate real protocol changed: %u -> %u.\n",
				site->id, site->conf.real_protocol,
				site->conf.protocol);
		site->conf.real_protocol = site->conf.protocol;
	}

	__bwr_site_head_inc(bwr, site->id);

done:
	write_unlock_irqrestore(&bwr->lock, flags2);
	spin_unlock_irqrestore(&site->s_state.lock, flags1);
	return ret;
}

static int __p_data_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *hadm_site;
	int ret;

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("__p_data_ack: no site %d\n", head->node_from);
		return -EINVAL;
	}

	if(head->errcode) {
		hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_STOPPED);
		hadm_site_set(hadm_site, SECONDARY_STATE, S_DSTATE, D_FAIL);
		return 0;
	}

	ret = __site_handle_data_ack(pack, hadm_site, dev->bwr);

	return ret;
}

static int __p_rs_data_ack(struct hadmdev *dev, struct hdpacket *pack)
{
	int cstate;
	struct hadm_site *hadm_site;
	struct packet *head = &pack->head;

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("%s: can not find site(%d).\n", __FUNCTION__,
				head->node_from);
		return -EKMOD_NONODE;
	}

	cstate = hadm_site_get(hadm_site, SECONDARY_STATE, S_CSTATE);
	if (cstate == C_DELTA_SYNC_DBM) {
		dbm_clear_sector(hadm_site->dbm, head->dev_sector);
	} else if (cstate == C_DELTA_SYNC_BWR) {
		bwr_site_head_inc(dev->bwr, head->node_from);
	} else {
		pr_err("%s: unexpected cstate %s\n", __FUNCTION__, cstate_name[cstate]);
	}

	return 0;
}

int p_data_send_ack(void *arg,int errcode)
{
	int type;
	struct hadmdev *hadmdev;
	struct packet *head;
	struct packet *ack_head;
	struct hdpacket *ack;
	struct hdpacket *node = arg;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	head = &node->head;
	hadmdev = find_hadmdev_by_minor(head->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_data_send_ack: no device %d\n", head->dev_id);
		return -ENODEV;
	}

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (ack == NULL)
		return -ENOMEM;
	if (head->type == P_SD_DATA)
		type = P_SD_DATA_ACK;
	else if (head->type == P_SD_RSDATA)
		type = P_SD_RSDATA_ACK;
	else
		type = P_UNKNOWN;
	ack_head = &ack->head;
	ack_head->type = type;
	ack_head->dev_id = head->dev_id;
	ack_head->node_to = (1 << head->node_from);
	ack_head->dev_sector = head->dev_sector;
	ack_head->bwr_sector = head->bwr_sector;
	ack_head->errcode = errcode;
	ack_head->bwr_seq = head->bwr_seq;

	memcpy(ack_head->md5, head->md5, 16);

	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __p_data(struct hadmdev *dev, struct hdpacket *pack)
{
	int d_state, data_state, cstate;
	char *data;
	uint64_t bwr_seq;
	struct packet *head = &pack->head;
	uint8_t md5[16];
	char md5_str[33];
	struct hadm_site *site;
	int err=0;

	if (head->node_from != hadmdev_get_primary_id(dev)) {
		return -1;
	}
	site = find_hadm_site_by_id(dev,head->node_from);
	if(site == NULL) {
		return -1;
	}
	if(io_failed(dev)) {
		err=-EIO;
		goto p_data_done;
	}

	if (head->len > 0) {
		data = page_address(pack->data->hv[0].page);
		fullsync_md5_hash(data, PAGE_SIZE, md5);
		if (memcmp(head->md5, md5, 16) != 0) {
			md5_print(md5_str, md5);
			pr_warn("%s: BAD MD5: %s(dev sector:%llu, bwr_sector:%llu, packet-len:%u)\n",
					__FUNCTION__,  md5_str, head->dev_sector, head->bwr_sector, head->len);
			return 0;
		}
	}

	if (head->type == P_SD_DATA) {
		data_state = DATA_CONSISTENT;
		d_state = D_CONSISTENT;
		bwr_seq = head->bwr_seq;

		cstate = hadm_site_get(dev->local_site, SECONDARY_STATE, S_CSTATE);
		if (head->len && cstate == C_SYNC)
			p_data_send_net_ack(pack,0); /* TODO: should check return value? rs_data?*/
	} else {
		data_state = DATA_DBM;
		d_state = D_INCONSISTENT;
		bwr_seq = 0;
	}

	/* TODO 新建一个bio，提交到w_bio_wrapper_list */
	err=set_last_primary(dev, d_state,
			head->node_from, head->uuid,
			bwr_seq, head->dev_sector, head->md5);
	if(err) {
		goto p_data_done;
	}
	hadm_site_set(dev->local_site, SECONDARY_STATE, S_DATA_STATE, data_state);
	hadm_site_set(dev->local_site, SECONDARY_STATE, S_DSTATE, d_state);
	if (head->len !=  0) {
		err = hadm_write_page_sync(dev->bdev, head->dev_sector,
				pack->data->hv[0].page, head->len);
	} else {
		return 0;
	}

p_data_done:
	if(err) {
		hadm_site_set(dev->local_site,SECONDARY_STATE, S_CSTATE, C_STOPPED);
		hadm_site_set(dev->local_site,SECONDARY_STATE, S_DSTATE, D_FAIL);

		hadm_site_set(site,SECONDARY_STATE,S_HANDSHAKE,HS_FAIL);
	}
	p_data_send_ack(pack,err);
	return 0;
}

static void __p_dbm_request__set_status(struct hadm_site *local_site, struct hadm_site *peer)
{
	pr_info("dbm transfer end, give up primary, fetch status from site %d\n", peer->id);
}

/* No lock, now is secondary */
static void __p_dbm_request__send_dbm(struct hadm_site *target, struct hdpacket *pack)
{
	int nr_bit;
	uint64_t nr_record;
	uint64_t total_bits;
	struct packet *head;
	struct hdpacket *ack;
	struct dbm_record *dbm_record;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	/*
	 * 当收到 P_DBM_REQ 之后，需要把 dbm 的数据发送到对端，当全部发送
	 * 完毕之后，再设置 error 表示发送完成了
	 */

	/* TODO: 如果后面的 dbm 都为 0， 不需要将所有的 dbm 都发送 */
	total_bits = atomic_read(&target->dbm->nr_bit);
	nr_record = 0;
	while (total_bits > 0) {
		dbm_record = dbm_find_record(target->dbm, nr_record);
		nr_bit = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		if (nr_bit) {
			/* FIXME: HADM_DATA_PAGE */
			ack = site_hdpacket_alloc(GFP_KERNEL, 1, HADM_DATA_NORMAL);
			if (!ack) {
				pr_err("%s alloc packet faild.\n", __FUNCTION__);
				return;
			}
			head = &ack->head;
			head->type = P_SD_DBM_REP;
			head->dev_id = pack->head.dev_id;
			head->node_to = (1 << pack->head.node_from);
			head->dev_sector = nr_record;

			memcpy(ack->data->buff, page_address(dbm_record->page), PAGE_SIZE);
			pr_info("send dbm, #record =%llu, remain=%llu\n",
					nr_record, total_bits);
			if (hadm_queue_push(q, &ack->list) < 0) {
				pr_err("%s: push ack pack failed.\n", __FUNCTION__);
				hdpacket_free(ack);
				return;
			}

			total_bits -= nr_bit;
		}
		nr_record++;
	}

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!ack) {
		pr_err("%s alloc dbm end packet faild.\n", __FUNCTION__);
		return;
	}
	head = &ack->head;
	head->type = P_SD_DBM_REP;
	head->dev_id = pack->head.dev_id;
	head->node_to = (1 << pack->head.node_from);
	head->errcode = -XCHG_DBM_END;
	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack);
		return;
	}

	atomic_set(&target->dbm->nr_bit, 0);
}

static void __p_dbm_request__role_error(struct hadm_site *target, struct hdpacket *pack)
{
	struct hdpacket *ack;
	struct packet *head;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	ack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!ack) {
		pr_err("__p_dbm_request__role_error: no memory\n");
		return;
	}
	head = &ack->head;
	head->type = P_SD_DBM_REP;
	head->dev_id = pack->head.dev_id;
	head->node_to = (1 << pack->head.node_from);
	head->errcode = -EKMOD_REMOTE_ROLE;

	if (hadm_queue_push(q, &ack->list) < 0) {
		pr_err("%s: push ack pack failed.\n", __FUNCTION__);
		hdpacket_free(ack);
	}
}

static void __p_dbm_request__gen_dbm(struct hadmdev *dev, struct hadm_site *runsite)
{
	dbm_gen(runsite);
}

static int __p_delta_sync_request(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *hadm_site;
	struct packet *head = &pack->head;

	pr_info("receive P_DBM_REQ...\n");

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (hadm_site == NULL || IS_ERR(hadm_site)) {
		pr_err("__p_dbm_request: no node %d\n", head->node_from);
		return -EINVAL;
	}

	send_startrep(dev->minor, hadm_site->id);
	return 0;
}

static int __p_dbm_request(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *hadm_site;
	struct bwr_meta *l_meta, *r_meta;
	struct packet *head = &pack->head;

	pr_info("receive P_DBM_REQ...\n");

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (hadm_site == NULL || IS_ERR(hadm_site)) {
		pr_err("__p_dbm_request: no node %d\n", head->node_from);
		return -EINVAL;
	}

	l_meta = &dev->bwr->mem_meta;
	r_meta = (struct bwr_meta *)pack->data->buff;
	spin_lock(&dev->primary_lock);
	if (dev->primary || !check_split_brain(l_meta, r_meta)) {
		__p_dbm_request__role_error(hadm_site, pack);
		spin_unlock(&dev->primary_lock);
		return -EKMOD_REMOTE_ROLE;
	}
	dev->primary = hadm_site;
	spin_unlock(&dev->primary_lock);

	spin_lock(&dev->local_site->s_state.lock);
	__hadm_site_set(&dev->local_site->s_state, S_HANDSHAKE, HS_SUCCESS);
	spin_unlock(&dev->local_site->s_state.lock);

	/* OK. Prepare cmsync */
	__p_dbm_request__gen_dbm(dev, hadm_site);
	if ((l_meta->last_primary.last_page_damaged && l_meta->local_primary.id == INVALID_ID) ||
			(r_meta->last_primary.last_page_damaged && l_meta->last_primary.uuid == r_meta->last_primary.uuid))
		dbm_set_sector(hadm_site->dbm, l_meta->last_primary.last_page);
	__p_dbm_request__send_dbm(hadm_site, pack);
	__p_dbm_request__set_status(dev->local_site, hadm_site);

	return 0;
}

static void __delta_sync_finished(struct hadm_site *hadm_site)
{
	struct bwr *bwr=hadm_site->hadmdev->bwr;
	struct bwr_data *bwr_data;
	uint64_t seq_id;

	hadm_site_set(hadm_site, SECONDARY_STATE, S_DATA_STATE, DATA_CONSISTENT);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_DSTATE, D_CONSISTENT);
	hadm_site_reset_send_head(hadm_site);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_SYNC);
	hadm_site_test_and_set(hadm_site, SECONDARY_STATE, S_HANDSHAKE, HS_FAIL, HS_SUCCESS);
	bwr_data = get_send_head_data(bwr, hadm_site->id);
	if (bwr_data) {
		seq_id = bwr_data->meta.bwr_seq - 1;
		bwr_data_put(bwr_data);
	} else {
		seq_id = bwr_seq(bwr);
	}
	send_uptodate_packet(hadm_site, seq_id);
	if(is_uptodate(hadm_site->hadmdev->bwr,hadm_site->id)&&
			atomic_read(&hadm_site->dbm->nr_bit) == 0) {
		pr_info("%s site %d already uptodate, tp: %u -> %u.\n",
				__FUNCTION__,
				hadm_site->id,
				hadm_site->conf.real_protocol,
				hadm_site->conf.protocol);
		hadm_site->conf.real_protocol = hadm_site->conf.protocol;
	}
}

int __delta_sync(struct hadm_site *hadm_site)
{
	struct hadmdev *hadmdev;
	struct bwr *bwr;
	int ret = 1, dstate,cstate;
	sector_t start, end;
	sector_t site_head, snd_head;

	hadmdev = hadm_site->hadmdev;
	bwr = hadmdev->bwr;

	snd_head = hadm_site_get(hadm_site, SECONDARY_STATE, S_SND_HEAD);
	site_head = bwr_site_head(bwr, hadm_site->id);
	pr_info("1site snd head:%lu. site_head:%lu\n", snd_head, site_head);
	/* NOTE: 需要能够随时退出 */
	while (bwr_site_head_cmp(bwr, get_site_id(), hadm_site->id) < 0) {
		pr_info("%s: waiting BWR head to reach site %d head\n", __FUNCTION__, hadm_site->id);
		msleep(1000);
	}
	dstate = hadm_site_get(hadm_site, SECONDARY_STATE, S_DSTATE);
	cstate = hadm_site_get(hadm_site, SECONDARY_STATE, S_CSTATE);
	if(dstate != D_INCONSISTENT || cstate != C_DELTA_SYNC_DBM){
		pr_info("dstate %d, cstate %d,delta_sync quit\n",
				dstate,cstate);
		ret=-1;
		goto delta_sync_done;
	}

	/* TODO: flush dbm to disk */
	hadm_site_set(hadm_site,SECONDARY_STATE,S_CSTATE,C_DELTA_SYNC_DBM);

	ret = dbm_delta_sync(hadm_site);
	if (ret) {
		if (ret == -EKMOD_CSTATE) {
			pr_info("%s: dbm_delta_sync failed\n", __FUNCTION__);
			ret=-1;
		} else if (ret == -EKMOD_DELTA_SYNC_EXIT) {
			ret=-2;
		}
		goto delta_sync_done;
	}

	start = bwr_site_head(bwr, hadm_site->id);
	end = bwr_site_head(bwr, get_site_id());
	pr_info("delta_sync_bwr: start=%llu, end=%llu\n", (unsigned long long)start, (unsigned long long)end);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_BWR);

	snd_head = hadm_site_get(hadm_site, SECONDARY_STATE, S_SND_HEAD);
	site_head = bwr_site_head(bwr, hadm_site->id);
	pr_info("2site snd head:%lu. site_head:%lu\n", snd_head, site_head);
	ret = delta_sync_bwr(hadm_site, start, end); /* 将 [start,end] 之间的数据发送到对端 */
	if (ret) {
		pr_info("%s: delta_sync_bwr failed, return code %d\n", __FUNCTION__, ret);
		goto delta_sync_done;
	}

	snd_head = hadm_site_get(hadm_site, SECONDARY_STATE, S_SND_HEAD);
	site_head = bwr_site_head(bwr, hadm_site->id);
	pr_info("3site snd head:%lu. site_head:%lu\n", snd_head, site_head);

	/* TODO: generate p_data packet to set peer dstate to consistence */
	__delta_sync_finished(hadm_site);

delta_sync_done:
	hadm_thread_terminate(hadm_site->delta_sync);
	return 0;
}

static int __p_dbm_reply(struct hadmdev *dev, struct hdpacket *pack)
{
	struct hadm_site *hadm_site;
	struct dbm_record *dbm_record;
	struct packet *head = &pack->head;
	int i, before, after, r_before;

	pr_info("receive P_DBM_REP...\n");

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (hadm_site == NULL || IS_ERR(hadm_site)) {
		pr_err("__p_dbm_reply: no node %d\n", head->node_from);
		return -EINVAL;
	}
	pr_info("dbm start=%llu, len=%d\n", head->dev_sector, head->len);

	/*
	 * 收到 P_DBM_REP 包，那么需要将它的数据和对应节点的 dbm 作或操作，
	 * 当所有的包都收完之后，执行 delta_sync 操作
	 */
	if (head->errcode == -EKMOD_REMOTE_ROLE && head->len == 0) {
		pr_err("__p_dbm_reply: remote role is not right\n");
		return -EKMOD_REMOTE_ROLE;
	}

	hadm_site_reset_send_head(hadm_site);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_CMSYNC_DBM);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_DSTATE, D_INCONSISTENT);
	/* FIXME need lock dbm? */
	if (head->errcode == -XCHG_DBM_END && head->len == 0) {
		dbm_gen(hadm_site);	/* FIXME gen from disk or read from memory? */
		pr_info("dbm receive from site %d end, remain %d bits before delta_sync\n",
			hadm_site->id, atomic_read(&hadm_site->dbm->nr_bit));
		hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_DBM);
		create_dbm_sync_thread(P_CMSYNC,hadm_site);
	} else {
		dbm_record = dbm_find_record(hadm_site->dbm, head->dev_sector);

		before = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		r_before = nr_bits(pack->data->buff, 0, head->len);
		pr_info("before dbm OR: local_site=%d, remote=%d\n", before, r_before);

		for (i = 0; i < head->len; i++) {
			char *data = page_address(dbm_record->page);
			data[i] |= pack->data->buff[i];
		}
		dbm_dirty_record(hadm_site->dbm, dbm_record);

		after = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		pr_info("after dbm OR: local_site=%d, remote=%d\n", after, r_before);
		atomic_add(after - before, &hadm_site->dbm->nr_bit);
	}

	return 0;
}

static int __p_delta_sync_done(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *target;

	target = find_hadm_site_by_id(dev, head->node_from);
	if (target == NULL || IS_ERR(target)) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		return -EKMOD_NONODE;
	}

	//dbm_clear_all(target->dbm);
	return 0;
}

static int __p_fullsync_request(struct hadmdev *dev, struct hdpacket *pack)
{
	int ret = 0;
	struct packet *head = &pack->head;
	struct packet *rhead;
	struct hdpacket *reply;
	struct hadm_site *hadm_site;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	pr_info("receive P_FULLSYNC_REQ...\n");

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		ret = -EINVAL;
		goto done;
	}

	if (hadmdev_set_primary(dev, hadm_site) < 0) {
		pr_err("reject node %d fullsync request, "
				"because I accepted node %d as primary\n",
				head->node_from, dev->primary->id);
		ret = -EINVAL;
		goto done;
	}
	hadm_site_set(hadm_site, SECONDARY_STATE, S_HANDSHAKE, HS_SUCCESS);
done:
	reply = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!reply) {
		pr_err("%s: alloc relpy packet faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	rhead = &reply->head;
	rhead->type = P_SD_FSYNC_REP;
	rhead->dev_id = head->dev_id;
	rhead->node_to = (1 << head->node_from);
	rhead->errcode = ret;

	if (hadm_queue_push(q, &reply->list) < 0) {
		pr_err("%s: push reply pack failed.\n", __FUNCTION__);
		hdpacket_free(reply);
		return -EHADM_QUEUE_FREEZE;
	}

	pr_info("send fullsync_reply to site %d, err:%d.\n", head->node_from, ret);
	return ret;
}

static int __fullsync(struct hadm_site *hadm_site)
{
	struct hadmdev *hadmdev;
	sector_t start,end;
	int ret, n_state;

	hadmdev = hadm_site->hadmdev;
	start=bwr_site_head(hadmdev->bwr,get_site_id());
	dbm_set_bit_all(hadm_site->dbm);
	msleep(2000);//wait dbm sync to bwr disk

	n_state = hadm_site_get(hadm_site, SECONDARY_STATE, S_NSTATE);
	if (n_state == N_DISCONNECT) {
		pr_info("%s: network disconnect, exited\n", __FUNCTION__);
		ret = -1;
		goto done;
	}

	bwr_set_site_head(hadmdev->bwr,hadm_site->id,start);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_DBM);
	hadm_site_set(hadm_site, SECONDARY_STATE, S_DATA_STATE, DATA_DBM);
	ret=dbm_fullsync(hadm_site);
	if(ret)
	{
		pr_info("fullsync to node %d is terminated \n",hadm_site->id);
		goto done;
	}
	hadm_site_set(hadm_site, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_BWR);
	end=bwr_site_head(hadmdev->bwr,get_site_id());
	ret=delta_sync_bwr(hadm_site,start,end);
	if(ret)
	{
		pr_info("fullsync to site %d is terminated \n",hadm_site->id);
		goto done;

	}

	__delta_sync_finished(hadm_site);
	ret = 0;
done:
	hadm_thread_terminate(hadm_site->delta_sync);
	return ret;
}

static int __p_fullsync_reply(struct hadmdev *dev, struct hdpacket *pack)
{
	struct packet *head = &pack->head;
	struct hadm_site *hadm_site=NULL;

	pr_info("receive P_FULLSYNC_REP...\n");

	if (head->errcode != 0) {
		pr_warn("%s: receive error %d\n", __FUNCTION__, head->errcode);
		return 0;
	}
	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("%s: no site %d\n", __FUNCTION__, head->node_from);
		return -EINVAL;
	}

	hadm_site_set(hadm_site, SECONDARY_STATE, S_HANDSHAKE, HS_SUCCESS);
	hadm_site_reset_send_head(hadm_site);
	create_dbm_sync_thread(P_FULLSYNC,hadm_site);

	return 0;
}

static int __p_fullsync_md5(struct hadmdev *dev, struct hdpacket *pack)
{
	char *data;
	char md5[16];
	int error=0;
	struct packet *head;
	struct packet *rhead;
	struct hdpacket *reply;
	struct page *page=NULL;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	head = &pack->head;
	if(head->dev_sector +8 > dev->bdev_disk_size) {
		pr_err("__p_fullsync_md5: request sector %llu beyond the disk size %llu \n",
				(unsigned long long)head->dev_sector,
				(unsigned long long)dev->bdev_disk_size);

		error=0;
		goto reply;

	}

	/* read data on right sector */
	page=alloc_page(GFP_KERNEL);
	if (IS_ERR_OR_NULL(page)) {
		pr_err("__p_fullsync_md5: no memory\n");
		goto reply;
	}
	if(hadm_read_page_sync(dev->bdev,head->dev_sector, page,PAGE_SIZE)){
		pr_err("%s: read sector %llu failed\n",__FUNCTION__,head->dev_sector);
		__free_page(page);
		goto reply;
	}
	data=page_address(page);
	/* compute data md5 */
	fullsync_md5_hash(data, PAGE_SIZE, md5);
	__free_page(page);

	/* compare local_site md5 and remote md5 */
	error = memcmp(md5, head->md5, 16) ? -FULLSYNC_DATA_REQ : 0;
reply:
	/* construct P_FULLSYNC_DATA_REQ packet */
	reply = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!reply) {
		pr_err("__p_fullsync_md5: no memory\n");
		return -ENOMEM;
	}
	rhead = &reply->head;
	rhead->type = P_SD_FSYNC_DATA;
	rhead->dev_id = head->dev_id;
	rhead->node_to = (1 << head->node_from);
	rhead->dev_sector = head->dev_sector;
	rhead->errcode = error;
	rhead->uuid = bwr_uuid(dev->bwr);

	if (hadm_queue_push(q, &reply->list) < 0) {
		pr_err("%s: push reply pack failed.\n", __FUNCTION__);
		hdpacket_free(reply);
		return -EHADM_QUEUE_FREEZE;
	}

	return 0;
}

static int __p_fullsync_data_request(struct hadmdev *dev, struct hdpacket *pack)
{
	int ret = 0;
	struct packet *head = &pack->head;
	struct hadm_site *hadm_site;

	hadm_site = find_hadm_site_by_id(dev, head->node_from);
	if (!hadm_site) {
		pr_err("%s: no node %d\n", __FUNCTION__, head->node_from);
		return -EINVAL;
	}

	if (head->errcode == 0) {
		dbm_clear_sector(hadm_site->dbm, head->dev_sector);
	} else if (head->errcode == -FULLSYNC_DATA_REQ) {
		/* send P_SD_RSDATA packet */
		ret = rssync_site_sector(hadm_site, head->dev_sector);
		if (ret < 0)
			pr_err("%s: send fullsync data faild.\n", __FUNCTION__);
	} else {
		pr_err("%s: unknown error code %d\n",
		       __FUNCTION__, head->errcode);
	}

	return ret;
}

int create_dbm_sync_thread(uint8_t dbm_type,struct hadm_site *hadm_site)
{
	thread_func_t func;
	char name[0x20];

	if(dbm_type==P_FULLSYNC) {
		func=(thread_func_t)__fullsync;
		snprintf(name, sizeof(name), "%s%d", "__fullsync", hadm_site->id);
	} else {
		func=(thread_func_t )__delta_sync;
		snprintf(name, sizeof(name), "%s%d", "__delta_sync", hadm_site->id);
	}

	if(hadm_site->delta_sync==NULL) {
		hadm_site->delta_sync = hadm_thread_alloc();
	} else if(hadm_thread_get_state(hadm_site->delta_sync)==HADM_THREAD_RUN){
		pr_info("delta_sync thread(%p) for site %d failed\n",(void *)hadm_site->delta_sync,hadm_site->id);
		return -1;
	} else {
		hadm_thread_free(&hadm_site->delta_sync);
		hadm_site->delta_sync = hadm_thread_alloc();
	}

	if(hadm_site->delta_sync==NULL) {
		pr_err("create delta_sync thread for site %d failed\n",hadm_site->id);
		return -ENOMEM;
	}
	hadm_thread_init(hadm_site->delta_sync, name, func, hadm_site, NULL);
	pr_info("create delta_sync thread %p for dbm sync\n",(void *)hadm_site->delta_sync);
	hadm_thread_start(hadm_site->delta_sync);
	return 0;
}

static struct device_handler p_functions[] = {
	[P_SD_DATA] = { __p_data },
	[P_SD_RSDATA] = { __p_data },
	[P_SD_NET_ACK] = { __p_data_net_ack },
	[P_SD_DATA_ACK] = { __p_data_ack },
	[P_SD_RSDATA_ACK] = { __p_rs_data_ack },
	[P_SD_DBM_REQ] = { __p_dbm_request },
	[P_SD_DSYNC_REQ] = { __p_delta_sync_request},
	[P_SD_DBM_REP] = { __p_dbm_reply },
	[P_SD_FSYNC_REQ] = { __p_fullsync_request },
	[P_SD_FSYNC_REP] = { __p_fullsync_reply },
	[P_SD_FSYNC_MD5] = { __p_fullsync_md5 },
	[P_SD_FSYNC_DATA] = { __p_fullsync_data_request },
	[P_DELTA_SYNC_DONE] = { __p_delta_sync_done },
	//[P_SD_END] = {NULL}
};

struct device_handler *get_site_data_handler()
{
	return p_functions;
}
