#define pr_fmt(fmt) "p_data: " fmt

#include <linux/module.h>

#include <linux/kthread.h>
#include <linux/delay.h>

#include "hadm_def.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "bio_handler.h"
#include "hadm_bio.h"
#include "bwr.h"
#include "hadm_packet.h"
#include "dbm.h"
#include "utils.h"
#include "fullsync.h"
#include "hadm_thread.h"
#include "p_worker.h"
#include "buffer.h"
#include "hadm_struct.h"
#include "../include/common_string.h"
#include "../include/errcode.h"

int p_data_send_net_ack(void *arg, int errcode)
{
	struct hadm_pack_node *node=(struct hadm_pack_node *)arg;
	struct packet *ack;
	unsigned long node_to;
	int type;

	ack = packet_alloc(0, GFP_KERNEL);
	if (ack == NULL)
		return -ENOMEM;

	node_to = 1 << node->pack->node_from;
	ack->kmod_to = (1 << node->pack->kmod_from);
	type = P_DATA_NET_ACK;
	packet_init(ack, type, node->pack->dev_id, node_to,
			node->pack->dev_sector, node->pack->bwr_sector, node->pack->bwr_seq,
			0, errcode);
	packet_send(ack);

	return 0;
}

static int __p_data_net_ack(void *arg)
{
	struct hadm_pack_node *hadm_pack_node=(struct hadm_pack_node *)arg;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	int cstate;
	int errcode;

	hadmdev = find_hadmdev_by_minor(hadm_pack_node->pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_data_ack: no device %d\n", hadm_pack_node->pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, hadm_pack_node->pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("__p_data_ack: no node %d for device hadm%d\n", 
                        hadm_pack_node->pack->node_from, hadmdev->minor);
		return -EINVAL;
	}
	cstate = hadm_node_get(hadm_node, SECONDARY_STATE, S_CSTATE);
	if(cstate != C_SYNC) {
		return  0;
	}
	hadm_node_net_head_inc(hadm_node, hadm_pack_node->pack->bwr_sector, hadm_pack_node->pack->bwr_seq);
	errcode = hadm_pack_node->pack->errcode;
	if(errcode) {
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
		//hadm_node_set(hadm_node, SECONDARY_STATE, S_DSTATE, D_FAIL);
	}

	return 0;
}

/*
 * why this?
 *
 * 增加这个函数是为了解决 remote_sync 和 dbm_sync 之间的竞争。假设收到一个
 * P_DATA_ACK，这个时候 dbm 满了，在 P_DATA_ACK 的处理函数中，在检查完状态后，
 * 开始增加节点 node_head 的值。
 *
 * 在增加节点的 node_head 之前，如果 BWR 满了，将会产生 dbm，那么在
 * dbm_sync 线程中将会设置 dbm 的状态。那么这个时候在 P_DATA_ACK 处理函数
 * 中，就不应该增加 node_head 的值。
 *
 * 假如这个时候增加了 node_head 的值，而 snd_head 还是保持不变，那么 node_head
 * 将会领先 snd_head 一个位置。这样就会使 dbm_sync 在产生 dbm 的过程中，导
 * 致 tail-1 的那个位置不能产生 dbm。
 */
static int __node_handle_data_ack(struct packet *pack, struct hadm_node *node,
				  struct bwr *bwr)
{
	unsigned long flags1, flags2;
	int cstate, ret = 0;
	sector_t node_head;

	/* require two lock:
	 * node->s_state.lock
	 *	bwr->lock
	 */
	spin_lock_irqsave(&node->s_state.lock, flags1);
	write_lock_irqsave(&bwr->lock, flags2);

	cstate = __hadm_node_get(&node->s_state, S_CSTATE);
	if (cstate != C_SYNC) {
//		pr_err("%s: give up(dev=%llu, bwr=%llu)\n", __FUNCTION__,
//			   (unsigned long long)pack->dev_sector,
//			   (unsigned long long)pack->bwr_sector);
		goto done;
	}

	node_head = __bwr_node_head(bwr, node->id);
	if (pack->bwr_sector != node_head) {
		pr_info("hadm%d: unexpect P_DATA packet(dev=%llu, bwr=%llu), head:%lu\n",
                        bwr->hadmdev->minor, 
                        (unsigned long long)pack->dev_sector,
                        (unsigned long long)pack->bwr_sector,
                        node_head);
		//__hadm_node_set(&node->s_state, S_CSTATE, C_STOPPED);
		//__hadm_node_reset_send_head(node);
		ret = -1;
		goto done;
	}

	if (node->conf.real_protocol != node->conf.protocol &&
			bwr_next_sector(bwr, node_head) == bwr->mem_meta.tail) {
		pr_info("hadm%d node %d translate real protocol changed: %u -> %u.\n",
                        bwr->hadmdev->minor, 
				node->id, node->conf.real_protocol,
				node->conf.protocol);
		node->conf.real_protocol = node->conf.protocol;
	}

	__bwr_node_head_inc(bwr, node->id);

done:
	write_unlock_irqrestore(&bwr->lock, flags2);
	spin_unlock_irqrestore(&node->s_state.lock, flags1);
	return ret;
}

static int __p_data_ack(void *arg)
{
	struct hadm_pack_node *node=(struct hadm_pack_node *)arg;
	struct packet *pack = node->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	int ret;

	hadmdev = find_hadmdev_by_minor(node->pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_data_ack: no device %d\n", node->pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, node->pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("__p_data_ack: no node %d for hadm%d\n", 
                        node->pack->node_from, hadmdev->minor);
		return -EINVAL;
	}

	if(node->pack->errcode) {
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
		//hadm_node_set(hadm_node, SECONDARY_STATE, S_DSTATE, D_FAIL);
		return 0;
	}

	ret = __node_handle_data_ack(pack, hadm_node, hadmdev->bwr);

	return ret;
}

static int node_seq_fn(struct list_head *arg1, struct list_head *arg2)
{
	struct hadm_pack_node *node1 = list_entry(arg1, struct hadm_pack_node, q_node);
	struct hadm_pack_node *node2 = list_entry(arg2, struct hadm_pack_node, q_node);
	return node1->pack->bwr_seq < node2->pack->bwr_seq;
}

static int __p_rs_data_ack(void *arg)
{
	struct hadm_pack_node *node=(struct hadm_pack_node *)arg;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct packet *rcv_pack;
	int cstate;
	struct hadm_queue *delta_packet_queue = NULL;

	rcv_pack = node->pack;
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if(!hadm_node) {
		return -1;
	}
	if(hadm_thread_get_state(hadm_node->delta_sync) != HADM_THREAD_RUN
			|| !hadm_node->dbm->dbm_sync_param){
		return -1;
	}

	cstate = hadm_node_get(hadm_node, SECONDARY_STATE, S_CSTATE);
	if (cstate == C_DELTA_SYNC_DBM) {
		dbm_clear_sector(hadm_node->dbm, rcv_pack->dev_sector);
	} else if (cstate == C_DELTA_SYNC_BWR) {
		delta_packet_queue = hadm_node->dbm->dbm_sync_param->delta_packet_queue;
		if(!delta_packet_queue) {
			BUG();
		}
		if(rcv_pack->bwr_sector){
			/**
			 *在这里，把接收到的包按照seq的大小放在delta_packet_queue里, 避免乱序
			 *
			 */
			hadm_pack_node_get(node);
			/**FIXME wait delta_packet_queue has space**/
			hadm_queue_push_in_seq(delta_packet_queue, &node->q_node, node_seq_fn);
			//dump_packet(__FUNCTION__, node->pack);
		}
	} else {
//		pr_err("%s: unexpected cstate %s\n", __FUNCTION__, cstate_name[cstate]);
//		dump_packet(__FUNCTION__, rcv_pack);
	}

	return 0;
}

struct packet *gen_data_ack(struct hadm_pack_node *node, int errcode)
{
	struct hadmdev *hadmdev;
	struct packet *ack;
	unsigned long node_to ;
	int type;
	hadmdev = find_hadmdev_by_minor(node->pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_data_send_ack: no device %d\n", node->pack->dev_id);
		return NULL;
	}

	ack = packet_alloc(0, GFP_KERNEL);
	if (ack == NULL)
		return NULL;
	node_to = 0, set_bit(node->pack->node_from, &node_to);
	ack->kmod_to = (1 << node->pack->kmod_from);
	if (node->pack->type == P_DATA)
		type = P_DATA_ACK;
	else if (node->pack->type == P_RS_DATA)
		type = P_RS_DATA_ACK;
	else
		type = P_UNKNOWN;
	packet_init(ack, type, node->pack->dev_id, node_to,
			node->pack->dev_sector, node->pack->bwr_sector, node->pack->bwr_seq,
			0, errcode);
	memcpy(ack->md5, node->pack->md5, 16);
	return ack;
}

struct hadm_pack_node *gen_data_ack_pack_node(struct hadm_pack_node *node, int errcode)
{
	struct hadm_pack_node *ack_node = NULL;
	struct packet *ack = NULL;
	ack = gen_data_ack(node, errcode);
	if(ack == NULL)
		return NULL;

	ack_node = hadm_pack_node_create(ack, node->sock);
	if(ack_node == NULL) {
		kfree(ack);
		return NULL;
	}
	return ack_node;
}

int p_data_send_ack(void *arg,int errcode)
{
	struct hadm_pack_node *node=(struct hadm_pack_node *)arg;
	struct hadmdev *hadmdev;
	struct packet *ack;
	unsigned long node_to;
	int type;
	hadmdev = find_hadmdev_by_minor(node->pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("p_data_send_ack: no device %d\n", node->pack->dev_id);
		return -ENODEV;
	}

	ack = packet_alloc(0, GFP_KERNEL);
	if (ack == NULL)
		return -ENOMEM;
	node_to = 0, set_bit(node->pack->node_from, &node_to);
	ack->kmod_to = (1 << node->pack->kmod_from);
	if (node->pack->type == P_DATA)
		type = P_DATA_ACK;
	else if (node->pack->type == P_RS_DATA)
		type = P_RS_DATA_ACK;
	else
		type = P_UNKNOWN;
	packet_init(ack, type, node->pack->dev_id, node_to,
			node->pack->dev_sector, node->pack->bwr_sector, node->pack->bwr_seq,
			0, errcode);
	ack->bwr_seq = node->pack->bwr_seq;
	memcpy(ack->md5, node->pack->md5, 16);
	packet_send(ack);

	return 0;
}

#if 0
static int p_data_io_handler(struct hadmdev *dev)
{
	struct hadm_pack_node *node ;
	struct hadm_queue *queue = dev->p_data_queue;
	struct packet *p;
	int d_state, data_state;
	int err = 0;
	sector_t bwr_seq,last_seq = 0;

	while (hadm_thread_get_state(dev->p_data_io_thread) == HADM_THREAD_RUN) {
		if(hadmdev_error(dev)){
			msleep(2000);
			continue;
		}

		node = (struct hadm_pack_node *)hadm_queue_pop_timeout(queue, msecs_to_jiffies(3000));
		if(IS_ERR_OR_NULL(node)) {
			continue;
		}

//#define IOTEST
#ifdef IOTEST
		msleep(500);
#endif
		//dump_packet("p_data_io", node->pack);
		p = node->pack;

		if(p->type == P_DATA) {
			/**当primary bwr满中断同步时，secondary应当停止从p_data_queue
			 * 获取数据写入到磁盘并发送data_ack

			if(hadm_node_get(dev->local, SECONDARY_STATE, S_CSTATE) != C_SYNC) {
				hadm_pack_node_free(node);
				continue;
			}
			*/
			if(last_seq == 0) {
				last_seq = bwr_lastpi_seq(dev->bwr);
			}
			if(p->bwr_seq != last_seq + 1){
				last_seq = bwr_lastpi_seq(dev->bwr);
				if(p->bwr_seq != last_seq + 1){
					pr_warning("%s:unordered bwr seq, last_seq = %llu, packet->bwr_seq = %llu\n",
							__FUNCTION__,
							(unsigned long long)last_seq,
							(unsigned long long)p->bwr_seq);
					err = -EINVAL;
					goto p_data_io_done;
				}else {
					pr_info("%s: reset last seq after secondary reconnect.\n",__FUNCTION__);
				}
			}
			bwr_seq = p->bwr_seq;
			d_state  = D_CONSISTENT;
			data_state = DATA_CONSISTENT;
		} else {
			bwr_seq = 0;
			last_seq = 0 ;
			d_state = D_INCONSISTENT;
			data_state = DATA_DBM;
		}
		err = write_bwr_meta(dev->bwr, LAST_PRIMARY, d_state, 0, p->node_from,
				p->uuid, bwr_seq, p->dev_sector, p->md5);
		if (err) {
			goto p_data_io_done;
		}else {
			last_seq = bwr_seq;
			hadm_node_set(dev->local, SECONDARY_STATE, S_DATA_STATE, data_state);
			hadm_node_set(dev->local, SECONDARY_STATE, S_DSTATE, d_state);
		}
		/*TODO: 对于P_RS_DATQ可以异步写*/
		if(p->len > 0){
			err = hadm_bio_write_sync(dev->bdev, p->dev_sector, p->data, p->len);
		}
p_data_io_done:
		if(err) {
			hadm_node_set(dev->local,SECONDARY_STATE, S_CSTATE, C_STOPPED);
			hadm_node_set(dev->local,SECONDARY_STATE, S_DSTATE, D_FAIL);
			hadm_node_set(dev->local,SECONDARY_STATE,S_HANDSHAKE,HS_FAIL);
		}
		if(p->len > 0) {
			p_data_send_ack(node,err);
		}
		hadm_pack_node_free(node);
	}
	if(hadm_pack_queue_clean(queue)){
		pr_warn("p_data queue still has data when p_data_io_thread is terminated\n");
	}
	complete(&dev->p_data_io_thread->ev_exit);
	return 0;
}

static int p_data_thread_init(struct hadmdev *dev)
{
	char name[MAX_QUEUE_NAME];
	int err;
	if(dev->p_data_io_thread){
		return 0;
	}
	dev->p_data_io_thread = hadm_thread_alloc();
	if(IS_ERR_OR_NULL(dev->p_data_io_thread)) {
		return -ENOMEM;
	}
	snprintf(name, MAX_QUEUE_NAME, "p_dataio%02d", dev->minor);
	err = hadm_thread_init(dev->p_data_io_thread, name,(thread_func_t)p_data_io_handler, (void *)dev, NULL);
	if (err)
	{
		hadm_thread_free(&dev->p_data_io_thread);
		return err;
	}
	hadm_thread_run(dev->p_data_io_thread);
	return 0;
}

#endif
static int __p_data(void *arg)
{
	struct hadm_pack_node *hadm_pack_node=(struct hadm_pack_node *)arg;
	struct hadmdev *hadmdev;
	struct packet *p = hadm_pack_node->pack;
	uint8_t md5[16];
	char md5_str[33];
	struct hadm_node *node;
	int err = 0,ret = 0;
	struct bio_wrapper *bio_wrapper = NULL;
	struct hadm_queue *wrapper_queue ;
	static int cur_p_type = -1;
	int dstate;


	//dump_packet((char *)__FUNCTION__, p);

	hadmdev = find_hadmdev_by_minor(hadm_pack_node->pack->dev_id);
	if(hadmdev == NULL) {
		return -1;
	}
	wrapper_queue = hadmdev->bio_wrapper_queue[HADM_IO_WRITE];

	if (p->node_from != hadmdev_get_primary_id(hadmdev)) {
		return -1;
	}
	node=find_hadm_node_by_id(hadmdev,p->node_from);
	if(node == NULL) {
		return -1;
	}
	if(hadmdev_error(hadmdev)) {
		err=-EIO;
		goto p_data_done;
	}
	/**
	 *允许不检测md5
	 */
	if (p->len > 0 && hadm_pack_node->pack->md5[0]) {
		fullsync_md5_hash(hadm_pack_node->pack->data, PAGE_SIZE, md5);
		if (memcmp(hadm_pack_node->pack->md5, md5, 16) != 0) {
			md5_print(md5_str, md5);
			pr_warn("%s: BAD MD5: %s(hadm%d dev sector:%llu, bwr_sector:%llu, packet-len:%u)\n",
					__FUNCTION__,  md5_str, hadmdev->minor, p->dev_sector, p->bwr_sector, p->len);
			return 0;
		}
	}
	dstate = hadm_node_get(hadmdev->local, SECONDARY_STATE, S_DSTATE);
	if(dstate == D_CONSISTENT && p->type == P_DATA) {
		/**TODO check seq is ordered**/

	}else if (dstate == D_INCONSISTENT && p->len > 0 && p->type == P_DATA){
		/**理论上如果一个secondary节点处于INCONSISTENT状态，是不应该接收P_DATA包的**/
		return -EINVAL;

	}else if(cur_p_type != p->type) {
		/**
		 *当p_data在P_DATA/P_RS_DATA之间切换的时候，需要等待之前的数据完成
		 *
		 */
		while(hadm_queue_len(wrapper_queue)>0) {
			if ( hadm_thread_get_state(hadmdev->worker_thread[P_DATA_TYPE]) != HADM_THREAD_RUN)
				goto p_data_done;
			msleep(1000);
		}
		cur_p_type = p->type;
	}
	/**
	 *当delta-sync完成或者接收到RS_DATA的包，需要重写
	 *meta 区，设置dstate
	 */
	if((p->len == 0 && p->type == P_DATA) ||
			p->type == P_RS_DATA) {
		if(p->len == 0 && p->type == P_DATA) {
			buffer_set_io_completed_seq(hadmdev->buffer, p->bwr_seq);
#if 0
			pr_info("%s:dump bwr data when receive updated packet\n", __FUNCTION__);
			bwr_dump(hadmdev->bwr);
#endif
		}else{
			buffer_set_io_completed_seq(hadmdev->buffer, 0);
		}
		err = write_bwr_meta(hadmdev->bwr, LAST_PRIMARY,
				p->type == P_DATA ? D_CONSISTENT : D_INCONSISTENT,
				0, p->node_from, p->uuid, p->type == P_DATA ? p->bwr_seq : 0,
				p->dev_sector, p->md5);
		if(err)
			goto p_data_done;
		if(p->len == 0) {
			return 0;
		}
	} else if(p->len && p->type == P_DATA){
		p_data_send_net_ack(hadm_pack_node,0); /* TODO: should check return value? rs_data?*/
	}



#if 0
	if (p_data_thread_init(hadmdev) != 0) {
		err = -ENOMEM;
		goto p_data_done;
	}
#endif
	bio_wrapper = gen_bio_wrapper_from_pack(hadm_pack_node);
	if(IS_ERR_OR_NULL(bio_wrapper)){
		err = PTR_ERR(bio_wrapper);
		hadmdev_set_error(hadmdev, __BWR_ERR);
		goto p_data_done;
	}


try:
	if (hadm_thread_get_state(hadmdev->worker_thread[P_DATA_TYPE]) != HADM_THREAD_RUN) {
		return 0;
	}

	ret = hadm_queue_push_timeout(wrapper_queue,  &bio_wrapper->node,
			msecs_to_jiffies(1000));
	if ( ret<0 ) {
		if( hadmdev_error(hadmdev) ) {
			err  =	-EIO;
			goto p_data_done;
		}
		if (ret  ==  -EHADM_QUEUE_FREEZE)
			msleep(500);
		goto try;
	}
#if 0
	if(p->type == P_RS_DATA) {
		pr_info("%s:push bio_wrapper(node %p) to bio_wrapper_queue[WRITE]", __FUNCTION__, &bio_wrapper->node);
	}
#endif
	//	  dump_packet("p_data", p);
	return 0;

p_data_done:
	if(err) {
		cur_p_type = -1;
		hadm_node_set(hadmdev->local,SECONDARY_STATE, S_CSTATE, C_STOPPED);
		//hadm_node_set(hadmdev->local,SECONDARY_STATE, S_DSTATE, D_FAIL);

		hadm_node_set(node,SECONDARY_STATE,S_HANDSHAKE,HS_FAIL);
	}
	p_data_send_ack(hadm_pack_node,err);
	return 0;
}

static void __p_dbm_request__set_status(struct hadm_node *local, struct hadm_node *peer)
{
	pr_info("hadm%d dbm transfer end, give up primary, fetch status from node %d\n", 
                    peer->hadmdev->minor, peer->id);
}

/* No lock, now is secondary */
static void __p_dbm_request__send_dbm(struct hadm_node *target)
{
	int nr_bit;
	unsigned long node_to;
	uint64_t nr_record, total_bits;
	struct packet *reply;
	struct dbm_record *dbm_record;

	/*
	 * 当收到 P_DBM_REQ 之后，需要把 dbm 的数据发送到对端，当全部发送
	 * 完毕之后，再设置 error 表示发送完成了
	 */

	/* TODO: 如果后面的 dbm 都为 0， 不需要将所有的 dbm 都发送 */

	node_to = 0, set_bit(target->id, &node_to);
	total_bits = atomic_read(&target->dbm->nr_bit);
	nr_record = 0;
	while (total_bits > 0) {
		dbm_record = dbm_find_record(target->dbm, nr_record);
		nr_bit = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		if (nr_bit) {
			reply = packet_alloc_for_node(PAGE_SIZE, GFP_KERNEL, target);
			if (!reply) {
				pr_err("%s alloc packet faild.\n", __FUNCTION__);
				return;
			}
			reply->type = P_DBM_REP;
			reply->dev_id = target->hadmdev->minor;
			reply->dev_sector = nr_record;

			memcpy(reply->data, page_address(dbm_record->page), PAGE_SIZE);
			pr_info("hadm%d send dbm, #record =%llu, remain=%llu\n",
                            target->hadmdev->minor, nr_record, total_bits);
			packet_send(reply);

			total_bits -= nr_bit;
		}
		nr_record++;
	}
	reply = packet_alloc_for_node(0, GFP_KERNEL, target);
	if (!reply) {
		pr_err("%s: alloc hadm%d end dbm packet failed.\n", __func__, target->hadmdev->minor);
		return;
	}
	reply->type = P_DBM_REP;
	reply->dev_id = target->hadmdev->minor;
	reply->errcode = -XCHG_DBM_END;

	packet_send(reply);

	atomic_set(&target->dbm->nr_bit, 0);
}

static void __p_dbm_request__role_error(struct hadm_node *target, struct packet *pack)
{
	unsigned long node_to;
	struct packet *reply;

	reply = packet_alloc(0, GFP_KERNEL);
	if (reply == NULL || IS_ERR(reply)) {
		pr_err("__p_dbm_request__role_error: no memory\n");
		return;
	}
	node_to = 0, set_bit(pack->node_from, &node_to);
	packet_init(reply, P_DBM_REP, pack->dev_id, node_to, 0, 0, 0, 0, -EKMOD_REMOTE_ROLE);
	packet_send(reply);
}

static int __p_dbm_request__gen_dbm(struct hadmdev *dev, struct hadm_node *runnode)
{
	return dbm_gen(runnode);
}

static int __p_delta_sync_request(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct bwr_meta *l_meta, *r_meta;
	struct bwr *bwr;

	pr_info("hadm%d receive P_DBM_REQ...\n", pnode->pack->dev_id);

	rcv_pack = pnode->pack;
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_dbm_request: no device %d\n", rcv_pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("__p_dbm_request: no node %d for hadm%d\n", rcv_pack->node_from, hadmdev->minor);
		return -EINVAL;
	}
	bwr = hadmdev->bwr;
	l_meta = &hadmdev->bwr->mem_meta;
	r_meta = (struct bwr_meta *)rcv_pack->data;

	send_startrep(hadmdev->minor, hadm_node);
	return 0;
}

static int __p_dbm_request(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack = pnode->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct bwr_meta *l_meta, *r_meta;
	struct bwr *bwr;
	int local_node_id = get_node_id();

	pr_info("hadm%d receive P_DBM_REQ...\n", rcv_pack->dev_id);

	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_dbm_request: no device %d\n", rcv_pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("__p_dbm_request: no node %d\n", rcv_pack->node_from);
		return -EINVAL;
	}

	bwr = hadmdev->bwr;
	l_meta = &hadmdev->bwr->mem_meta;
	r_meta = (struct bwr_meta *)rcv_pack->data;
	pr_info("hadm%d local_meta(node id %d): lastp id:uuid:seq:lpd(%d:%llu:%llu:%d).localp id:uuid:seq(%d:%llu:%llu).\n",
                    hadmdev->minor,
			local_node_id,
			l_meta->last_primary.id,
			l_meta->last_primary.uuid,
			l_meta->last_primary.bwr_seq,
			l_meta->last_primary.last_page_damaged,
			l_meta->local_primary.id,
			l_meta->local_primary.uuid,
			l_meta->local_primary.bwr_seq);
	pr_info("hadm%d remote_meta(node id %d): lastp id:uuid:seq:lpd(%d:%llu:%llu:%d).localp id:uuid:seq(%d:%llu:%llu).\n",
                    hadmdev->minor,
			hadm_node->id,
			r_meta->last_primary.id,
			r_meta->last_primary.uuid,
			r_meta->last_primary.bwr_seq,
			r_meta->last_primary.last_page_damaged,
			r_meta->local_primary.id,
			r_meta->local_primary.uuid,
			r_meta->local_primary.bwr_seq);


	spin_lock(&hadmdev->primary_lock);
	if ((hadmdev->primary && hadmdev->primary->id != hadm_node->id) || !check_split_brain(l_meta, r_meta)) {
		__p_dbm_request__role_error(hadm_node, rcv_pack);
		spin_unlock(&hadmdev->primary_lock);
		return -EKMOD_REMOTE_ROLE;
	}
	hadmdev->primary = hadm_node;
	spin_unlock(&hadmdev->primary_lock);

	spin_lock(&hadmdev->local->s_state.lock);
	__hadm_node_set(&hadmdev->local->s_state, S_HANDSHAKE, HS_SUCCESS);
	spin_unlock(&hadmdev->local->s_state.lock);

	hadm_node->kmod_id = rcv_pack->kmod_from;

	/* OK. Prepare cmsync */
	if ((l_meta->last_primary.last_page_damaged && l_meta->local_primary.id == INVALID_ID) ||
			(r_meta->last_primary.last_page_damaged && l_meta->last_primary.uuid == r_meta->last_primary.uuid))
		dbm_set_sector(hadm_node->dbm, l_meta->last_primary.last_page);
	create_dbm_sync_thread(P_CMSYNC, hadm_node);

	return 0;
}

static void __delta_sync_finished(struct hadm_node *hadm_node)
{
	struct bwr *bwr=hadm_node->hadmdev->bwr;
	struct bwr_data *bwr_data;
	uint64_t seq_id, snd_head, tail;

	hadm_node_reset_send_head(hadm_node);
	/**FIXME maybe need get seq from local primary**/
	snd_head = hadm_node_get(hadm_node, SECONDARY_STATE, S_SND_HEAD);
	tail = bwr_tail(bwr);
	pr_info("hadm%d __delta_sync_finished, node %d snd_head = %llu, bwr tail = %llu\n",
                    hadm_node->hadmdev->minor, 
			hadm_node->id, snd_head, tail);
	bwr_data = get_send_head_data(bwr, hadm_node->id, 0);
	if (bwr_data) {
		seq_id = bwr_data->meta.bwr_seq - 1;
		bwr_data_put(bwr_data);
	} else {
		if(snd_head == bwr_tail(bwr)) {
			seq_id = bwr_seq(bwr);
		}else {
			pr_warn("%s:get hadm%d send head (snd_head = %llu) data from bwr failed\n", __FUNCTION__,
                            hadm_node->hadmdev->minor,
					(unsigned long long)hadm_node_get(hadm_node, SECONDARY_STATE, S_SND_HEAD));
			bwr_dump(bwr);
			BUG();
			return ;
		}
	}
	hadm_node_set(hadm_node, SECONDARY_STATE, S_DATA_STATE, DATA_CONSISTENT);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_DSTATE, D_CONSISTENT);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_SYNC);
	hadm_node_test_and_set(hadm_node, SECONDARY_STATE, S_HANDSHAKE, HS_FAIL, HS_SUCCESS);

	send_uptodate_packet(hadm_node, seq_id);
	if(is_uptodate(hadm_node->hadmdev->bwr,hadm_node->id)&&
			atomic_read(&hadm_node->dbm->nr_bit) == 0) {
		pr_info("%s hadm%d node %d already uptodate, tp: %u -> %u.\n",
				__FUNCTION__,
                hadm_node->hadmdev->minor,
				hadm_node->id,
				hadm_node->conf.real_protocol,
				hadm_node->conf.protocol);
		hadm_node->conf.real_protocol = hadm_node->conf.protocol;
	}
}

int __delta_sync(struct hadm_node *hadm_node)
{
	struct hadmdev *hadmdev;
	struct bwr *bwr;
	int ret = 1, dstate,cstate;
	sector_t start, end;
	sector_t node_head, snd_head;
	struct dbm *dbm = hadm_node->dbm;

	dbm->dbm_sync_param = dbm_sync_param_create(dbm);
	if(IS_ERR_OR_NULL(dbm->dbm_sync_param)) {
		ret =  -ENOMEM;
		goto delta_sync_done;
	}

	hadmdev = hadm_node->hadmdev;
	bwr = hadmdev->bwr;
	hadm_node_reset_send_head(hadm_node);
	/**
	 *这里做一些优化，__delta_sync的入口是进行delta_sync和交换完对方的dbm后
	 *因为这时候，本地的bwr可能存在大量数据，尤其是进行cmsync之前，所以需要
	 *这一部分数据也转化为dbm。这时候依赖sync_dbm_thread会非常慢，所以在这里
	 *异步io来转化，并确保hadm_node->id在local_node_id之前
	 */
	hadm_node_set(hadm_node,SECONDARY_STATE,S_CSTATE,C_DELTA_SYNC_DBM);
	snd_head = hadm_node_get(hadm_node, SECONDARY_STATE, S_SND_HEAD);
	node_head = bwr_node_head(bwr, hadm_node->id);
	pr_info("%s: hadm%d node %d 1node snd head:%lu. node_head:%lu\n", 
                    __FUNCTION__, hadmdev->minor, hadm_node->id, 
                    snd_head, node_head);
	do {
		ret = __p_dbm_request__gen_dbm(hadmdev, hadm_node);
		if(ret ) {
			goto delta_sync_done;
		}
		pr_info("gen dbm from hadm%d bwr for node %d, now node head = %lu, local head = %lu, tail = %lu\n",
                        hadmdev->minor,
				hadm_node->id, bwr_node_head(bwr, hadm_node->id), bwr_node_head(bwr, get_node_id()),
				bwr_tail(bwr));
	}while (bwr_node_head_cmp(bwr, get_node_id(), hadm_node->id) < 0) ;
	/**
	while (bwr_node_head_cmp(bwr, get_node_id(), hadm_node->id) < 0) {
		pr_info("%s: waiting BWR head to reach node %d head\n", __FUNCTION__, hadm_node->id);
		msleep(1000);
	}
	**/
	dstate = hadm_node_get(hadm_node, SECONDARY_STATE, S_DSTATE);
	cstate = hadm_node_get(hadm_node, SECONDARY_STATE, S_CSTATE);
	if(dstate != D_INCONSISTENT || cstate != C_DELTA_SYNC_DBM){
		pr_info("hadm%d node %d dstate %d, cstate %d,delta_sync quit\n",
                        hadmdev->minor, hadm_node->id, 
				dstate,cstate);
		ret=-1;
		goto delta_sync_done;
	}


	/* TODO: flush dbm to disk */

	ret = dbm_delta_sync(hadm_node);
	if (ret) {
		if (ret == -EKMOD_CSTATE) {
			pr_info("%s: hadm%d dbm_delta_sync failed\n", 
                            __FUNCTION__, hadmdev->minor);
			ret=-1;
		} else if (ret == -EKMOD_DELTA_SYNC_EXIT) {
			ret=-2;
		}
		goto delta_sync_done;
	}

	start = bwr_node_head(bwr, hadm_node->id);
	end = bwr_node_head(bwr, get_node_id());
	pr_info("delta_sync_bwr hadm%d: start=%llu, end=%llu\n", 
                    hadmdev->minor, (unsigned long long)start, (unsigned long long)end);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_BWR);

	hadm_node_reset_send_head(hadm_node);
	snd_head = hadm_node_get(hadm_node, SECONDARY_STATE, S_SND_HEAD);
	node_head = bwr_node_head(bwr, hadm_node->id);
	pr_info("hadm%d node%d 2node snd head:%lu. node_head:%lu\n", 
                    hadmdev->minor, hadm_node->id, snd_head, node_head);
	ret = delta_sync_bwr(hadm_node, start, end); /* 将 [start,end] 之间的数据发送到对端 */
	if (ret) {
		pr_info("%s: hadm%d delta_sync_bwr to node %d failed, return code %d\n", 
                        __FUNCTION__, hadmdev->minor, hadm_node->id, ret);
		goto delta_sync_done;
	}

	snd_head = hadm_node_get(hadm_node, SECONDARY_STATE, S_SND_HEAD);
	node_head = bwr_node_head(bwr, hadm_node->id);
	pr_info("hadm%d node%d 2node snd head:%lu. node_head:%lu\n", 
			hadmdev->minor, hadm_node->id, snd_head, node_head);


	/* TODO: generate p_data packet to set peer dstate to consistence */
	__delta_sync_finished(hadm_node);

delta_sync_done:
	dbm_sync_param_free(dbm);
	hadm_thread_terminate(hadm_node->delta_sync);
	if(ret){
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
	}
	return ret;
}

static int __p_dbm_reply(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack = pnode->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct dbm_record *dbm_record;
	int i, before, after, r_before;

	pr_info("hadm%d receive P_DBM_REP...\n", rcv_pack->dev_id);

	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_dbm_reply: no device %d\n", rcv_pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("__p_dbm_reply: no node %d for hadm%d\n", rcv_pack->node_from, 
                        hadmdev->minor);
		return -EINVAL;
	}
	pr_info("hadm%d node %d dbm start=%lu, len=%d\n", 
                    hadmdev->minor, hadm_node->id, 
                    (unsigned long)rcv_pack->dev_sector, (unsigned)rcv_pack->len);

	/*
	 * 收到 P_DBM_REP 包，那么需要将它的数据和对应节点的 dbm 作或操作，
	 * 当所有的包都收完之后，执行 delta_sync 操作
	 */
	if (rcv_pack->errcode == -EKMOD_REMOTE_ROLE && rcv_pack->len == 0) {
		pr_err("__p_dbm_reply hadm%d: remote role is not right\n", hadmdev->minor);
		return -EKMOD_REMOTE_ROLE;
	}
	hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_CMSYNC_DBM);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_DSTATE, D_INCONSISTENT);
	/* FIXME need lock dbm? */
	if (rcv_pack->errcode == -XCHG_DBM_END && rcv_pack->len == 0) {
		//dbm_gen(hadm_node); /* FIXME gen from disk or read from memory? */
		pr_info("hadm%d dbm receive from node %d end, remain %d bits before delta_sync\n",
                        hadmdev->minor, 
                        hadm_node->id, atomic_read(&hadm_node->dbm->nr_bit));
		hadm_node_set(hadm_node, SECONDARY_STATE, S_DATA_STATE, DATA_DBM);
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_DBM);
		hadm_node->kmod_id = rcv_pack->kmod_from;
		create_dbm_sync_thread(P_DELTA_SYNC, hadm_node);
	} else {
		dbm_record = dbm_find_record(hadm_node->dbm, rcv_pack->dev_sector);

		before = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		r_before = nr_bits(rcv_pack->data, 0, rcv_pack->len);
		pr_info("hadm%d node %d before dbm OR: local=%d, remote=%d\n", 
                        hadmdev->minor, hadm_node->id, 
                        before, r_before);

		for (i = 0; i < rcv_pack->len; i++) {
			char *data = page_address(dbm_record->page);
			data[i] |= rcv_pack->data[i];
		}
		dbm_dirty_record(hadm_node->dbm, dbm_record);

		after = nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		pr_info("hadm%d node %d after dbm OR: local=%d, remote=%d\n", 
                        hadmdev->minor, hadm_node->id, 
                        after, r_before);
		atomic_add(after - before, &hadm_node->dbm->nr_bit);
	}

	return 0;
}

static int __p_delta_sync_done(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack = pnode->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *target;

	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, rcv_pack->dev_id);
		return -ENODEV;
	}

	target = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (target == NULL || IS_ERR(target)) {
		pr_err("%s: no node %d for hadm%d\n", __FUNCTION__, rcv_pack->node_from, hadmdev->minor);
		return -EKMOD_NONODE;
	}

	//dbm_clear_all(target->dbm);
	return 0;
}

static int __p_fullsync_request(void *arg)
{
	int ret = 0;
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack;
	struct hadmdev *hadmdev;
	struct packet *reply;
	struct hadm_node *hadm_node;

	pr_info("hadm%d receive P_FULLSYNC_REQ...\n", pnode->pack->dev_id);

	rcv_pack = pnode->pack;
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, rcv_pack->dev_id);
		ret = -ENODEV;
		goto done;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("%s: no node %d\n", __FUNCTION__, rcv_pack->node_from);
		ret = -EINVAL;
		goto done;
	}

	if (hadmdev_set_primary(hadmdev, hadm_node) < 0) {
		pr_err("hadm%d reject node %d fullsync request, "
				"because I accepted node %d as primary\n",
                hadmdev->minor, 
				rcv_pack->node_from, hadmdev->primary->id);
		ret = -EINVAL;
		goto done;
	}
	hadm_node_set(hadm_node, SECONDARY_STATE, S_HANDSHAKE, HS_SUCCESS);
	hadm_node->kmod_id = rcv_pack->kmod_from;
done:
	reply = packet_alloc(0, GFP_KERNEL);
	if (!reply) {
		pr_err("%s: alloc reply packet failed.\n", __func__);
		return -ENOMEM;
	}
	reply->type = P_FULLSYNC_REP;
	reply->dev_id = rcv_pack->dev_id;
	reply->errcode = ret;
	reply->node_to = (1 << rcv_pack->node_from);
	reply->kmod_to = (1 << rcv_pack->kmod_from);

	if (packet_send(reply) < 0)
		pr_err("%s: send reply failed.\n", __func__);
	atomic_set(&hadmdev->async_io_pending[READ], 0);
	pr_info("hadm%d send fullsync_reply to node %d, err:%d.\n", 
                    hadmdev->minor, rcv_pack->node_from, ret);
	return ret;
}

static int __cmsync(struct hadm_node *hadm_node)
{
	struct hadmdev *hadmdev = hadm_node->hadmdev;
	struct dbm *dbm = hadm_node->dbm;
	int error = 0;
	dbm->dbm_sync_param = dbm_sync_param_create(dbm);
	if(IS_ERR_OR_NULL(dbm->dbm_sync_param)) {
		return -ENOMEM;
	}

	error = __p_dbm_request__gen_dbm(hadmdev, hadm_node);
	if(error) {
		goto done;
	}
	__p_dbm_request__send_dbm(hadm_node);
	__p_dbm_request__set_status(hadmdev->local, hadm_node);
done:
	dbm_sync_param_free(dbm);
	hadm_thread_terminate(hadm_node->delta_sync);
	return error;
}

static int __fullsync(struct hadm_node *hadm_node)
{
	struct hadmdev *hadmdev;
	sector_t start,end;
	int ret, n_state;
	struct dbm *dbm = hadm_node->dbm;

	hadmdev = hadm_node->hadmdev;
	start=bwr_node_head(hadmdev->bwr,get_node_id());
	dbm_set_bit_all(hadm_node->dbm);
	msleep(2000);//wait dbm sync to bwr disk
    dbm->dbm_sync_param = NULL;
	n_state = hadm_node_get(hadm_node, SECONDARY_STATE, S_NSTATE);
	if (n_state == N_DISCONNECT) {
		pr_info("%s: hadm%d network disconnect, exited\n", 
                        __FUNCTION__, hadm_node->hadmdev->minor);
		ret = -1;
		goto done;
	}
	dbm->dbm_sync_param = dbm_sync_param_create(dbm);
	if(IS_ERR_OR_NULL(dbm->dbm_sync_param)) {
		ret =  -ENOMEM;
		goto done;
	}

	bwr_set_node_head(hadmdev->bwr, hadm_node->id, start, 1);
	//hadm_node_reset_send_head(hadm_node);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_DBM);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_DATA_STATE, DATA_DBM);
	hadm_node_set(hadm_node, SECONDARY_STATE, S_DSTATE, D_INCONSISTENT);
	ret=dbm_fullsync(hadm_node);
	if(ret)
	{
		pr_info("hadm%d fullsync to node %d is terminated \n",
                        hadm_node->hadmdev->minor, hadm_node->id);
		goto done;
	}
	hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_DELTA_SYNC_BWR);
	end=bwr_node_head(hadmdev->bwr,get_node_id());
	ret=delta_sync_bwr(hadm_node,start,end);
	if(ret)
	{
        pr_info("hadm%d fullsync to node %d is terminated \n",
            hadm_node->hadmdev->minor, hadm_node->id);

		goto done;

	}

	__delta_sync_finished(hadm_node);
	ret = 0;
done:
	dbm_sync_param_free(dbm);
	hadm_thread_terminate(hadm_node->delta_sync);
	if(ret){
		hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
	}
	return ret;
}

static int __p_fullsync_reply(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack = pnode->pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node=NULL;

	pr_info("hadm%d receive P_FULLSYNC_REP from node %d...\n",
                    rcv_pack->dev_id, rcv_pack->node_from);

	if (rcv_pack->errcode != 0) {
		pr_warn("%s: receive error %d\n", __FUNCTION__, rcv_pack->errcode);
		return 0;
	}
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, rcv_pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("%s: no node %d\n", __FUNCTION__, rcv_pack->node_from);
		return -EINVAL;
	}

	hadm_node_set(hadm_node, SECONDARY_STATE, S_HANDSHAKE, HS_SUCCESS);
	hadm_node->kmod_id = rcv_pack->kmod_from;
	create_dbm_sync_thread(P_FULLSYNC,hadm_node);

	return 0;
}

static void __p_fullsync_md5_end_io(struct bio *bio, int error)
{
	struct hadm_pack_node *ack_node = (struct hadm_pack_node *)bio->bi_private;
	struct hadmdev *hadmdev = find_hadmdev_by_minor(ack_node->pack->dev_id);
	char *data;
	if(IS_ERR_OR_NULL(hadmdev)){
		pr_warn("%s: invalid device id %d\n", __FUNCTION__, ack_node->pack->dev_id);
		return ;
	}
	if(error){
		hadmdev_set_error(hadmdev, __BDEV_ERR);
		ack_node->pack->errcode = -EIO;
	}else {
		data = page_address(bio->bi_io_vec[0].bv_page);
		memcpy(ack_node->pack->data, data, PAGE_SIZE);
		//fullsync_md5_hash(data, PAGE_SIZE, private->ack_node->pack->md5);
		//private->ack_node->pack->errcode = memcmp(private->ack_node->pack->md5, private->org_node->pack->md5, 16) ? -FULLSYNC_DATA_REQ : 0;
	}
	if(packet_node_send(ack_node, 0)){
		BUG();
	}
	hadm_free_bio(bio);
}

static int __p_fullsync_md5(void *arg)
{
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct hadmdev *hadmdev;
	struct packet *rcv_pack, *req;
    struct hadm_node *hadm_node;
	struct hadm_pack_node *ack_node = NULL;
	unsigned long node_to;

	rcv_pack = pnode->pack;
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("__p_fullsync_md5: no device %d\n", rcv_pack->dev_id);
		return -ENODEV;
	}
    hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
    if(hadm_node == NULL) {
            return -EINVAL;
    }
	node_to = 0;
	set_bit(rcv_pack->node_from, &node_to);
	req = packet_alloc(PAGE_SIZE, GFP_KERNEL);
	if (req == NULL || IS_ERR(req)) {
		pr_err("__p_fullsync_md5: no memory\n");
		return -ENOMEM;
	}

	packet_init(req, P_FULLSYNC_DATA_REQ, rcv_pack->dev_id, node_to, rcv_pack->dev_sector, 0, 0, 0,  0);
	req->node_to = (1 << rcv_pack->node_from);
	req->kmod_to = (1 << rcv_pack->kmod_from);
	memcpy(req->md5, rcv_pack->md5, 16);
	req->uuid = hadmdev->bwr->mem_meta.last_primary.uuid;

	if(rcv_pack->dev_sector +8 > hadmdev->bdev_disk_size) {
		pr_err("__p_fullsync_md5 hadm%d: request sector %llu beyond the disk size %llu \n",
                        hadmdev->minor,
				(unsigned long long)rcv_pack->dev_sector,
				(unsigned long long)hadmdev->bdev_disk_size);

		req->errcode = 0 ;
		goto reply;
	}
	ack_node = hadm_pack_node_create(req, NULL);
	if(!ack_node) {
		req->errcode = -ENOMEM;
		goto reply;
	}


	req->errcode = write_bwr_meta(hadmdev->bwr, 
                    LAST_PRIMARY, D_INCONSISTENT, 0, 
                    rcv_pack->node_from, rcv_pack->uuid, 0, 0, rcv_pack->md5);
	if(req->errcode) {
		goto reply;
	}
	/**check sender_queue free space**/
	if(hadm_queue_reserve_timeout(hadmdev->p_sender_queue[P_DATA_TYPE], 1,
				msecs_to_jiffies(10000))) {
		pr_err("%s: wait for device %d's sender queue space timeout.\n",
				__FUNCTION__, hadmdev->minor);
		req->errcode = -EBUSY;
		goto reply;
	}
    
	if(hadm_read_page_async(hadmdev->bdev, 
				rcv_pack->dev_sector, 
				__p_fullsync_md5_end_io, 
				(void *)ack_node)) {
		pr_err("%s: read hadm%d sector %llu failed\n",
				__FUNCTION__,hadmdev->minor, rcv_pack->dev_sector);
		req->errcode = -ENOMEM;
		goto reply;
	}
	return 0;

reply:
	/* construct P_FULLSYNC_DATA_REQ packet */

	/* send packet */
    if(req->errcode !=0 && req->errcode != -FULLSYNC_DATA_REQ) {
            hadm_node_set(hadm_node, SECONDARY_STATE, S_CSTATE, C_STOPPED);
    }
	if(ack_node)
		kfree(ack_node);
	packet_send(req);

	return 0;
}

static int __p_fullsync_data_request(void *arg)
{
	int ret = 0;
	struct hadm_pack_node *pnode=(struct hadm_pack_node *)arg;
	struct packet *rcv_pack;
	struct hadmdev *hadmdev;
	struct hadm_node *hadm_node;
	struct dbm *dbm;

	rcv_pack = pnode->pack;
	hadmdev = find_hadmdev_by_minor(rcv_pack->dev_id);
	if (hadmdev == NULL || IS_ERR(hadmdev)) {
		pr_err("%s: no device %d\n", __FUNCTION__, rcv_pack->dev_id);
		return -ENODEV;
	}
	hadm_node = find_hadm_node_by_id(hadmdev, rcv_pack->node_from);
	if (hadm_node == NULL || IS_ERR(hadm_node)) {
		pr_err("%s: no node %d\n", __FUNCTION__, rcv_pack->node_from);
		return -EINVAL;
	}
	if(hadm_node_get(hadm_node, SECONDARY_STATE, S_CSTATE) != C_DELTA_SYNC_DBM) {
		return -EINVAL;
	}
	dbm = hadm_node->dbm;

	if (rcv_pack->errcode == 0) {
		dbm_clear_sector(hadm_node->dbm, rcv_pack->dev_sector);
	} else if (rcv_pack->errcode == -FULLSYNC_DATA_REQ) {
		/* send P_RS_DATA packet */
		if(!dbm || !dbm->dbm_sync_param) {
			BUG();
		}
		if(hadm_queue_reserve_timeout(dbm->dbm_sync_param->delta_packet_queue, 1, 
					msecs_to_jiffies(10000))){
			return -EBUSY;
		}
		ret = delta_sync_read_page_async(hadm_node, rcv_pack->dev_sector, P_RS_DATA);
		if (ret < 0)
			pr_err("%s: hadm%d send fullsync data faild.\n", __FUNCTION__, hadmdev->minor);
	} else {
		pr_err("%s: hadm%d unknown error code %d\n",
			   __FUNCTION__, hadmdev->minor, rcv_pack->errcode);
		/*TODO disconnect peer */
	}

	return ret;
}

int create_dbm_sync_thread(uint8_t dbm_type,struct hadm_node *hadm_node)
{
	thread_func_t func;
	char name[0x20];

	if(dbm_type==P_FULLSYNC) {
		func = (thread_func_t)__fullsync;
		snprintf(name, sizeof(name), "%s_%d_%d", "__fullsync", hadm_node->hadmdev->minor, hadm_node->id);
	}else if(dbm_type == P_DELTA_SYNC) {
		func = (thread_func_t )__delta_sync;
		snprintf(name, sizeof(name), "%s_%d_%d", "__dbmsync", hadm_node->hadmdev->minor, hadm_node->id);
	}else if(dbm_type == P_CMSYNC) {
		func = (thread_func_t )__cmsync;
		snprintf(name, sizeof(name), "%s_%d_%d", "__cmsync", hadm_node->hadmdev->minor, hadm_node->id);
	}else {
		return -1;
	}

	if(hadm_node->delta_sync==NULL) {
		hadm_node->delta_sync = hadm_thread_alloc();
	} else if(hadm_thread_get_state(hadm_node->delta_sync)==HADM_THREAD_RUN){
		pr_info("delta_sync thread(%p) for hadm%d node %d failed\n",
                        (void *)hadm_node->delta_sync,hadm_node->hadmdev->minor, hadm_node->id);
		return -1;
	} else {
		hadm_thread_free(&hadm_node->delta_sync);
		hadm_node->delta_sync = hadm_thread_alloc();
	}

	if(hadm_node->delta_sync==NULL) {
		pr_err("create delta_sync thread for hadm%d node %d failed\n",
                        hadm_node->hadmdev->minor, hadm_node->id);
		return -ENOMEM;
	}
	hadm_thread_init(hadm_node->delta_sync, name, func, hadm_node, NULL);
	pr_info("create delta_sync thread %p for hadm%d node %d dbm sync\n",
                    (void *)hadm_node->delta_sync, hadm_node->hadmdev->minor, hadm_node->id);
	hadm_thread_run(hadm_node->delta_sync);
	return 0;
}

static struct packet_handler p_functions[] = {
	[P_DATA] = { __p_data },
	[P_RS_DATA] = { __p_data },
	[P_DATA_NET_ACK] = { __p_data_net_ack },
	[P_DATA_ACK] = { __p_data_ack },
	[P_RS_DATA_ACK] = { __p_rs_data_ack },
	[P_DBM_REQ] = { __p_dbm_request },
	[P_DELTA_SYNC_REQ] = { __p_delta_sync_request},
	[P_DBM_REP] = { __p_dbm_reply },
	[P_FULLSYNC_REQ] = { __p_fullsync_request },
	[P_FULLSYNC_REP] = { __p_fullsync_reply },
	[P_FULLSYNC_MD5] = { __p_fullsync_md5 },
	[P_FULLSYNC_DATA_REQ] = { __p_fullsync_data_request },
	[P_DELTA_SYNC_DONE] = { __p_delta_sync_done },
	[P_DATA_END] = {NULL}
};

packet_handler_t get_data_worker_handler(int type)
{
	if(P_DATA_START<type&&type<P_DATA_END)
		return p_functions[type].func;
	else
		return NULL;
}
