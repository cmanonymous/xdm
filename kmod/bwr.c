#define pr_fmt(fmt) "bwr: " fmt

#include <linux/delay.h>
#include <linux/crc32.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "hadm_packet.h"
#include "hadm_config.h"
#include "hadm_bio.h"
#include "primary_info.h"
#include "hadm_thread.h"

#include "bwr.h"
#include "bio_handler.h"
#include "dbm.h"
#include "buffer.h"
#include "utils.h"
#include "bio_helper.h"
#include "fullsync.h"

static sector_t bwr_distance(struct bwr * bwr, sector_t head, sector_t tail)
{
	return (tail + bwr->max_size - head) % bwr->max_size;
}

/* test s1 <=> s2 *
 * return -1 0 1
 */
int bwr_sector_cmp(struct bwr *bwr, sector_t s1, sector_t s2, sector_t tail)
{
	if (s1 == s2)
		return 0;
	else if (s1 == INVALID_SECTOR)
		return 1;
	else if (s2 == INVALID_SECTOR)
		return -1;
	else
		return (bwr_distance(bwr, s1, tail) > bwr_distance(bwr, s2, tail)) ? -1 : 1;
}

struct bwr *bwr_alloc(size_t size, int gfp_mask)
{
	struct bwr *bwr;
	int ret;

	bwr = kzalloc(size, gfp_mask);
	if (bwr == NULL) {
		ret = -ENOMEM;
		goto err_bwr;
	}

	return bwr;

err_bwr:
	return ERR_PTR(ret);
}

void free_bwr(struct bwr *bwr)
{
	if (bwr == NULL || IS_ERR(bwr))
		return;
	kfree(bwr);
}

sector_t bwr_start_sector(struct bwr *bwr)
{
	return bwr->start_sector;
}

static int __bwr_empty(struct bwr *bwr)
{
	return bwr->inuse_size == 0;
}

int bwr_empty(struct bwr *bwr)
{
	int ret;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	ret = __bwr_empty(bwr);
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

int __bwr_full(struct bwr *bwr)
{
	return bwr->inuse_size == bwr->max_size - BWR_ALIGN_SECTOR;
}

void __bwr_dump(struct bwr *bwr)
{
	pr_info("hadm%d bwr inuse_size = %lu, min_disk_head = %lu, min_node_mask = %u\n",
			bwr->hadmdev->minor,
			bwr->inuse_size, bwr->min_disk_head, bwr->min_node_mask);

	pr_info("=============hadm%d bwr mem_data===============", bwr->hadmdev->minor);
	bwr_meta_dump(&bwr->mem_meta);
	pr_info("=============hadm%d bwr disk_data===============", bwr->hadmdev->minor);
	bwr_meta_dump(&bwr->disk_meta);
}


int bwr_full(struct bwr *bwr)
{
	int ret;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	ret = __bwr_full(bwr);
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

void __bwr_set_inuse_size(struct bwr *bwr, sector_t size)
{
//	pr_info("try set inuse size from %lu to %lu.\n",
//			bwr->inuse_size, size);
	if (bwr->inuse_size != size) {
		if (unlikely(size > bwr->max_size)) {
			pr_err("try set hadm%d bwr inuse size larger than maxsize.\n", 
					bwr->hadmdev->minor);
			dump_stack();
			return;
		}

		if (size > bwr->inuse_size)
			pr_info("warning set hadm%d bwr size increase, head:%llu(0)%llu(1), tail:%llu.\n",
					bwr->hadmdev->minor,
					bwr->disk_meta.head[0],
					bwr->disk_meta.head[1],
					bwr->mem_meta.tail);
		if (__bwr_full(bwr) && !completion_done(&bwr->not_full)) {
			pr_info("notify hadm%d bwr not full.\n", bwr->hadmdev->minor);
			complete(&bwr->not_full);
		}
		bwr->inuse_size = size;
	}
}

int __bwr_inuse_size_dec(struct bwr *bwr)
{
	if (unlikely(__bwr_empty(bwr))) {
		pr_err("BUG!! try decrease hadm%d bwr inuse size, which equals 0.\n", bwr->hadmdev->minor);
		dump_stack();
		return -1;
	}
	if (__bwr_full(bwr) && !completion_done(&bwr->not_full)) {
		pr_info("notify hadm%d bwr not full.\n", bwr->hadmdev->minor);
		complete(&bwr->not_full);
	}
	bwr->inuse_size -= BWR_ALIGN_SECTOR;
	return 0;
}

void __bwr_inuse_size_sub(struct bwr *bwr, int nr)
{
	if (nr <= 0) {
		pr_info("%s: warning sub hadm%d bwr inuse size where nr <= 0 (%d).\n", 
				__FUNCTION__, bwr->hadmdev->minor, nr);
	}
	if (nr > 0 && __bwr_full(bwr) && !completion_done(&bwr->not_full)) {
		pr_info("notify hadm%d bwr not full.\n", bwr->hadmdev->minor);
		complete(&bwr->not_full);
	}
	bwr->inuse_size -= nr * BWR_ALIGN_SECTOR;
}

void __bwr_inuse_size_inc(struct bwr *bwr)
{
	if (unlikely(__bwr_full(bwr))) {
		pr_err("BUG!! try increase hadm%d bwr inuse size, which equals max_size.\n", bwr->hadmdev->minor);
		dump_stack();
		return;
	}
	bwr->inuse_size += BWR_ALIGN_SECTOR;
}

void __bwr_inuse_size_add(struct bwr *bwr, int nr)
{
	bwr->inuse_size += nr * BWR_ALIGN_SECTOR;
	if (unlikely(bwr->inuse_size >= bwr->max_size)) {
		pr_err("BUG!! try add hadm%d bwr inuse size, which larger max_size.\n", bwr->hadmdev->minor);
		dump_stack();
		return;
	}
}

int bwr_inuse_size_pre_occu(struct bwr *bwr)
{
	unsigned long flags;
	struct hadm_node *runnode;
	uint32_t min_node_mask;

try_occupy:
	write_lock_irqsave(&bwr->lock, flags);
	if (__bwr_full(bwr)) {
		min_node_mask = bwr->min_node_mask;
		write_unlock_irqrestore(&bwr->lock, flags);
		pr_info("hadm%d bwr is full , min_node_mask=%u\n", 
				bwr->hadmdev->minor, min_node_mask);
		bwr_dump(bwr);
		list_for_each_entry(runnode, &bwr->hadmdev->hadm_node_list, node) {
			if (runnode == bwr->hadmdev->local)
				continue;
			if (min_node_mask & (1 << runnode->id)) {
				pr_info("hadm%d bwr is full, try set node:%d state to inconsistent.\n", 
						bwr->hadmdev->minor, runnode->id);
				/* BWR 满了，就应该使 delta_sync 线程退出 */
				/* hadm_thread_stop(runnode->delta_sync); */
				hadm_node_become_inconsitent(runnode);
			}
		}
		pr_info("hadm%d bwr occupy try wait.\n", bwr->hadmdev->minor);
		if (wait_for_completion_timeout(&bwr->not_full, msecs_to_jiffies(100000)) == 0) {
			pr_err("%s timeout, hadm%d bwr head:%llu(0)%llu(1), tail:%llu, inuse_size:%lu.\n",
					__FUNCTION__, bwr->hadmdev->minor, bwr->mem_meta.head[0], bwr->mem_meta.head[1],
					bwr->mem_meta.tail, bwr->inuse_size);
			bwr_dump(bwr);
			hadmdev_set_error(bwr->hadmdev, __BWR_ERR);
			return -1;
		}
		goto try_occupy;
	}

	/* FIXME need guarantee bwr->disk_meta->min_head after this area. */
	__bwr_inuse_size_inc(bwr);
	write_unlock_irqrestore(&bwr->lock, flags);
	return 0;
}

sector_t bwr_get_inuse_size(struct bwr *bwr)
{
	sector_t size;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	size = __bwr_get_inuse_size(bwr);
	read_unlock_irqrestore(&bwr->lock, flags);

	return size;
}

void bwr_update_inuse_size(struct bwr *bwr)
{
	unsigned long flags;
	uint32_t node_mask;
	sector_t min_head, delta;
	write_lock_irqsave(&bwr->lock, flags);
	min_head = __bwr_get_min_head(bwr, &node_mask);
	if (min_head != bwr->min_disk_head) {
		bwr->min_node_mask = node_mask;
		if(bwr->min_disk_head != INVALID_SECTOR) {
			delta = bwr_distance(bwr, bwr->min_disk_head, min_head);
			if(bwr->inuse_size < delta ){
				pr_warn("%s: hadm%d inuse size over flow, inuse_size = %lu, sub = %lu, min_head = %lu, bwr->min_disk_head = %lu.\n",
						__FUNCTION__, bwr->hadmdev->minor, 
						bwr->inuse_size, delta,
						min_head, bwr->min_disk_head);
				__bwr_dump(bwr);
				write_unlock_irqrestore(&bwr->lock, flags);
				//BUG();
				hadmdev_set_error(bwr->hadmdev, __BWR_ERR);
				return;
			}else {
				__bwr_inuse_size_sub(bwr, delta / BWR_ALIGN_SECTOR);
			}
		}else {
			delta = bwr_distance(bwr, min_head, bwr->disk_meta.tail);
			__bwr_set_inuse_size(bwr, delta);

		}
		bwr->min_disk_head = min_head;
	}
	write_unlock_irqrestore(&bwr->lock, flags);
}

sector_t bwr_next_nr_sector(struct bwr * bwr, sector_t sector, int nr)
{
	return bwr->start_sector + (sector - bwr->start_sector + nr * BWR_ALIGN_SECTOR) % bwr->max_size;
}

sector_t bwr_next_sector(struct bwr * bwr, sector_t sector)
{
	return bwr_next_nr_sector(bwr, sector, 1);
}

sector_t bwr_lastpi_seq(struct bwr *bwr)
{
	unsigned long flags;
	sector_t seq;

	read_lock_irqsave(&bwr->lock, flags);
	seq = bwr->mem_meta.last_primary.bwr_seq;
	read_unlock_irqrestore(&bwr->lock, flags);

	return seq;
}

sector_t bwr_seq(struct bwr *bwr)
{
	unsigned long flags;
	sector_t seq;

	read_lock_irqsave(&bwr->lock, flags);
	if(bwr->mem_meta.local_primary.id != INVALID_ID) {
		seq = bwr->mem_meta.local_primary.bwr_seq;
	}else if(bwr->mem_meta.last_primary.id != INVALID_ID) {
		seq = bwr->mem_meta.last_primary.bwr_seq;
	}else{
		return 0;
	}
	read_unlock_irqrestore(&bwr->lock, flags);
	return seq;
}

sector_t bwr_seq_add(struct bwr * bwr, sector_t sector)
{
	unsigned long flags;
	sector_t seq;

	write_lock_irqsave(&bwr->lock, flags);
	seq = bwr->mem_meta.local_primary.bwr_seq;
	bwr->mem_meta.local_primary.bwr_seq += sector;
	write_unlock_irqrestore(&bwr->lock, flags);

	return seq;
}


sector_t bwr_disk_tail(struct bwr *bwr)
{
	sector_t tail;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	tail = bwr->disk_meta.tail;
	read_unlock_irqrestore(&bwr->lock, flags);

	return tail;
}

sector_t bwr_tail(struct bwr * bwr)
{
	sector_t tail;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	tail = bwr->mem_meta.tail;
	read_unlock_irqrestore(&bwr->lock, flags);

	return tail;
}

int valid_bwr_sector(struct bwr *bwr, int node_id, sector_t sector)
{
	int ret = 0;
	unsigned long flags;
	read_lock_irqsave(&bwr->lock, flags);
	ret = (sector == bwr->mem_meta.tail) ? 0 : sector_in_area(sector, bwr->mem_meta.head[node_id], bwr->mem_meta.tail) ;
	read_unlock_irqrestore(&bwr->lock, flags);
	return ret;
}

static void __bwr_tail_add_sector(struct bwr * bwr, sector_t sector)
{
	bwr->mem_meta.tail = bwr->start_sector + (bwr->mem_meta.tail - bwr->start_sector + sector) % bwr->max_size;
}

void bwr_tail_add(struct bwr *bwr, int nr)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_tail_add_sector(bwr, nr * BWR_ALIGN_SECTOR);
	__bwr_inuse_size_add(bwr, nr);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_tail_add_occupied(struct bwr *bwr, int nr)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_tail_add_sector(bwr, nr * BWR_ALIGN_SECTOR);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_tail_inc(struct bwr *bwr)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_tail_add_sector(bwr, BWR_ALIGN_SECTOR);
	__bwr_inuse_size_inc(bwr);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_tail_inc_occupied(struct bwr *bwr)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_tail_add_sector(bwr, BWR_ALIGN_SECTOR);
	write_unlock_irqrestore(&bwr->lock, flags);
}

uint64_t bwr_add_seq_n_tail(struct bwr * bwr, sector_t sector)
{
	unsigned long flags;
	uint64_t bwr_seq;

	write_lock_irqsave(&bwr->lock, flags);
	if(bwr->mem_meta.local_primary.id != INVALID_ID) {
		bwr->mem_meta.local_primary.bwr_seq += sector;
		bwr_seq = bwr->mem_meta.local_primary.bwr_seq;
	}else {
		bwr->mem_meta.last_primary.bwr_seq += sector;
		bwr_seq = bwr->mem_meta.last_primary.bwr_seq;
	}
	__bwr_tail_add_sector(bwr, sector * BWR_ALIGN_SECTOR);
	write_unlock_irqrestore(&bwr->lock, flags);
	return bwr_seq;

}



int bwr_node_head_cmp(struct bwr *bwr, uint8_t node1,uint8_t node2)
{
	int ret=0;
	unsigned long flags;

	BUG_ON(!VALID_NODE(node1) || !VALID_NODE(node2));

	read_lock_irqsave(&bwr->lock, flags);
	ret = bwr_sector_cmp(bwr,
			bwr->mem_meta.head[node1],
			bwr->mem_meta.head[node2],
			bwr->mem_meta.tail);
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

int bwr_sector_less(struct bwr *bwr, sector_t s1, sector_t s2, sector_t tail)
{
	return bwr_sector_cmp(bwr, s1, s2, tail) < 0;
}

sector_t __bwr_get_min_head(struct bwr *bwr, uint32_t *node_map)
{
	sector_t min_head = INVALID_SECTOR;
	int i = 0, result;
	uint32_t map = 0;
	int local_node_id = get_node_id();
	/**
	 * 对于secondary节点的写操作，因为只有local head，所以
	 * 也比较local head
	 **/

	if(bwr->mem_meta.local_primary.id == INVALID_ID) {
		min_head = bwr->disk_meta.head[local_node_id] ;
		*node_map = 1 << local_node_id;
		return min_head;
	}

	for (i = 0; i < MAX_NODES; i++) {
		if (i == local_node_id) {
			continue;
		}

		if (bwr->disk_meta.head[i] != INVALID_SECTOR) {
			result = bwr_sector_cmp(bwr,
					min_head, bwr->disk_meta.head[i],
					bwr->disk_meta.tail);
			switch (result) {
			case 1:
				min_head = bwr->disk_meta.head[i];
				map = 1 << i;
				break;
			case 0:
				map |= 1 << i;
				break;
			case -1:
				break;
			}
		}
	}

	if (node_map != NULL)
		*node_map = map;
	//pr_info("%s: get min_head=%lu, min_node_mask=%u\n", __FUNCTION__, min_head, map);

	return min_head;
}

uint64_t bwr_get_uuid(struct bwr *bwr)
{
	uint64_t uuid = 0;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	uuid = bwr->mem_meta.local_primary.uuid;
	read_unlock_irqrestore(&bwr->lock, flags);
	return uuid;
}

uint64_t __bwr_node_head_inc(struct bwr *bwr, int node_id)
{
	return (bwr->mem_meta.head[node_id] = bwr_next_sector(bwr, bwr->mem_meta.head[node_id]));
	//if (bwr->min_node_mask & (1 << node_id))
	//__bwr_clear_min_node(bwr, node_id);
}

void __bwr_node_head_add(struct bwr *bwr, int node_id, int nr)
{
	bwr->mem_meta.head[node_id] = bwr_next_nr_sector(bwr, bwr->mem_meta.head[node_id], nr);
	//if (bwr->min_node_mask & (1 << node_id))
	//__bwr_clear_min_node(bwr, node_id);
}

uint64_t bwr_node_head_inc(struct bwr *bwr, int node_id)
{
	unsigned long flags;
	uint64_t ret = 0 ;

	write_lock_irqsave(&bwr->lock, flags);
	ret = __bwr_node_head_inc(bwr, node_id);
	write_unlock_irqrestore(&bwr->lock, flags);
	return ret;
}

void bwr_node_head_condition_inc(struct bwr *bwr, int node_id, uint64_t expect_head)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	if(bwr->mem_meta.head[node_id] == expect_head)
		__bwr_node_head_inc(bwr, node_id);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_node_head_add(struct bwr *bwr, int node_id, int nr)
{
	BUG_ON(nr < 0);
	if (!nr)
		return;
	write_lock(&bwr->lock);
	__bwr_node_head_add(bwr, node_id, nr);
	write_unlock(&bwr->lock);
}

void __bwr_set_node_head(struct bwr *bwr, int node_id, sector_t head)
{
	bwr->mem_meta.head[node_id]  =  head;
#if 0
	sector_t min_head, orig_head, distance;
	//pr_info("%s for node %d from %llu to %lu.\n", __FUNCTION__,
	//node_id, bwr->mem_meta.head[node_id], head);
	if (bwr->mem_meta.head[node_id] != head){
		orig_head = bwr->mem_meta.head[node_id];
		bwr->mem_meta.head[node_id] = head;
		if (bwr->min_node_mask & (1 << node_id)) {
			pr_info("node %d is in min_node_mask %u, clear it.\n",
					node_id, bwr->min_node_mask);
			bwr->min_node_mask &= ~((uint32_t)1 << node_id);
			if (!bwr->min_node_mask) {
				min_head = __bwr_get_min_head(bwr, &bwr->min_node_mask);
				distance = bwr_distance(bwr, orig_head, min_head);
				__bwr_inuse_size_sub(bwr, distance/BWR_ALIGN_SECTOR);
			}
		}
		bwr->mem_meta.head[node_id] = head;
	}
#endif
}

void bwr_set_node_head(struct bwr *bwr, int node_id, sector_t head, int lock_node_state)
{
	unsigned long flags, flags2;
	struct hadm_node *node = find_hadm_node_by_id(bwr->hadmdev, node_id);
	if(node == NULL){
		return ;
	}
	write_lock_irqsave(&bwr->lock, flags);
	__bwr_set_node_head(bwr, node_id, head);
	if(lock_node_state)
		spin_lock_irqsave(&node->s_state.lock, flags2);
	node->s_state.snd_head = node->s_state.snd_ack_head = head;
	if(lock_node_state)
		spin_unlock_irqrestore(&node->s_state.lock, flags2);
	write_unlock_irqrestore(&bwr->lock, flags);
}

sector_t bwr_node_head(struct bwr *bwr, int node_id)
{
	sector_t node_head;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	node_head = __bwr_node_head(bwr, node_id);
	read_unlock_irqrestore(&bwr->lock, flags);

	return node_head;
}

/* Note: caller gurantee C_STATE == C_SYNC */
int is_uptodate(struct bwr *bwr ,int node_id)
{
	unsigned long flags;
	int ret=0;

	read_lock_irqsave(&bwr->lock, flags);
	ret = bwr->mem_meta.head[node_id] == bwr->mem_meta.tail;
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

static uint64_t pack_node_seq(struct list_head *q_node)
{
	struct hadm_pack_node *node = list_entry(q_node, struct hadm_pack_node, q_node);
	return node->pack->bwr_seq;
}

/*
 * 将 BWR 的数据发送到指定的节点，返回 0 表示成功，返回非 0 表示失败
 *
 * 如果是第二次进入这个函数，那么就会发生设置磁盘状态为 D_CONSISTENT 的时机拖后，
 * 现在的处理是接受这种状态。
 */
int delta_sync_bwr(struct hadm_node *node, sector_t start, sector_t end)
{
	struct bwr_data *bwr_data;
	struct bwr *bwr = node->hadmdev->bwr;
	struct hadm_queue *delta_packet_queue = node->dbm->dbm_sync_param->delta_packet_queue;
	int cstate, ret = 0;
	sector_t last_seq = 0 , start_seq = 0;
	uint32_t un_acked = 0 ;
	uint32_t npack = bwr_distance(bwr, start, end)/BWR_ALIGN_SECTOR;
	uint32_t completed = 0 ;
	int work = 0 ;
	int percent, last_percent = 0;
	unsigned long start_jif = jiffies;
	pr_info("start delta sync hadm%d bwr from sector %lu to %lu, %d blocks should be synced\n",
			bwr->hadmdev->minor, 
			start, end, npack);

	while (npack || un_acked) {
		if (hadm_thread_get_state(node->delta_sync) != HADM_THREAD_RUN) {
			ret = -EKMOD_DELTA_SYNC_EXIT;
			goto done;
		}

		cstate = hadm_node_get(node, SECONDARY_STATE, S_CSTATE);
		if (cstate != C_DELTA_SYNC_BWR) {
			pr_info ("%s: hadm%d cstate is not C_DELTA_SYNC_BWR, its real cstate=%d\n",
					__FUNCTION__, bwr->hadmdev->minor, cstate);
			ret = -EKMOD_BAD_CSTATE;
			break;
		}
		work = 0 ;
		if(un_acked < hadm_queue_free_space(delta_packet_queue) && npack) {

			bwr_data = get_send_head_data(bwr, node->id, last_seq);
			if (bwr_data == NULL) {
				pr_err("%s: get hadm%d BWR data failed\n", __FUNCTION__, bwr->hadmdev->minor);
				ret = -EKMOD_UNKNOWN_STATE;
				goto done;
			}
			last_seq = bwr_data->meta.bwr_seq;
			if(start_seq == 0){
				start_seq = last_seq;
			}
			ret = sync_node_bwrdata(node, bwr_data, P_RS_DATA);
			//pr_info("%s: send bwr data  bwr_seq = %llu\n", __FUNCTION__, bwr_data->meta.bwr_seq);
			bwr_data_put(bwr_data);
			if (ret < 0) {
				pr_err("%s sync hadm%d bwrdata faild.\n", __FUNCTION__, bwr->hadmdev->minor);
				goto done;
			}
			un_acked ++;
			npack -- ;
			work ++;

			snd_head_condition_update(node, S_CSTATE, C_DELTA_SYNC_BWR);
			start = bwr_next_sector(bwr, start);
		}
		for(; un_acked ;){
			struct hadm_pack_node *pnode = NULL;
			struct list_head *q_node = hadm_queue_pop_in_seq_timeout(delta_packet_queue, pack_node_seq, start_seq, 1000);
			if(q_node == NULL)
				break;
			pnode = list_entry(q_node, struct hadm_pack_node, q_node);
			hadm_pack_node_free(pnode);
			bwr_node_head_inc(bwr, node->id);
			start_seq ++;
			un_acked --;
			completed ++;
			work ++;
		}
		if(!work){
			schedule();
		}
		percent = 100 * completed / (npack + un_acked + completed);
		if( percent - last_percent >= 10){
			pr_info("%s: hadm%d pack remained = %d, unacked = %d, completed = %d%%, sync rate = %u KBytes/Sec\n",
					__FUNCTION__, bwr->hadmdev->minor, npack, un_acked, percent,
					completed *4 *1000/jiffies_to_msecs(jiffies - start_jif));
			last_percent = percent;
		}

	}

done:
	return ret;
}



int sync_disk_meta(struct bwr *bwr)
{
	struct bwr_disk_info *disk_info;
	int ret = 0;
	unsigned long flags;
	int updated = 0;

	disk_info = kzalloc(sizeof(struct bwr_disk_info), GFP_KERNEL);
	if (disk_info == NULL) {
		pr_err("%s: no memory\n", __FUNCTION__);
		ret = -ENOMEM;
		goto done;
	}
	wait_for_completion(&bwr->wait);	/* 不是等待，而是获取资源 */
	read_lock_irqsave(&bwr->lock, flags);
	if(bwr->mem_meta.local_primary.id != INVALID_ID ||
			bwr->mem_meta.last_primary.id != INVALID_ID) {
		/**
		 *在把meta写入磁盘时，检测meta是否合法，包括bwr_seq 和tail是否对应
		 */
		if(unlikely(valid_bwr_meta(bwr))) {
			pr_info("%d bwr meta invalid.\n", bwr->hadmdev->minor);
			bwr_dump(bwr);
			read_unlock_irqrestore(&bwr->lock, flags);
			hadmdev_set_error(bwr->hadmdev, __BWR_ERR);
			return -EINVAL;
		}

	}

	if(memcmp(&bwr->mem_meta, &bwr->disk_meta, sizeof(struct bwr_meta)) != 0) {
		updated = 1;
		memcpy(&disk_info->meta, &bwr->mem_meta, sizeof(struct bwr_meta));
	}
	read_unlock_irqrestore(&bwr->lock, flags);
	if(!updated){
		goto done;
	}
	/* NOTE: 写入磁盘失败了怎么办？ */
	ret = hadm_bio_write_sync(bwr->hadmdev->bwr_bdev,
			bwr->disk_meta.meta_start,
			(char *)disk_info,
			sizeof(struct bwr_disk_info));
	if (ret ) {
		pr_err("%s: hadm%d write disk failed: want=%d, write=%d\n",
				__FUNCTION__, bwr->hadmdev->minor, (int)sizeof(struct bwr_disk_info), ret);
		ret = -EIO;
		goto done;
	}
	/**TODO: 锁的实现需要调整**/
	write_lock_irqsave(&bwr->lock, flags);
	memcpy(&bwr->disk_meta, &disk_info->meta, sizeof(struct bwr_meta));
	write_unlock_irqrestore(&bwr->lock, flags);
	//bwr_dump(bwr);
	bwr_update_inuse_size(bwr);
done:
	kfree(disk_info);
	complete(&bwr->wait);	/* 释放资源 */
	return ret;
}

int update_bwr_meta(struct bwr *bwr, int which,
		int dstate, uint64_t tail,
		uint32_t node_id, uint64_t uuid, uint64_t seq,
		uint64_t dev_sector, uint8_t md5[])
{
	int i;
	unsigned long flags;
	uint64_t bwr_seq = 0;
	/**
	 *当节点从secondary变成primary，或者从primary端从delta_sync
	 *到bwr_sync之间切换的话，需要将bwr里的head、dbm 信息reset
	 *对于前者，当local_primary.id从INVALID_ID到node_id时，reset_bwr =1
	 *对于后者，当d_state发生变化时，reset_bwr=1
	 *?是不是只有这两种情况需要reset_bwr?
	 */
	int reset_bwr = 0 ;
	write_lock_irqsave(&bwr->lock, flags);
	if (which == UPDATE_BWR_META) {
		/* nothing, just write mem_meta to disk */ ;
	} else if (which == UPDATE_TAIL) {
		bwr->mem_meta.tail = tail;
		bwr->mem_meta.local_primary.bwr_seq += 1;
	} else if (which == LOCAL_PRIMARY) {
		if(bwr->mem_meta.local_primary.id == INVALID_ID){
			reset_bwr = 1;
		}


		bwr->mem_meta.local_primary.id = node_id;
		if (bwr->mem_meta.local_primary.uuid == 0)
			bwr->mem_meta.local_primary.uuid = uuid;
		if (bwr->mem_meta.local_primary.bwr_seq == 0)
			bwr->mem_meta.local_primary.bwr_seq = 1;
		bwr_seq = bwr->mem_meta.local_primary.bwr_seq;
	} else if (which == LAST_PRIMARY) {
		if(bwr->mem_meta.disk_state != dstate ||
				(bwr->mem_meta.last_primary.bwr_seq && !seq) ||
				(!bwr->mem_meta.last_primary.bwr_seq && seq)) {
			reset_bwr = 1;
		}
		bwr->mem_meta.disk_state = dstate;
		hadm_node_set(bwr->hadmdev->local, SECONDARY_STATE, S_DSTATE, dstate);
		bwr->mem_meta.last_primary.id = node_id;
		bwr->mem_meta.last_primary.uuid = uuid;
		bwr->mem_meta.local_primary.id = INVALID_ID;
		bwr->mem_meta.local_primary.uuid = 0;
		bwr->mem_meta.local_primary.bwr_seq = 0;
		bwr->mem_meta.last_primary.last_page_damaged = 0;
		if (bwr->mem_meta.disk_state == D_CONSISTENT) {
			bwr->mem_meta.last_primary.bwr_seq = seq;
			bwr->mem_meta.last_primary.last_page = dev_sector;
			for (i = 0; i < 16; i++)
				bwr->mem_meta.last_primary.last_page_md5[i] = md5[i];
		}else {
			bwr->mem_meta.last_primary.bwr_seq = 0;

		}
		bwr_seq = bwr->mem_meta.last_primary.bwr_seq;
	}
	/**
	 *在reset bwr的时候，将修改内存状态和同步到磁盘相分离。
	 */
	write_unlock_irqrestore(&bwr->lock, flags);
	if(reset_bwr) {
		struct hadm_node *hadm_node;
		unsigned long flags;
		pr_info("%s: reset hadm%d bwr, bwr_seq = %llu\n", __FUNCTION__, bwr->hadmdev->minor, bwr_seq);
		write_lock_irqsave(&bwr->lock, flags);
		bwr->last_seq = 0;
		bwr->mem_meta.tail = seq_to_bwr(bwr_seq + 1, bwr);
        	bwr->min_disk_head = INVALID_SECTOR;
		list_for_each_entry(hadm_node, &bwr->hadmdev->hadm_node_list, node) {
			if(which == LOCAL_PRIMARY || hadm_node->id == get_node_id() ) {
				bwr->mem_meta.head[hadm_node->id] = bwr->mem_meta.tail;
			}else {
				bwr->mem_meta.head[hadm_node->id] = bwr->mem_meta.tail;
			}
		}
		write_unlock_irqrestore(&bwr->lock, flags);

		list_for_each_entry(hadm_node, &bwr->hadmdev->hadm_node_list, node)
			hadm_node_reset_send_head(hadm_node);

		//bwr->min_disk_head = bwr->mem_meta.tail;
		clear_data_buffer(bwr->hadmdev->buffer);
		bwr_meta_dump(&bwr->mem_meta);
	}

	/**
	if (which == LAST_PRIMARY) {
		if (bwr->disk_meta.local_primary.id != INVALID_ID) {
			bwr_reset(bwr, 0);
			clear_data_buffer(bwr->hadmdev->buffer);
		}
	}**/
	return reset_bwr;
}

void set_last_primary(struct bwr *bwr, uint32_t node_id, uint64_t uuid)
{
	unsigned long flags;
	struct hadm_node *hadm_node;
	int local_node_id = get_node_id();
	write_lock_irqsave(&bwr->lock, flags);
	if(bwr->mem_meta.local_primary.id != INVALID_ID){
		bwr->mem_meta.local_primary.id = INVALID_ID;
		bwr->mem_meta.local_primary.uuid = 0 ;
		bwr->mem_meta.local_primary.bwr_seq = 0 ;

	}
	if(bwr->mem_meta.last_primary.id != node_id ||
			bwr->mem_meta.last_primary.uuid != uuid) {
		bwr->mem_meta.last_primary.id = node_id;
		bwr->mem_meta.last_primary.uuid = uuid;
		if(bwr->mem_meta.disk_state == D_CONSISTENT) {
			bwr->mem_meta.last_primary.bwr_seq = 1;
		}else {
			bwr->mem_meta.last_primary.bwr_seq = 0 ;
		}
		/**
		 *当节点从primary变成secondary或者更改primary，需要重新设置
		 *head
		 */
	}
	/**
	 *当secondary曾经变成primary，这时候head信息会被修改，但是再次握手时，
	 *bwr_seq=1会被认为是没有数据，所以依然握手成功，但是此时last_primary的
	 *bwr_seq > 1 ，从而会在保存数据时认为bwr非法
	 */
	list_for_each_entry(hadm_node, &bwr->hadmdev->hadm_node_list, node) {
		bwr->mem_meta.head[hadm_node->id] = -1;
	}
	bwr->min_disk_head =
		bwr->mem_meta.head[local_node_id] =
		bwr->mem_meta.tail = seq_to_bwr(bwr->mem_meta.last_primary.bwr_seq + 1, bwr);
	/**
	 *当和primary重新连接时，需要清除掉buffer里的内容，
	 *比如在多个节点primary变化时，seq也会跟着变化，这时候如果不清除buffer，
	 *会导致io sequence 校验出错
	 */
	clear_data_buffer(bwr->hadmdev->buffer);

	pr_info("%s: set hadm%d node %d as my last primary, uuid = %llu, bwr_seq = %llu\n",
			__FUNCTION__, bwr->hadmdev->minor, 
			bwr->mem_meta.last_primary.id,
			bwr->mem_meta.last_primary.uuid,
			bwr->mem_meta.last_primary.bwr_seq);
	write_unlock_irqrestore(&bwr->lock, flags);

}
int write_bwr_meta(struct bwr *bwr, int which,
		int dstate, uint64_t tail,
		uint32_t node_id, uint64_t uuid, uint64_t seq,
		uint64_t dev_sector, uint8_t md5[])
{
	int reset_bwr = 0;
	reset_bwr = update_bwr_meta(bwr, which, dstate, tail, node_id,
			uuid, seq, dev_sector, md5);
	if(reset_bwr) {
		reset_dbm(bwr->hadmdev);
	}
	return sync_disk_meta(bwr);
}

static int bwr_init_data_list(struct bwr *bwr)
{
	struct bwr_data_block *block;
	struct bwr_data *bwr_data;
	uint64_t offset;
	struct page *page;
	int ret = 0, local_node_id;
	struct data_buffer *buffer = bwr->hadmdev->buffer;

	if (bwr->disk_meta.local_primary.id == INVALID_ID)
		return 0;
	pr_info("try load hadm%d unfinished local data.\n", bwr->hadmdev->minor);
	local_node_id = get_node_id();
	block = kzalloc(sizeof(struct bwr_data_block), GFP_KERNEL);
	for (offset = bwr->disk_meta.head[local_node_id];
			offset != bwr->disk_meta.tail;
			offset = bwr_next_sector(bwr, offset)) {
		hadm_read_bwr_block(bwr->hadmdev->bwr_bdev,offset,(char *)block,sizeof(struct bwr_data_block));
		if (offset != block->meta.bwr_sector) {
			pr_err("%s: offset(%lu) not equal to hadm%d block bwr sector (%lu)\n",
					__FUNCTION__, (unsigned long)offset, bwr->hadmdev->minor, 
					(unsigned long)block->meta.bwr_sector);
			ret = -1;
			goto done;
		}

		page = alloc_page(GFP_KERNEL);
		if (!page) {
			ret = -1;
			goto done;
		}
		bwr_data = init_bwr_data(offset, block->meta.dev_sector,
				block->meta.bwr_seq, block->meta.checksum, block->meta.uuid, page);
		if (!bwr_data) {
			pr_err("%s hadm%d alloc_bwr_data faild.\n", 
					__FUNCTION__, bwr->hadmdev->minor);
			__free_page(page);
			ret = -1;
			goto done;
		}

		memcpy(page_address(bwr_data->data_page), block->data_block, PAGE_SIZE);
		ret = buffer_data_add(buffer, bwr_data);
		if (ret < 0) {
			pr_err("%s hadm%d bwr_data add faild.\n", __FUNCTION__, bwr->hadmdev->minor);
			__free_page(page);
			kfree(bwr_data);
			goto done;
		}
	}
done:
	if (ret < 0)
		free_data_buffer(buffer);
	kfree(block);
	return ret;
}
static int __meta_last_page_valid(struct bwr_meta *meta)
{
	int i;

	for (i = 0; i < 16; i++)
		if (meta->last_primary.last_page_md5[i])
			return 1;
	return 0;
}

static void __bwr_check_last(struct bwr_meta *meta, struct hadmdev *hadmdev)
{
	int i;
	uint8_t md5[16];
	int error;
	struct page *data;
	data=alloc_page(GFP_KERNEL);
	if(IS_ERR_OR_NULL(data)) {
		return ;
	}
	error=hadm_read_page_sync(hadmdev->bdev,meta->last_primary.last_page,data,PAGE_SIZE);
	if(error) {
		__free_page(data);
		return ;
	}
	fullsync_md5_hash(page_address(data), PAGE_SIZE, md5);
	for (i = 0; i < 16; i++) {
		if (md5[i] != meta->last_primary.last_page_md5[i]) {
			pr_info("warning: hadm%d bwr last page damaged!", hadmdev->minor);
			meta->last_primary.last_page_damaged = 1;
			break;
		}
	}
	__free_page(data);
}

static int __bwr_check_data(struct bwr_meta *meta, struct hadmdev *hadmdev)
{
	int ret;
	u32 crc;
	char *buf;
	uint64_t *tail, *bwr_seq, *head, seq;
	struct bwr_data_meta *data_meta;
	struct primary_info *pi = NULL;

	buf = kzalloc(PAGE_SIZE + HADM_SECTOR_SIZE, GFP_KERNEL);
	if (!buf || IS_ERR(buf)) {
		pr_err("%s: alloc mem faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	if(meta->local_primary.id != INVALID_ID) {
		pi = &meta->local_primary;
		pr_info("%s: init hadm%d bwr data as a primary node\n", __FUNCTION__, hadmdev->minor);
	}else if(meta->last_primary.id != INVALID_ID){
		pi = &meta->last_primary;
		pr_info("%s: init hadm%d bwr data as a secondary node\n", __FUNCTION__, hadmdev->minor);
	}else
	{
		return -EINVAL;
	}


	pr_info("check hadm%d bwr data.\n", hadmdev->minor);
	head = &meta->head[get_node_id()];
	tail = &meta->tail;
	bwr_seq = &pi->bwr_seq;
	pr_info("%s:init hadm%d bwr data: head = %llu,  tail = %llu, seq = %llu.keep searching unsaved bwr data.\n",
			__FUNCTION__, hadmdev->minor,
			(unsigned long long)meta->head[get_node_id()],
			(unsigned long long)meta->tail,
			(unsigned long long)pi->bwr_seq);
	if(*bwr_seq > 1) {
		seq = *bwr_seq - bwr_distance(hadmdev->bwr, *head, *tail) / BWR_ALIGN_SECTOR ;
	}else{
		seq = 1;
	}

	/**
	 *从bwr head位置一直检索数据，直到bwr块invalid
	 *这里存在一个问题，如果head = tail的话，需要block的bwr_seq是否<local_primary.bwr_seq，
	 *如果小于，则表明tail的数据是非法的
	 *
	 */
	for (;;) {
		ret = hadm_read_bwr_block(hadmdev->bwr_bdev, *head,
				buf, PAGE_SIZE + HADM_SECTOR_SIZE);
		if (ret != PAGE_SIZE + HADM_SECTOR_SIZE) {
			pr_err("%s: read hadm%d bwr_data faild.\n", __FUNCTION__, hadmdev->minor);
			goto out;
		}
		data_meta = (struct bwr_data_meta *)buf;
		/**
		 *检索head开始的所有bwr block，要求
		 *1、uuid相等
		 *2、seq相差1
		 *3、bwr_sector = *head
		 *4、seq_to_bwr(seq, bwr) = bwr_sector
		 */
		/**
		if(*head == *tail && data_meta->bwr_seq < *bwr_seq){
			break;
		}**/
		if (data_meta->uuid != pi->uuid ||
				(seq && data_meta->bwr_seq != seq+1) ||
				data_meta->bwr_sector != *head ||
				seq_to_bwr(data_meta->bwr_seq , hadmdev->bwr) != data_meta->bwr_sector){
			pr_info("%s:invalid bwr block,  hadm%d block sector:%llu(expect:%llu), seq:%llu(expect:%llu), uuid:%llu(expect:%llu), bwr data search terminated\n",
					__FUNCTION__, hadmdev->minor,
					(unsigned long long)data_meta->bwr_sector, (unsigned long long)*head,
					(unsigned long long)data_meta->bwr_seq,  (unsigned long long)seq+1,
					(unsigned long long)data_meta->uuid,  (unsigned long long)pi->uuid);
			break;
		}
		crc = crc32(0, buf + HADM_SECTOR_SIZE, PAGE_SIZE);
		if (crc != data_meta->checksum) {
			pr_info("crc32 not equal.(data:meta)(%u:%u). check hadm%d bwr data exit.\n",
					crc, data_meta->checksum, hadmdev->minor);
			break;
		}
#if 0
		pr_info("%s:init data, load unsaved data(sector %llu) from bwr sector %llu, seq %llu, uuid %llu\n",
				__FUNCTION__,
				(unsigned long long)data_meta->dev_sector,
				(unsigned long long)data_meta->bwr_sector,
				(unsigned long long)data_meta->bwr_seq,
				(unsigned long long)data_meta->uuid);
#endif
		ret = hadm_bio_write_sync(hadmdev->bdev, data_meta->dev_sector, buf+HADM_SECTOR_SIZE, PAGE_SIZE);
		if(ret) {
			break;
		}
		*head= bwr_next_sector(hadmdev->bwr, *head);
		seq = data_meta->bwr_seq;
	}
	*bwr_seq = seq ;
	*tail = *head;
	if(seq_to_bwr(*bwr_seq +1 , hadmdev->bwr) != *tail) {
		pr_warn("%s:init hadm%d bwr data seq %llu is not matched with tail %llu, expect tail = %llu\n",
				__FUNCTION__, hadmdev->minor, (unsigned long long)*bwr_seq, (unsigned long long)*tail,
				(unsigned long long)seq_to_bwr(*bwr_seq + 1 , hadmdev->bwr));
		ret = -1;
	}else {
		pr_info("%s:init hadm%d bwr data , load all unsaved data from bwr,  now tail = %llu, seq = %llu\n",
				__FUNCTION__, hadmdev->minor, (unsigned long long)*tail, (unsigned long long)*bwr_seq);
		ret = 0;
	}
out:
	kfree(buf);
	return ret;
}

static int bwr_init_meta(struct bwr *bwr, uint64_t meta_offset)
{
	struct bwr_disk_info *disk_meta;
	int ret = 0;
	struct page *page;
	int error;

	page=alloc_page(GFP_KERNEL);
	if(IS_ERR_OR_NULL(page)){
		pr_err("%s: no memory\n", __FUNCTION__);
		return -ENOMEM;
	}
	error=hadm_read_page_sync(bwr->hadmdev->bwr_bdev,meta_offset,page,sizeof(struct bwr_disk_info));
	if(error) {
		return error;
	}
	disk_meta=(struct bwr_disk_info *)page_address(page);
	if (disk_meta->meta.magic == MAGIC) {
		if (disk_meta->meta.local_primary.id == INVALID_ID &&
				__meta_last_page_valid(&disk_meta->meta)){
			__bwr_check_last(&disk_meta->meta, bwr->hadmdev);
		}
		if ((disk_meta->meta.local_primary.id != INVALID_ID ||
				disk_meta->meta.last_primary.id != INVALID_ID) && disk_meta->meta.disk_state == D_CONSISTENT){
			if(__bwr_check_data(&disk_meta->meta, bwr->hadmdev)){
				ret = -EINVAL;
				goto done;
			}
		}else if(disk_meta->meta.last_primary.id != INVALID_ID && disk_meta->meta.disk_state == D_INCONSISTENT) {
			disk_meta->meta.last_primary.bwr_seq = 0 ;

		}
		memcpy(&bwr->mem_meta, &disk_meta->meta, sizeof(struct bwr_meta));
		sync_disk_meta(bwr);
#if 0
		/**
		 *当手动删除一个节点时，必须重新init meta，否则该节点的head仍然保存在bwr
		 *中，会造成bug，因为__bwr_get_min_head不校验节点是否存在，而sync_dbm_thread
		 *会，这就导致sync_dbm_thread无法将不存在的节点的head进行更改，导致bwr一直处于
		 *满的状态
		 */
		for(i = 0 ; i < MAX_NODES; i++) {
			if(find_hadm_node_by_id(bwr->hadmdev, i) == NULL) {
				disk_meta->meta.head[i] = INVALID_SECTOR;
			}
		}
		sync_disk_meta(bwr);
		local_node_id = get_node_id();

		distance = bwr_distance(bwr,
				bwr->disk_meta.head[local_node_id],
				bwr->disk_meta.tail);
		if (distance > get_max_bwr_cache_size()) {
			pr_err("%s: BWR cache too big, head = %llu,  tail = %llu\n", __FUNCTION__,
					(unsigned long long)bwr->disk_meta.head[local_node_id],
					(unsigned long long)bwr->disk_meta.tail);
			ret = -EINVAL;
			goto done;
		}
		/* init phase: mema_meta equals disk_meta */
		bwr_update_inuse_size(bwr);
		bwr->min_disk_head = __bwr_get_min_head(bwr, &bwr->min_node_mask);
		distance = bwr_distance(bwr, bwr->min_disk_head, bwr->mem_meta.tail);
		__bwr_set_inuse_size(bwr, distance);
		pr_info("%s: set bwr inuse size to %lu, min_disk_head = %lu\n", __FUNCTION__,
				bwr->inuse_size, bwr->min_disk_head);
#endif
	} else if (disk_meta->meta.magic == BWR_UNINIT_MAGIC) {
		/* using default meta which already inited */
	} else {
		pr_err("%s: hadm%d BWR magic is NOT right\n", __FUNCTION__, bwr->hadmdev->minor);
		ret = -EINVAL;
		goto done;
	}

done:
	__free_page(page);
	return ret;
}

void bwr_meta_init_default(struct bwr_meta *meta, uint8_t dev_id, uint64_t bwr_disk_size,
		sector_t meta_start, sector_t dbm_start, sector_t bwr_start)
{
	int i;

	meta->magic = MAGIC;
	meta->dev_id = dev_id;
	meta->bwr_disk_size = bwr_disk_size;
	meta->meta_start = meta_start;
	meta->dbm_start = dbm_start;
	meta->bwr_start = bwr_start;

	for (i = 0; i < MAX_NODES; i++)
		meta->head[i] = INVALID_SECTOR;
	meta->head[get_node_id()] = meta->bwr_start;
	meta->tail = meta->bwr_start;
	meta->disk_state = D_CONSISTENT;
	primary_info_init(&meta->last_primary);
	primary_info_init(&meta->local_primary);
}

void __bwr_init(struct bwr *bwr, sector_t max_sector, uint64_t bwr_disk_size,
		uint64_t meta_offset, uint64_t dbm_offset, uint64_t bwr_offset)
{
	bwr->start_sector = bwr_offset;
	bwr->max_sector = max_sector;
	bwr->max_size = max_sector - bwr_offset;
	bwr->inuse_size = 0;
	bwr->last_seq = 0;
	bwr->min_disk_head = INVALID_SECTOR;
	bwr->min_node_mask = 0 ;
	atomic64_set(&bwr->cache, 0);
	atomic64_set(&bwr->nleft, max_sector - bwr_offset);
	init_completion(&bwr->have_snd_data);
	init_completion(&bwr->not_full);

	rwlock_init(&bwr->lock);
	bwr_meta_init_default(&bwr->disk_meta, bwr->hadmdev->minor,
			bwr_disk_size,
			meta_offset, dbm_offset, bwr_offset);
	memcpy(&bwr->mem_meta, &bwr->disk_meta, sizeof(struct bwr_meta));
	init_completion(&bwr->wait);
	complete(&bwr->wait);	/* 在同一个时刻只有一个线程可以写 meta */

	init_completion(&bwr->sync_node_finish);
	spin_lock_init(&bwr->sync_node_mask_lock);

	rwlock_init(&bwr->bwr_data_list_rwlock);
	INIT_LIST_HEAD(&bwr->bwr_data_list);
	bwr->bwr_data_list_max_size = DEFAULT_BWR_DATA_LIST_SIZE;
	bwr->waiters = 0;
	init_completion(&bwr->ev_wait);
	sema_init(&bwr->sema, 0);
}

int valid_bwr_meta(struct bwr *bwr)
{
	struct bwr_meta *meta = &bwr->mem_meta;
	struct primary_info *pi = NULL;
	int secondary = 0 ;
	if(meta->local_primary.id != INVALID_ID) {
		pi = &meta->local_primary;
	}else if (meta->last_primary.id != INVALID_ID){
		pi = &meta->last_primary;
		secondary = 1;
	}else {
		return 0;
	}
	if(secondary && meta->disk_state == D_INCONSISTENT && pi->bwr_seq > 0 ){
		return -1;
	}
	if(seq_to_bwr(pi->bwr_seq + 1, bwr) != meta->tail) {
		return -1;
	}
	return 0;
}

int bwr_init(struct hadmdev *dev, char *bwr_disk, uint64_t bwr_max, uint64_t bwr_disk_size,
		uint64_t meta_offset, uint64_t dbm_offset, uint64_t bwr_offset)
{
	static char *bwr_identity = "bwr_init";
	struct bwr *bwr = dev->bwr;
	struct request_queue *q;
	int ret = 0;

	dev->bwr_bdev = blkdev_get_by_path(bwr_disk, BWRDEV_MODE, (void *)bwr_identity);
	if (IS_ERR(dev->bwr_bdev)) {
		pr_err("%s: hadm%d get %s failed\n",
				__FUNCTION__, bwr->hadmdev->minor, dev->local->conf.bwr_disk);
		return PTR_ERR(dev->bwr_bdev);
	}
	q = bdev_get_queue(dev->bwr_bdev);
	blk_queue_merge_bvec(q, NULL);

	__bwr_init(bwr, bwr_max, bwr_disk_size, meta_offset, dbm_offset, bwr_offset);

	ret = bwr_init_meta(bwr, meta_offset);
	if (ret < 0) {
		pr_err("%s: init hadm%d bwr meta failed\n", __FUNCTION__, bwr->hadmdev->minor);
		goto done;
	}
	ret = bwr_init_data_list(bwr);
	if (ret < 0) {
		pr_err("%s: init hadm%d data list failed\n", __FUNCTION__, bwr->hadmdev->minor);
		goto done;
	}
	ret = valid_bwr_meta(bwr);
	if (ret < 0) {
		pr_err("%s: hadm%d BWR meta is invalid\n", __FUNCTION__, bwr->hadmdev->minor);
		bwr_dump(bwr);
		goto done;
	}

done:
	return ret;
}

void bwr_data_list_clean(struct bwr *bwr)
{
	struct bwr_data *bwr_data, *tmp;

	write_lock(&bwr->bwr_data_list_rwlock);
	list_for_each_entry_safe(bwr_data, tmp, &bwr->bwr_data_list, list) {
		list_del_init(&bwr_data->list);
		kfree(bwr_data);
	}
	write_unlock(&bwr->bwr_data_list_rwlock);
}


void bwr_meta_dump(struct bwr_meta *meta)
{
	int i;
	printk(KERN_INFO "%s:\n", __FUNCTION__);
	printk(KERN_INFO "\tmagic: %llu, dev_id: %d\n"
			"disk_size: %llu, bwr_disk_size: %llu\n"
			"meta_start: %llu, dbm_start: %llu, bwr_start: %llu\n\n",
			(unsigned long long)meta->magic, meta->dev_id,
			(unsigned long long)meta->disk_size, (unsigned long long)meta->bwr_disk_size,
			(unsigned long long)meta->meta_start, (unsigned long long)meta->dbm_start, (unsigned long long)meta->bwr_start);

	printk(KERN_INFO "head:\n");
	for (i = 0; i < MAX_NODES; i++){
		if(meta->head[i] != INVALID_SECTOR) {
			printk(KERN_INFO "%d:%llu", i, (unsigned long long)meta->head[i]);
		}
	}
	printk(KERN_INFO "\ntail: %llu, disk_state: %d\n\n", (unsigned long long)meta->tail, meta->disk_state);

	printk(KERN_INFO "last_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
			meta->last_primary.id, (unsigned long long)meta->last_primary.uuid,
			(unsigned long long)meta->last_primary.bwr_seq);
	printk(KERN_INFO "local_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
			meta->local_primary.id, (unsigned long long)meta->local_primary.uuid,
			(unsigned long long)meta->local_primary.bwr_seq);
}

void bwr_dump(struct bwr *bwr)
{
	unsigned long flags;
	//dump_stack();
	read_lock_irqsave(&bwr->lock, flags);
	__bwr_dump(bwr);
	read_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_reset(struct bwr *bwr,  uint64_t bwr_seq)
{

}

/* -------------------------------- obsolete functions ------------------------*/
