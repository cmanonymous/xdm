#define pr_fmt(fmt) "bwr: " fmt

#include <linux/delay.h>
#include <linux/crc32.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_device.h"
#include "hadm_site.h"
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

struct bwr *bwr_alloc(int gfp_mask)
{
	struct bwr *bwr;

	bwr = kzalloc(sizeof(struct bwr), gfp_mask);
	if (!bwr) {
		pr_err("%s: alloc failed.\n", __func__);
		return NULL;
	}

	return bwr;
}

void free_bwr(struct bwr *bwr)
{
	if (bwr == NULL || IS_ERR(bwr))
		return;
	if (bwr->hadmdev->bwr_bdev)
		set_device_ro(bwr->hadmdev->bwr_bdev, 0);
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
	pr_info("try set inuse size from %lu to %lu.\n",
			bwr->inuse_size, size);
	if (bwr->inuse_size != size) {
		if (unlikely(size > bwr->max_size)) {
			pr_err("try set bwr inuse size larger than maxsize.\n");
			dump_stack();
			return;
		}

		if (size > bwr->inuse_size)
			pr_info("warning set bwr size increase, head:%llu(0)%llu(1), tail:%llu.\n",
					bwr->disk_meta.head[0],
					bwr->disk_meta.head[1],
					bwr->mem_meta.tail);
		if (__bwr_full(bwr) && !completion_done(&bwr->not_full)) {
			pr_info("notify bwr not full.\n");
			complete(&bwr->not_full);
		}
		bwr->inuse_size = size;
	}
}

int __bwr_inuse_size_dec(struct bwr *bwr)
{
	if (unlikely(__bwr_empty(bwr))) {
		pr_err("BUG!! try decrease bwr inuse size, which equals 0.\n");
		dump_stack();
		return -1;
	}
	if (__bwr_full(bwr) && !completion_done(&bwr->not_full)) {
		pr_info("notify bwr not full.\n");
		complete(&bwr->not_full);
	}
	bwr->inuse_size -= BWR_ALIGN_SECTOR;
	return 0;
}

void __bwr_inuse_size_sub(struct bwr *bwr, int nr)
{
	if (nr <= 0) {
		pr_info("%s: warning sub bwr inuse size where nr <= 0 (%d).\n", __func__, nr);
		return;
	}
	if (nr) {
		if (__bwr_full(bwr) && !completion_done(&bwr->not_full)) {
			pr_info("notify bwr not full.\n");
			complete(&bwr->not_full);
		}
		bwr->inuse_size -= nr * BWR_ALIGN_SECTOR;
	}
}

void __bwr_inuse_size_inc(struct bwr *bwr)
{
	if (unlikely(__bwr_full(bwr))) {
		pr_err("BUG!! try increase bwr inuse size, which equals max_size.\n");
		dump_stack();
		return;
	}
	bwr->inuse_size += BWR_ALIGN_SECTOR;
	/* level trigger, or edge trigger? */
	if (bwr->inuse_size / 10 * 10 == bwr->high_water) {
		pr_info("%s: wake up flush.\n", __func__);
		hadm_thread_wake_up(bwr->hadmdev->threads[DBM_FLUSH_HANDLER]);
	}
}

void __bwr_inuse_size_add(struct bwr *bwr, int nr)
{
	bwr->inuse_size += nr * BWR_ALIGN_SECTOR;
	if (unlikely(bwr->inuse_size >= bwr->max_size)) {
		pr_err("BUG!! try add bwr inuse size, which larger max_size.\n");
		dump_stack();
		return;
	}
}

int bwr_inuse_size_pre_occu(struct bwr *bwr)
{
        unsigned long flags;
	struct hadm_site *runsite;
	uint32_t min_site_mask;

try_occupy:
	write_lock_irqsave(&bwr->lock, flags);
	if (__bwr_full(bwr)) {
		min_site_mask = bwr->min_site_mask;
                write_unlock_irqrestore(&bwr->lock, flags);
		list_for_each_entry(runsite, &bwr->hadmdev->hadm_site_list, site) {
			if (runsite == bwr->hadmdev->local_site)
				continue;
			if (min_site_mask & (1 << runsite->id)) {
				pr_info("bwr is full, try set site:%d state.\n", runsite->id);
				/* BWR 满了，就应该使 delta_sync 线程退出 */
				/* hadm_thread_stop(runsite->delta_sync); */
				hadm_site_become_inconsitent(runsite);
			}
		}
		hadm_thread_wake_up(bwr->hadmdev->threads[DBM_FLUSH_HANDLER]);
		(void)hadmdev_send_site_state(bwr->hadmdev);
		pr_info("bwr occupy try wait.\n");
		if (wait_for_completion_timeout(&bwr->not_full, msecs_to_jiffies(10000)) == 0) {
			pr_err("%s timeout, head:%llu(0)%llu(1), tail:%llu, inuse_size:%lu.\n",
					__func__, bwr->mem_meta.head[0], bwr->mem_meta.head[1],
					bwr->mem_meta.tail, bwr->inuse_size);
			hadmdev_set_error(bwr->hadmdev);
			return -1;
//			if ((hadm_thread_get_state(bio_handler)) != HADM_THREAD_RUN) {
//				return -1;
//			}
		}
		goto try_occupy;
	}

	/* FIXME need guarantee bwr->disk_meta->min_head after this area. */
	__bwr_inuse_size_inc(bwr);
//	pr_info("pre occu:inuse_size:%lu|max_size:%lu.\n",
//			bwr->inuse_size,
//			bwr->max_size);
	write_unlock_irqrestore(&bwr->lock, flags);
	return 0;
}

int bwr_low_water(struct bwr *bwr)
{
	return bwr->inuse_size < bwr->low_water;
}

int bwr_high_water(struct bwr *bwr)
{
	return bwr->inuse_size > bwr->high_water;
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

/* FIXME: update? */
void bwr_update_inuse_size(struct bwr *bwr)
{
	unsigned long flags;
	uint32_t site_mask;
	sector_t min_head, delta;

	/* Note: 未加锁，目前该函数在仅sync_bwr_meta()中调用，disk_head的修改非并发*/
	min_head = __bwr_get_min_head(bwr, &site_mask);
	write_lock_irqsave(&bwr->lock, flags);
	if (min_head != bwr->min_disk_head) {
		bwr->min_site_mask = site_mask;
		delta = bwr_distance(bwr, bwr->min_disk_head, min_head);
		__bwr_inuse_size_sub(bwr, delta / BWR_ALIGN_SECTOR);
		//__bwr_set_inuse_size(bwr, inuse_size);
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

sector_t bwr_seq(struct bwr *bwr)
{
	unsigned long flags;
	sector_t seq;

	read_lock_irqsave(&bwr->lock, flags);
	seq = bwr->mem_meta.local_primary.bwr_seq;
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


int bwr_site_head_cmp(struct bwr *bwr, uint8_t site1,uint8_t site2)
{
	int ret=0;
	unsigned long flags;

	BUG_ON(!VALID_SITE(site1) || !VALID_SITE(site2));

	read_lock_irqsave(&bwr->lock, flags);
	ret = bwr_sector_cmp(bwr,
			     bwr->mem_meta.head[site1],
			     bwr->mem_meta.head[site2],
			     bwr->mem_meta.tail);
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

int bwr_sector_less(struct bwr *bwr, sector_t s1, sector_t s2, sector_t tail)
{
	return bwr_sector_cmp(bwr, s1, s2, tail) < 0;
}

sector_t __bwr_get_min_head(struct bwr *bwr, uint32_t *site_map)
{
	sector_t min_head = INVALID_SECTOR;
	int i = 0, result;
	uint32_t map = 0;

	for (i = 0; i < MAX_NODES; i++) {
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

	if (site_map != NULL)
		*site_map = map;
	return min_head;
}

uint64_t bwr_uuid(struct bwr *bwr)
{
	uint64_t uuid = 0;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	uuid = bwr->mem_meta.local_primary.uuid;
	read_unlock_irqrestore(&bwr->lock, flags);
	return uuid;
}

void __bwr_site_head_inc(struct bwr *bwr, int site_id)
{
	bwr->mem_meta.head[site_id] = bwr_next_sector(bwr, bwr->mem_meta.head[site_id]);
	//if (bwr->min_site_mask & (1 << site_id))
		//__bwr_clear_min_site(bwr, site_id);
}

void __bwr_site_head_add(struct bwr *bwr, int site_id, int nr)
{
	bwr->mem_meta.head[site_id] = bwr_next_nr_sector(bwr, bwr->mem_meta.head[site_id], nr);
	//if (bwr->min_site_mask & (1 << site_id))
		//__bwr_clear_min_site(bwr, site_id);
}

void bwr_site_head_inc(struct bwr *bwr, int site_id)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_site_head_inc(bwr, site_id);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void bwr_site_head_add(struct bwr *bwr, int site_id, int nr)
{
	unsigned long flags;

	BUG_ON(nr < 0);
	if (!nr)
		return;
	write_lock_irqsave(&bwr->lock, flags);
	__bwr_site_head_add(bwr, site_id, nr);
	write_unlock_irqrestore(&bwr->lock, flags);
}

void __bwr_set_site_head(struct bwr *bwr, int site_id, sector_t head)
{
	bwr->mem_meta.head[site_id] = head;
#if 0
	sector_t min_head, orig_head, distance;
	//pr_info("%s for site %d from %llu to %lu.\n", __func__,
			//site_id, bwr->mem_meta.head[site_id], head);
	if (bwr->mem_meta.head[site_id] != head){
		orig_head = bwr->mem_meta.head[site_id];
		bwr->mem_meta.head[site_id] = head;
		if (bwr->min_site_mask & (1 << site_id)) {
			pr_info("site %d is in min_site_mask %u, clear it.\n",
					site_id, bwr->min_site_mask);
			bwr->min_site_mask &= ~((uint32_t)1 << site_id);
			if (!bwr->min_site_mask) {
				min_head = __bwr_get_min_head(bwr, &bwr->min_site_mask);
				distance = bwr_distance(bwr, orig_head, min_head);
				__bwr_inuse_size_sub(bwr, distance/BWR_ALIGN_SECTOR);
			}
		}
		bwr->mem_meta.head[site_id] = head;
	}
#endif
}

void bwr_set_site_head(struct bwr *bwr, int site_id, sector_t head)
{
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	__bwr_set_site_head(bwr, site_id, head);
	write_unlock_irqrestore(&bwr->lock, flags);
}

sector_t bwr_site_head(struct bwr *bwr, int site_id)
{
	sector_t site_head;
	unsigned long flags;

	read_lock_irqsave(&bwr->lock, flags);
	site_head = __bwr_site_head(bwr, site_id);
	read_unlock_irqrestore(&bwr->lock, flags);

	return site_head;
}

/* Note: caller gurantee C_STATE == C_SYNC */
int is_uptodate(struct bwr *bwr ,int site_id)
{
	unsigned long flags;
	int ret=0;

	read_lock_irqsave(&bwr->lock, flags);
	ret = bwr->mem_meta.head[site_id] == bwr->mem_meta.tail;
	read_unlock_irqrestore(&bwr->lock, flags);

	return ret;
}

/*
 * 将 BWR 的数据发送到指定的节点，返回 0 表示成功，返回非 0 表示失败
 *
 * 如果是第二次进入这个函数，那么就会发生设置磁盘状态为 D_CONSISTENT 的时机拖后，
 * 现在的处理是接受这种状态。
 */
int delta_sync_bwr(struct hadm_site *site, sector_t start, sector_t end)
{
	struct bwr_data *bwr_data;
	struct bwr *bwr = site->hadmdev->bwr;
	int cstate, ret = 0;

	cstate = hadm_site_get(site, SECONDARY_STATE, S_CSTATE);
	if (cstate != C_DELTA_SYNC_BWR)
		return -EKMOD_BAD_CSTATE;

	while (start != end) {
		if (hadm_thread_get_state(site->delta_sync) == HADM_THREAD_EXIT) {
			ret = -EKMOD_DELTA_SYNC_EXIT;
			goto done;
		}

		cstate = hadm_site_get(site, SECONDARY_STATE, S_CSTATE);
		if (cstate != C_DELTA_SYNC_BWR) {
			pr_info ("%s: cstate is not C_DELTA_SYNC_BWR, its real cstate=%d\n",
				 __func__, cstate);
			ret = -EKMOD_BAD_CSTATE;
			break;
		}

		bwr_data = get_send_head_data(bwr, site->id);
		if (bwr_data == NULL) {
			pr_err("%s: get BWR data failed\n", __func__);
			ret = -EKMOD_UNKNOWN_STATE;
			goto done;
		}
		ret = sync_site_bwrdata(site, bwr_data, P_SD_RSDATA);
		bwr_data_put(bwr_data);
		if (ret < 0) {
			pr_err("%s sync bwrdata faild.\n", __func__);
			goto done;
		}

		snd_head_condition_update(site, S_CSTATE, C_DELTA_SYNC_BWR);
		start += BWR_ALIGN_SECTOR;
	}

	/* 等待 sync 完成 */
	while (!ret) {
		sector_t head = bwr_site_head(bwr, site->id);
		pr_info("delta_sync_bwr: head=%llu, end=%llu\n",
			(unsigned long long)head, (unsigned long long)end);
		if (head == end)
			break;
		if (hadm_thread_get_state(site->delta_sync) == HADM_THREAD_EXIT) {
			ret = -EKMOD_DELTA_SYNC_EXIT;
			goto done;
		}
		cstate = hadm_site_get(site, SECONDARY_STATE, S_CSTATE);
		if (cstate != C_DELTA_SYNC_BWR) {
			ret = 0;
			break;
		}
		msleep(1000);
	}

done:
	return ret;
}

struct async_bwr_meta_data {
	struct page *meta_page;
	struct bwr *bwr;
};

void async_bwr_meta_endio(void *data)
{
	struct async_bwr_meta_data *meta_data = data;
	struct bwr *bwr = meta_data->bwr;
	struct page *meta_page = meta_data->meta_page;
	struct bwr_disk_info *disk_info = page_address(meta_page);

	bwr->disk_meta = disk_info->meta;
	bwr_update_inuse_size(bwr);

	kfree(data);
	__free_page(meta_page);
}

int async_bwr_meta(struct bwr *bwr)
{
	int ret = 0;
	unsigned long flags;
	struct page *meta_page;
	struct bwr_disk_info *disk_info;
	struct async_bwr_meta_data *data;
	struct hadm_io iov;

	data = kmalloc(GFP_KERNEL, sizeof(struct async_bwr_meta_data));
	if (!data) {
		ret = -ENOMEM;
		goto done;
	}
	data->bwr = bwr;

	meta_page = alloc_page(GFP_KERNEL);
	if (!meta_page) {
		ret = -ENOMEM;
		kfree(data);
		goto done;
	}
	disk_info = page_address(meta_page);
	data->meta_page = meta_page;

	read_lock_irqsave(&bwr->lock, flags);
	disk_info->meta = bwr->mem_meta;
	read_unlock_irqrestore(&bwr->lock, flags);

	iov.page = meta_page;
	iov.start = 0;
	iov.len = PAGE_SIZE;

	return abi_add(&bwr->abi, bwr->hadmdev->bwr_bdev,
			bwr->disk_meta.meta_start, &iov, 1,
			async_bwr_meta_endio, data);
done:
	return ret;
}

int sync_bwr_meta(struct bwr *bwr)
{
	int ret = 0;
	unsigned long flags;
	struct page *meta_page;
	struct bwr_disk_info *disk_info;

	meta_page = alloc_page(GFP_KERNEL);
	if (!meta_page) {
		ret = -ENOMEM;
		goto done;
	}
	disk_info = page_address(meta_page);

	wait_for_completion(&bwr->wait);	/* 不是等待，而是获取资源 */
	read_lock_irqsave(&bwr->lock, flags);
	disk_info->meta = bwr->mem_meta;
	read_unlock_irqrestore(&bwr->lock, flags);

	/* NOTE: 写入磁盘失败了怎么办？ */
	ret = hadm_write_page_sync(bwr->hadmdev->bwr_bdev, bwr->disk_meta.meta_start,
			meta_page, PAGE_SIZE);
	if (ret < 0) {
		pr_err("%s: sync meta failed.\n", __func__);
		ret = -EIO;
		goto free_page;
	}

	bwr->disk_meta = disk_info->meta;
	bwr_update_inuse_size(bwr);

free_page:
	__free_page(meta_page);
	complete(&bwr->wait);	/* 释放资源 */
done:
	return ret;
}


int update_bwr_meta(struct bwr *bwr, int which,
		   int dstate, uint64_t tail,
		   uint32_t site_id, uint64_t uuid, uint64_t seq,
		   uint64_t dev_sector, uint8_t md5[])
{
	int i;
	int ret = 0;
	unsigned long flags;

	write_lock_irqsave(&bwr->lock, flags);
	if (which == UPDATE_BWR_META) {
		/* nothing, just write mem_meta to disk */ ;
	} else if (which == UPDATE_TAIL) {
		bwr->mem_meta.tail = tail;
		bwr->mem_meta.local_primary.bwr_seq += 1;
	} else if (which == LOCAL_PRIMARY) {
		bwr->mem_meta.local_primary.id = site_id;
		if (bwr->mem_meta.local_primary.uuid == 0)
			bwr->mem_meta.local_primary.uuid = uuid;
		if (bwr->mem_meta.local_primary.bwr_seq == 0)
			bwr->mem_meta.local_primary.bwr_seq = 1;
	} else if (which == LAST_PRIMARY) {
		bwr->mem_meta.disk_state = dstate;
		bwr->mem_meta.last_primary.id = site_id;
		bwr->mem_meta.last_primary.uuid = uuid;
		bwr->mem_meta.last_primary.bwr_seq = seq;
		bwr->mem_meta.local_primary.id = INVALID_ID;
		bwr->mem_meta.local_primary.uuid = 0;
		bwr->mem_meta.local_primary.bwr_seq = 0;
		bwr->mem_meta.last_primary.last_page_damaged = 0;
		if (bwr->mem_meta.disk_state == D_CONSISTENT) {
			bwr->mem_meta.last_primary.last_page = dev_sector;
			for (i = 0; i < 16; i++)
				bwr->mem_meta.last_primary.last_page_md5[i] = md5[i];
		}
	} else {
		pr_err("%s: invalid write mode\n", __func__);
		ret = -EINVAL;
	}

	write_unlock_irqrestore(&bwr->lock, flags);
	return ret;
}

int write_bwr_meta(struct bwr *bwr, int which,
		   int dstate, uint64_t tail,
		   uint32_t site_id, uint64_t uuid, uint64_t seq,
		   uint64_t dev_sector, uint8_t md5[])
{
	struct bwr_disk_info *disk_info;
	int ret = 0;


	ret = update_bwr_meta(bwr, which, dstate, tail, site_id,
			uuid, seq, dev_sector, md5);
	if (ret < 0) {
		pr_err("%s: update mem_meta failed.\n", __func__);
		return ret;
	}

	wait_for_completion(&bwr->wait);	/* 不是等待，而是获取资源 */
	if (which == LAST_PRIMARY) {
		/* FIXME how about wrapper_list, packet_queue? */
		if (bwr->disk_meta.local_primary.id != INVALID_ID) {
			bwr_reset(bwr);
			clear_data_buffer(bwr->hadmdev->buffer);
		}
	}

	disk_info = kzalloc(sizeof(struct bwr_disk_info), GFP_KERNEL);
	if (disk_info == NULL) {
		pr_err("%s: no memory\n", __func__);
		ret = -ENOMEM;
		goto done;
	}
	memcpy(&disk_info->meta, &bwr->mem_meta, sizeof(struct bwr_meta));
	/* NOTE: 写入磁盘失败了怎么办？ */
	ret = hadm_bio_write_sync(bwr->hadmdev->bwr_bdev,
				  bwr->disk_meta.meta_start,
				  (char *)disk_info,
				  sizeof(struct bwr_disk_info));
	if (ret) {
		pr_err("%s: write disk failed: want=%d, write=%d\n",
		       __func__, (int)sizeof(struct bwr_disk_info), ret);
		ret = -EIO;
		goto err_io;
	}
	memcpy(&bwr->disk_meta, &disk_info->meta, sizeof(struct bwr_meta));

err_io:
	kfree(disk_info);
done:
	//write_unlock_irqrestore(&bwr->lock, flags);
	complete(&bwr->wait);	/* 释放资源 */
	return ret;
}

static void __bwr_check_last(struct bwr_meta *meta, struct bwr *bwr)
{
	int i, ret;
	uint8_t md5[16];
	struct page *data;

	data = alloc_page(GFP_KERNEL);
	if (!data)
		return;

	ret = hadm_read_page_sync(bwr->hadmdev->bdev,
			meta->last_primary.last_page,
			data, PAGE_SIZE);
	if (ret < 0) {
		__free_page(data);
		return ;
	}

	fullsync_md5_hash(page_address(data), PAGE_SIZE, md5);
	for (i = 0; i < 16; i++) {
		if (md5[i] != meta->last_primary.last_page_md5[i]) {
			pr_info("warning: last page damaged!");
			meta->last_primary.last_page_damaged = 1;
			break;
		}
	}
	__free_page(data);
}

static int __meta_last_page_valid(struct bwr_meta *meta)
{
	int i;

	for (i = 0; i < 16; i++)
		if (meta->last_primary.last_page_md5[i])
			return 1;
	return 0;
}

static int __bwr_check_tail(struct bwr_meta *meta, struct bwr *bwr)
{
	u32 crc;
	int ret = 0;
	uint64_t *head, *tail, *bwr_seq;
	struct bwr_data *bwr_data;
	struct bwr_data_meta *data_meta;
	struct hadmdev *dev = bwr->hadmdev;
	int local_site_id = get_site_id();

	head = &meta->head[local_site_id];
	tail = &meta->tail;
	bwr_seq = &meta->local_primary.bwr_seq;
	for (;;) {
		bwr_data = bwr_data_read(bwr, *tail);
		if (!bwr_data) {
			pr_err("%s: read bwr_data faild.\n", __func__);
			ret = -ENOMEM;
			break;
		}
		data_meta = &bwr_data->meta;
		if (data_meta->uuid != meta->local_primary.uuid ||
				data_meta->bwr_seq != *bwr_seq + 1) {
			pr_info("%s: meta not equal, seq(%llu:%llu),"
					"uuid(%llu:%llu)(data:meta)."
					"check bwr data exit.\n", __func__,
					data_meta->bwr_seq, *bwr_seq,
					data_meta->uuid, meta->local_primary.uuid);
			bwr_data_put(bwr_data);
			break;
		}
		crc = crc32(0, page_address(bwr_data->data_page), PAGE_SIZE);
		if (crc != data_meta->checksum) {
			pr_info("crc32 not equal.(data:meta)(%u:%u). check bwr data exit.\n",
					crc, data_meta->checksum);
			bwr_data_put(bwr_data);
			break;
		}

		ret = hadm_write_page_sync(dev->bdev, data_meta->dev_sector,
				bwr_data->data_page, PAGE_SIZE);
		if (ret < 0) {
			pr_err("%s: write unfinished tail data failed.\n",
					__func__);
			bwr_data_put(bwr_data);
			break;
		}


		*head = bwr_next_sector(bwr, *tail);
		*tail = bwr_next_sector(bwr, *tail);
		(*bwr_seq)++;

		bwr_data_put(bwr_data);
	}

	return ret;
}

int __bwr_load_unfinished_data(struct bwr_meta *meta, struct bwr *bwr)
{
	int ret = 0;
	uint64_t *head;
	struct bwr_data *bwr_data;
	struct bwr_data_meta *data_meta;

	pr_info("%s: try load unfinished local data.\n", __func__);
	head = &meta->head[get_site_id()];
	while (*head != meta->tail) {
		bwr_data = bwr_data_read(bwr, *head);
		if (!bwr_data) {
			pr_err("%s: read bwr data(%llu) failed.\n",
					__func__, *head);
			return -ENOMEM;
		}

		data_meta = &bwr_data->meta;
		if (*head != data_meta->bwr_sector) {
			pr_err("%s: offset(%llu) not equal to block bwr"
					"sector (%lu)\n",
			     __func__, *head, data_meta->bwr_sector);
			bwr_data_put(bwr_data);
			ret = -EINVAL;
			break;
		}

		ret = hadm_write_page_sync(bwr->hadmdev->bdev,
				data_meta->dev_sector, bwr_data->data_page, PAGE_SIZE);
		if (ret < 0) {
			pr_err("%s: write bwr data failed.\n",
					__func__);
			dump_bwr_data(__func__, bwr_data);
			ret = -EIO;
			break;
		}

		dump_bwr_data(__func__, bwr_data);
		(*head) = bwr_next_sector(bwr, *head);
		bwr_data_put(bwr_data);

		//buffer_data_add(buffer, bwr_data);
	}

	pr_info("%s: head: %llu.\n", __func__, *head);
	return ret;
}

/* load disk meta to memory meta */
int load_bwr_meta(struct bwr *bwr)
{
	int ret;
	struct page *meta_page;
	struct bwr_meta *disk_meta;
	int local_site_id = get_site_id();

	meta_page = alloc_page(GFP_KERNEL);
	if (!meta_page) {
		ret = -ENOMEM;
		goto done;
	}

	ret = hadm_read_page_sync(bwr->hadmdev->bwr_bdev,
			bwr->disk_meta.meta_start,
			meta_page, PAGE_SIZE);
	if (ret < 0) {
		pr_err("%s: sync meta failed.\n", __func__);
		ret = -EIO;
		goto free_page;
	}

	disk_meta = &((struct bwr_disk_info *)page_address(meta_page))->meta;
	if (disk_meta->magic == MAGIC) {
		if (disk_meta->local_primary.id == INVALID_ID) {
			/* secondary: check last bwr_data */
			if (__meta_last_page_valid(disk_meta))
				__bwr_check_last(disk_meta, bwr);
		} else {
			/* primary: load unfinished data */
			if (disk_meta->head[local_site_id] != disk_meta->tail)
				__bwr_load_unfinished_data(disk_meta, bwr);
			__bwr_check_tail(disk_meta, bwr);
		}

		bwr->disk_meta = bwr->mem_meta = *disk_meta;

		bwr->min_disk_head = __bwr_get_min_head(bwr, &bwr->min_site_mask);

		//distance = bwr_distance(bwr, bwr->min_disk_head, bwr->mem_meta.tail);
		/* init phase: mema_meta equals disk_meta */
		//__bwr_set_inuse_size(bwr, distance);
		//bwr_update_inuse_size(bwr);
	} else if (disk_meta->magic == BWR_UNINIT_MAGIC) {
		/* using default meta which already inited */
	} else {
		pr_err("%s: BWR magic is NOT right\n", __func__);
		ret = -EINVAL;
		goto free_page;
	}

	sync_bwr_meta(bwr);

free_page:
	__free_page(meta_page);
done:
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
	meta->head[get_site_id()] = meta->bwr_start;
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

	bwr->low_water = bwr->max_size * BWR_FLUSH_LOW_WATER / 10;
	bwr->high_water = bwr->max_size * BWR_FLUSH_HIGH_WATER / 10;
	abi_init(&bwr->abi);

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

	init_completion(&bwr->sync_site_finish);
	spin_lock_init(&bwr->sync_site_mask_lock);

	rwlock_init(&bwr->bwr_data_list_rwlock);
	INIT_LIST_HEAD(&bwr->bwr_data_list);
	bwr->bwr_data_list_max_size = DEFAULT_BWR_DATA_LIST_SIZE;
	bwr->waiters = 0;
	init_completion(&bwr->ev_wait);
	sema_init(&bwr->sema, 0);
}

int bwr_init(struct hadmdev *dev, uint64_t bwr_max, uint64_t bwr_disk_size,
	     uint64_t meta_offset, uint64_t dbm_offset, uint64_t bwr_offset)
{
	static char *bwr_identity = "bwr_init";
	struct bwr *bwr = dev->bwr;
	int ret;

	dev->bwr_bdev = blkdev_get_by_path(dev->local_site->conf.bwr_disk,
					   BWRDEV_MODE, (void *)bwr_identity);
	if (IS_ERR(dev->bwr_bdev)) {
		ret = PTR_ERR(dev->bwr_bdev);
		dev->bwr_bdev = NULL;
		pr_err("%s: get %s failed\n",
		       __func__, dev->local_site->conf.bwr_disk);
		return ret;
	}
	set_device_ro(dev->bwr_bdev, 1);
	__bwr_init(bwr, bwr_max, bwr_disk_size, meta_offset, dbm_offset, bwr_offset);

	return 0;
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

/* TODO: 检查 dbm 的大小和它的 disk_state 是否一致。一致返回 0，否则返回非 0 */
int valid_bwr_meta(struct bwr *bwr)
{
	return 0;
}

void bwr_meta_dump(struct bwr_meta *meta)
{
	int i;

	printk(KERN_INFO "%s:\n", __func__);
	printk(KERN_INFO "\tmagic: %llu, dev_id: %d\n"
	       "disk_size: %llu, bwr_disk_size: %llu\n"
	       "meta_start: %llu, dbm_start: %llu, bwr_start: %llu\n\n",
	       (unsigned long long)meta->magic, meta->dev_id,
	       (unsigned long long)meta->disk_size, (unsigned long long)meta->bwr_disk_size,
	       (unsigned long long)meta->meta_start, (unsigned long long)meta->dbm_start, (unsigned long long)meta->bwr_start);

	printk(KERN_INFO "head:\n");
	for (i = 0; i < MAX_NODES; i++)
		printk(KERN_INFO " %llu", (unsigned long long)meta->head[i]);
	printk(KERN_INFO "\ntail: %llu, disk_state: %d\n\n", (unsigned long long)meta->tail, meta->disk_state);

	printk(KERN_INFO "last_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
	       meta->last_primary.id, (unsigned long long)meta->last_primary.uuid,
	       (unsigned long long)meta->last_primary.bwr_seq);
	printk(KERN_INFO "local_primary: id=%d, uuid=%llu, bwr_seq=%llu\n",
	       meta->local_primary.id, (unsigned long long)meta->local_primary.uuid,
	       (unsigned long long)meta->local_primary.bwr_seq);
}

void bwr_reset(struct bwr *bwr)
{
	struct hadm_site *hadm_site;

	pr_info("reset bwr meta & dbm:");
	bwr->mem_meta.tail = bwr->mem_meta.bwr_start;
	list_for_each_entry(hadm_site, &bwr->hadmdev->hadm_site_list, site) {
		bwr->mem_meta.head[hadm_site->id] = bwr->mem_meta.bwr_start;
		__hadm_site_reset_send_head(hadm_site);
		__hadm_site_set(&hadm_site->s_state, S_DSTATE, D_CONSISTENT);
		if (hadm_site->id != get_site_id()) {
			pr_info("clean dbm for site:%d.\n", hadm_site->id);
			//dbm_dump(hadm_site->dbm);
			dbm_clear_bit_all(hadm_site->dbm);
			dbm_store(hadm_site->dbm);
		}
	}
}

uint64_t gen_sync_site_mask(struct bwr *bwr)
{
	struct hadm_site *hadm_site;
	uint64_t sync_site_mask = 0;
	int local_site_id = get_site_id();

	spin_lock(&bwr->sync_site_mask_lock);
	list_for_each_entry(hadm_site, &bwr->hadmdev->hadm_site_list, site) {
		if (hadm_site->id != local_site_id &&
				hadm_site->conf.real_protocol == PROTO_SYNC)
			sync_site_mask |= 1 << hadm_site->id;
	}
	bwr->sync_site_mask = sync_site_mask;
	spin_unlock(&bwr->sync_site_mask_lock);

	return sync_site_mask;
}

/* -------------------------------- obsolete functions ------------------------*/
int bwr_init_meta(struct bwr *bwr, uint64_t meta_offset)
{
	int ret;
	int64_t distance;
	int local_site_id;
	struct page *page;
	struct bwr_meta *disk_meta;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		ret = -ENOMEM;
		pr_err("%s: no memory\n", __func__);
		goto out;
	}

	ret = hadm_read_page_sync(bwr->hadmdev->bwr_bdev, meta_offset,
			page, PAGE_SIZE);
	if (ret < 0) {
		pr_err("%s: read disk meta failed.\n", __func__);
		goto free_page;
	}

	disk_meta = &((struct bwr_disk_info *)page_address(page))->meta;
	if (disk_meta->magic == MAGIC) {
		if (disk_meta->local_primary.id == INVALID_ID)
			if (__meta_last_page_valid(disk_meta))
				__bwr_check_last(disk_meta, bwr);
		if (disk_meta->local_primary.id != INVALID_ID)
			__bwr_check_tail(disk_meta, bwr);
		memcpy(&bwr->disk_meta, disk_meta, sizeof(struct bwr_meta));
		memcpy(&bwr->mem_meta, disk_meta, sizeof(struct bwr_meta));
		bwr->min_disk_head = __bwr_get_min_head(bwr, &bwr->min_site_mask);
		local_site_id = get_site_id();

		distance = bwr_distance(bwr,
					bwr->disk_meta.head[local_site_id],
					bwr->disk_meta.tail);
		if (distance > get_max_bwr_cache_size()) {
			pr_err("%s: BWR cache too big\n", __func__);
			ret = -EINVAL;
			goto free_page;
		}

		distance = bwr_distance(bwr, bwr->min_disk_head, bwr->disk_meta.tail);
		/* init phase: mema_meta equals disk_meta */
		__bwr_set_inuse_size(bwr, distance);
		//bwr_update_inuse_size(bwr);
	} else if (disk_meta->magic == BWR_UNINIT_MAGIC) {
		/* using default meta which already inited */
	} else {
		pr_err("%s: BWR magic is NOT right\n", __func__);
		ret = -EINVAL;
		goto free_page;
	}

free_page:
	__free_page(page);
out:
	return ret;
}

int bwr_init_data_list(struct bwr *bwr)
{
	struct bwr_data_block *block;
	struct bwr_data *bwr_data;
	uint64_t offset;
	struct page *page;
	int ret = 0, local_site_id;
	struct data_buffer *buffer = bwr->hadmdev->buffer;

	if (bwr->disk_meta.local_primary.id == INVALID_ID)
		return 0;
	pr_info("try load unfinished local_site data.\n");
	local_site_id = get_site_id();
	block = kzalloc(sizeof(struct bwr_data_block), GFP_KERNEL);
	for (offset = bwr->disk_meta.head[local_site_id];
	     offset != bwr->disk_meta.tail;
	     offset = bwr_next_sector(bwr, offset)) {
		hadm_read_bwr_block(bwr->hadmdev->bwr_bdev,offset,(char *)block,sizeof(struct bwr_data_block));
		if (offset != block->meta.bwr_sector) {
			pr_err("%s: offset(%lu) not equal to block bwr sector (%lu)\n",
			     __func__, (unsigned long)offset,
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
			pr_err("%s alloc_bwr_data faild.\n", __func__);
			__free_page(page);
			ret = -1;
			goto done;
		}

		memcpy(page_address(bwr_data->data_page), block->data_block, PAGE_SIZE);
		ret = buffer_data_add(buffer, bwr_data);
		if (ret < 0) {
			pr_err("%s bwr_data add faild.\n", __func__);
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
