#define pr_fmt(fmt) "dbm: " fmt

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/blkdev.h>
#include <linux/bio.h>
#include <linux/device-mapper.h> /* SECTOR_SHIFT */

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "hadm_struct.h"
#include "hadm_bio.h"
#include "hadm_thread.h"

#include "bio_handler.h"
#include "dbm.h"
#include "dbm.h"
#include "hadm_packet.h"
#include "bwr.h"
#include "fullsync.h"
#include "utils.h"
#include "../include/common_string.h"

char dbm_indentify[] = "dbm_indentify";

struct dbm_record *alloc_dbm_record(gfp_t flags, uint64_t page_number)
{
	struct page *page;
	struct dbm_record *dbm_record;

	page = alloc_page(flags);
	if (!page) {
		pr_err("%s alloc page faild.\n", __FUNCTION__);
		return NULL;
	}
	dbm_record = kmalloc(sizeof(struct dbm_record), flags);
	if (!dbm_record) {
		pr_err("%s alloc dbm_record faild.\n", __FUNCTION__);
		__free_page(page);
		return NULL;
	}
	dbm_record->page = page;
	dbm_record->page_number = page_number;
	dbm_record->next = NULL;

	return dbm_record;
}


void free_dbm_zones(struct dbm_zone **dbm_zones, int nr_zone)
{
	int i, j;
	struct dbm_record *dbm_record;

	if (dbm_zones) {
		for (i = 0; i < nr_zone; i++) {
			if (dbm_zones[i]) {
				if(dbm_zones[i]->bz_record) {
					for (j = 0; j < dbm_zones[i]->record_num; j++) {
						dbm_record = &dbm_zones[i]->bz_record[j];
						if(dbm_record->page)
							__free_page(dbm_record->page);
						else
							break;
					}
					kfree(dbm_zones[i]->bz_record);
				}
				kfree(dbm_zones[i]);
				pr_info("free dbm_zones[%d]:%p", i, dbm_zones[i]);
			}
		}
		pr_info("free dbm_zones:%p", dbm_zones);
		kfree(dbm_zones);
	}
}

struct dbm_zone **alloc_dbm_zones(gfp_t gfp_flag, uint64_t disk_size)
{
	int i, j, nr_zones;
	uint64_t total_pages, pages_alloced;
	uint64_t page_num;
	struct page *page;
	struct dbm_zone **dbm_zones;
	struct dbm_record *dbm_record;

	nr_zones = DIV_ROUND_UP(disk_size, DBM_BDEV_SIZE_PER_ZONE);
	total_pages = DIV_ROUND_UP(disk_size, DBM_BDEV_SIZE_PER_PAGE);
	pr_info("%s DBM_BDEV_SIZE_PER_ZONE:%llu, DBM_BDEV_SIZE_PER_PAGE:%llu,"
			"DBM_ZONE_SIZE:%d, DBM_ZONE_RECORDS:%d, sizeof(dbm_zone):%lu."
			"data_size:%llu, nr_zones:%d, total_pages:%llu.\n",
			__FUNCTION__,
			DBM_BDEV_SIZE_PER_ZONE,
			DBM_BDEV_SIZE_PER_PAGE,
			DBM_ZONE_SIZE,
			DBM_ZONE_RECORDS,
			sizeof(struct dbm_zone),
			disk_size, nr_zones,
			total_pages);
	dbm_zones = kzalloc(sizeof(struct dbm_zone *) * nr_zones, gfp_flag);
	if (!dbm_zones) {
		pr_err("%s alloc dbm_pages faild.\n", __FUNCTION__);
		goto alloc_faild;
	}
	pr_info("%s alloc dbm_zones %p.\n", __FUNCTION__, dbm_zones);
	for (i = 0; i < nr_zones; i++) {
		pages_alloced = total_pages - i * DBM_ZONE_RECORDS;

		dbm_zones[i] = (struct dbm_zone *)kzalloc(sizeof(struct dbm_zone), gfp_flag);
		if (!dbm_zones[i]) {
			pr_err("%s alloc dbm_zones[%d] faild.\n", __FUNCTION__, i);
			goto alloc_faild;
		}
		dbm_zones[i]->record_num = pages_alloced;
		dbm_zones[i]->bz_record = (struct dbm_record *)kzalloc(pages_alloced * sizeof(struct dbm_record), gfp_flag);
		pr_info("%s alloc dbm_zone %p, record_num %llu.\n", __FUNCTION__, dbm_zones[i], pages_alloced);
		/* perharps, we could allocate pages when real set dbm */
		for (j = 0; j < pages_alloced ; j++) {
			dbm_record = &dbm_zones[i]->bz_record[j];

			page_num = i * DBM_ZONE_RECORDS + j;
			if (page_num == total_pages)
				goto done;
			page = alloc_page(gfp_flag);
			if (!page) {
				pr_err("%s alloc page faild.\n", __FUNCTION__);
				goto alloc_faild;
			}
			dbm_record->page_number = page_num;
			dbm_record->page = page;
			dbm_record->next = NULL;
			//pr_info("init dbm_record:%p, page:%p. page_num:%llu.\n", dbm_record, page, page_num);
		}
	}
done:
	return dbm_zones;
alloc_faild:
	free_dbm_zones(dbm_zones, nr_zones);
	dbm_zones = NULL;
	goto done;
}

struct dbm *alloc_dbm(gfp_t gfp_flag, struct block_device *bdev,
		struct hadm_node *node, uint64_t disk_size, sector_t start_sector)
{
	struct dbm *dbm;
	struct dbm_zone **dbm_zone;
	int minor = node->hadmdev->minor;

	dbm = kmalloc(sizeof(struct dbm), gfp_flag);
	if (!dbm) {
		pr_err("%s alloc hadm%d dbm faild.\n", __FUNCTION__, minor);
		return NULL;
	}
	pr_info("%s alloc hadm%d dbm %p.\n", __FUNCTION__, minor, dbm);

	dbm_zone = alloc_dbm_zones(gfp_flag, disk_size);
	if (!dbm_zone) {
		pr_err("%s alloc hadm%d dbm zone faild.\n", __FUNCTION__, minor);
		kfree(dbm);
		return NULL;
	}

	spin_lock_init(&dbm->dbm_lock);
	dbm->node = node;
	dbm->bdev = bdev;
	dbm->disk_size = disk_size;
	dbm->start_sector = start_sector;
	dbm->last_flush_time = jiffies;

	dbm->last_dirty_record = NULL;
	dbm->dbm_zones = dbm_zone;

	return dbm;
}

void free_dbm(struct dbm *dbm)
{
	if (dbm) {
		free_dbm_zones(dbm->dbm_zones,
				DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE));
		pr_info("free hadm%d dbm:%p.", dbm->node->hadmdev->minor, dbm);
		kfree(dbm);
	}
}

struct dbm *dbm_create(struct block_device *bdev, sector_t start,
		struct hadm_node *node, uint64_t disk_size, int gfp_flag)
{
	int local_node_id;
	sector_t offset;
	struct dbm *dbm;
	ssize_t nr_bits = 0;

	offset = start + DIV_ROUND_UP(disk_size, DBM_BDEV_SIZE_PER_BYTE * HADM_SECTOR_SIZE) * node->id;
	dbm = alloc_dbm(gfp_flag, bdev, node, disk_size, offset);
	if (!dbm) {
		pr_err("%s alloc hadm%d dbm faild.\n", __FUNCTION__, dbm->node->hadmdev->minor);
		return NULL;
	}

	local_node_id = get_node_id();
	if (local_node_id != node->id) {
		nr_bits = dbm_load(dbm);
		if (nr_bits > 0) {
			hadm_node_set(dbm->node, SECONDARY_STATE, S_DATA_STATE, DATA_DBM);
			hadm_node_set(dbm->node, SECONDARY_STATE, S_DSTATE, D_INCONSISTENT);
		} else if (nr_bits < 0) {
			pr_err("%s load hadm%d dbm faild.\n", __FUNCTION__, dbm->node->hadmdev->minor);
			free_dbm(dbm);
			return NULL;
		}
		dbm->node->s_state.dbm_set = nr_bits;
		atomic_set(&dbm->nr_bit, nr_bits);
		pr_info("hadm%d dbm_create: "
				"node id=%d, start=%lu(sector), dbm->disk_size=%lld(byte), disk_size:%llu bits=%d\n",
				dbm->node->hadmdev->minor, 
				node->id,
				offset,
				(long long int)dbm->disk_size,
				disk_size,
				atomic_read(&dbm->nr_bit));
	}
	return dbm;
}

struct dbm_record *dbm_last_dirty_record(struct dbm *dbm)
{
	struct dbm_record *last_record;

	spin_lock(&dbm->dbm_lock);
	last_record = dbm->last_dirty_record;
	spin_unlock(&dbm->dbm_lock);

	return last_record;
}

static void __dbm_dirty_record(struct dbm *dbm, struct dbm_record *dbm_record)
{
	if (dbm_record_is_dirt(dbm_record))
		return;
	if (dbm->last_dirty_record) {
		dbm_record->next = dbm->last_dirty_record->next;
		dbm->last_dirty_record->next = dbm_record;
		dbm->last_dirty_record = dbm_record;
	} else {
		dbm->last_dirty_record = dbm_record;
		dbm_record->next = dbm_record;
	}
}

void dbm_dirty_record(struct dbm *dbm, struct dbm_record *dbm_record)
{
	spin_lock(&dbm->dbm_lock);
	__dbm_dirty_record(dbm, dbm_record);
	spin_unlock(&dbm->dbm_lock);
}

struct dbm_record *dbm_pop_dirty_record(struct dbm *dbm)
{
	struct dbm_record *dbm_record = NULL;

	spin_lock(&dbm->dbm_lock);
	if (dbm->last_dirty_record) {
		dbm_record = dbm->last_dirty_record->next;
		if (dbm_record->next == dbm_record) {
			dbm->last_dirty_record = NULL;
		} else {
			dbm->last_dirty_record->next = dbm_record->next;
		}
		dbm_record->next = NULL;
	}
	spin_unlock(&dbm->dbm_lock);

	return dbm_record;
}

int dbm_set_sector(struct dbm *dbm, sector_t sector)
{
	uint64_t nbits = sector << HADM_SECTOR_SHIFT >> DBM_SHIFT;

	return dbm_set_bit(dbm, nbits);
}

/* set/clear 只操作在内存中的 dbm */
int dbm_set_bit(struct dbm *dbm, uint64_t bit)
{
	int nr_bit, ret = 0;
	struct dbm_record *dbm_record;

	if ((bit * DBM_BDEV_SIZE_PER_BIT) > dbm->disk_size) {
		dump_stack();
		pr_err("%s try set bit %llu beyond hadm%d scope.\n", __FUNCTION__, bit, dbm->node->hadmdev->minor);
		return -1;
	}
	dbm_record = dbm_find_record(dbm, bit >> (DBM_SHIFT + BYTE_SHIFT));
	nr_bit = bit & PAGE_BIT_MASK;
	spin_lock(&dbm->dbm_lock);
	if (!test_bit(nr_bit, page_address(dbm_record->page))) {
		set_bit(nr_bit, page_address(dbm_record->page));
		__dbm_dirty_record(dbm, dbm_record);
		atomic_inc(&dbm->nr_bit);
		ret = 1;
	}
	spin_unlock(&dbm->dbm_lock);

	return ret;
}

/* NOTE: 要求dbm以字节对齐，且没有pad的bit. */
void dbm_set_bit_all(struct dbm *dbm)
{
	int i, j;
	int nr_zones, last_page_byte = 0;
	uint64_t total_pages;
	struct dbm_record *dbm_record = NULL;

	nr_zones = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE);
	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);
	last_page_byte = (dbm->disk_size / DBM_BDEV_SIZE_PER_BYTE) % PAGE_SIZE;
	for (i = 0; i < nr_zones; i++) {
		for (j = 0; j < dbm->dbm_zones[i]->record_num ; j++) {
			dbm_record = &dbm->dbm_zones[i]->bz_record[j];
			memset(page_address(dbm_record->page), 0xff, PAGE_SIZE);
			dbm_dirty_record(dbm, dbm_record);
			if (!--total_pages)
				goto done;
		}
	}
done:
	if (last_page_byte)
		memset(page_address(dbm_record->page) + last_page_byte, 0, PAGE_SIZE - last_page_byte);
	atomic_set(&dbm->nr_bit, dbm->disk_size / DBM_BDEV_SIZE_PER_BIT);
}

int dbm_clear_sector(struct dbm *dbm, sector_t sector)
{
	/**
	 *sector * 512/4096 =sector/8 ，定位sector对应到dbm的bit的位置
	 */
	uint64_t nbits = sector << HADM_SECTOR_SHIFT >> DBM_SHIFT;
	int ret = dbm_clear_bit(dbm, nbits);
#ifdef DBM_DBUG
	pr_info("%s: clear node %d's dbm at sector %lu, dbm nr_bit=%u\n",
			__FUNCTION__, dbm->node->id, sector, atomic_read(&dbm->nr_bit));
#endif
	return ret;
}

/* set/clear 只操作在内存中的 dbm */
int dbm_clear_bit(struct dbm *dbm, uint64_t bit)
{
	int nr_bit, ret = 0;
	struct dbm_record *dbm_record;
	/**
	 *bit/8/4096 对应到属于哪个dbm record
	 */
	dbm_record = dbm_find_record(dbm, bit >> (DBM_SHIFT + BYTE_SHIFT));
	if(!dbm_record || !dbm_record->page ){
		pr_warn("find hadm%d dbm record failed. node id = %d , bit = %llu\n", 
				dbm->node->hadmdev->minor, dbm->node->id, bit);
		BUG();
		return 0;
	}
	nr_bit = bit & PAGE_BIT_MASK;
	spin_lock(&dbm->dbm_lock);
	if (test_bit(nr_bit, page_address(dbm_record->page))) {
		clear_bit(nr_bit, page_address(dbm_record->page));
		__dbm_dirty_record(dbm, dbm_record);
		atomic_dec(&dbm->nr_bit);
		ret = 1;
	}
	spin_unlock(&dbm->dbm_lock);

	return ret;
}

void dbm_clear_bit_all(struct dbm *dbm)
{
	int i, j;
	int nr_zones, last_page_byte;
	uint64_t total_pages;
	struct dbm_record *dbm_record;

	nr_zones = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE);
	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);
	last_page_byte = (dbm->disk_size / DBM_BDEV_SIZE_PER_BYTE) % PAGE_SIZE;
	for (i = 0; i < nr_zones; i++) {
		for (j = 0; j < dbm->dbm_zones[i]->record_num; j++) {
			dbm_record = &dbm->dbm_zones[i]->bz_record[j];
			memset(page_address(dbm_record->page), 0x0, PAGE_SIZE);
			dbm_dirty_record(dbm, dbm_record);
			if (!--total_pages)
				goto done;
		}
	}
done:
	atomic_set(&dbm->nr_bit, 0);
}

inline sector_t dbm_to_sector(size_t n)
{
	return (sector_t)(n << (PAGE_SHIFT - HADM_SECTOR_SHIFT));
}

static void dbm_gen_end_io(struct bio *bio, int error)
{
	struct hadm_node *node = (struct hadm_node *)bio->bi_private;
	struct bwr_data_meta *dmeta;
	if(error){
		hadmdev_set_error(node->hadmdev, __BWR_ERR);
	}else {
		dmeta=(struct bwr_data_meta *)page_address(bio->bi_io_vec[0].bv_page);
		dbm_set_sector(node->dbm, dmeta->dev_sector);
	}
	atomic_dec(&node->dbm->dbm_sync_param->pending_io);
	wake_up(&node->dbm->dbm_sync_param->wait);
	hadm_free_bio(bio);

}
#define MAX_DBM_READ_IO	(1 << 14)
int dbm_gen(struct hadm_node *node)
{
	sector_t offset, tail;
	int ret = 0,error;
	offset = bwr_node_head(node->hadmdev->bwr, node->id);
	tail = bwr_tail (node->hadmdev->bwr);
	pr_info("gen hadm%d dbm for node %d , from %lu to %lu\n", 
			node->hadmdev->minor, node->id, offset, tail);
	while(hadm_thread_get_state(node->delta_sync) == HADM_THREAD_RUN) {
		if (offset == tail)
			break;
		if(wait_event_timeout(node->dbm->dbm_sync_param->wait,
					atomic_read(&node->dbm->dbm_sync_param->pending_io) < MAX_DBM_READ_IO,
					msecs_to_jiffies(1000)) == 0){
			continue;
		}

		atomic_inc(&node->dbm->dbm_sync_param->pending_io);
		error=hadm_read_page_async(node->hadmdev->bwr_bdev, offset, dbm_gen_end_io, (void *)node);
		if (error) {
			atomic_dec(&node->dbm->dbm_sync_param->pending_io);
			pr_err("%s: read hadm%d bwr failed: want=%d, error=%d\n",
					__FUNCTION__, node->hadmdev->minor, 
					HADM_SECTOR_SIZE, error);
			ret = error;
			goto done;
		}
		offset = bwr_next_sector(node->hadmdev->bwr, offset);
		schedule();
		/**
		  hadm_node_send_head_inc(node, 0);
		  bwr_node_head_inc(node->hadmdev->bwr, node->id);
		 **/
	}
done:
	wait_event(node->dbm->dbm_sync_param->wait,atomic_read(&node->dbm->dbm_sync_param->pending_io) == 0);
#if 0
	while(atomic_read(&node->dbm->dbm_sync_param->pending_io)) {
		/**
		 * 注意，这里不能在线程被结束时退出，
		 * 否则在end_io函数里可能会访问到空指针
		 */
		/**
		  if(hadm_thread_get_state(node->delta_sync) != HADM_THREAD_RUN){
		  ret = -EKMOD_DELTA_SYNC_EXIT;
		  goto done;
		  }
		  if(hadmdev_error(node->hadmdev)){
		  ret = -EIO;
		  goto done;
		  }
		 **/
		msleep(1000);
	}
#endif

	if(!ret){
		bwr_set_node_head(node->hadmdev->bwr, node->id, offset, 1);
		dbm_store(node->dbm);
	}
	return ret;
}

int dbm_delta_sync_sector(struct hadm_node *node, sector_t sector)
{
	return rssync_node_sector(node, sector);
}

#if 0
static int __dbm_delta_sync_record(struct hadm_node *node, struct dbm_record *dbm_record)
{
	int i;
	unsigned long nr_bit, start_bit;
	unsigned long  tmp, *data;

	data = (unsigned long *)page_address(dbm_record->page);
	start_bit = dbm_record->page_number << (PAGE_SHIFT + BYTE_SHIFT);
	for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
		tmp = data[i];
		while (tmp) {
			if (hadm_thread_get_state(node->delta_sync) == HADM_THREAD_EXIT)
				return -EKMOD_DELTA_SYNC_EXIT;
			nr_bit = start_bit + i * BITS_PER_LONG + __ffs(tmp);
			dbm_delta_sync_sector(node, dbm_to_sector(nr_bit));
			tmp &= tmp - 1;
		}
	}

	return 0;
}
#endif

void dbm_sync_param_free(struct dbm *dbm)
{
	struct dbm_sync_param *dp = dbm->dbm_sync_param;
	if(IS_ERR_OR_NULL(dp))
		return ;
	hadm_pack_queue_clean(dp->delta_packet_queue);
	hadm_queue_free(dp->delta_packet_queue);
	kfree(dp);
	dbm->dbm_sync_param = NULL;
}

#define MAX_DBM_SYNC_QUEUE_SIZE  (1<<10)
struct dbm_sync_param *dbm_sync_param_create(struct dbm *dbm)
{
	struct dbm_sync_param *dp = NULL;
	char queue_name[MAX_NAME_LEN];
	const int packet_queue_size = MAX_DBM_SYNC_QUEUE_SIZE;
	dp = kzalloc(sizeof(struct dbm_sync_param), GFP_KERNEL);
	if(IS_ERR_OR_NULL(dp)){
		goto fail;
	}
	snprintf(queue_name, MAX_NAME_LEN - 1, "delta_sync_packet_queue%d", dbm->node->id);
	dp->delta_packet_queue = hadm_queue_create(queue_name, packet_queue_size);
	if(IS_ERR_OR_NULL(dp->delta_packet_queue)) {
		pr_info("%s: hadm%d create queue %s failed\n", __FUNCTION__, 
				dbm->node->hadmdev->minor, queue_name);
		goto fail;
	}
	atomic_set(&dp->pending_io, 0);
	init_waitqueue_head(&dp->wait);

	return dp;
fail:
	dbm_sync_param_free(dbm);
	return NULL;

}

struct dbm_bio_private {
	struct hadm_pack_node *node;
	struct dbm *dbm;
};

static void dbm_delta_data_end_io(struct bio *bio, int error)
{
	struct dbm_bio_private *private = (struct dbm_bio_private *)bio->bi_private;
	if(error) {
		hadmdev_set_error(private->dbm->node->hadmdev, __BDEV_ERR);
		hadm_pack_node_free(private->node);
	}else{
		if(private->dbm->dbm_sync_param == NULL){
			BUG();
		}
		/**TODO maybe zerocopy **/
		memcpy(private->node->pack->data,
				page_address(bio->bi_io_vec[0].bv_page), PAGE_SIZE);
		if(hadm_queue_push_nowait(private->dbm->dbm_sync_param->delta_packet_queue, &(private->node->q_node))) {
			pr_info("%s: hadm%d node %d push packet to delta_packet_queue failed, packet queue len = %u, pending io = %d\n",
					__FUNCTION__, private->dbm->node->hadmdev->minor, private->dbm->node->id, 
					hadm_queue_len(private->dbm->dbm_sync_param->delta_packet_queue),
					atomic_read(&private->dbm->dbm_sync_param->pending_io));
			BUG();
		}
#ifdef DBM_DBUG
		pr_info("read block %llu , gen pack node %p , push to queue, now queue len %u\n",
				private->node->pack->dev_sector, private->node, hadm_queue_len(private->dbm->dbm_sync_param->delta_packet_queue));
#endif
	}
	atomic_dec(&private->dbm->dbm_sync_param->pending_io);
	//wake_up(&private->dbm->dbm_sync_param->wait);
	kfree(private);
	hadm_free_bio(bio);
}
/**
 *这个函数负责从bdev里异步读取数据，并保存在private->node->pack的data里。
 */
int delta_sync_read_page_async(struct hadm_node *node, sector_t bdev_offset, int p_type)
{
	struct dbm_bio_private *private = NULL;
	struct packet *pack;
	int ret = -ENOMEM;
	uint64_t uuid = bwr_get_uuid(node->hadmdev->bwr);

	/**
	 *每次读1个page，8个sector，检测是否磁盘越界访问
	 */
	if(bdev_offset + 8 > node->hadmdev->bdev_disk_size){
		return 0;
	}
	pack = packet_alloc_for_node(PAGE_SIZE, GFP_KERNEL, node);
	if(!pack) {
		goto fail;
	}
	private = kzalloc(sizeof(struct dbm_bio_private), GFP_KERNEL);
	if(!private) {
		goto fail;
	}
	private->node = hadm_pack_node_create(pack, NULL);
	if(!private->node){
		goto fail;
	}
	private->dbm = node->dbm;
	pack->type = p_type;
	pack->dev_id = node->hadmdev->minor;
	pack->uuid = uuid;
	pack->dev_sector = bdev_offset;

	if(hadm_read_page_async(node->hadmdev->bdev, bdev_offset, dbm_delta_data_end_io, (void *)private)){
		pr_info("%s read page from hadm%d bdev offset %lu failed\n", __FUNCTION__, 
				node->hadmdev->minor, bdev_offset);
		hadmdev_set_error(node->hadmdev, __BDEV_ERR);
		ret = -EIO;
		goto fail;
	}
	atomic_inc(&node->dbm->dbm_sync_param->pending_io);
	return 0;
fail:
	if(private){
		hadm_pack_node_free(private->node);
		kfree(private);
	}
	return ret;

}
/**
 *这个函数是吧dbm_data包含的64bits的数据对应的bdev的内容
 *生成packet放入packet_queue。当dbm_data对应的位为1时，找到
 *bdev里对应的offset，然后生成异步io，在end_io里将生成的packet_node
 *push到packet_queue，为了防止在end_io里阻塞，实现需要等待packet_queue
 *有足够的空间
 */
static int dbm_read_delta_data_async(struct hadm_node *node,
		sector_t dbm_offset,
		unsigned long dbm_data)
{
	sector_t offset, bdev_offset;
	int err = 0 ;
	unsigned st, et;

	while(dbm_data){
		offset = dbm_offset + __ffs(dbm_data);
		bdev_offset = dbm_to_sector(offset);
		st=jiffies;
		if(hadm_queue_reserve_timeout(node->dbm->dbm_sync_param->delta_packet_queue, 
				1, msecs_to_jiffies(10000))){
			et=jiffies;
			pr_info("%s:hadm%d queue %s reserve space timeout, timeout=%u\n",
					__FUNCTION__, node->hadmdev->minor, 
					node->dbm->dbm_sync_param->delta_packet_queue->name, 
					et-st);

			return -EBUSY;
		}
		err = delta_sync_read_page_async(node, bdev_offset, P_RS_DATA);
		if(err)
			return err;
		dbm_data &= dbm_data -1;
	}
	return 0;
}

/* 前置条件：产生了 dbm； 后置条件：将 dbm 清零，同时将与之相关的数据发送出去 */
static int __dbm_delta_sync(struct hadm_node *node)
{
	int zone_index, page_index, record_index, ret = 0;
	int nr_zones;
	uint64_t total_pages;
	unsigned long record_start_bit, dbm_offset;
	struct dbm_record *dbm_record;
	struct dbm *dbm = node->dbm;
	unsigned long *data;
	struct hadm_pack_node *pack_node = NULL;
	struct hadm_queue *delta_packet_queue;
	unsigned long total_bit = atomic_read(&dbm->nr_bit), remain;
	unsigned long packet_send = 0 ;
	int last_percent = 100, percent;
	unsigned long start_jif, end_jif;
	start_jif = jiffies;

	delta_packet_queue = dbm->dbm_sync_param->delta_packet_queue;

	nr_zones = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE);
	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);

	zone_index = 0 ;
	page_index = 0 ;
	record_index = 0;

	dbm_record = &dbm->dbm_zones[zone_index]->bz_record[page_index];
	data = (unsigned long *)page_address(dbm_record->page);
	record_start_bit = dbm_record->page_number << (PAGE_SHIFT + BYTE_SHIFT);
	pr_info("%s: hadm%d start to delta sync dbm to node %d, nr_bit=%d\n",
			__FUNCTION__, node->hadmdev->minor, node->id, atomic_read(&dbm->nr_bit));
	while((remain = atomic_read(&dbm->nr_bit)) > 0) {
#ifdef DBM_DBUG
		pr_info("%s: nr_zones=%d, zone_index=%d, dbm_zone->record_num=%d, page_index=%d, record_index=%d\n",
				__FUNCTION__,
				nr_zones, zone_index, dbm->dbm_zones[zone_index]->record_num, page_index, record_index);
		pr_info("%s: pending_io=%d, delta_packet_queue length=%d\n", __FUNCTION__,
				atomic_read(&dbm->dbm_sync_param->pending_io), hadm_queue_len(delta_packet_queue));
#endif
		/**
		 *要等到pending_io = 0 才能退出，否则可能会在卸载模块的时候，还有endio没有返回，但是
		 *dbm_sync_param已经被释放
		 */
		if(hadm_node_get(node, SECONDARY_STATE, S_CSTATE) != C_DELTA_SYNC_DBM){
			pr_info("%s: hadm%d node %d cstate is NOT C_DELTA_SYNC", __FUNCTION__, 
					node->hadmdev->minor, node->id);
			ret = -EKMOD_CSTATE;
		}
		if(hadm_thread_get_state(node->delta_sync)!=HADM_THREAD_RUN) {
			ret = -EKMOD_DELTA_SYNC_EXIT;
		}
		if(hadmdev_error(node->hadmdev)){
			ret = -EIO;
		}
		if(ret){
			if(atomic_read(&dbm->dbm_sync_param->pending_io)){
				msleep(1000);
				continue;
			}else{
				break;
			}
		}
		/**
		 *内核日志里打印百分比
		 */
		percent = 100 * remain / total_bit;
		if( last_percent - percent >= 10) {
			end_jif = jiffies;
			pr_info("%s: delta sync hadm%d to node %d, block remained = %d%%(%lu/%lu), sync rate = %lu KBytes/Sec",
					__FUNCTION__, node->hadmdev->minor, 
					node->id, percent, remain, total_bit,
					(total_bit - remain) * 4 * 1000/ (1 + jiffies_to_msecs(end_jif - start_jif)) );
			last_percent = percent;
		}
		/**
		 *这个表明所有数据都已经发送完，只用等待dbm被清空
		 */
		if(!(zone_index < nr_zones ||
					atomic_read(&dbm->dbm_sync_param->pending_io) >0 ||
					hadm_queue_len(delta_packet_queue))) {
			if(packet_send != total_bit){
				/**BUG: 这说明bitmap里的nr_bit统计不准确**/
				/**Never to here, but sometimes BUGS**/
				pr_info("BUG: nr_bit of hadm%d node %d's dbm is mismatch.\n", node->hadmdev->minor, node->id);
				atomic_sub((total_bit - packet_send), &dbm->nr_bit);
			}
			msleep(1000);
			continue;
		}

		/**
		 * 每次从dbm_record->page里读取一个unsigned long（8位），读取本地数据，
		 * 然后生成packet，执行packet_send(在end_io函数里执行）
		 * 这里相当于一次发送64个page的bdev数据，所以需要等待队列里有64个空位
		 * 如果没有，继续执行packet_send
		 */
		/*
		 *使用一个变量，保存所有未完成的io个数，如果pending io > 队列free长度，
		 * 则不再提交io，等把队列里的内容发送出去才清空
		 */
		if(zone_index < nr_zones && 
				atomic_read(&node->dbm->dbm_sync_param->pending_io) + BITS_PER_LONG  <
				hadm_queue_free_space(node->dbm->dbm_sync_param->delta_packet_queue)
				) {
			dbm_offset = record_start_bit + record_index * BITS_PER_LONG;
#ifdef DBM_DEBUG
			pr_info("%s: dbm_read_delta_data_async node %d, record_start_bit %lu,  dbm_offset %lu, data %lx\n, pending_io=%u",
					__FUNCTION__,
					node->id, record_start_bit, dbm_offset, data[record_index], 
					atomic_read(&node->dbm->dbm_sync_param->pending_io));
			hadm_queue_dump(__FUNCTION__, node->dbm->dbm_sync_param->delta_packet_queue);
#endif
			ret = dbm_read_delta_data_async(node, dbm_offset, data[record_index]);
			if(ret)
				break;
			/**
			 *扫描完dbm_record的page里的8个字节
			 *如果扫描完一个dbm_record, 则page_index需要+1
			 */
			record_index++;
			if(record_index >= PAGE_SIZE/sizeof(unsigned long)) {
				page_index++;
				record_index = 0;
				if(page_index >= dbm->dbm_zones[zone_index]->record_num){
					zone_index ++;
					page_index = 0 ;
				}
				if(zone_index < nr_zones){
					if(page_index < dbm->dbm_zones[zone_index]->record_num){
						dbm_record = &dbm->dbm_zones[zone_index]->bz_record[page_index];
						data = (unsigned long *)page_address(dbm_record->page);
						record_start_bit = dbm_record->page_number << (PAGE_SHIFT + BYTE_SHIFT);
					}else {
						pr_info("%s: nr_zones=%d, zone_index=%d, dbm_zone->record_num=%d, page_index=%d, record_index=%d\n",
								__FUNCTION__,
								nr_zones, zone_index, dbm->dbm_zones[zone_index]->record_num, page_index, record_index);

						hadmdev_set_error(node->hadmdev, __BWR_ERR);
						ret = -EIO;
						break;
					}
				}
			}

		}else{

		}
		for(;;) {
			pack_node = (struct hadm_pack_node *)hadm_queue_pop_nowait(delta_packet_queue);
			if(IS_ERR_OR_NULL(pack_node)) {
				break;
			}
			packet_node_send(pack_node, 1);
			packet_send ++;
		}
	}


#if 0
	for (i = 0; i < nr_zones; i++) {
		for (j = 0; j < dbm_zones[i]->record_num; j++) {
			dbm_record = &dbm->dbm_zones[i]->bz_record[j];
			ret = __dbm_delta_sync_record(node, dbm_record);
			if (ret < 0) {
				pr_err("%s delta_sync record faild.\n", __FUNCTION__);
				goto done;
			}
			if (!--total_pages)
				goto done;
		}
	}
#endif
	end_jif = jiffies;
	wait_event(node->dbm->dbm_sync_param->wait,
			atomic_read(&node->dbm->dbm_sync_param->pending_io) == 0);
	pr_info("%s hadm%d node %d:terminate with retcode=%d, total_bit = %lu, remain = %lu, time cost %u ms, sync_rate = %lu KBytes/Sec\n",
			__FUNCTION__, node->hadmdev->minor, node->id, 
			ret, total_bit, remain, jiffies_to_msecs(end_jif - start_jif),
			(total_bit - remain) * 4 * 1000/ ( 1 + jiffies_to_msecs(end_jif - start_jif)) );
	return ret;
}

int dbm_delta_sync(struct hadm_node *node)
{
	return  __dbm_delta_sync(node);

}


int dbm_fullsync(struct hadm_node *node)
{
	unsigned long remain;
	int ret = 0 ;
	sector_t sector,bdev_sector;
	int cstate;
	struct dbm *dbm = node->dbm;
	struct hadm_queue *delta_packet_queue = NULL;
	struct hadm_pack_node *pack_node = NULL;
	unsigned long nr_bit, total_bit;
	int last_percent = 100 , percent;
	unsigned long start_jif = jiffies, end_jif;

	bdev_sector=node->hadmdev->bdev_disk_size;
	/**
	 *这里按照dbm对应的大小搜索磁盘，如果sector超过
	 *bdev_sector，则将对应的dbm置0
	 */
	total_bit = nr_bit = atomic_read(&node->dbm->nr_bit);
	pr_info("start fullsync device hadm%d to node %d, bdev_sector=%llu, dbm->data_size=%lu, nr_bit=%lu\n",
			node->hadmdev->minor, node->id,
			(unsigned long long)bdev_sector,
			(unsigned long)node->dbm->disk_size,
			nr_bit);
	delta_packet_queue = dbm->dbm_sync_param->delta_packet_queue;

	sector = 0 ;
	while ((remain = atomic_read(&node->dbm->nr_bit)) > 0) {
		cstate = hadm_node_get(node,SECONDARY_STATE,S_CSTATE);
		if(cstate != C_DELTA_SYNC_DBM){
			pr_info("%s: hadm%d node %d cstate is NOT C_DELTA_SYNC", __FUNCTION__,
					node->hadmdev->minor, node->id);
			ret = -EKMOD_CSTATE;
		}
		if(hadm_thread_get_state(node->delta_sync)!=HADM_THREAD_RUN) {
			ret = -EKMOD_DELTA_SYNC_EXIT;
		}
		if(hadmdev_error(node->hadmdev)){
			ret = -EIO;
		}
		if(ret){
			if(atomic_read(&dbm->dbm_sync_param->pending_io)) {
				msleep(1000);
				continue;
			}else {
				break;
			}
		}
		percent = 100UL * remain / total_bit;
		if( last_percent - percent >= 10) {
			end_jif = jiffies;
			pr_info("%s: fullsync hadm%d to node %d, block remained = %d%%(%lu), last sector = %lu, sync rate = %lu KBytes/Sec",
					__FUNCTION__, node->hadmdev->minor, node->id, percent, remain, sector,
					(total_bit - remain) * 4 * 1000/ ( 1 + jiffies_to_msecs(end_jif - start_jif)) );
			last_percent = percent;
		}

		/**
		 *这里说明所有的数据都已经发送给对方，等待同步完成了
		 */
		if(!(sector < (node->dbm->disk_size >> HADM_SECTOR_SHIFT) ||
					atomic_read(&dbm->dbm_sync_param->pending_io) ||
					hadm_queue_len(dbm->dbm_sync_param->delta_packet_queue) > 0))  {
			/**
			 *确认所有dbm对应的sector是否发送出去
			 */
			if(nr_bit != 0){
				BUG();
			}
			msleep(1000);
			continue;
		}


		/**
		 *这里为什么要*2？ 因为当发送P_FULLSYNC_MD5，对端节点会发送P_FULLSYNC_DATA_REQ
		 *这时候，在__p_fullsync_data_request里无法等待队列有空闲空间，所以在这里预先等待
		 *因为1个P_FULLSYNC_MD5至多产生一个新的data_request包
		 */
		if(sector < (node->dbm->disk_size >> HADM_SECTOR_SHIFT)) {
			if(sector + 8 > bdev_sector){
				dbm_clear_sector(node->dbm, sector);
				nr_bit--;
				sector += 8;
			}else if(hadm_queue_reserve_timeout(dbm->dbm_sync_param->delta_packet_queue, 
						1, 0) == 0){
				delta_sync_read_page_async(node, sector, P_FULLSYNC_MD5);
				nr_bit--;
				sector += 8 ;
			}
		}
		for(;;) {
			pack_node = (struct hadm_pack_node *)hadm_queue_pop_nowait(delta_packet_queue);
			if(IS_ERR_OR_NULL(pack_node)) {
				break;
			}
			wake_up(&dbm->dbm_sync_param->wait);
			if(pack_node->pack->type == P_FULLSYNC_MD5) {
				fullsync_md5_hash(pack_node->pack->data, PAGE_SIZE, pack_node->pack->md5);
			}
			packet_node_send(pack_node, 1);
		}



	}
	end_jif = jiffies;
	pr_info("fullsync hadm%d to node %d terminated, dbm total_bit = %lu, remained = %lu, ret = %d, time costed = %u ms, sync rate = %lu KBytes/Sec\n",
			dbm->node->hadmdev->minor, 
			dbm->node->id, total_bit, remain, ret, jiffies_to_msecs(end_jif - start_jif),
			(total_bit - remain) * 4 * 1000/ (1 + jiffies_to_msecs(end_jif - start_jif)) );
	return ret;
}

struct dbm_record *dbm_find_record(struct dbm *dbm, int nr)
{
	struct dbm_record *dbm_record;
	int zone_index = nr/DBM_ZONE_RECORDS;
	int rec_index = nr%DBM_ZONE_RECORDS;
	if(dbm->dbm_zones[zone_index] == NULL || rec_index >= dbm->dbm_zones[zone_index]->record_num){
		pr_err("%s: find hadm%d record error, nr = %d, zone_index = %d, rec_index = %d \n",
				__FUNCTION__, dbm->node->hadmdev->minor, 
				nr, zone_index, rec_index);
		return NULL;
	}
	dbm_record = &dbm->dbm_zones[zone_index]->bz_record[rec_index];
	if (!dbm_record->page)
	{
		pr_err("nr:%d.\n", nr);
		return NULL;
	}
	return dbm_record;
}

static sector_t dbm_record_sector(struct dbm *dbm, struct dbm_record *dbm_record)
{
	return dbm->start_sector + (dbm_record->page_number << (PAGE_SHIFT - HADM_SECTOR_SHIFT));
}

ssize_t dbm_load(struct dbm *dbm)
{
	int i, err, total_pages;
	ssize_t total_bits = 0;
	size_t total_size = 0 ;
	int read_bytes; sector_t sector;
	struct dbm_record *dbm_record;
	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);
	total_size = DIV_ROUND_UP(dbm->disk_size , DBM_BDEV_SIZE_PER_BYTE);
	sector = dbm->start_sector;
	for (i = 0; i < total_pages ; i++) {
		dbm_record = dbm_find_record(dbm, i);
		read_bytes = total_size > PAGE_SIZE ? PAGE_SIZE : total_size;
		err = hadm_read_page_sync(dbm->bdev, sector, dbm_record->page, read_bytes);
		if(err) {
			pr_err("%s hadm%d node %d load dbm %d page faild.\n", __FUNCTION__, 
					dbm->node->hadmdev->minor, dbm->node->id, i);
			return err;
		}
		total_bits += nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		sector += 8;
		total_size -= read_bytes;
	}

	return total_bits;
}

int dbm_store_record(struct dbm *dbm, struct dbm_record *dbm_record)
{
	int ret;
	sector_t sector;
	struct page *page;
	struct hadm_io hadm_io_vec[1];

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s alloc page faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	hadm_io_vec[0].page = page;
	hadm_io_vec[0].start = 0;
	hadm_io_vec[0].len = PAGE_SIZE;

	spin_lock(&dbm->dbm_lock);
	memcpy(page_address(page), page_address(dbm_record->page), PAGE_SIZE);
	spin_unlock(&dbm->dbm_lock);

	sector = dbm_record_sector(dbm, dbm_record);
	ret = hadm_io_rw_sync(dbm->bdev, sector, WRITE, hadm_io_vec, 1);
	if (ret < 0) {
		pr_err("%s write faild.(%d)\n", __FUNCTION__, ret);
		goto done;
	}

done:
	__free_page(page);
	return ret;
}

ssize_t dbm_store(struct dbm *dbm)
{
	int ret = 0;
	struct dbm_record *dbm_record, *last_record;
	struct page *page;
	sector_t sector;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s alloc page faild.\n", __FUNCTION__);
		return -ENOMEM;
	}

	last_record = dbm_last_dirty_record(dbm);
	while ((dbm_record = dbm_pop_dirty_record(dbm)) != NULL) {
		struct hadm_io hadm_io_vec[] = {
			{page, 0, PAGE_SIZE},
		};

		sector = dbm_record_sector(dbm, dbm_record);
		memcpy(page_address(page), page_address(dbm_record->page), PAGE_SIZE);
		ret = hadm_io_rw_sync(dbm->bdev, sector, WRITE, hadm_io_vec, 1);
		if (ret < 0) {
			pr_err("%s store dbm_record faild.\n", __FUNCTION__);
			goto done;
		}
#ifdef DBM_DEBUG
		pr_info("%s store sector:%lu. nr_bits:%llu, dbm_record:%p.\n", __FUNCTION__,
				sector, nr_bits(page_address(page), 0, PAGE_SIZE),
				dbm_record);
#endif
		if (dbm_record == last_record) {
			ret = 1;
			break;
		}
	}
done:
	__free_page(page);
	return ret;
}

/**TODO tunable**/
int time_to_flush_dbm(struct dbm *dbm)
{
	int ret=0;

	spin_lock(&dbm->dbm_lock);
	ret=time_before(dbm->last_flush_time + (DBM_FLUSH_INVL*HZ), jiffies);
	spin_unlock(&dbm->dbm_lock);

	return ret;
}

void set_last_flush_time(struct dbm *dbm)
{

	spin_lock(&dbm->dbm_lock);
	dbm->last_flush_time=jiffies;
	spin_unlock(&dbm->dbm_lock);
}

int reset_dbm(struct hadmdev *dev)
{
	struct hadm_node *hadm_node;
	list_for_each_entry(hadm_node, &dev->hadm_node_list, node) {
		if(hadm_node->id != get_node_id()) {
			pr_info("clean hadm%d dbm for node:%d.\n", hadm_node->hadmdev->minor, hadm_node->id);
			dbm_clear_bit_all(hadm_node->dbm);
			dbm_store(hadm_node->dbm);
		}
	}
	return 0;
}
