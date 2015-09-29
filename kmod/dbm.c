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
#include "hadm_site.h"
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

void free_dbm_record(struct dbm_record *dbm_record)
{
	if (dbm_record) {
		pr_info("free dbm_record:%p page:%p.\n", dbm_record, dbm_record->page);
		if (dbm_record->page)
			__free_page(dbm_record->page);
		kfree(dbm_record);
	}
}

void free_dbm_zones(struct dbm_zone **dbm_zones, int nr_zone)
{
	int i, j;
	struct dbm_record *dbm_record;

	if (dbm_zones) {
		for (i = 0; i < nr_zone; i++) {
			if (dbm_zones[i]) {
				for (j = 0; j < DBM_ZONE_RECORDS; j++) {
					dbm_record = &dbm_zones[i]->bz_record[j];
					if (dbm_record->page)
						__free_page(dbm_record->page);
					else
						break;
				}
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
	uint64_t total_pages;
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
		dbm_zones[i] = (struct dbm_zone *)kzalloc(sizeof(struct dbm_zone), gfp_flag);
		if (!dbm_zones[i]) {
			pr_err("%s alloc dbm_zones[%d] faild.\n", __FUNCTION__, i);
			goto alloc_faild;
		}
		pr_info("%s alloc dbm_zone %p.\n", __FUNCTION__, dbm_zones[i]);
		/* perharps, we could allocate pages when real set dbm */
		for (j = 0; j < DBM_ZONE_RECORDS; j++) {
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
			pr_info("init dbm_record:%p, page:%p. page_num:%llu.\n", dbm_record, page, page_num);
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
		struct hadm_site *site, uint64_t disk_size, sector_t start_sector)
{
	struct dbm *dbm;
	struct dbm_zone **dbm_zone;

	dbm = kmalloc(sizeof(struct dbm), gfp_flag);
	if (!dbm) {
		pr_err("%s alloc dbm faild.\n", __FUNCTION__);
		return NULL;
	}
	pr_info("%s alloc dbm %p.\n", __FUNCTION__, dbm);

	dbm_zone = alloc_dbm_zones(gfp_flag, disk_size);
	if (!dbm_zone) {
		pr_err("%s alloc dbm zone faild.\n", __FUNCTION__);
		kfree(dbm);
		return NULL;
	}

	spin_lock_init(&dbm->dbm_lock);
	dbm->site = site;
	dbm->bdev = bdev;
	dbm->disk_size = disk_size;
	dbm->start_sector = start_sector;
	dbm->last_flush_time = jiffies;

	atomic_set(&dbm->dsi.count, 0);
	dbm->dsi.maxcount = DBM_FLUSH_MAX_DEPTH;

	dbm->last_dirty_record = NULL;
	dbm->dbm_zones = dbm_zone;

	return dbm;
}

void free_dbm(struct dbm *dbm)
{
	if (dbm) {
		free_dbm_zones(dbm->dbm_zones,
				DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE));
		pr_info("free dbm:%p.", dbm);
		kfree(dbm);
	}
}

struct dbm *dbm_create(struct block_device *bdev, sector_t start,
			     struct hadm_site *site, uint64_t disk_size, int gfp_flag)
{
	int local_site_id;
	sector_t offset;
	struct dbm *dbm;
	ssize_t nr_bits = 0;

	offset = start + DIV_ROUND_UP(disk_size, DBM_BDEV_SIZE_PER_BYTE * HADM_SECTOR_SIZE) * site->id;
	dbm = alloc_dbm(gfp_flag, bdev, site, disk_size, offset);
	if (!dbm) {
		pr_err("%s alloc dbm faild.\n", __FUNCTION__);
		return NULL;
	}

	local_site_id = get_site_id();
	if (local_site_id != site->id) {
		nr_bits = dbm_load(dbm);
		if (nr_bits > 0) {
			hadm_site_set(dbm->site, SECONDARY_STATE, S_DATA_STATE, DATA_DBM);
			hadm_site_set(dbm->site, SECONDARY_STATE, S_DSTATE, D_INCONSISTENT);
		} else if (nr_bits < 0) {
			pr_err("%s load dbm faild.\n", __FUNCTION__);
			free_dbm(dbm);
			return NULL;
		}
		dbm->site->s_state.dbm_set = nr_bits;
		atomic_set(&dbm->nr_bit, nr_bits);
		pr_info("dbm_create: "
				"id=%d, start=%lu(sector), dbm->disk_size=%lld(byte), disk_size:%llu bits=%d\n",
				site->id,
				offset,
				(long long int)dbm->disk_size,
				disk_size,
				atomic_read(&dbm->nr_bit));
	}
	site->dbm = dbm;

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
		//pr_info("%s: wake up flush.\n", __func__);
		hadm_thread_wake_up(dbm->site->hadmdev->threads[DBM_FLUSH_HANDLER]);
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
		pr_err("%s try set bit %llu beyond scope.\n", __FUNCTION__, bit);
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
		for (j = 0; j < DBM_ZONE_RECORDS; j++) {
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
	uint64_t nbits = sector << HADM_SECTOR_SHIFT >> DBM_SHIFT;

	return dbm_clear_bit(dbm, nbits);
}

/* set/clear 只操作在内存中的 dbm */
int dbm_clear_bit(struct dbm *dbm, uint64_t bit)
{
	int nr_bit, ret = 0;
	struct dbm_record *dbm_record;

	dbm_record = dbm_find_record(dbm, bit >> (DBM_SHIFT + BYTE_SHIFT));
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
		for (j = 0; j < DBM_ZONE_RECORDS; j++) {
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

int dbm_gen(struct hadm_site *site)
{
	sector_t offset;
	int ret = 0,error;
	struct bwr_data_meta *dmeta;
	struct page *page;

	page=alloc_page(GFP_KERNEL);
	if (IS_ERR_OR_NULL(page)) {
		pr_err("%s: no memory\n", __FUNCTION__);
		return -ENOMEM;
	}

	for (;;) {
		offset = bwr_site_head(site->hadmdev->bwr, site->id);
		if (offset == bwr_tail(site->hadmdev->bwr))
			break;
		error=hadm_read_page_sync(site->hadmdev->bwr_bdev,offset,page,HADM_SECTOR_SIZE);
		if (error) {
			pr_err("%s: read bwr failed: want=%d, error=%d\n",
			       __FUNCTION__, HADM_SECTOR_SIZE, error);
			ret = error;
			goto done;
		}
		dmeta=(struct bwr_data_meta *)page_address(page);
		dbm_set_sector(site->dbm, dmeta->dev_sector);

		offset = bwr_next_sector(site->hadmdev->bwr, offset);
		hadm_site_send_head_inc(site);
		bwr_site_head_inc(site->hadmdev->bwr, site->id);
	}

done:
	__free_page(page);
	dbm_store(site->dbm);
	return ret;
}

int dbm_delta_sync_sector(struct hadm_site *site, sector_t sector)
{
	return rssync_site_sector(site, sector);
}

static int __dbm_delta_sync_record(struct hadm_site *site, struct dbm_record *dbm_record)
{
	int i;
	unsigned long nr_bit, start_bit;
	unsigned long tmp, *data;

	data = (unsigned long *)page_address(dbm_record->page);
	start_bit = dbm_record->page_number << (PAGE_SHIFT + BYTE_SHIFT);
	for (i = 0; i < PAGE_SIZE / sizeof(unsigned long); i++) {
		tmp = data[i];
		while (tmp) {
			if (hadm_thread_get_state(site->delta_sync) == HADM_THREAD_EXIT)
				return -EKMOD_DELTA_SYNC_EXIT;
			nr_bit = start_bit + (i << 6) + __ffs(tmp);
			dbm_delta_sync_sector(site, dbm_to_sector(nr_bit));
			tmp &= tmp - 1;
		}
	}

	return 0;
}

/* 前置条件：产生了 dbm； 后置条件：将 dbm 清零，同时将与之相关的数据发送出去 */
static int __dbm_delta_sync(struct hadm_site *site)
{
	int i, j, ret = 0;
	int nr_zones;
	uint64_t total_pages;
	struct dbm_record *dbm_record;
	struct dbm *dbm = site->dbm;

	nr_zones = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_ZONE);
	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);
	for (i = 0; i < nr_zones; i++) {
		for (j = 0; j < DBM_ZONE_RECORDS; j++) {
			dbm_record = &dbm->dbm_zones[i]->bz_record[j];
			ret = __dbm_delta_sync_record(site, dbm_record);
			if (ret < 0) {
				pr_err("%s delta_sync record faild.\n", __FUNCTION__);
				goto done;
			}
			if (!--total_pages)
				goto done;
		}
	}

done:
	return ret;
}

int dbm_delta_sync(struct hadm_site *site)
{
	struct hadmdev *hadmdev;
	struct dbm *dbm;
	uint64_t remain, last_remain;
	int cstate, loop, ret;

	dbm = site->dbm;
	hadmdev = site->hadmdev;

	ret = __dbm_delta_sync(site);
	if (ret == -EKMOD_DELTA_SYNC_EXIT)
		return ret;

	last_remain = 0;
	loop = 0;
	while ((remain = atomic_read(&dbm->nr_bit))) {
		pr_info("dbm_delta_sync: remain=%lu\n", (unsigned long)remain);
		cstate = hadm_site_get(site, SECONDARY_STATE, S_CSTATE);
		if (cstate != C_DELTA_SYNC_DBM) {
			pr_info("%s: cstate is NOT C_DELTA_SYNC_DBM", __FUNCTION__);
			return -EKMOD_CSTATE;
		}
		msleep(1000);
	}

	return 0;
}

static void __dbm_fullsync_bit(struct hadm_site *site, uint64_t dev_sector)
{
	char *data;
	struct page *page;
	struct packet *head;
	struct hdpacket *md5_pack;
	struct hadmdev *hadmdev = site->hadmdev;
	struct hadm_queue *q = g_hadm->p_sender_queue[P_DATA_TYPE];

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		pr_err("%s: no memory\n", __FUNCTION__);
		return;
	}

	/* read data */
	if(hadm_read_page_sync(hadmdev->bdev,dev_sector, page,PAGE_SIZE)){
		pr_err("%s: read sector %llu failed\n",__FUNCTION__,dev_sector);
		__free_page(page);
		return ;
	}
	data=page_address(page);

	md5_pack = site_hdpacket_alloc(GFP_KERNEL, 0, HADM_DATA_NORMAL);
	if (!md5_pack) {
		pr_err("%s: alloc md5 pack faild.\n", __FUNCTION__);
		__free_page(page);
		return;
	}

	head = &md5_pack->head;
	head->type = P_SD_FSYNC_MD5;
	head->dev_id = hadmdev->minor;
	head->uuid = bwr_uuid(hadmdev->bwr);
	head->node_to = (1 << site->id);
	head->dev_sector = dev_sector;
	/* compute md5 */
	fullsync_md5_hash(data, PAGE_SIZE, head->md5);
	__free_page(page);

	/* send md5 packet */
	if (hadm_queue_push(q, &md5_pack->list) < 0) {
		pr_err("%s: push to data queue faild.\n", __FUNCTION__);
		return;
	}
}

int dbm_fullsync(struct hadm_site *site)
{
	uint64_t remain;
	sector_t sector,bdev_sector;
	int cstate;

	bdev_sector=site->hadmdev->bdev_disk_size;
	/**
	 *这里按照dbm对应的大小搜索磁盘，如果sector超过
	 *bdev_sector，则将对应的dbm置0
	 */
	pr_info("start fullsync device %d to site %d, bdev_sector=%llu, dbm->data_size=%lu\n",
			site->hadmdev->minor, site->id,
			(unsigned long long)bdev_sector,
			(unsigned long)site->dbm->disk_size);

	for(sector = 0; sector < (site->dbm->disk_size >> HADM_SECTOR_SHIFT); sector += 8){
		if(sector + 8 > bdev_sector){
			dbm_clear_sector(site->dbm, sector);
			continue;
		}
		cstate=hadm_site_get(site,SECONDARY_STATE,S_CSTATE);
		if(cstate!=C_DELTA_SYNC_DBM){
			pr_info("%s: cstate is NOT C_DELTA_SYNC", __FUNCTION__);
			return -EKMOD_CSTATE;
		}
		if(hadm_thread_get_state(site->delta_sync)!=HADM_THREAD_RUN) {
			return -EKMOD_DELTA_SYNC_EXIT;
		}
		__dbm_fullsync_bit(site,sector);
	}

	pr_info("%s:send %llu sectors to site %d, dbm=%lu\n",
			__FUNCTION__,
			(unsigned long long)sector,
			site->id,
			(unsigned long)atomic_read(&site->dbm->nr_bit));
	while ((remain = atomic_read(&site->dbm->nr_bit))) {
		if(hadm_thread_get_state(site->delta_sync)!=HADM_THREAD_RUN) {
			return -EKMOD_DELTA_SYNC_EXIT;
		}
		msleep(1000);
		cstate = hadm_site_get(site, SECONDARY_STATE, S_CSTATE);
		if (cstate != C_DELTA_SYNC_DBM) {
			pr_info("%s: cstate is NOT C_DELTA_SYNC_DBM", __FUNCTION__);
			return -EKMOD_CSTATE;
		}
		pr_info("dbm_fullsync: remain=%lu,cstate=%s\n",
				(unsigned long)remain,cstate_name[cstate]);
	}

	return 0;
}

struct dbm_record *dbm_find_record(struct dbm *dbm, int nr)
{
	struct dbm_record *dbm_record;
	dbm_record = &dbm->dbm_zones[nr/DBM_ZONE_RECORDS]->bz_record[nr%DBM_ZONE_RECORDS];
	if (!dbm_record->page)
		pr_err("nr:%d.\n", nr);
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
	sector_t sector;
	struct dbm_record *dbm_record;

	total_pages = DIV_ROUND_UP(dbm->disk_size, DBM_BDEV_SIZE_PER_PAGE);
	sector = dbm->start_sector;
	for (i = 0; i < total_pages; i++) {
		dbm_record = dbm_find_record(dbm, i);
		err = hadm_read_page_sync(dbm->bdev, sector, dbm_record->page, PAGE_SIZE);
		if(err) {
			pr_err("%s load %d page faild.\n", __FUNCTION__, i);
			return err;
		}
		total_bits += nr_bits(page_address(dbm_record->page), 0, PAGE_SIZE);
		sector += PAGE_SIZE >> HADM_SECTOR_SHIFT;
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
	sector_t sector;

	last_record = dbm_last_dirty_record(dbm);
	while ((dbm_record = dbm_pop_dirty_record(dbm)) != NULL) {
		struct hadm_io hadm_io_vec[] = {
			{dbm_record->page, 0, PAGE_SIZE},
		};

		sector = dbm_record_sector(dbm, dbm_record);
		ret = hadm_io_rw_sync(dbm->bdev, sector, WRITE, hadm_io_vec, 1);
		if (ret < 0) {
			pr_err("%s store dbm_record faild.\n", __FUNCTION__);
			goto done;
		}
		pr_info("%s store sector:%lu. dbm_record:%p.\n", __FUNCTION__,
				sector, dbm_record);
		if (dbm_record == last_record) {
			ret = 1;
			break;
		}
	}
done:
	return ret;
}

int dsi_valid(struct dbm_flush_info *dsi)
{
	return !!dsi->flags;
}

static int dsi_push(struct dbm_flush_info *dsi, sector_t head)
{
	if (atomic_read(&dsi->count) == dsi->maxcount) {
		pr_info("%s: dsi count :%d.\n", __func__, atomic_read(&dsi->count));
		return -1;
	}

	atomic_inc(&dsi->count);
	dsi->head = head;

	return 0;
}

static void dsi_pop(struct dbm_flush_info *dsi, int err)
{
	unsigned long flags;
	struct hadm_site *site = DSI_DBM(dsi)->site;

	BUG_ON(atomic_read(&dsi->count) <= 0);
	if (atomic_dec_and_test(&dsi->count) && !err) {
		spin_lock_irqsave(&site->s_state.lock, flags);
		if (__hadm_site_get(&site->s_state, S_CSTATE) == C_STOPPED)
			bwr_set_site_head(site->hadmdev->bwr, site->id,
				dsi->head);
		spin_unlock_irqrestore(&site->s_state.lock, flags);
	}
	if (err)
		pr_err("%s: flush dbm failed %d.\n", __func__, err);
}

void dbm_async_endio(struct bio *bio, int err)
{
	struct dbm *dbm = bio->bi_private;

	/* FIXME: err handle? */
	if (err)
		pr_err("%s: err %d.\n", __func__, err);
	dsi_pop(&dbm->dsi, err);
}

ssize_t dbm_store_async(struct dbm *dbm)
{
	int ret = 0;
	unsigned long flags;
	struct hadm_site *site = dbm->site;
	struct dbm_flush_info *dsi = &dbm->dsi;
	struct dbm_record *dbm_record, *last_record;
	struct hadm_io hadm_io_vec[1];
	sector_t sector, head;

	last_record = dbm_last_dirty_record(dbm);
	if (!last_record) {
		/* maybe have flushed, or maybe uptodate already */
		if (!atomic_read(&dbm->dsi.count)) {
			head = hadm_site_get(site, SECONDARY_STATE, S_SND_HEAD);
			spin_lock_irqsave(&site->s_state.lock, flags);
			if (__hadm_site_get(&site->s_state, S_CSTATE) == C_STOPPED)
				bwr_set_site_head(site->hadmdev->bwr, site->id,
						head);
			spin_unlock_irqrestore(&site->s_state.lock, flags);
		}/* else {
			pr_info("%s no more, and %d have not finished.\n", __func__,
					atomic_read(&dbm->dsi.count));
		}
		*/
		goto done;
	}
	//pr_info("%s: last_record %p.\n", __func__, last_record);
	//msleep(1000);
	for (;;) {
		head = hadm_site_get(site, SECONDARY_STATE, S_SND_HEAD);
		if (dsi_push(dsi, head) < 0)
			break;
		dbm_record = dbm_pop_dirty_record(dbm);
		BUG_ON(!dbm_record);

		hadm_io_vec[0].page = dbm_record->page;
		hadm_io_vec[0].start = 0;
		hadm_io_vec[0].len = PAGE_SIZE;

		sector = dbm_record_sector(dbm, dbm_record);
		ret = hadm_io_rw_async(dbm->bdev, sector, WRITE, hadm_io_vec, 1,
				dbm_async_endio, dbm);
		if (ret < 0) {
			pr_err("%s store dbm_record faild.\n", __FUNCTION__);
			goto done;
		}
		if (dbm_record == last_record) {
			ret = 1;
			break;
		}
	}
done:
	return ret;
}

/**TODO tunable**/
#define DBM_FLUSH_INVL	1000
int time_to_flush_dbm(struct dbm *dbm)
{
	int ret=0;

	spin_lock(&dbm->dbm_lock);
	ret=time_before64((unsigned long long)dbm->last_flush_time + (unsigned long long)msecs_to_jiffies(DBM_FLUSH_INVL),
			  (unsigned long long)jiffies);
	spin_unlock(&dbm->dbm_lock);

	return ret;
}

void set_last_flush_time(struct dbm *dbm)
{

	spin_lock(&dbm->dbm_lock);
	dbm->last_flush_time=jiffies;
	spin_unlock(&dbm->dbm_lock);
}
