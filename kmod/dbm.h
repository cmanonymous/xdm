#ifndef DBM_H
#define DBM_H

#include <linux/list.h>
#include <linux/blkdev.h>

#define PAGE_BIT_MASK ((1 << (PAGE_SHIFT + BYTE_SHIFT)) - 1)
#ifndef SCAN_BLOCK
#define SCAN_BLOCK 4096
#define SCAN_BLOCK_SHIFT 12
#endif

#ifndef RESCAN_TIMEOUT
#define RESCAN_TIMEOUT 180	/* 3 minutes */
#endif	/* RESCAN_TIMEOUT */

#define DBM_FLUSH_INVL	1
struct hadm_node;
struct bwr;
struct bwr_data;
/*
 *dbm指向每个节点在bwr上对应的bitmap
 *考虑到内核的限制（一个连续的内存块大小不能超过4M），所以一
 *个dbm zone的大小为4M，包含4M/sizeof(dbm_record) = 128K个dbm record
 *一个dbm record包含一个page(4k)的dbm，对应4k*8*4k=128M 的bdev的数据。
 *从而一个dbm zone可以标示  128M*128K=16T的数据
 */
#define DBM_RECORD_SIZE_SHIFT	5
#define DBM_RECORD_SIZE		(1 << DBM_RECORD_SIZE_SHIFT)
struct dbm_record {
	union {
		struct {
			uint64_t page_number;
			struct page *page;
			struct dbm_record *next;
		};
		char data[32];
	};
};

extern struct dbm_record *alloc_dbm_record(gfp_t flags, uint64_t page_number);
extern void free_dbm_record(struct dbm_record *dbm_record);

#define DBM_ZONE_SIZE_SHIFT	(22)
#define DBM_ZONE_SIZE	(1 << DBM_ZONE_SIZE_SHIFT)	/* default KMALLOC_MAX_SIZE */
#define DBM_ZONE_RECORDS_SHIFT	(DBM_ZONE_SIZE_SHIFT - 5) /* FIXME: compile time caculate */
#define DBM_ZONE_RECORDS	((DBM_ZONE_SIZE >> DBM_RECORD_SIZE_SHIFT) - 1)

/*
 *一个dbm_zone至多包含 DBM_ZONE_RECORDS=128K的dbm_record 
 */

struct dbm_zone{
	/*
	 * TODO DBM_ZONE_RECORDS 指向4M的内存，能够标示16T BDEV的bitmapi
	 * 通常磁盘没有这么大的时候，可以动态分配bz_record，这样，可以减少内存
	 * 的占用
	 **/
	//struct dbm_record bz_record[DBM_ZONE_RECORDS];
	int record_num;
	struct dbm_record *bz_record;
};

extern struct dbm_zone **alloc_dbm_zones(gfp_t gfp_flag, uint64_t disk_size);
extern void free_dbm_zones(struct dbm_zone **dbm_zones, int nr_zone);

#define DBM_BDEV_SIZE_PER_BIT	(1ULL << PAGE_SHIFT)
#define DBM_BDEV_SIZE_PER_BYTE	(DBM_BDEV_SIZE_PER_BIT << BYTE_SHIFT)
#define DBM_BDEV_SIZE_PER_PAGE	(DBM_BDEV_SIZE_PER_BYTE << PAGE_SHIFT)
#define DBM_BDEV_SIZE_PER_ZONE	(DBM_BDEV_SIZE_PER_PAGE * DBM_ZONE_RECORDS)

struct dbm_sync_param {
	atomic_t pending_io; /* 在delta_sync/full_sync里记录已提交但位返回的读io个数 */
	struct hadm_queue *delta_packet_queue; /* 在delta_sync/full_sync保存异步io提交的packet node */
	wait_queue_head_t wait;
};
struct dbm {
	spinlock_t dbm_lock;
	unsigned long last_flush_time;

	atomic_t nr_bit;
	struct dbm_zone **dbm_zones;
	struct dbm_record *last_dirty_record;

	sector_t start_sector;	/* start sector in bwr device */
	uint64_t disk_size;	/* bdev size */
	struct block_device *bdev;	/* bwr device */
	struct hadm_node *node;	/* point back */
	struct dbm_sync_param *dbm_sync_param; /* param used in dleta sync */
	void *private;
};
#define dbm_record_is_dirt(dbm_record) (dbm_record->next != NULL)

extern struct dbm *alloc_dbm(gfp_t gfp_mask, struct block_device *bdev,
		struct hadm_node *node, uint64_t data_size, sector_t start_sector);
extern int dbm_init(struct dbm *dbm, struct block_device *bdev, sector_t start, size_t data_size);
extern struct dbm *dbm_create(struct block_device *bdev, sector_t start,
			     struct hadm_node *node, uint64_t disk_size, int gfp_flag);
extern void free_dbm(struct dbm *dbm);
extern int reset_dbm(struct hadmdev *dev);

extern void pr_dbm_bits(struct hadmdev *dev);
extern void dbm_dump(struct dbm *dbm);
extern int dbm_nr_bits_seted(struct dbm *dbm);
extern int dbm_test_bit(struct dbm *dbm, size_t n);
extern int dbm_set_sector(struct dbm *dbm, sector_t sector);
extern int dbm_set_bit(struct dbm *dbm, uint64_t bit);
extern void dbm_set_bit_all(struct dbm *dbm);
extern int dbm_clear_sector(struct dbm *dbm, sector_t sector);
extern int dbm_clear_bit(struct dbm *dbm, uint64_t bit);
extern void dbm_clear_bit_all(struct dbm *dbm);
extern sector_t dbm_to_sector(size_t n);
extern struct dbm_record *dbm_find_record(struct dbm *dbm, int nr);
extern void dbm_dirty_record(struct dbm *dbm, struct dbm_record *dbm_record);

extern int dbm_delta_sync(struct hadm_node *node);
extern int dbm_fullsync(struct hadm_node *node);
extern int dbm_gen(struct hadm_node *node);

extern ssize_t dbm_store_bit(struct dbm *dbm, uint32_t nr);
extern ssize_t dbm_store(struct dbm *dbm);
extern ssize_t dbm_load(struct dbm *dbm);
extern int time_to_flush_dbm(struct dbm *dbm);
extern void set_last_flush_time(struct dbm *dbm);

extern int delta_sync_read_page_async(struct hadm_node *node, sector_t bdev_offset, int p_type);
extern struct dbm_sync_param *dbm_sync_param_create(struct dbm *dbm);

extern void dbm_sync_param_free(struct dbm *dbm);
#endif	/* DBM_H */
