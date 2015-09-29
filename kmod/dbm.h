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

struct hadm_site;
struct bwr;
struct bwr_data;

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

#define DBM_ZONE_SIZE_SHIFT	(20)
#define DBM_ZONE_SIZE	(1 << DBM_ZONE_SIZE_SHIFT)	/* default KMALLOC_MAX_SIZE */
#define DBM_ZONE_RECORDS_SHIFT	(DBM_ZONE_SIZE_SHIFT - 5) /* FIXME: compile time caculate */
#define DBM_ZONE_RECORDS	(1 << DBM_ZONE_RECORDS_SHIFT)

struct dbm_zone{
	struct dbm_record bz_record[DBM_ZONE_RECORDS];
};

extern struct dbm_zone **alloc_dbm_zones(gfp_t gfp_flag, uint64_t disk_size);
extern void free_dbm_zones(struct dbm_zone **dbm_zones, int nr_zone);

#define DBM_BDEV_SIZE_PER_BIT	(1ULL << PAGE_SHIFT)
#define DBM_BDEV_SIZE_PER_BYTE	(DBM_BDEV_SIZE_PER_BIT << BYTE_SHIFT)
#define DBM_BDEV_SIZE_PER_PAGE	(DBM_BDEV_SIZE_PER_BYTE << PAGE_SHIFT)
#define DBM_BDEV_SIZE_PER_ZONE	(DBM_BDEV_SIZE_PER_PAGE << DBM_ZONE_RECORDS_SHIFT)

#define DBM_FLUSH_MAX_DEPTH 128
struct dbm_flush_info {
	unsigned long flags;	// reserved
	sector_t head;
	atomic_t count;
	int maxcount;
};

struct dbm {
	spinlock_t dbm_lock;
	uint64_t last_flush_time;

	atomic_t nr_bit;
	struct dbm_zone **dbm_zones;
	struct dbm_record *last_dirty_record;
	struct dbm_flush_info dsi;

	sector_t start_sector;	/* start sector in bwr device */
	uint64_t disk_size;	/* bdev size */
	struct block_device *bdev;	/* bwr device */
	struct hadm_site *site;	/* point back */
	void *private;
};
#define dbm_record_is_dirt(dbm_record) (dbm_record->next != NULL)

#define DSI_DBM(pdsi) container_of((pdsi), struct dbm, dsi)

extern struct dbm *alloc_dbm(gfp_t gfp_mask, struct block_device *bdev,
		struct hadm_site *site, uint64_t data_size, sector_t start_sector);
extern int dbm_init(struct dbm *dbm, struct block_device *bdev, sector_t start, size_t data_size);
extern struct dbm *dbm_create(struct block_device *bdev, sector_t start,
			     struct hadm_site *site, uint64_t disk_size, int gfp_flag);
extern void free_dbm(struct dbm *dbm);

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

extern int dbm_delta_sync(struct hadm_site *site);
extern int dbm_fullsync(struct hadm_site *site);
extern int dbm_gen(struct hadm_site *site);

extern ssize_t dbm_store_bit(struct dbm *dbm, uint32_t nr);
extern ssize_t dbm_store(struct dbm *dbm);
extern ssize_t dbm_store_async(struct dbm *dbm);
extern ssize_t dbm_load(struct dbm *dbm);
extern int time_to_flush_dbm(struct dbm *dbm);
extern void set_last_flush_time(struct dbm *dbm);

#endif	/* DBM_H */
