#ifndef HADM_BIO_H
#define HADM_BIO_H

#include <linux/blkdev.h>

struct hadm_io {
	struct page *page;
	int start;
	int len;
};

typedef void (abi_callback_t) (void *data);

/* abi->bmap len, now fixed to 64 */
#define HADM_ABI_MAX_COUNT (sizeof(unsigned long) * 8)
#define HADM_ABI_MAX (1UL << (HADM_ABI_MAX_COUNT - 1))

#define ABI_DATA_FREE	0x100
#define ABI_DATA_FINISH 0x200
#define ABI_DATA_ABORT  0x400

/*
 * 一个简单的异步写入框架
 * 支持最多同时下发64个写入操作，用于支持dbm, bwr meta等
 * 并发不多，但是同步又影响性能的场景
 */
struct async_backing_info {
	unsigned long flags;
	spinlock_t lock;
	unsigned long bmap;	//FIXME ffs/fls require sizeof(int) == sizeof(uint64_t)
	int start;
	union {
		struct abi_data {
			int idx;
			abi_callback_t *endio;
			void *data;
		} data[HADM_ABI_MAX_COUNT];

		char __data;
	};
};

void abi_init(struct async_backing_info *abi);
void abi_destroy(struct async_backing_info *abi);
int abi_add(struct async_backing_info *abi, struct block_device *bdev,
		sector_t offset, struct hadm_io *io_vec, int nr_vec,
		abi_callback_t *endio, void *data);
void abi_dump(const char *msg, struct async_backing_info *abi);

extern int hadm_io_rw_sync(struct block_device *bdev, sector_t sector, int rw,
		struct hadm_io io_vec[], int nr_vecs);

extern int hadm_io_rw_async(struct block_device *, sector_t, int rw,
		struct hadm_io [], int , bio_end_io_t, void *);
extern int hadm_read_bwr_block(struct block_device *bdev, sector_t sector,
			      char *buf, int buflen);

extern int hadm_bio_write_sync(struct block_device *bdev, sector_t sector,
			       char *buf, int buflen);
extern int fullsync_read_page(struct block_device *bdev,sector_t offset, char *data);
extern int hadm_read_page_sync(struct block_device *bdev,sector_t offset, struct page *page,size_t size);
extern int hadm_write_page_sync(struct block_device *bdev, sector_t offset, struct page *page, size_t size);
extern int hadm_read_page_async(struct block_device *, sector_t, struct page *,
		size_t, bio_end_io_t, void *);
extern int hadm_write_page_async(struct block_device *, sector_t, struct page *,
		size_t, bio_end_io_t, void *);
extern void dump_hadm_io_vec(struct hadm_io *vec, int len);
extern void dump_kvec(struct kvec *vec, int len);

#endif	/* HADM_BIO_H */
