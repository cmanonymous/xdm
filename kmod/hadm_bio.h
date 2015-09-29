#ifndef HADM_BIO_H
#define HADM_BIO_H

#include <linux/blkdev.h>

struct hadm_io {
	struct page *page;
	int start;
	int len;
};

extern int hadm_io_rw_sync(struct block_device *bdev, sector_t sector, int rw,
		struct hadm_io io_vec[], int nr_vecs);

extern int hadm_read_bwr_block(struct block_device *bdev, sector_t sector,
			      char *buf, int buflen);

extern int hadm_bio_write_sync(struct block_device *bdev, sector_t sector,
			       char *buf, int buflen);
extern int fullsync_read_page(struct block_device *bdev,sector_t offset, char *data);
extern int hadm_read_page_sync(struct block_device *bdev,sector_t offset, struct page *page,size_t size);

extern int hadm_read_page_async(struct block_device *bdev, sector_t sector, bio_end_io_t *bio_end_io, void *private);
#endif	/* HADM_BIO_H */
