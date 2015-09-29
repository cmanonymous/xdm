#ifndef __BIO_HELPER_H__
#define __BIO_HELPER_H__

#include "hadm_queue.h"
#include "p_worker.h"

#define MAX_BIO_WRAPPER_LIST_SIZE (1 << 14)
#define META_SIZE 512

struct bio_struct {
	struct bio *bio;
	sector_t sector;
	int idx;

	struct list_head list;

	struct bio_wrapper *wrapper;
	void *private;
};

struct meta {
	union {
		sector_t dev_sector;
		char pack[META_SIZE];
	};
};

typedef void (bio_wrapper_end_io_t) (void *arg);
struct bio_wrapper {
	struct bio *bio;
	struct list_head bio_list;
	atomic_t count;
	uint32_t err;		/* err flag */

	bio_wrapper_end_io_t *end_io;
	struct hadmdev *hadmdev;     /* useful for end_io */
	struct list_head node; /* bio_wrapper list */
	unsigned long start_jif;
	uint64_t sync_node_mask;
	int local_completed; /*write to bwr and add to buffer*/

	unsigned long crc;
	void *private;
};

struct buffer_data {
	sector_t dev_sector;
	sector_t bwr_sector;
	struct page *data;
};

struct bio;

void hadm_bio_list_free(struct list_head *bio_list);
void hadm_bio_list_dump(struct bio_list *bio_list); /* FIXME */
int submit_bio_wrapper(struct bio_wrapper *wrapper);
int submit_read_wrapper(struct bio_wrapper *wrapper);
void free_bio_wrapper(struct bio_wrapper *bio_w);
void subbio_read_endio(struct bio *bio, int err);
void subbio_write_endio(struct bio *bio, int err);

void primary_data_end_io(void *arg);
struct bio_wrapper *alloc_bio_wrapper(void);
struct bio_wrapper *init_bio_wrapper(struct bio *bio, bio_wrapper_end_io_t *end_io);
struct bio_wrapper *gen_bio_wrapper_from_pack(struct hadm_pack_node *pack_node);
int wrapper_split(struct bio_wrapper *wrapper);
int hadm_bio_split(struct bio_wrapper *wrapper);
int set_sync_mask(void *arg);

void bio_wrapper_prepare_io(struct bio_wrapper *bio_wrapper);
void bio_wrapper_end_io(struct bio_wrapper *bio_wrapper);
int bio_wrapper_add_meta(void);
int bio_add_meta_page(struct bio *bio);

void pr_c_content(void *addr, unsigned int size);
void pr_content(void *addr, unsigned int size);
void dump_bio(struct bio *bio, const char *msg);
void dump_bio_wrapper(struct bio_wrapper *bio_wrapper);

struct bwr_data;
struct bio_struct *init_bio_struct(struct bio* bio, struct bio_wrapper *wrapper, struct bwr_data *bwr_data, int idx);
void free_bio_struct(struct bio_struct *bio_struct);

int bio_add_meta_page(struct bio *bio);
void bio_free_pages(struct bio *bio);
int bio_add_bwr_data(struct bio *bio, int pages);

void bio_wrapper_add_bwr_meta(struct bio_wrapper *bio_wrapper);
void bio_struct_fill_bwrinfo(struct bio_struct *bio_struct);

struct bwr;
int wait_sync_node_finsh(struct bwr *bwr);

int valid_wrapper(struct bio_wrapper *wrapper);

int sync_mask_clear_node(struct bio_wrapper *bio_w,int node_id, int irq_save);
int sync_mask_clear_after_node_disconnect(struct hadmdev *hadmdev, int node_id);
int sync_mask_clear_queue(struct hadmdev *hadmdev, uint64_t sync_mask, uint64_t prev_sync_mask);
void wrapper_queue_io_error(struct hadmdev *hadmdev);
#endif // __BIO_HELPER_H__
