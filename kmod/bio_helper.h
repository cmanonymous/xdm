#ifndef __BIO_HELPER_H__
#define __BIO_HELPER_H__

#include "hadm_queue.h"

/* HADM bio flags mask:
 * BIO_CLONED: hadm bio always own data
 */
#define HADM_BIO_FLAGS_MASK ((-1ULL) & ~(1 << BIO_CLONED))
#define MAX_BIO_WRAPPER_LIST_SIZE (1 << 14)
#define META_SIZE 512

struct bio_struct {
	struct list_head list;

	int idx;
	struct bio *bio;
	struct bio_wrapper *wrapper;
	void *private;
};

struct meta {
	union {
		sector_t dev_sector;
		char pack[META_SIZE];
	};
};

enum bio_wrapper_flag {
	__bw_remote,
};

struct bio_wrapper {
	struct list_head node;		/* bio_wrapper list */
	unsigned long flags;
	uint32_t err;			/* bio err flag */
	union {				/* local or remote bio */
		struct bio *bio;
		struct hdpacket *pack;
	};
	atomic_t count;
	struct list_head bio_list;

	struct hadmdev *hadmdev;	/* useful for end_io */

	unsigned long start_jif;
};

#define wrapper_remote(wrapper) test_bit(__bw_remote, &(wrapper)->flags)

struct buffer_data {
	sector_t dev_sector;
	sector_t bwr_sector;
	struct page *data;
};

struct bio;
struct hdpacket;

void hadm_bio_list_free(struct list_head *bio_list);
void hadm_bio_list_dump(struct bio_list *bio_list); /* FIXME */
int submit_bio_wrapper(struct bio_wrapper *wrapper);
void free_bio_wrapper(struct bio_wrapper *bio_w);
void subbio_read_endio(struct bio *bio, int err);
void subbio_write_endio(struct bio *bio, int err);

struct bio_wrapper *alloc_bio_wrapper(void);
struct bio_wrapper *init_bio_wrapper(struct bio *bio, bio_end_io_t *end_io);
struct bio_wrapper *hadmdev_create_local_wrapper(struct hadmdev *dev,
		struct bio *bio);
struct bio_wrapper *hadmdev_create_remote_wrapper(struct hadmdev *dev,
		struct hdpacket *pack);

void bio_wrapper_prepare_io(struct bio_wrapper *bio_wrapper);
void bio_wrapper_end_io(struct bio_wrapper *bio_wrapper,int error);
int bio_wrapper_add_meta(void);

void pr_c_content(void *addr, unsigned int size);
void pr_content(void *addr, unsigned int size);
void dump_bio(struct bio *bio, const char *msg);
void dump_bio_wrapper(struct bio_wrapper *bio_wrapper);

struct bwr_data;
struct bio_struct *create_bio_struct(struct bio* bio,
		struct bio_wrapper *wrapper, struct bwr_data *bwr_data, int idx);
void free_bio_struct(struct bio_struct *bio_struct);

struct kvec *kvec_create_from_bio(struct bio *bio);
int bio_add_meta_page(struct bio *bio);
void bio_free_pages(struct bio *bio);
int bio_add_bwr_data(struct bio *bio, int pages);

void bio_wrapper_add_bwr_meta(struct bio_wrapper *bio_wrapper);
void bio_struct_fill_bwrinfo(struct bio_struct *bio_struct);

struct bwr;
int wait_sync_node_finsh(struct bwr *bwr);

void wrapper_queue_free(struct hadm_queue *);

int valid_wrapper(struct bio_wrapper *wrapper);


/* ------------------------------------------------------------------------- */
/* slaver bio */

struct sbio {
	struct list_head list;
	struct bio *bio;
};

struct sbio *sbio_create(struct bio *bio, gfp_t gfp_flag);
void sbio_free(struct sbio *sbio);

#endif // __BIO_HELPER_H__
