#ifndef __BIO_BUFFER_H
#define __BIO_BUFFER_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/semaphore.h>
#include <linux/mm_types.h>

#define HASH_ENTRIES_SHIFT 12
#define HASH_ENTRIES (1 << HASH_ENTRIES_SHIFT)

#ifndef BUFF_DEBUG
#define BUFF_DEBUG 0
#endif

#define BUFFER_DEBUG(...) \
	do { if (BUFF_DEBUG) pr_info(__VA_ARGS__); } while (0)
struct bio_wrapper;
struct data_buffer {
	spinlock_t lock;
	struct list_head data_list;
        struct hlist_head *hash_list;
	struct semaphore data_sema;	/* for consumer */
	struct completion not_full;	/* for producer */

	struct bwr_data *inuse_head;   /*head for data that not written to bdev*/
	struct bwr_data *io_completed_tail; /*the last io complete bwr_data*/
	sector_t io_completed_seq; /**the last io completed seq**/
	uint64_t tail_seq;
	int64_t maxsize;
	int64_t inuse_size;
	int64_t data_size;

	void *private;
};

static inline void buffer_set_tail_seq(struct data_buffer *buffer, uint64_t seq)
{
	buffer->tail_seq = seq;
}

static inline void _buffer_set_io_completed_seq(struct data_buffer *buffer, sector_t seq)
{
	buffer->io_completed_seq = seq;
}


struct data_buffer *init_data_buffer(uint64_t maxsize, void *private);
void clear_data_buffer(struct data_buffer *buffer);
void free_data_buffer(struct data_buffer *buffer);
int buffer_is_full(struct data_buffer *buffer);
int buffer_inuse_is_full(struct data_buffer *buffer);
int buffer_inuse_is_empty(struct data_buffer *buffer);

struct bwr_data *get_find_data_by_bwr(struct data_buffer *buffer, sector_t bwr_sector, sector_t prev_bwr_seq);
struct bwr_data *get_find_data(struct data_buffer *buffer, sector_t disk_sector);
struct bwr_data *get_buffer_next_data(struct data_buffer *buffer, struct bwr_data *prev);
struct bwr_data *__get_buffer_next_data(struct data_buffer *buffer, struct bwr_data *prev);
struct bwr_data *get_find_data_hash(struct data_buffer *buffer, sector_t disk_sector);
struct bwr_data *get_find_data_inuse(struct data_buffer *buffer, sector_t disk_sector);
struct bwr_data *get_head_data_inuse(struct data_buffer *buffer);
struct bwr_data *get_tail_data_inuse(struct data_buffer *buffer);
int buffer_data_add(struct data_buffer *buffer, struct bwr_data *bwr_data);
int buffer_data_seq_add(struct data_buffer *buffer, struct bwr_data *bwr_data);
int buffer_data_seq_add_occd(struct data_buffer *buffer, struct bwr_data *bwr_data);
void buffer_inuse_pre_occu(struct data_buffer *buffer);
void buffer_inuse_del_occd(struct data_buffer *buffer);
int buffer_inuse_del(struct data_buffer *buffer, struct bwr_data *entry);
void buffer_set_io_completed(struct bio_wrapper *bio_wrapper);
void buffer_add_bio_wrapper(struct bio_wrapper *bio_wrapper);
void buffer_set_io_completed_seq(struct data_buffer *buffer, sector_t seq);

#endif          /* __BIO_BUFFER */
