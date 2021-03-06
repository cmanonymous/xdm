#ifndef BWR_H
#define BWR_H

#include <linux/spinlock.h>
#include <linux/blkdev.h>

#include "hadm_def.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "primary_info.h"

#define DEFAULE_META_OFFSET (0L)
#define DEFAULT_BWR_DATA_LIST_SIZE 16384
struct hadm_node;
#define BWR_ALIGN_SECTOR \
	(((sizeof(struct packet) + (HADM_SECTOR_SIZE - 1)) >> HADM_SECTOR_SHIFT) + \
	((PAGE_SIZE + (HADM_SECTOR_SIZE - 1)) >> HADM_SECTOR_SHIFT))

/*
 * struct bwr_meta define in include/bwr.inc, hadm_def.h already included it.
 */

struct bwr_disk_info {
	union {
		struct bwr_meta meta;
		char __pack[PAGE_SIZE];
	};
};


struct bwr_data_block {
	union {
		struct bwr_data_meta meta;
		char __pack[HADM_SECTOR_SIZE];
	};
	char data_block[PAGE_SIZE];
};

struct bwr_data {
	unsigned long flags;
	atomic_t refcnt;
	struct bwr_data_meta meta;
	struct page *data_page;
	struct list_head list;
	struct hlist_node list_hash;
	void *private;
};

enum bwr_data_flags {
       __bd_inbuffer,	/* add in buffer */
       __bd_seqinbuffer,/* sequence added */
       __bd_synced,	/* synced to bdev */
       __bd_seqsynced,	/* sequence synced */
       __bd_flag_max,
};

#define BWR_DATA_FNS(name)					\
static inline void set_bwr_data_##name(struct bwr_data *data)	\
{								\
       set_bit(__bd_##name, &(data)->flags);                    \
}								\
static inline void clear_bwr_data_##name(struct bwr_data *data) \
{								\
       clear_bit(__bd_##name, &(data)->flags);			\
}								\
static inline int bwr_data_##name(struct bwr_data *data)	\
{								\
       return test_bit(__bd_##name, &(data)->flags);            \
}

BWR_DATA_FNS(inbuffer)
BWR_DATA_FNS(seqinbuffer)
BWR_DATA_FNS(synced)
BWR_DATA_FNS(seqsynced)

#define bwr_data_seq(v) ((v)->meta.bwr_seq)
extern struct bwr_data *init_bwr_data(sector_t bwr_sector, sector_t dev_sector,
		uint64_t bwr_seq, u32 checksum, uint64_t uuid, struct page *data_page);
extern void bwr_data_put(struct bwr_data *bwr_data);

static inline struct bwr_data *bwr_data_get(struct bwr_data *bwr_data)
{
	if (bwr_data) {
		if (atomic_read(&bwr_data->refcnt) <= 0) {
			pr_err("get bwr_data %p where its refcnt(%d) <= 0.\n",
					bwr_data, atomic_read(&bwr_data->refcnt));
			dump_stack();
		}
		atomic_inc(&bwr_data->refcnt);
//		pr_info("get bwr_data %p, now refcnt = %d\n",
//				bwr_data, atomic_read(&bwr_data->refcnt));
	}
	return bwr_data;
}

extern struct bwr_data *alloc_bwr_data(gfp_t gfp_mask);
extern struct bwr_data *find_get_bwr_data(struct hadmdev *dev, sector_t offset);
extern void bwr_data_add(struct bwr *bwr, struct bwr_data *data);
extern struct bwr_data *get_send_head_data(struct bwr *bwr, int node_id, sector_t prev_seq);

#define MAX_BWR_CACHE_SIZE (1 << 14)
static inline uint64_t get_max_bwr_cache_size(void)
{
	return MAX_BWR_CACHE_SIZE;
}

struct bwr {
	sector_t start_sector;
	sector_t max_sector;
	sector_t max_size;	/* how much bwr_data can use */
	sector_t inuse_size;
	uint32_t min_node_mask;
	sector_t min_disk_head;
	uint64_t disk_size;
	uint64_t seq_id;
	atomic64_t cache;
	atomic64_t nleft;
	struct completion not_full;
	struct completion have_snd_data;

	rwlock_t lock;
	struct bwr_meta disk_meta;
	struct bwr_meta mem_meta;
	sector_t last_seq; //last seq submit to bwr in submit_bio_wrapper
	struct completion wait;	/* for sync */

	uint64_t sync_node_mask;
	spinlock_t sync_node_mask_lock;
	struct completion sync_node_finish;

	rwlock_t bwr_data_list_rwlock;
	struct list_head bwr_data_list;
	int bwr_data_list_len;
	uint64_t bwr_data_list_max_size;
	int waiters;
	struct completion ev_wait;

	struct semaphore sema;
	struct hadmdev *hadmdev; /* point back */
	void *private;
};

/* start sequence is 1 */
#define seq_to_bwr(seq, bwr) ((seq < 2)? (bwr)->start_sector : ((bwr)->start_sector + ((seq) - 2) * 9 % (bwr)->max_size))
extern void free_bwr(struct bwr *bwr);
extern struct bwr *bwr_alloc(size_t size, int gfp_mask);
extern int bwr_init(struct hadmdev *dev, char *bwr_disk, uint64_t bwr_max, uint64_t bwr_disk_size,
		    uint64_t meta_offset, uint64_t dbm_offset, uint64_t bwr_offset);
extern int valid_bwr_meta(struct bwr *bwr);
extern int valid_bwr_sector(struct bwr *bwr, int node_id, sector_t sector) ;
extern void bwr_dump(struct bwr *bwr) ;
extern void bwr_meta_dump(struct bwr_meta *meta);
extern void bwr_reset(struct bwr *bwr, uint64_t bwr_seq);

enum { UPDATE_BWR_META, UPDATE_TAIL, LOCAL_PRIMARY, LAST_PRIMARY };
extern int write_bwr_meta(struct bwr *bwr, int which,
		   int dstate, uint64_t tail,
		   uint32_t node_id, uint64_t uuid, uint64_t seq,
		   uint64_t dev_sector, uint8_t md5[]);

extern int sync_disk_meta(struct bwr *bwr);
extern void set_last_primary(struct bwr *bwr, uint32_t node_id, uint64_t uuid);

extern void __bwr_inuse_size_sub(struct bwr *bwr, int nr);
extern void __bwr_set_inuse_size(struct bwr *bwr, sector_t size);
static inline sector_t __bwr_get_inuse_size(struct bwr *bwr)
{
	return bwr->inuse_size;
}
extern sector_t bwr_get_inuse_size(struct bwr *bwr);
extern void bwr_update_inuse_size(struct bwr *bwr);
extern int bwr_empty(struct bwr *bwr);
extern int bwr_full(struct bwr *bwr);
extern int bwr_write_full(struct bwr *bwr, struct bio *bio);
extern int bwr_wait_free_slot(struct bwr *bwr);
extern int bwr_inuse_size_pre_occu(struct bwr *bwr);

static inline sector_t __bwr_node_head(struct bwr *bwr, int node_id)
{
	return bwr->mem_meta.head[node_id];
}

extern sector_t bwr_node_head(struct bwr *bwr, int node_id);
extern void __bwr_set_node_head(struct bwr *bwr,int node_id,sector_t head);
extern uint64_t __bwr_node_head_inc(struct bwr *bwr, int node_id);
extern uint64_t bwr_node_head_inc(struct bwr *bwr, int node_id);
extern void bwr_node_head_condition_inc(struct bwr *bwr, int node_id, uint64_t expect_head);
extern void bwr_node_head_add(struct bwr *bwr, int node_id, int nr);
extern sector_t bwr_seq_add(struct bwr *bwr, sector_t sector);
extern sector_t bwr_seq(struct bwr *bwr);
extern sector_t bwr_tail(struct bwr *bwr);
extern sector_t bwr_lastpi_seq(struct bwr *bwr);
extern void bwr_tail_add(struct bwr *bwr, int nr);
extern void bwr_tail_add_occupied(struct bwr *bwr, int nr);
extern void bwr_tail_inc(struct bwr *bwr);
extern sector_t bwr_next_nr_sector(struct bwr * bwr, sector_t sector, int nr);
extern sector_t bwr_next_sector(struct bwr *bwr, sector_t sector);
extern sector_t __bwr_get_min_head(struct bwr *bwr, uint32_t *node_map);
extern sector_t bwr_get_min_head(struct bwr *bwr);

#define __bwr_update_min_node_mask(bwr) __bwr_get_min_head((bwr), &(bwr)->min_node_mask)

extern loff_t read_bwr(char *data, struct bwr *bwr, sector_t offset, loff_t nbytes);
extern int delta_sync_bwr(struct hadm_node *node, sector_t start, sector_t end);

extern uint64_t bwr_get_uuid(struct bwr *bwr);
extern struct bwr_data *alloc_bwr_data(gfp_t gfp_mask);
extern void bwr_data_list_clean(struct bwr *bwr);

extern uint64_t bwr_add_seq_n_tail(struct bwr * bwr, sector_t sector);
extern int bwr_sector_cmp(struct bwr *bwr, sector_t s1, sector_t s2, sector_t tail);
extern int bwr_node_head_cmp(struct bwr *bwr, uint8_t node1,uint8_t node2);

extern struct bwr_data_meta *alloc_bwr_data_meta(sector_t dev_sector, sector_t bwr_sector,
		uint64_t bwr_seq);

extern void bwr_set_node_head(struct bwr *bwr,int node_id,sector_t head, int lock_node_state);
extern int is_uptodate(struct bwr *bwr ,int node_id);

#endif	/* BWR_H */
