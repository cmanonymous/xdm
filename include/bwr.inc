#ifndef __BWR_INC__
#define __BWR_INC__

struct primary_info {
	uint8_t id;
	uint64_t uuid;
	uint64_t bwr_seq;
	uint64_t last_page;
	uint8_t last_page_damaged;
	uint8_t last_page_md5[16];
};

struct bwr_meta {
	/* static */
	uint64_t magic;
	uint8_t dev_id;
	uint64_t disk_size;
	uint64_t bwr_disk_size;
	uint64_t meta_start;	/* 0 ~ 1M */
	uint64_t dbm_start;
	uint64_t bwr_start;

	/* dynamic */
	uint64_t head[MAX_NODES];
	uint64_t tail;
	uint8_t disk_state;
	struct primary_info last_primary;
	struct primary_info local_primary;

};

#endif  /* __BWR_INC__ */
