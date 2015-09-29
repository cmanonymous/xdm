#ifndef __UTILS__
#define __UTILS__

#include "hadm_def.h"
#include "hadm_config.h"
#include "dbm.h"

#define MD5_FORMAT \
	"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x"
#define MD5_ARGS(md5_hash) \
	md5_hash[0],  md5_hash[1],  md5_hash[2],  md5_hash[3], \
	md5_hash[4],  md5_hash[5],  md5_hash[6],  md5_hash[7], \
	md5_hash[8],  md5_hash[9],  md5_hash[10], md5_hash[11],\
	md5_hash[12], md5_hash[13], md5_hash[14], md5_hash[15]

#define BLK_SHIFT 12

struct site_config *get_site_by_id(int id, struct config *cfg);

uint64_t get_disk_size(struct dbm* dbm);

uint64_t n_bits(char *data, uint64_t beg, uint64_t end);

void pr_c_content(void *addr, unsigned int size);

int sector_in_area(sector_t target, sector_t start, sector_t end);

char *md5_print(char *out, u8 *in);

uint64_t nr_bits(char *data, uint64_t begin, uint64_t len);

#endif
