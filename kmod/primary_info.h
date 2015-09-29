#ifndef PRIMARY_INFO_H
#define PRIMARY_INFO_H

#include "hadm_def.h"

/*
 * struct primary_info defined in include/bwr.inc, hadm_def.h already included
 * it.
 */

extern void primary_info_init(struct primary_info *info);
extern void primary_info__set_id(struct primary_info *info, uint8_t id);
extern void primary_info__set_uuid(struct primary_info *info, uint64_t uuid);
extern void primary_info__set_bwrseq(struct primary_info *info, uint64_t seq);
extern int set_local_primary(struct hadmdev *dev, uint32_t node_id, uint64_t uuid);
extern int get_last_primary(struct hadmdev *dev);
extern int check_split_brain(struct bwr_meta *local, struct bwr_meta *remote);

#endif	/* PRIMARY_INFO_H */
