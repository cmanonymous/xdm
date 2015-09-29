#include <linux/module.h>

#include "hadm_config.h"
#include "hadm_device.h"
#include "bwr.h"

#include "primary_info.h"

void primary_info_init(struct primary_info *info)
{
	info->id = 0;
	info->uuid = 0;
	info->bwr_seq = 0;
}

void primary_info__set_id(struct primary_info *info, uint8_t id)
{
	info->id = id;
}

void primary_info__set_uuid(struct primary_info *info, uint64_t uuid)
{
	info->uuid = uuid;
}

void primary_info__set_bwrseq(struct primary_info *info, uint64_t seq)
{
	info->bwr_seq = seq;
}

int set_local_primary(struct hadmdev *dev, uint32_t node_id, uint64_t uuid)
{
	return write_bwr_meta(dev->bwr, LOCAL_PRIMARY, 0, 0, node_id, uuid, 0, 0, NULL);
}

int get_last_primary(struct hadmdev *dev)
{
	int last_primary;

	read_lock(&dev->bwr->lock);
	last_primary = dev->bwr->mem_meta.last_primary.id;
	read_unlock(&dev->bwr->lock);

	return last_primary;
}

/* split brain: 1; otherwise: 0 */
int check_split_brain(struct bwr_meta *local, struct bwr_meta *remote)
{
	return (remote->local_primary.id != INVALID_ID &&
			((local->last_primary.id != INVALID_ID &&
			  local->last_primary.uuid == remote->last_primary.uuid &&
			  local->last_primary.bwr_seq == remote->last_primary.bwr_seq) ||
			 local->local_primary.uuid == remote->last_primary.uuid ||
			 local->last_primary.uuid == remote->local_primary.uuid));
}
