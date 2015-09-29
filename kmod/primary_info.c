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

int set_last_primary(struct hadmdev *dev, int dstate,
		uint32_t node_id, uint64_t uuid, uint64_t seq,
		uint64_t disk_sector, uint8_t md5[])
{
	static int last_dstate = -1;
	static uint32_t last_node_id;
	static uint64_t last_uuid;
	static uint64_t last_seq;
	int err=0;

	if (last_dstate != dstate ||
			last_seq != seq ||
			last_uuid != uuid ||
			last_node_id != node_id) {
		err = write_bwr_meta(dev->bwr, LAST_PRIMARY, dstate, 0, node_id, uuid, seq, disk_sector, md5);
		if (err) {
			return err;
		}
		if ((last_seq + 1) != seq || last_uuid != uuid)
			printk(KERN_INFO "set last_primary to: id=%d, uuid=%llu, bwr_seq=%llu\n",
					node_id, uuid, seq);
		last_dstate = dstate;
		last_seq = seq;
		last_uuid = uuid;
		last_node_id = node_id;
	}
	return 0;
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
int check_split_brain(struct bwr_meta *local_site, struct bwr_meta *remote)
{
	return (remote->local_primary.id != INVALID_ID &&
			((local_site->last_primary.id != INVALID_ID &&
			  local_site->last_primary.uuid == remote->last_primary.uuid &&
			  local_site->last_primary.bwr_seq == remote->last_primary.bwr_seq) ||
			 local_site->local_primary.uuid == remote->last_primary.uuid ||
			 local_site->last_primary.uuid == remote->local_primary.uuid));
}
