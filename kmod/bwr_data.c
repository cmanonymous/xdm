#include <linux/module.h>

#include <linux/blkdev.h>

#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_node.h"
#include "hadm_bio.h"

#include "bwr.h"
#include "bio_helper.h"
#include "buffer.h"

void bwr_data_copy(struct bwr_data *dst, struct bwr_data *src)
{
	char *srcaddr, *dstaddr;

	dst->meta.dev_sector = src->meta.dev_sector;
	dst->meta.bwr_sector = src->meta.bwr_sector;

	dstaddr = page_address(dst->data_page);
	srcaddr = page_address(src->data_page);
	memcpy(dstaddr, srcaddr, PAGE_SIZE);
}

struct bwr_data *get_remote_send_head_data(struct bwr *bwr, int node_id)
{
	sector_t snd_head;
	char *buf;
	int buflen;
	struct bwr_data *bwr_data;
	struct bwr_data_meta *meta;
	struct hadm_node *runnode;
	char *src, *dst;

	buflen = PAGE_SIZE + HADM_SECTOR_SIZE;
	buf = kzalloc(buflen, GFP_KERNEL);

	runnode = find_hadm_node_by_id(bwr->hadmdev, node_id);
	if (runnode == NULL || IS_ERR(runnode)) {
		pr_err("%s: no node %d\n", __FUNCTION__, node_id);
		return NULL;
	}
	snd_head = hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD);
	hadm_read_bwr_block(bwr->hadmdev->bwr_bdev, snd_head, buf, buflen);

	bwr_data = alloc_bwr_data(GFP_KERNEL);

	meta = (struct bwr_data_meta *)buf;
	bwr_data->meta.dev_sector = meta->dev_sector;
	bwr_data->meta.bwr_sector = snd_head;
	bwr_data->meta.bwr_seq = meta->bwr_seq;
	bwr_data->meta.uuid = meta->uuid;
	bwr_data->meta.checksum = meta->checksum;
	src = (char *)meta + HADM_SECTOR_SIZE;
	dst = page_address(bwr_data->data_page);
	memcpy(dst, src, PAGE_SIZE);

	kfree(buf);
	return bwr_data;
}

/**
 * we want snd_head_data lock free, so we need check it.
 * */
struct bwr_data *get_snd_head_data_from_buffer(struct bwr *bwr, struct hadm_node *runnode, sector_t prev_seq)
{
	sector_t snd_head;
	struct bwr_data *copy_bwr_data = NULL;
	struct data_buffer *buffer = bwr->hadmdev->buffer;
	if(!prev_seq)
		return NULL;
	/* snd_head_data update when finish sync it. */
	snd_head = hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD);
	if (runnode->s_state.snd_head_data != NULL) {
		if (unlikely(runnode->s_state.snd_head_data->meta.bwr_sector != snd_head)) {
			pr_info("%s: hadm%d node %d's snd_head_data(%p seq:%llu bwr_sector:%llu) is mismatched with snd_head %llu, reset now\n",
					__FUNCTION__, runnode->hadmdev->minor,
					runnode->id, runnode->s_state.snd_head_data,
					(unsigned long long)runnode->s_state.snd_head_data->meta.bwr_seq,
					(unsigned long long)runnode->s_state.snd_head_data->meta.bwr_sector,
					(unsigned long long)snd_head);

			hadm_node_send_head_data_set(runnode, NULL);
		}
		else {
			if(unlikely(prev_seq && runnode->s_state.snd_head_data->meta.bwr_seq != prev_seq + 1)){
				pr_warn("%s:hadm%d send head data sequence is mismatch, seq %llu, expect %llu\n",
						__FUNCTION__, runnode->hadmdev->minor,
						(unsigned long long)runnode->s_state.snd_head_data->meta.bwr_seq ,
						(unsigned long long)(prev_seq + 1));
				hadm_node_send_head_data_set(runnode, NULL);
			}else {
				bwr_data_get(runnode->s_state.snd_head_data);
				copy_bwr_data = runnode->s_state.snd_head_data;
			}
		}
	}
	if (!copy_bwr_data) {
		BUFFER_DEBUG("%s: hadm%d get node %d snd head data from buffer failed. search it in buffer, snd_head = %llu, prev_seq = %llu\n",
			       	__FUNCTION__, runnode->hadmdev->minor, runnode->id,
				(unsigned long long)snd_head,
				(unsigned long long)prev_seq);
		copy_bwr_data = get_find_data_by_bwr(buffer, snd_head, prev_seq);
		if (copy_bwr_data){
			BUFFER_DEBUG("%s: hadm%d node %d's snd head(now %p) is set to %p by get_find_data_by_bwr.\n",
					__FUNCTION__,
					runnode->hadmdev->minor, 
					runnode->id, runnode->s_state.snd_head_data, copy_bwr_data);
			hadm_node_send_head_data_set(runnode, copy_bwr_data);
		}
	}

	return copy_bwr_data;
}


#if 0
/* FIXME common_get_send_head_data ? or
 * common_get_send_head_data_from_buffer ?
 */
struct bwr_data *common_get_send_head_data(struct bwr *bwr, int node_id)
{
	struct bwr_data *copy_bwr_data;
	sector_t snd_head;
	struct hadm_node *runnode;
	struct data_buffer *buffer = bwr->hadmdev->buffer;

	/* NOTE: debug */
	return NULL;

	runnode = find_hadm_node_by_id(bwr->hadmdev, node_id);
	if (runnode == NULL || IS_ERR(runnode)) {
		pr_err("%s: no node %d\n", __FUNCTION__, node_id);
		return NULL;
	}
	snd_head = hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD);

	copy_bwr_data = get_find_data_by_bwr(buffer, snd_head);

	return copy_bwr_data;
}
#endif

struct bwr_data *get_send_head_data(struct bwr *bwr, int node_id, sector_t prev_seq)
{
	int local_node_id = get_node_id();
	struct bwr_data *bwr_data = NULL;
	sector_t snd_head;
	struct hadm_node *runnode;
	int from = 0 ;

	runnode = find_hadm_node_by_id(bwr->hadmdev, node_id);
	if (runnode == NULL || IS_ERR(runnode)) {
		pr_err("%s: no node %d\n", __FUNCTION__, node_id);
		return NULL;
	}
	if(bwr_seq(bwr) == 1) {
		//1 mean no data in bwr
		return NULL;
	}

	snd_head = hadm_node_get(runnode, SECONDARY_STATE, S_SND_HEAD);
	if(!valid_bwr_sector(bwr, node_id, snd_head)) {
		return NULL;
	}
	if(prev_seq || node_id == local_node_id){
		bwr_data = get_snd_head_data_from_buffer(bwr, runnode, prev_seq);
	}
	//bwr_data = common_get_send_head_data(bwr, node_id);
	if (bwr_data == NULL && node_id != local_node_id){
//		pr_info("can not get send_head data from buffer.!");
		bwr_data = get_remote_send_head_data(bwr, node_id);
		from = 1;
	}
	if(bwr_data == NULL) {
		return NULL;
	}
	if(unlikely(seq_to_bwr(bwr_data->meta.bwr_seq , bwr) != bwr_data->meta.bwr_sector ||
			bwr_data->meta.bwr_sector != snd_head||
			(prev_seq && bwr_data->meta.bwr_seq != prev_seq + 1))) {
		pr_warn("%s:invalid bwr_data from %s , hadm%d node_id = %d snd_head %llu and seq %llu(expect:%llu) and bwr_sector %llu mismatched\n",
			       	__FUNCTION__, from ? "disk":"buffer",
			       	runnode->hadmdev->minor, runnode->id,
			       	(unsigned long long)snd_head,
				(unsigned long long)bwr_data->meta.bwr_seq ,
				(unsigned long long)(prev_seq + 1),
				(unsigned long long)bwr_data->meta.bwr_sector);
		pr_info("%s:hadm%d node %d's snd_head_data = %p (bwr_seq %llu, bwr_sector %llu)\n",
				__FUNCTION__, runnode->hadmdev->minor, 
				runnode->id, runnode->s_state.snd_head_data ,
				(runnode->s_state.snd_head_data) ? (unsigned long long)runnode->s_state.snd_head_data->meta.bwr_seq : 0,
				(runnode->s_state.snd_head_data) ? (unsigned long long)runnode->s_state.snd_head_data->meta.bwr_sector : 0);
		bwr_dump(bwr);
		if(BUFF_DEBUG) {
			dump_stack();
			BUG();
		}
		else{
			hadmdev_set_error(bwr->hadmdev, __BWR_ERR);
			return NULL;
		}
	}

	return bwr_data;
}

void bwr_data_add(struct bwr *bwr, struct bwr_data *data)
{
	write_lock(&bwr->bwr_data_list_rwlock);
	if (bwr->bwr_data_list_len == bwr->bwr_data_list_max_size) {
		bwr->waiters += 1;
		write_unlock(&bwr->bwr_data_list_rwlock);
		wait_for_completion(&bwr->ev_wait);
		write_lock(&bwr->bwr_data_list_rwlock);
	}
	list_add_tail(&data->list, &bwr->bwr_data_list);
	bwr->bwr_data_list_len += 1;
	write_unlock(&bwr->bwr_data_list_rwlock);
}


struct bwr_data *alloc_bwr_data(gfp_t gfp_mask)
{
	struct page *page;
	struct bwr_data *bwr_data;

	page = alloc_page(gfp_mask);
	if (!page)
		goto alloc_page_fail;

	bwr_data = kmalloc(sizeof(struct bwr_data), gfp_mask);
	if (!bwr_data)
		goto alloc_bwr_data_fail;
	atomic_set(&bwr_data->refcnt, 1);
	INIT_LIST_HEAD(&bwr_data->list);
	bwr_data->flags = 0UL;
	bwr_data->data_page = page;

	return bwr_data;

alloc_bwr_data_fail:
	__free_page(page);

alloc_page_fail:
	pr_err("%s: no mem.\n", __FUNCTION__);
	return NULL;
}

static void __free_bwr_data(struct bwr_data *data)
{
	if (bwr_data_inbuffer(data)) {
		pr_err("try free bwr_data still in buffer\n");
		dump_stack();
		return;
	}
	if (data->data_page) {
		//pr_info("%s: free page's count:%d.\n", __FUNCTION__, page_count(data->data_page));
		set_page_private(data->data_page, 0);
		__free_page(data->data_page);
	}
	kfree(data);
	data = NULL;
}

void bwr_data_put(struct bwr_data *bwr_data)
{
	if (unlikely(!bwr_data)) {
		pr_info("BUG, try put a null bwr_data.\n");
		dump_stack();
		return;
	}
	if (unlikely(atomic_read(&bwr_data->refcnt) == 0)) {
		pr_err("put bwr_data %p, which refcnt equals zero. BUG\n", bwr_data);
		dump_stack();
		return;
	}
//	pr_info("put bwr_data %p, now refcnt = %d\n",
//			bwr_data, atomic_read(&bwr_data->refcnt) - 1);
	if (atomic_dec_and_test(&bwr_data->refcnt))
		__free_bwr_data(bwr_data);
}

/* FIXME duplicate function init_bwr_data, alloc_bwr_data */
struct bwr_data *init_bwr_data(sector_t bwr_sector, sector_t dev_sector,
		uint64_t bwr_seq, u32 checksum, uint64_t uuid, struct page *data_page)
{
	struct bwr_data *bwr_data;

	bwr_data = kmalloc(sizeof(struct bwr_data), GFP_KERNEL);
	if (bwr_data == NULL) {
		return NULL;
	}

	atomic_set(&bwr_data->refcnt, 1);
	INIT_LIST_HEAD(&bwr_data->list);
        INIT_HLIST_NODE(&bwr_data->list_hash);
	bwr_data->meta.bwr_sector = bwr_sector;
	bwr_data->meta.dev_sector = dev_sector;
	bwr_data->meta.bwr_seq = bwr_seq;
	bwr_data->meta.checksum = checksum;
	bwr_data->meta.uuid = uuid;
	bwr_data->data_page = data_page;
	bwr_data->flags = 0UL;
	if (data_page)
		set_page_private(data_page, (unsigned long)bwr_data);
	bwr_data->private = NULL;

	return bwr_data;
}

struct bwr_data *find_get_bwr_data(struct hadmdev *dev, sector_t offset)
{
	struct bwr_data *bwr_data;
	sector_t tail;
	sector_t i = 0;
	sector_t head = 0;
	struct bwr_data *p = NULL;
	char *src, *dst;

	bwr_data = kzalloc(sizeof(struct bwr_data), GFP_KERNEL);
	if (bwr_data == NULL) {
	}
	bwr_data->data_page = alloc_page(GFP_KERNEL);
	if (bwr_data->data_page == NULL) {
	}

	/* FIXME: add rw arg */
	read_lock(&dev->bwr->lock);
	tail = dev->bwr->mem_meta.tail;
	/* get from memory */
	head = __bwr_get_min_head(dev->bwr, NULL);
	if (bwr_sector_cmp(dev->bwr, offset, head, tail)) {
		i = 0;
		list_for_each_entry(p, &dev->bwr->bwr_data_list, list) {
			if (i == offset) {
				memcpy(bwr_data, p, sizeof(struct bwr_data));
				dst = page_address(bwr_data->data_page);
				src = page_address(p->data_page);
				memcpy(dst, src, PAGE_SIZE);
				break;
			}
			i += 9;
		}
		read_unlock(&dev->bwr->lock);
	}

	/* get from disk */
	else {
		read_unlock(&dev->bwr->lock);
		/* read from bwr, offset */
		/* read_from_bwr(bwr_data, offset); */
	}

	return p;
}
