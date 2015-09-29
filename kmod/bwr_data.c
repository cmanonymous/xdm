#include <linux/module.h>

#include <linux/blkdev.h>

#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_bio.h"

#include "bwr.h"
#include "bio_helper.h"
#include "buffer.h"


struct bwr_data *bwr_data_read(struct bwr *bwr, sector_t start)
{
	int ret;
	struct page *page0;
	struct page *page1;
	struct bwr_data *data;
	struct bwr_data_meta *meta;
	struct hadm_io io_vec[2];

	data = NULL;
	/* meta sector */
	page0 = alloc_page(GFP_KERNEL);
	if (!page0) {
		pr_err("%s: alloc page0 failed.\n", __func__);
		return NULL;
	}
	io_vec[0].page = page0;
	io_vec[0].start = 0;
	io_vec[0].len = HADM_SECTOR_SIZE;
	/* data sector */
	page1 = alloc_page(GFP_KERNEL);
	if (!page1) {
		pr_err("%s: alloc page1 failed.\n", __func__);
		goto free_page0;
	}
	io_vec[1].page = page1;
	io_vec[1].start = 0;
	io_vec[1].len = PAGE_SIZE;

	ret = hadm_io_rw_sync(bwr->hadmdev->bwr_bdev, start, READ, io_vec, 2);
	if (ret < 0) {
		pr_err("%s: read bwr data failed.\n", __func__);
		goto free_page1;
	}

	data = alloc_bwr_data(GFP_KERNEL);
	if (!data) {
		pr_err("%s: alloc data failed.\n", __FUNCTION__);
		goto free_page1;
	}
	meta = (struct bwr_data_meta *)(page_address(page0));
	data->meta.dev_sector = meta->dev_sector;
	data->meta.bwr_sector = start;
	data->meta.bwr_seq = meta->bwr_seq;
	data->meta.uuid = meta->uuid;
	data->meta.checksum = meta->checksum;
	get_page(page1);
	data->data_page = page1;
	set_page_private(page1, (unsigned long)data);

free_page1:
	__free_page(page1);
free_page0:
	__free_page(page0);
	return data;
}

/**
 * we want snd_head_data lock free, so we need check it.
 * */
struct bwr_data *get_snd_head_data_from_buffer(struct bwr *bwr, struct hadm_site *runsite)
{
	sector_t snd_head;
	struct bwr_data *copy_bwr_data = NULL;
	struct data_buffer *buffer = bwr->hadmdev->buffer;

	/* snd_head_data update when finish sync it. */
	snd_head = hadm_site_get(runsite, SECONDARY_STATE, S_SND_HEAD);
	if (runsite->s_state.snd_head_data != NULL) {
		if (unlikely(runsite->s_state.snd_head_data->meta.bwr_sector != snd_head))
			hadm_site_send_head_data_set(runsite, NULL);
		else {
			bwr_data_get(runsite->s_state.snd_head_data);
			copy_bwr_data = runsite->s_state.snd_head_data;
		}
	}
	if (!copy_bwr_data) {
		copy_bwr_data = get_find_data_by_bwr(buffer, snd_head);
		if (copy_bwr_data)
			hadm_site_send_head_data_set(runsite, copy_bwr_data);
	}

	return copy_bwr_data;
}

/* get(refcnt++) head bwr data for non-local site */
struct bwr_data *get_send_head_data(struct bwr *bwr, int node_id)
{
	struct bwr_data *bwr_data;
	sector_t snd_head, tail;
	struct hadm_site *runsite;

	if (node_id == get_site_id()) {
		pr_err("%s: Not for local site.\n", __FUNCTION__);
		return NULL;
	}

	runsite = find_hadm_site_by_id(bwr->hadmdev, node_id);
	if (runsite == NULL || IS_ERR(runsite)) {
		pr_err("%s: no node %d\n", __FUNCTION__, node_id);
		return NULL;
	}

	bwr_data = NULL;
	tail = bwr_tail(bwr);
	snd_head = hadm_site_get(runsite, SECONDARY_STATE, S_SND_HEAD);
	if (snd_head == tail)
		return NULL;

	/* FIXME: snd_head_data in s_state, but not protected by s_state lock
	 * TODO:  summarize the usage of snd_head_data
	 * */
	/* first search in cache snd_head_data */
	if (runsite->s_state.snd_head_data != NULL) {
		if (unlikely(runsite->s_state.snd_head_data->meta.bwr_sector != snd_head))
			hadm_site_send_head_data_set(runsite, NULL);
		else {
			bwr_data_get(runsite->s_state.snd_head_data);
			bwr_data = runsite->s_state.snd_head_data;
		}
	}
	/* then search in buffer */
	if (!bwr_data) {
		bwr_data = get_find_data_by_bwr(bwr->hadmdev->buffer, snd_head);
		if (bwr_data)
			hadm_site_send_head_data_set(runsite, bwr_data);
	}

	/* finally, read from disk */
	if (!bwr_data) {
		//pr_info("can not get send_head data from buffer.!");
		bwr_data = bwr_data_read(bwr, snd_head);
	}

	return bwr_data;
}

struct bwr_data *alloc_bwr_data(gfp_t gfp_mask)
{
	struct bwr_data *bwr_data;

	bwr_data = kmalloc(sizeof(struct bwr_data), gfp_mask);
	if (!bwr_data)
		return NULL;
	atomic_set(&bwr_data->refcnt, 1);
	INIT_LIST_HEAD(&bwr_data->list);
        INIT_HLIST_NODE(&bwr_data->list_hash);
	bwr_data->flags = 0UL;
	bwr_data->data_page = NULL;
	bwr_data->private = NULL;

	return bwr_data;
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
		pr_err("put bwr_data, which refcnt equals zero. BUG\n");
		dump_stack();
		return;
	}
	if (atomic_dec_and_test(&bwr_data->refcnt))
		__free_bwr_data(bwr_data);
}

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

void dump_bwr_data(const char *msg, struct bwr_data *data)
{
	struct bwr_data_meta *meta = &data->meta;

	pr_info("%s:\n"
		"flags:%lu|refcnt:%d|data_page:%p\n"
		"uuid:%llu|seq:%llu|checksum:%u|bwr_sector:%lu|"
		"dev_sector:%lu.\n",
		msg, data->flags, atomic_read(&data->refcnt), data->data_page,
		meta->uuid, meta->bwr_seq, meta->checksum, meta->bwr_sector,
		meta->dev_sector);
}
