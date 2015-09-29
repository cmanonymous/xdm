#include <linux/module.h>
#include <linux/completion.h>

#include "hadm_def.h"
#include "hadm_config.h"
#include "hadm_device.h"
#include "hadm_bio.h"
#include "bio_helper.h"
#include "bio_handler.h"

struct bio_result {
	struct completion event;
	int error;
};

struct async_endio_data {
	struct abi_data *data;
	struct async_backing_info *abi;
};

static void __bio_end_io(struct bio *bio, int error)
{
	struct bio_result *bio_result=bio->bi_private;
	int uptodate = bio_flagged(bio, BIO_UPTODATE);

	if(error) {
		bio_result->error = error;
	} else if(!uptodate) {
		bio_result->error = -EIO;
	}

	complete(&bio_result->event);
}

int hadm_read_bwr_block(struct block_device *bdev, sector_t sector,
		       char *buf, int buflen)
{
	struct bio *bio;
	struct page *page;
	struct bio_result bio_result;
	char *src, *dst;
	int ret;

	ret = buflen;
	bio = bio_alloc(GFP_KERNEL, 1);
	if (bio == NULL || IS_ERR(bio)) {
		pr_err("%s: bio_alloc failed\n", __FUNCTION__);
		return -ENOMEM;
	}
	bio_result.error=0;
	bio->bi_bdev = bdev;
	bio->bi_sector = 0;
	bio->bi_end_io = __bio_end_io;
	bio->bi_private = &bio_result;

	page = alloc_page(GFP_KERNEL);
	if(bio_add_page(bio, page, 512, 0)!=512){
		pr_err("%s:bio_add_page 512 failed\n",__FUNCTION__);
		dump_stack();
		pr_info("device:%s, start_sector:%lu, nr_sectors:%lu. sector:%lu.\n",
				bdev->bd_part->__dev.kobj.name,
				bdev->bd_part->start_sect,
				bdev->bd_part->nr_sects,
				sector);
		return -ENOMEM;
	}
	page = alloc_page(GFP_KERNEL);
	if(bio_add_page(bio, page, PAGE_SIZE, 0)!=PAGE_SIZE){
		pr_err("%s:bio_add_page 4096 failed\n",__FUNCTION__);
		dump_stack();
		pr_info("device:%s, start_sector:%lu, nr_sectors:%lu. sector:%lu.\n",
				bdev->bd_part->__dev.kobj.name,
				bdev->bd_part->start_sect,
				bdev->bd_part->nr_sects,
				sector);
		return -ENOMEM;
	}
	bio->bi_sector = sector;

	bio_result.error = 0;
	init_completion(&bio_result.event);
	submit_bio(READ, bio);
	/**TODO check timeout **/
	wait_for_completion(&bio_result.event);
	if(bio_result.error)
	{
		ret=bio_result.error;
		set_io_fail_flag(bdev);
		goto read_done;
	}

	src = page_address(bio->bi_io_vec[0].bv_page);
	dst = buf;
	memcpy(dst, src, 512);

	src = page_address(bio->bi_io_vec[1].bv_page);
	dst = buf + 512;
	memcpy(dst, src, PAGE_SIZE);

read_done:
	hadm_free_bio(bio);
	return ret;
}

int hadm_bio_write_sync(struct block_device *bdev, sector_t sector,
			char *buf, int buflen)
{
	struct bio *bio;
	struct page *page;
	struct bio_result bio_result;
	char *src, *dst;
	int nbytes, remain, ret = 0;

	bio = bio_alloc(GFP_KERNEL, 1);
	if (bio == NULL || IS_ERR(bio)) {
		pr_err("%s: bio_alloc failed\n", __FUNCTION__);
		return -ENOMEM;
	}
	bio_result.error=0;

	bio->bi_bdev = bdev;
	bio->bi_sector = sector;
	bio->bi_end_io = __bio_end_io;
	bio->bi_private = &bio_result;

	remain = buflen;
	src = buf;
	while (remain > 0) {
		nbytes = min((int)PAGE_SIZE, remain);

		page = alloc_page(GFP_KERNEL);
		if ( bio_add_page(bio, page, nbytes, 0) !=nbytes){
			pr_err("%s: bio_add_page failed: \n",__FUNCTION__);
			ret = -ENOMEM;
			goto done;
		}
		dst = page_address(page);
		memcpy(dst, src, nbytes);

		src += nbytes;
		remain -= nbytes;
	}

	bio_result.error = 0;
	init_completion(&bio_result.event);
	submit_bio(WRITE, bio);
	wait_for_completion(&bio_result.event);
	if (bio_result.error) {
		ret=bio_result.error;
		set_io_fail_flag(bdev);
	}

done:
	hadm_flush_device(bdev);
	hadm_free_bio(bio);
	return ret;
}

void hadm_vec_rw_sync_endio(struct bio *bio, int err)
{
	if (err)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	if (bio->bi_private)
		complete(bio->bi_private);
	bio_put(bio);
}

int hadm_io_rw_async(struct block_device *bdev, sector_t sector, int rw,
		struct hadm_io io_vec[], int nr_vecs, bio_end_io_t endio,
		void *private)
{
	int i, ret = 0;
	struct bio *bio;
	struct hadm_io *hvec;

	bio = bio_alloc(GFP_KERNEL, nr_vecs);
	if (!bio) {
		pr_err("%s alloc bio faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	bio->bi_bdev = bdev;
	bio->bi_sector = sector;
	bio->bi_end_io = endio;
	bio->bi_private = private;
	for (i = 0; i < nr_vecs; i++) {
		hvec = &io_vec[i];
		if (!bio_add_page(bio, hvec->page, hvec->len, hvec->start)) {
			pr_err("%s: bio add page faild. errcode:%d.\n",
					__FUNCTION__, ret);
			dump_bio(bio, __func__);
			ret = -EIO;
			goto fail;
		}
	}
	submit_bio(rw, bio);

	return 0;
fail:
	bio_put(bio);
	return ret;
}

int hadm_io_rw_sync(struct block_device *bdev, sector_t sector, int rw,
		struct hadm_io io_vec[], int nr_vecs)
{
	int i, ret = 0;
	struct bio *bio;
	struct hadm_io *hvec;
	DECLARE_COMPLETION_ONSTACK(wait);

	bio = bio_alloc(GFP_KERNEL, nr_vecs);
	if (!bio) {
		pr_err("%s alloc bio faild.\n", __FUNCTION__);
		return -ENOMEM;
	}
	bio->bi_bdev = bdev;
	bio->bi_sector = sector;
	bio->bi_private = &wait;
	bio->bi_end_io = hadm_vec_rw_sync_endio;
	for (i = 0; i < nr_vecs; i++) {
		hvec = &io_vec[i];
		if (!bio_add_page(bio, hvec->page, hvec->len, hvec->start)) {
			pr_err("%s bio add page faild. errcode:%d.\n",
					__FUNCTION__, ret);
			dump_bio(bio, __func__);
			ret = -EIO;
			goto done;
		}
	}
	bio_get(bio);
	submit_bio(rw, bio);

	wait_for_completion(&wait);
	if (!bio_flagged(bio, BIO_UPTODATE))
		ret = -EIO;
done:
	bio_put(bio);
	return ret;
}

int hadm_read_page_sync(struct block_device *bdev, sector_t offset, struct page *page, size_t size)
{
	struct hadm_io hv = {
		.page = page,
		.start = 0,
		.len = size,
	};

	return hadm_io_rw_sync(bdev, offset, READ, &hv, 1);
}

int hadm_read_page_async(struct block_device *bdev, sector_t offset,
		struct page *page, size_t size, bio_end_io_t endio,
		void *private)
{
	struct hadm_io hv = {
		.page = page,
		.start = 0,
		.len = size,
	};

	return hadm_io_rw_async(bdev, offset, READ, &hv, 1, endio, private);
}

int hadm_write_page_sync(struct block_device *bdev, sector_t offset, struct page *page, size_t size)
{
	struct hadm_io hv = {
		.page = page,
		.start = 0,
		.len = size,
	};

	return hadm_io_rw_sync(bdev, offset, WRITE, &hv, 1);
}

int hadm_write_page_async(struct block_device *bdev, sector_t offset,
		struct page *page, size_t size, bio_end_io_t endio,
		void *private)
{
	struct hadm_io hv = {
		.page = page,
		.start = 0,
		.len = size,
	};

	return hadm_io_rw_async(bdev, offset, WRITE, &hv, 1, endio, private);
}

void dump_hadm_io_vec(struct hadm_io *vec, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		pr_info("address:%p(%p %lx)|start:%d|offset:%d.\n",
				page_address(vec[idx].page),
				vec[idx].page,
				vec[idx].page->flags,
				vec[idx].start,
				vec[idx].len);
}

void dump_kvec(struct kvec *vec, int len)
{
	int idx;

	for (idx = 0; idx < len; idx++)
		pr_info("address:%p|len:%lu\n",
				vec->iov_base,
				vec->iov_len);
}

int abi_data_finished(struct abi_data *data)
{
	return data->idx & ABI_DATA_FINISH;
}

int abi_data_abort(struct abi_data *data)
{
	return data->idx & ABI_DATA_ABORT;
}

void abi_init(struct async_backing_info *abi)
{
	int idx;
	struct abi_data *data_iter;

	spin_lock_init(&abi->lock);
	//memset(abi->data, 0, sizeof(abi->data));
	abi->start = 0;
	for (idx = 0; idx < HADM_ABI_MAX_COUNT; idx++) {
		data_iter = &abi->data[idx];
		data_iter->idx = ABI_DATA_FREE;
	}
}

void abi_destroy(struct async_backing_info *abi)
{
	if (abi->bmap)
		pr_info("%s: try destroy unfinished abi\n", __func__);
	kfree(abi);
}

/**
 * abi_remove - Remove a data from @abi
 * @abi: abi pop from
 * @idx: data idx to pop
 * @how: reason to pop, include ABI_DATA_ABORT/ABI_DATA_FINISH
 */
void abi_remove(struct async_backing_info *abi, int idx, int how)
{
	unsigned long flags;
	struct abi_data *data_iter, *valid_data;

	//pr_info("%s: try remove idx:%d, how:%d. bmap:%lu.\n", __func__,
			//idx, how, abi->bmap);
	spin_lock_irqsave(&abi->lock, flags);

	if (!abi->bmap) {
		pr_err("%s: try remove from empty bmap.\n", __func__);
		spin_unlock_irqrestore(&abi->lock, flags);
		return;
	}

	valid_data = NULL;
	data_iter = &abi->data[(abi->start + idx) % HADM_ABI_MAX_COUNT];
	data_iter->idx |= how;

	if (__ffs(abi->bmap) != idx) {
		//pr_info("%s: %d not the first(%lu:(%lx)).\n", __func__,
				//idx, __ffs((int)(abi->bmap)), abi->bmap);
		clear_bit(idx, &abi->bmap);
		spin_unlock_irqrestore(&abi->lock, flags);
		return;
	}

	clear_bit(idx, &abi->bmap);
	while (abi_data_finished(data_iter) ||
			abi_data_abort(data_iter)) {
		if (abi_data_finished(data_iter))
			valid_data = data_iter;
		data_iter->idx = ABI_DATA_FREE;

		idx++;
		data_iter = &abi->data[(abi->start + idx) % 64];
	}

	if (valid_data)
		valid_data->endio(valid_data->data);

	spin_unlock_irqrestore(&abi->lock, flags);
}

int __abi_rotate(struct async_backing_info *abi)
{
	int ret = 0;
	int idx, offset;
	struct abi_data *abi_data;

	//spin_lock(&abi->lock);
	if (!abi->bmap || abi->bmap & 0x1) {
		ret = -1;
		goto out;
	}
	//abi_dump("before rotate", abi);

	offset = __ffs(abi->bmap);
	abi->bmap >>= offset;
	for (idx = offset; idx < HADM_ABI_MAX_COUNT; idx++) {
		abi_data = &abi->data[(abi->start + idx) % HADM_ABI_MAX_COUNT];
		/* abi_data->idx = 0 will never be rotated */
		if (!(abi_data->idx & 0x700))
			abi_data->idx -= offset;
	}
	abi->start = (abi->start + offset) % HADM_ABI_MAX_COUNT;

	//abi_dump("after rotate", abi);
out:
	//spin_unlock(&abi->lock);
	return ret;
}

void abi_generic_endio(struct bio *bio, int err)
{
	struct async_endio_data *data = bio->bi_private;

	if (err)
		abi_remove(data->abi, data->data->idx, ABI_DATA_ABORT);
	else
		abi_remove(data->abi, data->data->idx, ABI_DATA_FINISH);
	kfree(data);
	bio_put(bio);
}

/* FIXME 循环使用 */
int abi_add(struct async_backing_info *abi, struct block_device *bdev,
		sector_t offset, struct hadm_io *io_vec, int nr_vec,
		abi_callback_t *endio, void *data)
{
	int ret, idx;
	unsigned long flags;
	struct abi_data *abi_data;
	struct async_endio_data *end_data;

	/* check if full */
	//pr_info("%s: try add to abi bmap:%lu.\n", __func__, abi->bmap);
	spin_lock_irqsave(&abi->lock, flags);
	if (abi->bmap & HADM_ABI_MAX) {
		//pr_info("%s full, try rotate.\n", __func__);
		if (__abi_rotate(abi) < 0) {
			spin_unlock_irqrestore(&abi->lock, flags);
			return -1;
		}
	}
	idx = abi->bmap ? (__fls(abi->bmap) + 1) : 0;
	abi_data = &abi->data[(abi->start + idx) % HADM_ABI_MAX_COUNT];
	abi_data->idx = idx;
	abi_data->endio = endio;
	abi_data->data = data;
	set_bit(abi_data->idx, &abi->bmap);
	spin_unlock_irqrestore(&abi->lock, flags);
	//pr_info("%s: add data to idx:%d.bmap:%lu\n", __func__, idx, abi->bmap);

	end_data = kmalloc(GFP_KERNEL, sizeof(struct async_endio_data));
	if (!end_data) {
		pr_err("%s: alloc data failed.\n", __func__);
		abi_remove(abi, idx, ABI_DATA_ABORT);
		return -1;
	}
	end_data->data = abi_data;
	end_data->abi = abi;

	ret = hadm_io_rw_async(bdev, offset, WRITE, io_vec, nr_vec,
			abi_generic_endio, end_data);
	if (ret < 0) {
		abi_remove(abi, idx, ABI_DATA_ABORT);
		kfree(end_data);
		return ret;
	}
	//pr_info("%s: add abio data success.\n", __func__);

	return idx;
}

void abi_dump(const char *msg, struct async_backing_info *abi)
{
	int idx;
	struct abi_data *abi_data;

	pr_info("%s: abi bmap:%lx, start:%d.\n", msg, abi->bmap, abi->start);

	for (idx = 0; idx < HADM_ABI_MAX_COUNT; idx++) {
		abi_data = &abi->data[(idx + abi->start) % HADM_ABI_MAX_COUNT];
		pr_info("\t[%x]\n", abi_data->idx);
	}
}
