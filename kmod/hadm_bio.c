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

/*
 * bio_put() 似乎不会释放加入的 page，需要手动释放 bio_add_page() 加入的 page
 */
int hadm_read_page_sync(struct block_device *bdev,sector_t offset, struct page *page,size_t size)
{
	struct bio *bio;
	struct bio_result bio_result;

	bio_result.error=0;
	bio = bio_alloc(GFP_KERNEL, 1);
	bio->bi_bdev = bdev;
	bio->bi_sector = offset;
	bio->bi_end_io = __bio_end_io;
	bio->bi_private = &bio_result;

	get_page(page);
	bio_add_page(bio, page, (size>PAGE_SIZE)?PAGE_SIZE:size, 0);

	bio_result.error = 0;
	init_completion(&bio_result.event);
	submit_bio(READ, bio);
	wait_for_completion(&bio_result.event);
	hadm_free_bio(bio);
	if(bio_result.error) {
		set_io_fail_flag(bdev);
	}
	return bio_result.error;
}

void hadm_vec_rw_sync_endio(struct bio *bio, int err)
{
	if (err)
		clear_bit(BIO_UPTODATE, &bio->bi_flags);
	if (bio->bi_private)
		complete(bio->bi_private);
	bio_put(bio);
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

int hadm_read_page_async(struct block_device *bdev, sector_t sector, bio_end_io_t *bio_end_io, void *private)
{
	struct bio *bio = NULL;
	struct page *page = NULL;
	bio = bio_alloc(GFP_KERNEL, 1);
	if (!bio) {
		pr_info("%s: alloc bio failed\n", __FUNCTION__);
		goto fail;
	}
	bio->bi_bdev = bdev;
	bio->bi_sector = sector;
	bio->bi_private = private;
	bio->bi_end_io = bio_end_io;
	page = alloc_page(GFP_KERNEL);
	if(!page) {
		pr_info("%s: alloc page failed\n", __FUNCTION__);
		goto fail;
	}
	if(bio_add_page(bio, page, PAGE_SIZE, 0) == 0) {
		pr_info("%s: add page %p to bio %p failed\n", __FUNCTION__, page, bio);
		goto fail;
	}
	submit_bio(READ, bio);
	return 0;
fail:
	if(bio){
		hadm_free_bio(bio);
	}
	return -ENOMEM;


}
