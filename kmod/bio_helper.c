//#define DEBUG_IO
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/buffer_head.h>
#include <linux/kthread.h>
#include <linux/bio.h>
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/crc32.h>
#include <linux/bio.h>

#include "bio_helper.h"
#include "bwr.h"
#include "buffer.h"
#include "hadm_thread.h"
#include "hadm_def.h"
#include "hadm_bio.h"

static DECLARE_COMPLETION(subbio_finish);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16)
#define _hadm_start_io_acct(...) do {} while (0)
#define _hadm_end_io_acct(...)   do {} while (0)
#else

static void _hadm_start_io_acct(struct bio_wrapper *wrapper)
{
	struct  bio *bio=wrapper->bio;
	const int rw=bio_data_dir(bio);
	struct hadmdev *mdev;
	int cpu;

	mdev=wrapper->hadmdev;
	cpu=part_stat_lock();
	part_round_stats(cpu, &mdev->disk->part0);
	part_stat_inc(cpu, &mdev->disk->part0, ios[rw]);
	part_stat_add(cpu, &mdev->disk->part0, sectors[rw], bio_sectors(bio));
	part_inc_in_flight(&mdev->disk->part0, rw);
	part_stat_unlock();
}

static void _hadm_end_io_acct(struct bio_wrapper *wrapper)
{
	struct  bio *bio=wrapper->bio;
	const int rw=bio_data_dir(bio);
	struct hadmdev *mdev;
	int cpu;
	unsigned long duration=jiffies-wrapper->start_jif;

	mdev=wrapper->hadmdev;
	cpu = part_stat_lock();
	part_stat_add(cpu, &mdev->disk->part0, ticks[rw], duration);
	part_round_stats(cpu, &mdev->disk->part0);
	part_dec_in_flight(&mdev->disk->part0, rw);
	part_stat_unlock();
}

#endif

void subbio_read_endio(struct bio *bio, int err)
{
	struct bio_wrapper *bio_w;
	struct hadmdev *hadmdev;
	struct bio_struct *bio_struct;

	bio_struct = (struct bio_struct *)bio->bi_private;
	bio_w = bio_struct->wrapper;
	hadmdev = bio_w->hadmdev;

	if (bio_data_dir(bio) == WRITE) {
		BUG();
	} else {
		hadmdev->acct_info[R_SUBBIO_FINISH]++;
	}

	if (err) {
		bio_w->err |= err;
	}

	IO_DEBUG("%s: bio:%p sector:%lu+(%d*8). finish.\n", __func__,
			bio, bio->bi_sector, bio_struct->idx);
	if (atomic_dec_and_test(&bio_w->count)) {
		bio_wrapper_end_io(bio_w, bio_w->err);
	}
}

void subbio_write_endio(struct bio *bio, int err)
{
	int count;
	struct bio_wrapper *bio_w;
	struct bwr_data *bwr_data;
	struct page *page;
	struct hadmdev *hadmdev;
	struct bio_struct *bio_struct;

	BUG_ON(bio_data_dir(bio) != WRITE);
	bio_struct = (struct bio_struct *)bio->bi_private;
	bwr_data = (struct bwr_data *)bio_struct->private;
	bio_w = bio_struct->wrapper;
	hadmdev = bio_w->hadmdev;

	if (bio_data_dir(bio) == WRITE) {
		hadmdev->acct_info[W_SUBBIO_FINISH]++;
	} else {
		BUG();
	}

	if (unlikely(err)) {
		pr_err("BUG %s: submit subbio err. %d.\n", __FUNCTION__, err);
		bio_w->err |= err;
		buffer_inuse_del_occd(hadmdev->buffer);
		kfree(bwr_data);
	} else {
		page = bio->bi_io_vec[1].bv_page;
		get_page(page);			/* put in free_bwr_data */
		bwr_data->data_page = page;
		set_page_private(page, (unsigned long)bwr_data);

		count = buffer_data_seq_add_occd(hadmdev->buffer, bwr_data);
		if (count < 0) {
			pr_err("%s: insert into buffer faild.\n", __FUNCTION__);
		} else if (count > 0) {
			bwr_seq_add(hadmdev->bwr, count);
			bwr_tail_add_occupied(hadmdev->bwr, count);
		}
	}

	if (wrapper_remote(bio_w)) {
		IO_DEBUG("%s: remote wrapper:%p %d(-%d) subbio finish(%llu).\n",
				__func__, bio_w, bio_struct->idx,
				atomic_read(&bio_w->count), bio_w->pack->head.dev_sector);
	}
	/* if add meta, release it in submit_bio_wrapper ?
	 * yes, we need the error flag.
	 */
	if (atomic_dec_and_test(&bio_w->count)) {
		bio_wrapper_end_io(bio_w, bio_w->err);
	}
}

void hadm_bio_list_free(struct list_head *bio_list)
{
	struct bio_struct *bio_struct;
	struct bio_struct *temp;

	list_for_each_entry_safe(bio_struct, temp, bio_list, list) {
		list_del(&bio_struct->list);
		free_bio_struct(bio_struct);
	}
}

void hadm_bio_list_dump(struct bio_list *bio_list)      /* FIXME */
{
	struct bio_vec *bvec;
	struct bio *bio = bio_list->head;
	int i;

	pr_info("xxxx bio = %p", bio);
	while(bio != NULL) {
		pr_info("=============");
		pr_info("bio->bi_sector = %lu", bio->bi_sector);
		pr_info("bio->bi_vcnt = %u", bio->bi_vcnt);
		bio_for_each_segment(bvec, bio, i) {
			pr_info("bvec->bv_page = %p", bvec->bv_page);
		}

		bio = bio->bi_next;
		pr_info("=============");
	}
}

struct bio_wrapper *alloc_bio_wrapper(void)
{
	return (struct bio_wrapper *)kzalloc(GFP_KERNEL, sizeof(struct bio_wrapper));
}

int local_wrapper_split(struct bio_wrapper *wrapper)
{
	int i, ret;
	struct bio *bio;
	struct bio *sbio;
	struct bio_vec *bv;
	sector_t bi_sector;
	struct bwr_data *bwr_data;
	struct page *data_page;
	struct bio_struct *bio_struct;
	struct hadmdev *dev = wrapper->hadmdev;

	bio = wrapper->bio;
	if (bio->bi_idx != 0 ||
			bio->bi_size == 0 ||
			bio->bi_vcnt == 0) {
		pr_info("bio->bi_sector:%lu, bio->bi_rw:%lu, bio->bi_size:%u,"
				"bio->bi_vcnt:%d, bio->bi_idx:%d.\n",
				bio->bi_sector, bio->bi_rw, bio->bi_size,
				bio->bi_vcnt, bio->bi_idx);
		pr_err("special bio?!\n");
		dump_stack();
		return -1;
	}

	bi_sector = bio->bi_sector;
	/* create subbio struct for each bio page */
	for (i = 0; i < bio->bi_vcnt; i++) {
		bv = &bio->bi_io_vec[i];
		bwr_data = NULL;

		/* right now, only support PAGE_SIZE bio */
		if (bv->bv_len != PAGE_SIZE) {
			pr_err("%s: warnning unsupport bio data size."
					"sector:%lu|offset:%u|len:%u\n",
					__func__, bio->bi_sector,
					bv->bv_offset, bv->bv_len);
			if (bio_data_dir(bio) == WRITE)
				goto free_bio_list;
		}

		sbio = bio_alloc(GFP_NOIO, 1);
		if (!sbio) {
			pr_err("%s: alloc subbio failed.\n", __FUNCTION__);
			goto free_bio_list;
		}
		sbio->bi_rw = bio->bi_rw;
		sbio->bi_bdev = dev->bdev;
		sbio->bi_flags = bio->bi_flags & HADM_BIO_FLAGS_MASK;
		sbio->bi_sector = bi_sector;

		if (bio_data_dir(bio) == READ) {
			sbio->bi_end_io = subbio_read_endio;
			get_page(bv->bv_page);
			data_page = bv->bv_page;
		} else {
			bwr_data = alloc_bwr_data(GFP_KERNEL);
			if (!bwr_data) {
				pr_err("%s: alloc bwr_data failed.\n",
						__FUNCTION__);
				goto err_bio;
			}
			bwr_data->meta.dev_sector = sbio->bi_sector;

			if (bio_add_meta_page(sbio) != 0) {
				pr_err("add meta failed.\n");
				goto err_bio;
			}

			data_page = alloc_page(GFP_KERNEL);
			if (!data_page) {
				pr_err("%s: alloc data page failed.\n",
						__FUNCTION__);
				goto err_bio;
			}
			memcpy(page_address(data_page),
					page_address(bv->bv_page), PAGE_SIZE);

			sbio->bi_end_io = subbio_write_endio;
			/* We need write the data to bwr disk, fill bi_sector when submit */
			sbio->bi_sector = 0;
		}

		ret = bio_add_page(sbio, data_page, bv->bv_len, bv->bv_offset);
		if (ret != bv->bv_len) {
			pr_err("%s: add data page failed.len:%u|offset:%u.\n",
					__FUNCTION__, bv->bv_len, bv->bv_offset);
			goto err_bio;
		}

		bio_struct = create_bio_struct(sbio, wrapper, bwr_data, i);
		if (bio_struct == NULL) {
			pr_err("%s: create bio_struct failed.\n", __FUNCTION__);
			goto err_bio;
		}
		sbio->bi_private = bio_struct;
		list_add_tail(&bio_struct->list, &wrapper->bio_list);
		bi_sector += (bv->bv_len >> HADM_SECTOR_SHIFT);
	}

	return 0;

err_bio:
	bio_free_pages(sbio);
	bio_put(sbio);
free_bio_list:
	hadm_bio_list_free(&wrapper->bio_list);
	return -1;
}

/**
 * alloc & init a local bio_wrapper
 * add meta page at bio->bi_io_vec[bio->bi_idx]
 */
struct bio_wrapper *hadmdev_create_local_wrapper(struct hadmdev *hadmdev,
		struct bio *bio)
{
	int ret;
	struct bio_wrapper *wrapper;

	wrapper = kzalloc(GFP_KERNEL, sizeof(struct bio_wrapper));
	if (!wrapper) {
		pr_err("%s alloc wrapper faild.\n", __FUNCTION__);
		return NULL;
	}
	wrapper->hadmdev = hadmdev;
	wrapper->bio = bio;
	INIT_LIST_HEAD(&wrapper->bio_list);
	INIT_LIST_HEAD(&wrapper->node);
	wrapper->flags = 0;
	atomic_set(&wrapper->count, bio->bi_vcnt);

	wrapper->start_jif = jiffies;

	ret = local_wrapper_split(wrapper);
	if (ret < 0) {
		pr_err("%s bio split faild.\n", __FUNCTION__);
		kfree(wrapper);
		return NULL;
	}

	return wrapper;
}

int remote_wrapper_split(struct bio_wrapper *wrapper)
{
	int i, ret;
	int len, remain;
	struct bio *sbio;
	struct hadm_io *hv;
	struct bwr_data *bwr_data;
	struct page *data_page;
	struct bio_struct *bio_struct;
	struct packet *head = &wrapper->pack->head;
	struct hdpack_data *data = wrapper->pack->data;
	struct hadmdev *dev = wrapper->hadmdev;

	if (head->bi_size & (PAGE_SIZE - 1)) {
		pr_err("%s: warning unsupport size.%u|rw:%llu.\n", __func__,
				head->bi_size, head->bi_rw);
		if (head->bi_rw & WRITE)
			return -EKMOD_NOT_SUPPORT;
	}

	/* create subbio struct for each bio page,
	 * use max_vcnt, for read sbio, we need alloc page here */
	remain = head->bi_size;
	for (i = 0; i < data->max_vcnt; i++) {
		hv = &data->hv[i];
		bwr_data = NULL;

		sbio = bio_alloc(GFP_NOIO, 1);
		if (!sbio) {
			pr_err("%s: alloc subbio failed.\n", __FUNCTION__);
			goto free_bio_list;
		}
		sbio->bi_rw = head->bi_rw;
		sbio->bi_bdev = dev->bdev;
		sbio->bi_flags = head->bi_flags & HADM_BIO_FLAGS_MASK;
		sbio->bi_sector = head->dev_sector + 8 * i;

		if (head->bi_rw & WRITE) {
			bwr_data = alloc_bwr_data(GFP_KERNEL);
			if (!bwr_data) {
				pr_err("%s: alloc bwr_data failed.\n",
						__FUNCTION__);
				goto err_bio;
			}
			bwr_data->meta.dev_sector = sbio->bi_sector;
			set_bwr_data_remote(bwr_data);

			sbio->bi_sector = 0;
			if (bio_add_meta_page(sbio) != 0) {
				pr_err("add meta failed.\n");
				goto err_bio;
			}

			if (!hv->page) {
				pr_err("%s: null page. max cnt:%d|idx:%d|len:%d.\n",
						__func__, data->max_vcnt, i, head->len);
				goto err_bio;
			}
			get_page(hv->page);
			data_page = hv->page;
			sbio->bi_end_io = subbio_write_endio;
		} else {
			/* alloc page for read, add to reply packet */
			data_page = alloc_page(GFP_KERNEL);
			if (!data_page) {
				pr_err("%s: alloc data page failed.\n",
						__FUNCTION__);
				goto err_bio;
			}

			len = min(remain, (int)PAGE_SIZE);
			get_page(data_page);
			ret = hdpacket_add_page(wrapper->pack, data_page, 0,
					len);
			if (ret < 0) {
				pr_err("%s: add data page failed.\n", __func__);
				goto err_bio;
			}

			remain -= len;
			sbio->bi_end_io = subbio_read_endio;
		}

		ret = bio_add_page(sbio, data_page, hv->len, hv->start);
		if (ret != hv->len) {
			pr_err("%s: add data page failed.len:%u|offset:%u.\n",
					__FUNCTION__, hv->len, hv->start);
			goto err_bio;
		}

		bio_struct = create_bio_struct(sbio, wrapper, bwr_data, i);
		if (bio_struct == NULL) {
			pr_err("%s: create bio_struct failed.\n", __FUNCTION__);
			goto err_bio;
		}
		sbio->bi_private = bio_struct;
		list_add_tail(&bio_struct->list, &wrapper->bio_list);
	}

	return 0;

err_bio:
	bio_free_pages(sbio);
	bio_put(sbio);
free_bio_list:
	hadm_bio_list_free(&wrapper->bio_list);
	return -1;
}

struct bio_wrapper *hadmdev_create_remote_wrapper(struct hadmdev *dev,
		struct hdpacket *pack)
{
	int ret;
	struct bio_wrapper *wrapper;

	wrapper = kzalloc(GFP_KERNEL, sizeof(struct bio_wrapper));
	if (!wrapper) {
		pr_err("%s alloc wrapper faild.\n", __FUNCTION__);
		return NULL;
	}
	wrapper->hadmdev = dev;
	wrapper->pack = pack;
	INIT_LIST_HEAD(&wrapper->bio_list);
	INIT_LIST_HEAD(&wrapper->node);
	wrapper->flags |= (1 << __bw_remote);
	atomic_set(&wrapper->count, pack->data->max_vcnt);

	wrapper->start_jif = jiffies;

	ret = remote_wrapper_split(wrapper);
	if (ret < 0) {
		pr_err("%s bio split faild.\n", __FUNCTION__);
		kfree(wrapper);
		return NULL;
	}

	return wrapper;
}

int valid_wrapper(struct bio_wrapper *wrapper)
{
	return 1;
}

void free_bio_wrapper(struct bio_wrapper *bio_w)
{
	hadm_bio_list_free(&bio_w->bio_list);
	kfree(bio_w);
}

/**
 *io开始和结束的接口
 */
void bio_wrapper_prepare_io(struct bio_wrapper *bio_wrapper)
{
	_hadm_start_io_acct(bio_wrapper);
}

void bio_wrapper_end_io(struct bio_wrapper *wrapper,int error)
{
	if (wrapper_remote(wrapper)) {
		if (!(wrapper->pack->head.bi_rw & WRITE)) {
			IO_DEBUG("%s wrapper finish, pack:%p dev_sector:%llu.\n",
					__func__, wrapper->pack, wrapper->pack->head.dev_sector);
			hadmdev_sbio_packet_end(wrapper->hadmdev,
					wrapper->pack, error);
		}
	} else if (!(wrapper->bio->bi_rw & WRITE)) {
		wrapper->hadmdev->acct_info[R_BIO_FINISH]++;
		IO_DEBUG("%s local wrapper finish, bio:%p [%s]\n", __func__,
				wrapper->bio,
				bio_data_dir(wrapper->bio) == READ ? "read" : "write");
		bio_endio(wrapper->bio,error);
	}
	_hadm_end_io_acct(wrapper);
	free_bio_wrapper(wrapper);
}

int submit_bio_wrapper(struct bio_wrapper *wrapper)
{
	char *src;
	struct bio *bio;
	struct bio_vec *bvec;
	struct bio_struct *bio_struct;
	struct bwr_data *buffer_data;
	struct list_head *head, *tmp;

#if 0
	if (wrapper_remote(wrapper)) {
		IO_DEBUG("%s: rw=%s, rl=remote, disk_sector=%llu, size=%u[qaaz2]\n", __FUNCTION__,
				wrapper->pack->head.bi_rw & WRITE ? "WRITE" : "read",
				wrapper->pack->head.dev_sector,
				wrapper->pack->head.bi_size);

	} else {
		bio = wrapper->bio;
		IO_DEBUG("%s: rw=%s, rl=local, disk_sector=%llu, size=%u, wrapper bio=:%p[qaaz2]\n", __FUNCTION__,
				bio_data_dir(bio) == READ ? "READ" : "WRITE",
				(unsigned long long)bio->bi_sector,
				bio->bi_size,
				bio);
		if (bio_data_dir(wrapper->bio) == WRITE)
			wrapper->hadmdev->acct_info[W_SUBMIT_WRAPPER]++;
		else
			wrapper->hadmdev->acct_info[R_SUBMIT_WRAPPER]++;

	}
#endif

	head = &wrapper->bio_list;
	list_for_each_entry(bio_struct, head, list) {
		tmp = bio_struct->list.next;
		bio = bio_struct->bio;

		if (bio_data_dir(bio) == READ) {
			/* FIXME what if bv->bv_len != PAGE_SIZE ?
			 * for super block, it may occur
			 */
			wrapper->hadmdev->acct_info[R_SUBBIO]++;
			buffer_data = get_find_data_inuse(wrapper->hadmdev->buffer, bio->bi_sector,
					bio->bi_size);
			if (buffer_data) {
				IO_DEBUG("%s: read wrapper:%p:%d in buffer.\n", __func__,
						wrapper, bio_struct->idx);
				wrapper->hadmdev->acct_info[R_SUBBIO_FINISH]++;
				bvec = &wrapper->bio->bi_io_vec[bio_struct->idx];
				src = page_address(buffer_data->data_page) +
					((bio->bi_sector - buffer_data->meta.dev_sector) << HADM_SECTOR_SHIFT);
				memcpy(page_address(bvec->bv_page) + bvec->bv_offset,
						src, bvec->bv_len);
				bwr_data_put(buffer_data);
				if (atomic_dec_and_test(&wrapper->count)) {
					IO_DEBUG("%s: wrapper %p disk_sector:%lu finish.[qaaz3]\n",
							__func__, wrapper, wrapper->bio->bi_sector);
					bio_wrapper_end_io(wrapper, 0);
					break;
				}
				continue;
			} else {
				IO_DEBUG("%s: not in buffer, read from disk.\n", __func__);
			}
		} else {	/* WRITE */
			if (bwr_inuse_size_pre_occu(wrapper->hadmdev->bwr) < 0)
				return -1;
			buffer_inuse_pre_occu(wrapper->hadmdev->buffer);
			bio_struct_fill_bwrinfo(bio_struct);
			wrapper->hadmdev->acct_info[W_SUBBIO]++;
		}

		generic_make_request(bio);
		if (tmp == head)
			break;
	}

	return 0;
}

void dump_bio(struct bio *bio, const char *msg)
{
	pr_info("=========%s================", msg);
	pr_info("bio->sector = %lu", bio->bi_sector);
	pr_info("bio->bi_vcnt = %u", bio->bi_vcnt);
	pr_info("bio->bi_idx = %u", bio->bi_idx);
	pr_info("bio->bi_size = %u", bio->bi_size);
	pr_info("bio->bi_bdev = %p", bio->bi_bdev);
	pr_info("bio->bi_rw = %s", bio->bi_rw & 1 ? "write" : "read");
	pr_info("=========%s=================", msg);
}

void __dump_bio_wrapper(struct bio *bio)
{

	pr_info("============wrapper=============");
	pr_info("bio->sector = %lu", bio->bi_sector);
	pr_info("bio->bi_vcnt = %u", bio->bi_vcnt);
	pr_info("bio->bi_idx = %u", bio->bi_idx);
	pr_info("bio->bi_size = %u", bio->bi_size);
	pr_info("=========================");
}

struct bio_struct *create_bio_struct(struct bio* bio, struct bio_wrapper *wrapper,
		struct bwr_data *bwr_data, int idx)
{
	struct bio_struct *bio_struct;

	bio_struct = kzalloc(sizeof(struct bio_struct), GFP_KERNEL);
	if (bio_struct == NULL) {
		pr_err("alloc bio_struct failed.\n");
		return NULL;
	}

	INIT_LIST_HEAD(&bio_struct->list);
	bio_struct->bio = bio;
	bio_struct->idx = idx;
	bio_struct->wrapper = wrapper;
	bio_struct->private = bwr_data;
	if (bio->bi_rw & WRITE
			&& idx == atomic_read(&wrapper->count) -1) {
		wrapper->hadmdev->acct_info[W_SUBBIO_SET_ENDIO]++;
		if (wrapper_remote(wrapper))
			bwr_data->private = wrapper->pack;
		else
			bwr_data->private = wrapper->bio;
	}
	return bio_struct;
}

void free_bio_struct(struct bio_struct *bio_struct)
{
	int i;
	struct bio *bio;
	struct bio_vec *bvec;

	bio = bio_struct->bio;
	__bio_for_each_segment(bvec, bio, i, 0) {
		__free_page(bvec->bv_page);
	}
	bio_put(bio);
	kfree(bio_struct);
}

void dump_bio_wrapper(struct bio_wrapper *bio_wrapper)
{
	struct bio_struct *bio_struct;

	pr_info("--------dump_bio_wrapper start:-----------\n");
	pr_info("wrapper bio:%p cnt:%d, hadmdev:%s,\n",
			bio_wrapper->bio, atomic_read(&bio_wrapper->count), bio_wrapper->hadmdev->name);
	list_for_each_entry(bio_struct, &bio_wrapper->bio_list, list) {
		pr_info("bio_struct:%p, bio:%p, rw=%s, bdev:%p.\n",
				bio_struct,
				bio_struct->bio,
				bio_data_dir(bio_struct->bio) == READ ? "READ" : "WRITE",
				bio_struct->bio->bi_bdev);
	}
	pr_info("--------dump_bio_wrapper end:-----------\n");
}

struct meta *init_meta(struct bio *bio)
{
	struct meta *meta;

	meta = kzalloc(sizeof(struct meta), GFP_KERNEL);
	if (meta == NULL)
		return NULL;

	meta->dev_sector = bio->bi_sector;
	return meta;
}

struct kvec *kvec_create_from_bio(struct bio *bio)
{
	int idx;
	int count;
	struct kvec *kvec;
	struct kvec *tmp;
	struct bio_vec *bvec;

	count = bio->bi_vcnt;
	if (!count) {
		pr_info("%s: zero count.\n", __FUNCTION__);
		return NULL;
	}

	kvec = kzalloc(sizeof(struct kvec) * count, GFP_KERNEL);
	if (!kvec)
		return NULL;
	for (idx = 0; idx < count; idx++) {
		bvec = &bio->bi_io_vec[idx];
		tmp = &kvec[idx];

		tmp->iov_base = page_address(bvec->bv_page) + bvec->bv_offset;
		tmp->iov_len = bvec->bv_len;
	}

	return kvec;
}

int bio_add_meta_page(struct bio *bio)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL);
	if (!page) {
		return -ENOMEM;
	}

	if (bio_add_page(bio, page, HADM_SECTOR_SIZE, 0) == 0) {
		goto err;
	}

	return 0;

err:
	__free_page(page);
	return -1;
}

void bio_free_pages(struct bio *bio)
{
	int i;
	struct bio_vec *bvec;

	__bio_for_each_segment(bvec, bio, i, 0) {
		__free_page(bvec->bv_page);
	}
}

int bio_add_bwr_data(struct bio *bio, int pages)
{
	int idx;
	int size;
	struct page *page;

	for (idx = 0; idx < pages; idx++) {
		page = alloc_page(GFP_KERNEL);
		if (page == NULL) {
			goto fail;
		}

		size = idx ? PAGE_SIZE : META_SIZE;
		if (bio_add_page(bio, page, size, 0) != size) {
			__free_page(page);
			goto fail;
		}
	}

	return 0;

fail:
	bio_free_pages(bio);
	return -1;
}

void bio_wrapper_add_bwr_meta(struct bio_wrapper *bio_wrapper)
{
}

void bio_struct_fill_bwrinfo(struct bio_struct *bio_struct)
{
	uint64_t mem_uuid;
	struct bio *bio = bio_struct->bio;
	struct bwr_data *bwr_data = bio_struct->private;
	struct bwr_data_meta *meta = page_address(bio->bi_io_vec[0].bv_page);
	struct hadmdev *hadmdev = bio_struct->wrapper->hadmdev;
	static sector_t local_bwr_sector;
	static uint64_t local_bwr_seq;
	static uint64_t uuid;

	mem_uuid = hadmdev->bwr->mem_meta.local_primary.uuid;
	if (unlikely(uuid != mem_uuid)) {
		uuid = mem_uuid;
		local_bwr_seq = bwr_seq(hadmdev->bwr) + 1;
		local_bwr_sector = bwr_tail(hadmdev->bwr);
	}
	bio->bi_bdev = hadmdev->bwr_bdev;
	meta->dev_sector = bwr_data->meta.dev_sector;
	meta->bwr_sector = bwr_data->meta.bwr_sector = bio->bi_sector = local_bwr_sector;
	local_bwr_sector = bwr_next_sector(hadmdev->bwr, local_bwr_sector);
	meta->bwr_seq = bwr_data->meta.bwr_seq = local_bwr_seq++;
	meta->uuid = bwr_data->meta.uuid = uuid;
	meta->checksum = bwr_data->meta.checksum = crc32(0, page_address(bio->bi_io_vec[1].bv_page), PAGE_SIZE);
}

int wait_sync_site_finsh(struct bwr *bwr)
{
	int ret = 0;
	struct hadm_thread *bio_handler;

	bio_handler = bwr->hadmdev->threads[BIO_WR_HANDLER];
	while (!ret) {
		if (hadm_thread_get_state(bio_handler) != HADM_THREAD_RUN)
			return 0;

		ret = wait_for_completion_timeout(&bwr->sync_site_finish,
				msecs_to_jiffies(3000));
	}

	return 0;
}

struct sbio *sbio_create(struct bio *bio, gfp_t gfp_flag)
{
	struct sbio *sbio;

	sbio = kmalloc(sizeof(struct sbio), gfp_flag);
	if (!sbio)
		return NULL;
	INIT_LIST_HEAD(&sbio->list);
	sbio->bio = bio;

	return sbio;
}

void sbio_free(struct sbio *sbio)
{
	kfree(sbio);
}
