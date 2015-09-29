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
#include "hadm_config.h"
#include "hadm_struct.h"

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
	if(wrapper->private) {
		return ;
	}

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
	if(wrapper->private) {
		return ;
	}

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

	if (err)
		bio_w->err |= err;

	if (atomic_dec_and_test(&bio_w->count))
		bio_wrapper_end_io(bio_w);
}

void primary_data_end_io(void *arg)
{
	struct bio_wrapper *bio_w = (struct bio_wrapper *)arg;
	sync_mask_clear_node(bio_w, -1, 0);
}

void p_data_end_io(void *arg)
{
	primary_data_end_io(arg);
}
/**
 *这里不能用原有的方式处理，因为queue->private指向的是最后一个被处理的node
 *但是对于rs的处理来说，最后处理的node可能在之前还有没有处理完，如果private为
 *NULL，又从head开始的话，就存在一个bio被submit两次的情况。
 */
void p_rs_data_end_io(void *arg)
{
	struct bio_wrapper *bio_w = (struct bio_wrapper *)arg;
#if 0
	struct hadmdev *dev = bio_w->hadmdev;
	struct hadm_queue *queue= dev->bio_wrapper_queue[HADM_IO_WRITE];
	unsigned long flags;
	hadm_queue_lock(queue, flags, 0);
	pr_info("%s: del bio_wrapper(node %p) from bio_wrapper_queue[WRITE], queue len = %u, unused = %u, private = %p\n",
			__FUNCTION__, &bio_w->node, queue->len, queue->unused, queue->private);
	if(&bio_w->node == queue->private) {
		queue->private = NULL;
	}
	__hadm_queue_del_node(queue, &bio_w->node);
	pr_info("%s: after del bio_wrapper(node %p) from bio_wrapper_queue[WRITE], queue len = %u, unused = %u, private = %p\n",
			__FUNCTION__, &bio_w->node, queue->len, queue->unused, queue->private);
	hadm_queue_unlock(queue, flags, 0);
#endif
	bio_wrapper_end_io(bio_w);
}

void wrapper_queue_io_error(struct hadmdev *hadmdev)
{
	unsigned long flags;
	struct bio_wrapper *bio_wrapper, *tmp;
	struct hadm_queue *queue = hadmdev->bio_wrapper_queue[HADM_IO_WRITE];
	if(atomic_read(&hadmdev->bwr_io_pending) > 0){
		return ;
	}
	hadm_queue_lock(queue, flags, 1);
	list_for_each_entry_safe(bio_wrapper, tmp, &queue->head, node) {
		bio_wrapper->err = -EIO;
		__hadm_queue_del_node(queue, &bio_wrapper->node);
		bio_wrapper_end_io(bio_wrapper);
	}
	hadm_queue_unlock(queue, flags, 1);

}

void subbio_write_endio(struct bio *bio, int err)
{
	struct bio_wrapper *bio_w;
	struct hadmdev *hadmdev;
	struct bio_struct *bio_struct;
//	int local_node_id = get_node_id();

	BUG_ON(bio_data_dir(bio) != WRITE);
	bio_struct = (struct bio_struct *)bio->bi_private;
	bio_w = bio_struct->wrapper;
	hadmdev = bio_w->hadmdev;
	IO_DEBUG("bio_struct %p , bio %p is completed , bio_wrapper->count = %d\n",
			bio_struct, bio, atomic_read(&bio_w->count));

	if (bio_data_dir(bio) == WRITE) {
		hadmdev->acct_info[W_SUBBIO_FINISH]++;
	} else {
		BUG();
	}

	if (unlikely(err) || hadmdev_error(hadmdev)) {
		pr_err("BUG %s: hadm%d submit subbio err. %d.\n", 
				__FUNCTION__, hadmdev->minor, err);
		bio_w->err |= err;
		hadmdev_set_error(hadmdev, __BWR_ERR);
	}
#if 0
	else {
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
#endif
	/* if add meta, release it in submit_bio_wrapper ?
	 * yes, we need the error flag.
	 */
	if (atomic_dec_and_test(&bio_w->count)) {
		/**FIXME lock whole bio_wrapper_list**/
		/**在这里分两种情况，如果是异步模式，sync_node_mask就已经为0了，这时候需要
		 * buffer_add_bio_wrapper和bio_wrapper_end_io；如果是同步模式，则必须等待
		 * 本地完成才能清除掉所以sync_node_mask的local bit。
		 *
		 */
		bio_wrapper_end_io_t *func = bio_w->end_io;
		(*func)(bio_w);
	}
	atomic_dec(&hadmdev->bwr_io_pending);
}

/**
 *sync_node_mask在下列几个函数里被触发
 *1、提交本地bio_wrapper的endio里，清除掉本节点的sync_node_mask
 *2、同步模式下，接收到对端节点发过来的netack，当接收对端节点的netack的时，
 *ack的seq和比较bio_wrapper_list里第一个元素最后一个bio对应的seq，如果相等，则触发此操作
 *3、当同步节点断开，清理掉bio_wrapper_list里所有节点的sync_node_mask
 */
/**
 *1. 如果清理某一个bio_wrapper的sync_node_mask, 首先，检测他在bio_wrapper_list前面的那些元素，是否本地完成了(sync_node_mask & (1<<local_node_id) == 0)，
 * 如果没有完成，那么它不应该被加到buffer里；如果本地完成了，则可以加入到buffer；同时遍历后面的节点，如果和他相连的节点本地完成了，需要把这些节点都加入到buffer
 * 2、如果他的sync_node_mask = 0，那么他需要遍历后面的节点，如果和他相连的节点也sync_node_mask = 0，那么这些节点都需要end_io，并从队列里删除
 *
 */
int sync_mask_clear_node(struct bio_wrapper *bio_wrapper, int node_id, int irq_save)
{
	struct bio_wrapper *bio_w, *tmp;
	struct hadmdev *hadmdev = bio_wrapper->hadmdev;
	struct hadm_queue *queue = hadmdev->bio_wrapper_queue[HADM_IO_WRITE];
	unsigned long flags = 0;
	int end_io_completed = 0;
	hadm_queue_lock(queue, flags, irq_save);

	if(((bio_wrapper->sync_node_mask) & (1UL<<(node_id + 1))) == 0){
		/**
		 * 这意味着之前node_id对应的节点之前处于async的模式，所以无需
		 * 在此处理io
		 **/
		hadm_queue_unlock(queue, flags, irq_save);
		return 0;
	}

	bio_wrapper->sync_node_mask &= ~(1UL<<(node_id+1));
	/**如果不是队列第一个，则返回**/
	list_for_each_entry_safe(bio_w, tmp, &queue->head, node) {
		/**遍历bio_wrapper前面的元素，如果有没有local_completed的元素，则不进行任何操作**/
		/**遍历bio_wrapper后面的元素，如果本地完成了，则设置local_completed，并加入到buffer**/
		if(((bio_w->sync_node_mask) & (1UL)) == 0) {
			if(!bio_w->local_completed ) {
				buffer_add_bio_wrapper(bio_w);
				bio_w->local_completed = 1;
			}
		} else {
			break;
		}
		if(hadmdev_error(hadmdev)){
			bio_w->err |= -EIO;
		}


		if(bio_w->sync_node_mask == 0 && !end_io_completed) {
			if(&bio_w->node == queue->private) {
				queue->private = NULL;
			}
			__hadm_queue_del_node(queue, &bio_w->node);
			bio_wrapper_end_io(bio_w);
		}else {
			end_io_completed = 1;
		}
	}
	hadm_queue_unlock(queue,flags, irq_save);
	return 0;
}

int sync_mask_clear_after_node_disconnect(struct hadmdev *hadmdev, int node_id)
{
	struct hadm_queue *bio_wrapper_queue = hadmdev->bio_wrapper_queue[HADM_IO_WRITE];
	struct bio_wrapper *bio_wrapper, *tmp;
	unsigned long flags;
	int first = 1;
	IO_DEBUG("%s: clear all submitted write bio 's sync_mask after node %d disconnect.\n",
			__FUNCTION__, node_id);
	//lock
	hadm_queue_lock(bio_wrapper_queue,flags, 1);

	list_for_each_entry_safe(bio_wrapper, tmp, &bio_wrapper_queue->head, node) {
		IO_DEBUG("%s:clear node %d from bio_wrapper %p(next %p) sync_node_mask %llu \n",
				__FUNCTION__, node_id, bio_wrapper, tmp,
				(unsigned long long)bio_wrapper->sync_node_mask);
		bio_wrapper->sync_node_mask &=  ~(1UL<<(node_id+1));
		if(bio_wrapper->sync_node_mask != 0 ) {
			first = 0;
			continue;
		} else {
			if(!first)
				continue;
			IO_DEBUG("%s:bio_wrapper %p , queue->private = %p is completed on all nodes,  end io now.\n",
					__FUNCTION__, bio_wrapper, bio_wrapper_queue->private);

			if(&bio_wrapper->node == bio_wrapper_queue->private) {
				bio_wrapper_queue->private = NULL;
			}
			__hadm_queue_del_node(bio_wrapper_queue, &bio_wrapper->node);

//			list_del(&bio_wrapper->node.node);
			bio_wrapper_end_io(bio_wrapper);
		}
	}
	hadm_queue_unlock(bio_wrapper_queue,flags, 1);
	return 0;
	//unlock

}

/**
 * 当某个节点断开，有sync模式变成async模式的时候，可能存在下列步骤：
 * 1、一个写操作发生make_request，产生一个bio，得到的sync_node_mask里该节点的位为1(sync模式）
 * 2、disconnect_node发生，hadm_queue里所有的bio_wrapper该节点的位被清空
 * 3、step 1的bio被加入到hadm_queue里
 * 这时，该bio里该节点的位永远不能被清空，从而造成该bio永远不能被返回。
 *
 * */

int sync_mask_clear_queue(struct hadmdev *hadmdev, uint64_t sync_mask, uint64_t prev_sync_mask)
{
	struct hadm_queue *queue = hadmdev->bio_wrapper_queue[HADM_IO_WRITE];
	unsigned long flags;
	struct bio_wrapper *bio_w, *tmp;
	int local_node_id = get_node_id();
	int i = 0;
	if(prev_sync_mask == 1){
		return 0;
	}
	hadm_queue_lock(queue, flags, 1);
	list_for_each_entry_safe(bio_w, tmp, &queue->head, node) {
		/**
		 *如果bio_w->sync_node_mask 有一位为1，而sync_mask 里为0，且该节点sync mode为async
		 *表明该bio_w是在sync_mask_clear_after_node_disconnect调用之前创建，而调用之后被插入到hadm_queue里的
		 *
		 */
		for(i=0; i<MAX_NODES; i++){
			if(i == local_node_id)
				continue;
			if((bio_w->sync_node_mask & (1UL<<(i+1))) && ! (sync_mask & (1UL<<(i+1)))) {
				pr_info("%s:hadm%d bio_wrapper %p(sync_mask = 0x%llx) is created before node %d disconnected , but submitted after sync_mask_clear_after_node_disconnect.\n",
						__FUNCTION__, hadmdev->minor, bio_w, (unsigned long long)bio_w->sync_node_mask, i);
				BUG();
			}
		}
		IO_DEBUG("%s: bio_w %p sync_node_mask 0x%llx\n", __FUNCTION__, bio_w, (unsigned long long)bio_w->sync_node_mask);

	}
	hadm_queue_unlock(queue, flags, 1);

	return 0;
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

/**
 *由于在创建sync_node_mask的时候bio_wrapper_list必须加锁，所以
 *set_sync_mask用于在hadm_queue_push_timeout_fn用作回调函数，
 *在加锁的时候设置wrapper的属性
 */
int set_sync_mask(void *arg)
{
	struct bio_wrapper *wrapper = (struct bio_wrapper *)arg;
	struct hadmdev *hadmdev = wrapper->hadmdev;
	struct bwr_data *bwr_data;
	struct bio_struct *bio_struct;
	int rw = bio_data_dir(wrapper->bio);
	if(rw != WRITE) {
		return 0;
	}
	if(list_empty(&wrapper->bio_list)) {
		return 0;
	}

	wrapper->sync_node_mask =(rw == WRITE) ?
		gen_sync_node_mask(hadmdev) : 0;
	if(wrapper->sync_node_mask & ~(1UL)){
		bio_struct = list_entry(wrapper->bio_list.prev, struct bio_struct, list);
		bwr_data = (struct bwr_data *)bio_struct->private;
		bwr_data->private = wrapper;
	}
	return 0;
}

static int wrapper_bio_check(struct bio *bio)
{
	if (bio->bi_idx || !bio->bi_size || !bio->bi_vcnt)
		goto check_fail;

	if (unlikely(bio->bi_sector & 0x7))
		//不支持非对齐的写操作(现在hadm处理数据的单位为page)
		if (bio_data_dir(bio) == WRITE)
			goto check_fail;

	return 0;

check_fail:
	pr_err("%s: bio->bi_sector:%lu|bio->bi_rw:%lu|bio->bi_size:%u|"
			"bio->bi_vcnt:%d|bio->bi_idx:%d\n", __func__,
			bio->bi_sector, bio->bi_rw, bio->bi_size,
			bio->bi_vcnt, bio->bi_idx);
	dump_stack();
	return -1;
}

static int read_wrapper_split(struct bio_wrapper *wrapper)
{
	int i;
	struct bio *sbio;
	struct bio_vec *bv;
	sector_t bi_sector;
	struct bio_struct *bio_struct;
	struct page *data_page;
	struct bio *bio = wrapper->bio;
	struct hadmdev *hadmdev = wrapper->hadmdev;

	bi_sector = bio->bi_sector;
	for (i = 0; i < bio->bi_vcnt; i++) {
		bv = &bio->bi_io_vec[i];

		if (bv->bv_len != PAGE_SIZE) {
			pr_info("%s: hadm%d unregular bv size:%u|sector:%lu[WARN]\n",
					__func__, hadmdev->minor, bv->bv_len, bio->bi_sector);
			if (bv->bv_len & (HADM_SECTOR_SIZE - 1)) {
				pr_err("%s: hadm%d unsupport bv size:%u|sector:%lu[ERROR]\n",
						__func__, hadmdev->minor, bv->bv_len, bio->bi_sector);
				goto free_bio_list;
			}
		}

		sbio = bio_alloc(GFP_NOIO, 1);
		if (!sbio) {
			pr_err("%s: hadm%d alloc subbio failed.\n", __func__, hadmdev->minor);
			goto free_bio_list;
		}

		sbio->bi_rw = bio->bi_rw;
		/* we need add page */
		sbio->bi_flags = bio->bi_flags & ~(1 << BIO_CLONED);
		sbio->bi_bdev = hadmdev->bdev;
		sbio->bi_sector = bi_sector;
		sbio->bi_end_io = subbio_read_endio;

		get_page(bv->bv_page);
		data_page = bv->bv_page;

		if (bio_add_page(sbio, data_page, bv->bv_len, bv->bv_offset) != bv->bv_len) {
			pr_err("%s: hadm%d add data page failed.(len:%u|offset:%u)\n",
					__func__, hadmdev->minor, bv->bv_len, bv->bv_offset);
			goto err_bio;
		}

		bio_struct = init_bio_struct(sbio, wrapper, NULL, i);
		if (!bio_struct) {
			pr_err("%s: hadm%d alloc & init bio_struct failed.\n", __func__, hadmdev->minor);
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
	hadmdev_set_error(hadmdev, __OTHER_ERR);
	return -1;
}

static int write_wrapper_split(struct bio_wrapper *wrapper)
{
	int i;
	struct bio *sbio;
	struct bio_vec *bv;
	sector_t bi_sector;
	struct bwr_data *bwr_data;
	struct bio_struct *bio_struct;
	struct page *data_page;
	struct bio *bio = wrapper->bio;
	struct hadmdev *hadmdev = wrapper->hadmdev;

	bi_sector = bio->bi_sector;
	for (i = 0; i < bio->bi_vcnt; i++) {
		bv = &bio->bi_io_vec[i];
		bwr_data = NULL;

		if (bv->bv_len != PAGE_SIZE) {
			pr_info("%s: hadm%d unregular subbio size:%u|sector:%lu[ERR]\n",
					__func__, hadmdev->minor, bv->bv_len, bio->bi_sector);
			goto free_bio_list;
		}

		sbio = bio_alloc(GFP_NOIO, 1);
		if (!sbio) {
			pr_err("%s: hadm%d alloc subbio failed.\n", __func__, hadmdev->minor);
			goto free_bio_list;
		}

		sbio->bi_rw = bio->bi_rw;
		sbio->bi_flags = bio->bi_flags & ~(1 << BIO_CLONED);
		//写入bwr时会比写入bdev的数据多出meta信息，可能bdev会显示越界
		sbio->bi_sector = 0;
		sbio->bi_bdev = hadmdev->bwr_bdev;
		sbio->bi_end_io = subbio_write_endio;

		bwr_data = init_bwr_data(0, bi_sector, 0, 0, 0, NULL);
		if (!bwr_data) {
			pr_err("%s: hadm%d alloc bwr data for subbio failed.\n", __func__, hadmdev->minor);
			goto err_bio;
		}

		if (bio_add_meta_page(sbio) < 0) {
			pr_err("%s: hadm%d subbio add meta failed.\n", __func__, hadmdev->minor);
			goto err_bio;
		}

		data_page = alloc_page(GFP_KERNEL);
		if (!data_page) {
			pr_err("%s: hadm%d alloc data page failed.\n", __func__, hadmdev->minor);
			goto err_bio;
		}
		memcpy(page_address(data_page), page_address(bv->bv_page), PAGE_SIZE);

		if (bio_add_page(sbio, data_page, bv->bv_len, bv->bv_offset) != bv->bv_len) {
			pr_err("%s: hadm%d add data page failed.(len:%u|offset:%u)\n",
					__func__, hadmdev->minor, bv->bv_len, bv->bv_offset);
			goto err_bio;
		}

		bio_struct = init_bio_struct(sbio, wrapper, bwr_data, i);
		if (!bio_struct) {
			pr_err("%s: hadm%d alloc & init bio_struct failed.\n", __func__, hadmdev->minor);
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
	hadmdev_set_error(hadmdev, __OTHER_ERR);
	return -1;
}

static int do_wrapper_split(struct bio_wrapper *wrapper)
{
	if (bio_data_dir(wrapper->bio) == READ)
		return read_wrapper_split(wrapper);
	else
		return write_wrapper_split(wrapper);
}

int wrapper_split(struct bio_wrapper *wrapper)
{
	return do_wrapper_split(wrapper);
}

int hadm_bio_split(struct bio_wrapper *wrapper)
{
	int i, dir;
	struct bio *sbio;
	struct bio_vec *bv;
	sector_t bi_sector;
	struct bwr_data *bwr_data;
	struct bio_struct *bio_struct;
	struct page *data_page;
	struct bio *bio = wrapper->bio;
	struct hadmdev *hadmdev = wrapper->hadmdev;

	if (bio->bi_idx != 0 ||
			bio->bi_size == 0 ||
			bio->bi_vcnt == 0) {
		pr_info("hadm%d bio->bi_sector:%lu, bio->bi_rw:%lu, bio->bi_size:%u, bio->bi_vcnt:%d, bio->bi_idx:%d.\n",
				hadmdev->minor, bio->bi_sector, bio->bi_rw, bio->bi_size, bio->bi_vcnt, bio->bi_idx);
		pr_err("special bio?!\n");
		dump_stack();
		return -1;
	}

	dir = bio_data_dir(bio);
	//不支持非对齐的写操作(现在hadm处理数据的单位为page, 由bwr_data表示)
	if (unlikely(bio->bi_sector & 0x7)) {
		if (dir == WRITE) {
			pr_err("hadm%d special bio?!\nbio->bi_sector:%lu, bio->bi_rw:%lu, bio->bi_size:%u,"
				"bio->bi_vcnt:%d, bio->bi_idx:%d.\n",
				hadmdev->minor, 
				bio->bi_sector, bio->bi_rw, bio->bi_size, bio->bi_vcnt, bio->bi_idx);
			dump_stack();
			return -1;
		}
	}

	bi_sector = bio->bi_sector;
	for (i = 0; i < bio->bi_vcnt; i++) {
		bv = &bio->bi_io_vec[i];
		bwr_data = NULL;

		if (bv->bv_len != PAGE_SIZE) {
			pr_info("%s: hadm%d warning unregular subbio size:%u(sector:%lu).\n",
					__func__, hadmdev->minor, bv->bv_len, bio->bi_sector);
			if (dir == WRITE ||
					(bv->bv_len & (HADM_SECTOR_SIZE - 1))) {
				pr_err("%s: ERROR hadm%d unsupport write bio size:%u at sector:%lu.\n",
						__func__, hadmdev->minor, bv->bv_len, bio->bi_sector);
				goto free_bio_list;
			}
		}

		sbio = bio_alloc(GFP_NOIO, 1);
		if (!sbio) {
			pr_err("%s: alloc subbio failed.\n", __func__);
			goto free_bio_list;
		}

		sbio->bi_rw = bio->bi_rw;
		sbio->bi_flags = bio->bi_flags & ~(1 << BIO_CLONED);	/* we need add page */

		if (dir == READ) {
			sbio->bi_bdev = hadmdev->bdev;
			sbio->bi_sector = bi_sector;
			sbio->bi_end_io = subbio_read_endio;
			get_page(bv->bv_page);
			data_page = bv->bv_page;
		} else {
			//写入bwr时会比写入bdev的数据多出meta信息，可能bdev会显示越界，而bwr不会.
			sbio->bi_sector = 0;
			sbio->bi_bdev = hadmdev->bwr_bdev;
			sbio->bi_end_io = subbio_write_endio;

			bwr_data = init_bwr_data(0, bi_sector, 0, 0, 0, NULL);
			if (!bwr_data) {
				pr_err("%s: hadm%d alloc bwr data for subbio failed.\n", __func__, hadmdev->minor);
				goto err_bio;
			}

			if (bio_add_meta_page(sbio) < 0) {
				pr_err("%s: hadm%d subbio add meta failed.\n", __func__, hadmdev->minor);
				goto err_bio;
			}

			data_page = alloc_page(GFP_KERNEL);
			if (!data_page) {
				pr_err("%s: hadm%d alloc data page failed.\n", __func__, hadmdev->minor);
				goto err_bio;
			}
			memcpy(page_address(data_page), page_address(bv->bv_page), PAGE_SIZE);
		}

		if (bio_add_page(sbio, data_page, bv->bv_len, bv->bv_offset) != bv->bv_len) {
			pr_err("%s: hadm%d add data page failed.(len:%u|offset:%u)\n",
					__func__, hadmdev->minor, bv->bv_len, bv->bv_offset);
			goto err_bio;
		}

		bio_struct = init_bio_struct(sbio, wrapper, bwr_data, i);
		if (!bio_struct) {
			pr_err("%s: hadm%d alloc & init bio_struct failed.\n", 
					__func__, hadmdev->minor);
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
	hadmdev_set_error(hadmdev, __OTHER_ERR);
	return -1;
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

static struct bio *gen_bio_from_pack(struct hadmdev *dev, struct packet *pack)
{
	struct bio *bio = NULL;
	struct page *page = NULL;
	struct bwr_data_meta *meta = NULL;
	int err = 0;
	bio = bio_alloc(GFP_NOIO, 1);
	if(IS_ERR_OR_NULL(bio)){
		err = -ENOMEM;
		goto gen_bio_out;
	}
	bio->bi_rw = WRITE;
	bio->bi_end_io = subbio_write_endio;
	if(pack->type == P_RS_DATA) {
		bio->bi_bdev = dev->bdev;
		bio->bi_sector = pack->dev_sector;
		page = alloc_page(GFP_KERNEL);
		if(page == NULL){
			err = -ENOMEM;
			goto gen_bio_out;
		}
		memcpy(page_address(page), pack->data, PAGE_SIZE);
		if(bio_add_page(bio, page, PAGE_SIZE, 0) == 0){
			pr_info("%s: hadm%d add data page to bio failed\n", 
					__FUNCTION__, dev->minor);
			__free_page(page);
			page = NULL;
			err = -ENOMEM;
			goto gen_bio_out;
		}
	}else{
		bio->bi_bdev = dev->bwr_bdev;
		bio->bi_sector = seq_to_bwr(pack->bwr_seq, dev->bwr);
		page = alloc_page(GFP_KERNEL);
		if(page == NULL){
			err = - ENOMEM;
			goto gen_bio_out;
		}
		meta = (struct bwr_data_meta *)page_address(page);
		meta->dev_sector = pack->dev_sector;
		meta->bwr_sector = bio->bi_sector;
		meta->bwr_seq = pack->bwr_seq;
		meta->uuid = pack->uuid;
		meta->checksum = crc32(0, pack->data, PAGE_SIZE);
		if(bio_add_page(bio, page, HADM_SECTOR_SIZE, 0) == 0){
			pr_info("%s: hadm%d add meta page to bio failed\n", __FUNCTION__, dev->minor);
			__free_page(page);
			page = NULL;
			err = -ENOMEM;
			goto gen_bio_out;
		}

		page = alloc_page(GFP_KERNEL);
		if(page == NULL){
			err = -ENOMEM;
			goto gen_bio_out;
		}
		memcpy(page_address(page), pack->data, PAGE_SIZE);
		if(bio_add_page(bio, page, PAGE_SIZE, 0) == 0){
			pr_info("%s: hadm%d add data page to bio failed\n", __FUNCTION__, dev->minor);
			__free_page(page);
			dump_bio(bio, __FUNCTION__);

			page = NULL;
			err = -ENOMEM;
			goto gen_bio_out;
		}
	}
gen_bio_out:
	if(err){
		if(bio) {
			bio_free_pages(bio);
			bio_put(bio);
		}
		return ERR_PTR(err);
	}
	return bio;

}

static struct bio_wrapper *create_bio_wrapper(struct hadmdev *hadmdev, struct bio *bio, bio_wrapper_end_io_t *end_io)
{
	struct bio_wrapper *wrapper;

	wrapper = alloc_bio_wrapper();
	if (wrapper == NULL) {
		pr_err("%s alloc wrapper faild.\n", __FUNCTION__);
		return NULL;
	}

	wrapper->crc = 0x9e3700012UL;
	wrapper->private = NULL;
	wrapper->hadmdev = hadmdev;
	wrapper->bio = bio;
	wrapper->end_io = end_io;
	wrapper->start_jif=jiffies;
	wrapper->local_completed = 0;
	wrapper->sync_node_mask = 1;
	atomic_set(&wrapper->count, bio->bi_vcnt);
	INIT_LIST_HEAD(&wrapper->bio_list);
	INIT_LIST_HEAD(&wrapper->node);
	return wrapper;

}

struct bio_wrapper *gen_bio_wrapper_from_pack(struct hadm_pack_node *pack_node)
{
	struct packet *pack = pack_node->pack;
	struct hadm_pack_node *ack_node = NULL;
	struct bio_struct *bio_struct = NULL;
	struct bio *bio = NULL ;
	struct hadmdev *dev;
	struct bwr_data *bwr_data = NULL;
	struct bio_wrapper *bio_wrapper = NULL;
	int retry = 0;
	int err = 0;
	dev = find_hadmdev_by_minor(pack->dev_id);
	if(dev == NULL){
		return ERR_PTR(-EINVAL);
	}
	ack_node = gen_data_ack_pack_node(pack_node, 0);
	if(IS_ERR_OR_NULL(ack_node)) {
		err = -ENOMEM;
		goto out;
	}
	while(retry++ < 3) {
		bio = gen_bio_from_pack(dev, pack);
		if(IS_ERR_OR_NULL(bio)) {
			schedule_timeout(msecs_to_jiffies(1000));
			continue;
		}else {
			break;
		}
	}
	if(IS_ERR_OR_NULL(bio)) {
		err = -ENOMEM;
		goto out;
	}
	bio_wrapper = create_bio_wrapper(dev, bio, (pack->type == P_RS_DATA) ? p_rs_data_end_io : p_data_end_io);
	if(IS_ERR_OR_NULL(bio_wrapper)){
		err = -ENOMEM;
		goto out;
	}
	atomic_set(&bio_wrapper->count, 1);
	bio_wrapper->private = ack_node;
	if(pack->type == P_DATA) {
		bwr_data = kzalloc(sizeof(struct bwr_data), GFP_KERNEL);
		if(IS_ERR_OR_NULL(bwr_data)){
			err = -ENOMEM;
			goto out;
		}
		memcpy(&bwr_data->meta, page_address(bio->bi_io_vec[0].bv_page), sizeof(struct bwr_data_meta));
		bwr_data->private = NULL;
		bwr_data->flags = 0UL;
		atomic_set(&bwr_data->refcnt, 1);
		INIT_LIST_HEAD(&bwr_data->list);
		INIT_HLIST_NODE(&bwr_data->list_hash);
	}

	bio->bi_private = bio_struct = init_bio_struct(bio, bio_wrapper, bwr_data, 0);
	list_add_tail(&bio_struct->list, &bio_wrapper->bio_list);

out:
	if(err){
		pr_info("%s: error occurs , err = %d\n", __FUNCTION__, err);
		if(ack_node) {
			hadm_pack_node_free(ack_node);
		}
		if(!IS_ERR_OR_NULL(bio)){
			bio_free_pages(bio);
			bio_put(bio);
		}
		if(bwr_data){
			kfree(bwr_data);
		}
		return ERR_PTR(err);
	}
	IO_DEBUG("%s: gen bio_wrapper successed, seq = %llu \n",
			__FUNCTION__, bwr_data ? bwr_data_seq(bwr_data) : 0);
	return bio_wrapper;

}

/*
 * search bio data from buffer inuse list
 * return 0 means can find all, otherwise return 1
 */
static int bio_find_data_buffer(struct bio *bio, struct data_buffer *buffer,
		struct bwr_data *data_list[])
{
	int miss;
	struct bwr_data *bwr_data;
	sector_t start, end, iter;

	//pr_info("%s: try find bio in buffer\n", __func__);
	//msleep(1000);
	miss = 0;
	start = round_down(bio->bi_sector, PAGE_SIZE >> HADM_SECTOR_SHIFT);
	end = round_down(bio->bi_sector + (bio->bi_size >> HADM_SECTOR_SHIFT) -1,
			PAGE_SIZE >> HADM_SECTOR_SHIFT);
	iter = 0;
	while (start <= end) {
		bwr_data = get_find_data_inuse(buffer, start);
		if (!bwr_data)
			miss = 1;
		else
			data_list[iter++] = bwr_data;
		start += PAGE_SIZE >> HADM_SECTOR_SHIFT;
	}
	//pr_info("%s: find bio in buffer end, missing:%d\n", __func__, miss);

	return miss;
}

static int wrapper_find_buffer(struct bio_wrapper *wrapper,
		struct data_buffer *buffer)
{
	int ret;
	struct bwr_data **data_list;
	struct bio *bio = wrapper->bio;

	//pr_info("%s: try find wrapper in buffer\n", __func__);
	//+1 for end NULL, +1 for bv may across two bwr_data
	data_list = kzalloc(sizeof(struct bwr_data *) * (bio->bi_vcnt + 1 + 1),
			GFP_KERNEL);
	if (!data_list)
		return -ENOMEM;

	ret = bio_find_data_buffer(bio, buffer, data_list);
	atomic_set(&wrapper->count, ret);
	wrapper->private = data_list;

	return 0;
}

/**
 * add meta page at bio->bi_io_vec[bio->bi_idx]
 */
struct bio_wrapper *init_bio_wrapper(struct bio *bio, bio_wrapper_end_io_t *end_io)
{
	int ret = 0 ;
	int minor;
	struct bio_wrapper *wrapper ;
	struct hadmdev *hadmdev;

	minor = MINOR(bio->bi_bdev->bd_dev);

	hadmdev = find_hadmdev_by_minor(minor);
	if (!hadmdev)
		return NULL;

	if (wrapper_bio_check(bio) < 0) {
		pr_err("%s: hadm%d unsupported bio size\n", __func__, hadmdev->minor);
		return NULL;
	}

	wrapper = create_bio_wrapper(hadmdev, bio, end_io);
	if (!wrapper)
		return NULL;

	if (bio_data_dir(bio) == READ)
		wrapper_find_buffer(wrapper, hadmdev->buffer);
	else {
		ret = wrapper_split(wrapper);
		if (ret < 0) {
			pr_err("%s bio split faild.\n", __FUNCTION__);
			kfree(wrapper);
			return NULL;
		}
	}
	return wrapper;
}

int valid_wrapper(struct bio_wrapper *wrapper)
{
	if (wrapper->crc != 0x9e3700012UL) {
		pr_err("corrupt wrapper. wrong crc.\n");
		return 0;
	}
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

void bio_wrapper_end_io(struct bio_wrapper *bio_wrapper)
{
	int rw = bio_data_dir(bio_wrapper->bio);
	struct hadm_pack_node *ack_node = NULL;
	int set_io_completed = 1;

	if(bio_wrapper->private == NULL) {
		bio_endio(bio_wrapper->bio,bio_wrapper->err);
	}else {
		ack_node = (struct hadm_pack_node *)bio_wrapper->private;
		if(ack_node->pack->type == P_RS_DATA_ACK) {
			set_io_completed = 0;
		}
		ack_node->pack->errcode = bio_wrapper->err;
		if(packet_node_send(ack_node, 0)){
			hadmdev_set_error(bio_wrapper->hadmdev, __BWR_ERR);
			goto out;
		}
	}
	/**
	 *对于P_RS_DATA的endio，无需set io completed
	 */
	if(rw  ==  WRITE && !bio_wrapper->err && set_io_completed) {
		buffer_set_io_completed(bio_wrapper);

	}
	_hadm_end_io_acct(bio_wrapper);
out:
	free_bio_wrapper(bio_wrapper);
}

void bio_copy_bwr_data_list(struct bio *bio, struct bwr_data *data_list[])
{
	int biter, diter;
	struct bio_vec *bv;
	void *bsrc, *dsrc;
	sector_t bstart, bend;	//bv start/end sector
	sector_t dstart, dend;	//bwr_data start/end sector
	sector_t cstart, cend;	//copy start/end sector
	struct bwr_data *data;

	//pr_info("%s: try copy data from data_list.\n", __func__);

	biter = 0;
	bv = &bio->bi_io_vec[biter];
	bstart = bio->bi_sector;
	bend = bstart + (bv->bv_len >> HADM_SECTOR_SHIFT) - 1;

	diter = 0;
	data = data_list[diter];
	if (!data)
		return;
	dstart = data->meta.dev_sector;
	dend = dstart + (PAGE_SIZE >> HADM_SECTOR_SHIFT) - 1;

	for (;;) {
		BUG_ON(dend < bstart);

		if (dstart > bend) {
			biter++;
			if (biter == bio->bi_vcnt)
				break;
			bv = &bio->bi_io_vec[biter];
			bstart = bend + 1;
			bend = bstart + (bv->bv_len >> HADM_SECTOR_SHIFT) - 1;
			continue;
		}

		//OK, we need do copy
		cstart = max(bstart, dstart);
		cend = min(bend, dend);
		bsrc = page_address(bv->bv_page) +
			((cstart - bstart) << HADM_SECTOR_SHIFT);
		dsrc = page_address(data->data_page) +
			((cstart - dstart) << HADM_SECTOR_SHIFT);
		memcpy(bsrc, dsrc, (cend - cstart + 1) << HADM_SECTOR_SHIFT);

		//update bv, bwr_data
		if (cend == bend) {
			biter++;
			if (biter == bio->bi_vcnt)
				break;
			bv = &bio->bi_io_vec[biter];
			bstart = bend + 1;
			bend = bstart + (bv->bv_len >> HADM_SECTOR_SHIFT) - 1;
		}
		if (cend == dend) {
			diter++;
			data = data_list[diter];
			if (!data)
				break;
			dstart = data->meta.dev_sector;
			dend = dstart + (PAGE_SIZE >> HADM_SECTOR_SHIFT) - 1;
		}
	}
}

static void bwr_data_list_free(struct bwr_data **data)
{
	int idx = 0;
	struct bwr_data *iter;

	iter = data[idx];
	while ((iter = data[idx++]))
		bwr_data_put(iter);
	kfree(data);
}

void read_wrapper_endio(struct bio_wrapper *wrapper)
{
	//pr_info("%s: wrapper bio:%p end.\n", __func__, wrapper->bio);
	if (!wrapper->err)
		bio_copy_bwr_data_list(wrapper->bio, wrapper->private);

	bwr_data_list_free(wrapper->private);
	bio_endio(wrapper->bio, wrapper->err);
}

static void read_bio_endio(struct bio *bio, int err)
{
	struct bio_wrapper *wrapper = bio->bi_private;
	struct hadmdev *hadmdev = wrapper->hadmdev;

	hadmdev->acct_info[R_SUBBIO_FINISH]++;

	//pr_info("%s: clone bio end~.\n", __func__);
	if (err)
		wrapper->err |= err;

	read_wrapper_endio(wrapper);
}

int submit_read_wrapper(struct bio_wrapper *wrapper)
{
	struct bio *bio;

	//pr_info("%s: try direct submit read bio:%p\n", __func__, wrapper->bio);
	if (!atomic_read(&wrapper->count)) {
		pr_info("%s: hadm%d all in buffer ^_^.\n", __func__, wrapper->hadmdev->minor);
		read_wrapper_endio(wrapper);
		return 0;
	}
	//pr_info("%s: ok, just submit to lower device.\n", __func__);
	bio = bio_clone(wrapper->bio, GFP_NOIO);
	if (!bio) {
		pr_err("%s: submit clone bio failed.\n", __func__);
		return -ENOMEM;
	}
	bio->bi_bdev = wrapper->hadmdev->bdev;
	bio->bi_private = wrapper;
	bio->bi_end_io = read_bio_endio;

	generic_make_request(bio);

	return 0;
}

/**
 *写数据时，从bio_wrapper_list获取bio_wrapper，依次submit_bio到bwr里，当一个bio_wrapper完成后，将bio_wrapper整体加入data buffer
 *三个线程(sync_local, sync_remote, sync_dbm)从buffer或者bwr里读取数据写入到本地硬盘、发送到对端节点以及写入到dbm
 *写入到本地硬盘的数据都是从buffer里读取，buffer里保存
 *
 */
int submit_bio_wrapper(struct bio_wrapper *wrapper)
{
	struct bio *bio;
	struct bio_struct *bio_struct;
	struct bwr_data *buffer_data;
	struct list_head *head, *tmp;
	void *src_addr;
	void *dst_addr;
	sector_t start_sector;

	bio = wrapper->bio;
	head = &wrapper->bio_list;
	if (bio_data_dir(wrapper->bio) == WRITE){
		wrapper->hadmdev->acct_info[W_SUBMIT_WRAPPER]++;
	} else{
		wrapper->hadmdev->acct_info[R_SUBMIT_WRAPPER]++;
	}
	list_for_each_entry(bio_struct, head, list) {
		tmp = bio_struct->list.next;
		bio = bio_struct->bio;

		if (bio_data_dir(bio) == READ) {
			wrapper->hadmdev->acct_info[R_SUBBIO]++;
			start_sector = bio->bi_sector >> 3 << 3;
			if (unlikely(start_sector != bio->bi_sector)) {
				if (((bio->bi_sector - start_sector) << HADM_SECTOR_SHIFT)
						+ bio->bi_size > PAGE_SIZE) {
					pr_info("hadm%d read unaligned IO from buffer: bio->bi_sector:%lu,"
							"bio->bi_rw:%lu, bio->bi_size:%u, bio->bv_offset:%d, bio->bv_len:%d",
							wrapper->hadmdev->minor,
							bio->bi_sector, bio->bi_rw, bio->bi_size,
							wrapper->bio->bi_io_vec[bio_struct->idx].bv_offset,
							wrapper->bio->bi_io_vec[bio_struct->idx].bv_len);

					wrapper->err |= -EIO;
					continue;
				}
			}

			buffer_data = get_find_data_inuse(wrapper->hadmdev->buffer, start_sector);
			if (buffer_data) {
				wrapper->hadmdev->acct_info[R_SUBBIO_FINISH]++;
				src_addr = page_address(buffer_data->data_page);
				dst_addr = page_address(wrapper->bio->bi_io_vec[bio_struct->idx].bv_page);
				memcpy(dst_addr + wrapper->bio->bi_io_vec[bio_struct->idx].bv_offset,
						src_addr + ((bio->bi_sector - start_sector) << HADM_SECTOR_SHIFT),
						wrapper->bio->bi_io_vec[bio_struct->idx].bv_len);
				bwr_data_put(buffer_data);
				if (atomic_dec_and_test(&wrapper->count)) {
					bio_wrapper_end_io(wrapper);
					break;
				}
				continue;
			}
		} else {	/* WRITE */
		/**
		 *当处理P_RS_DATA时，无需写bwr，所以无需等待bwr和buffer有空闲空间
		 *bio_struct->private 为空，表示现在处理的是P_RS_DATA
		 */
			if(bio_struct->private) {
				if (bwr_inuse_size_pre_occu(wrapper->hadmdev->bwr) < 0)
					return -1;
				buffer_inuse_pre_occu(wrapper->hadmdev->buffer);
				if(hadmdev_get_primary_id(wrapper->hadmdev) == get_node_id())
					bio_struct_fill_bwrinfo(bio_struct);
				IO_DEBUG("%s: submit WRITE op for data bwr_seq = %llu\n",
						__FUNCTION__,
						bio_struct->private ? bwr_data_seq((struct bwr_data *)bio_struct->private) : 0);
			}

			if(wrapper->private){
				/*
				 *这里需要等待p_data queue里的空间是否够
				 *
				 */
				if(hadm_queue_reserve_timeout(wrapper->hadmdev->p_sender_queue[P_DATA_TYPE], 1,
							msecs_to_jiffies(10000))){
					pr_info("%s: wait device %d's sender queue free space timeout.\n", 
							__FUNCTION__, 
							wrapper->hadmdev->minor);
					return -1;
				}
			}
			wrapper->hadmdev->acct_info[W_SUBBIO]++;
			atomic_inc(&wrapper->hadmdev->bwr_io_pending);
		}

		generic_make_request(bio);
		if (tmp == head)
			break;
	}

	return 0;
}

static void dump_bv(struct bio_vec *bv, const char *msg)
{
	pr_info("%s: bv->len:%u|bv->offset:%u\n",
			msg, bv->bv_len, bv->bv_offset);
}

void dump_bio(struct bio *bio, const char *msg)
{
	int i;
	struct request_queue *q = bdev_get_queue(bio->bi_bdev);
	pr_info("=========%s================", msg);
	pr_info("bio queue = %p \n", q);
	pr_info("queue->merge_bvec_fn = %p", q->merge_bvec_fn);
	pr_info("bio->bi_bdev = %s", bio->bi_bdev->bd_disk->disk_name);
	pr_info("bio->bi_phys_segments = %u(queue_max_segments = %u)", bio->bi_phys_segments, queue_max_segments(q));
	pr_info("bio->sector = %lu", bio->bi_sector);
	pr_info("bio->bi_vcnt = %u", bio->bi_vcnt);
	pr_info("bio->bi_max_vecs = %u", bio->bi_max_vecs);
	pr_info("bio->bi_idx = %u", bio->bi_idx);
	pr_info("bio->bi_size = %u", bio->bi_size);
	pr_info("bio->bi_rw = %s", bio->bi_rw & 1 ? "write" : "read");

	for (i = 0; i < bio->bi_vcnt; i++)
		dump_bv(&bio->bi_io_vec[i], "\t");

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

struct bio_struct *init_bio_struct(struct bio* bio, struct bio_wrapper *wrapper,
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
	bio_struct->sector = bio->bi_sector;
	bio_struct->wrapper = wrapper;
	bio_struct->private = bwr_data;

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
		pr_info("bio_struct:%p, bio:%p, rw=%s, bdev:%p, sector:%llu.\n",
				bio_struct,
				bio_struct->bio,
				bio_data_dir(bio_struct->bio) == READ ? "READ" : "WRITE",
				bio_struct->bio->bi_bdev,
				(unsigned long long)bio_struct->sector);
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

int bio_add_meta_page(struct bio *bio)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL);
	if (!page)
		return -ENOMEM;
	if (IS_ERR(page)) {
		pr_err("%s: what the fuck IS_ERR.%p\n", __func__, page);
		return -ENOMEM;
	}

	if (bio_add_page(bio, page, HADM_SECTOR_SIZE, 0) == 0) {
		pr_err("%s: add page failed.\n", __func__);
		__free_page(page);
		return -1;
	}

	return 0;
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


void bio_struct_fill_bwrinfo(struct bio_struct *bio_struct)
{
	uint64_t mem_uuid;
	struct bio *bio = bio_struct->bio;
	struct bwr_data *bwr_data = bio_struct->private;
	struct bwr_data_meta *meta = page_address(bio->bi_io_vec[0].bv_page);
	struct hadmdev *hadmdev = bio_struct->wrapper->hadmdev;
	struct bwr *bwr = hadmdev->bwr;
	unsigned long flags;
	sector_t last_bwr_seq;
	bio->bi_bdev = hadmdev->bwr_bdev;
	meta->dev_sector = bwr_data->meta.dev_sector;
	meta->checksum = bwr_data->meta.checksum = crc32(0, page_address(bio->bi_io_vec[1].bv_page), PAGE_SIZE);
	write_lock_irqsave(&bwr->lock, flags);
	if(bwr->last_seq == 0)
		bwr->last_seq = bwr->mem_meta.local_primary.bwr_seq;
	last_bwr_seq = bwr->last_seq + 1;
	meta->bwr_sector = bwr_data->meta.bwr_sector = bio->bi_sector = seq_to_bwr(last_bwr_seq, bwr);
	meta->bwr_seq = bwr_data->meta.bwr_seq = last_bwr_seq;
	meta->uuid = bwr_data->meta.uuid = bwr->mem_meta.local_primary.uuid;
	mem_uuid = bwr->mem_meta.local_primary.uuid;
	bwr->last_seq = last_bwr_seq;
	write_unlock_irqrestore(&bwr->lock, flags);
	IO_DEBUG("%s: hadm%d submit bio, seq=%lu\n", __FUNCTION__, hadmdev->minor, last_bwr_seq);

}


