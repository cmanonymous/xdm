#include <linux/slab.h>
#include <linux/hash.h>

#include "buffer.h"
#include "bwr.h"
#include "utils.h"
#include "hadm_device.h"

static inline uint64_t data_hash(sector_t sector)
{
        return hash_64(sector, HASH_ENTRIES_SHIFT);
}

static inline int get_hadmdev_minor_from_buffer(struct data_buffer *buffer)
{
	return ((struct hadmdev *)buffer->private)->minor;
}

int buffer_is_full(struct data_buffer *buffer)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	ret = buffer->data_size == buffer->maxsize;
        spin_unlock_irqrestore(&buffer->lock, flags);

	return ret;
}

struct data_buffer *init_data_buffer(uint64_t maxsize, void *private)
{
        int i;
        struct hlist_head *hash_list;
	struct data_buffer *buffer;

	buffer = kmalloc(sizeof(struct data_buffer), GFP_KERNEL);
	if (buffer == NULL) {
		return NULL;
	}

        hash_list = alloc_pages_exact(sizeof(struct hlist_head) << HASH_ENTRIES_SHIFT, GFP_KERNEL);
        if (hash_list == NULL) {
                kfree(buffer);
                return NULL;
        }
        for (i = 0; i < HASH_ENTRIES; i++) {
                INIT_HLIST_HEAD(&hash_list[i]);
        }
        buffer->hash_list = hash_list;

	INIT_LIST_HEAD(&buffer->data_list);
	spin_lock_init(&buffer->lock);
	sema_init(&buffer->data_sema, 0);
	init_completion(&buffer->not_full);
	buffer->inuse_head = buffer->io_completed_tail = NULL;
	buffer->data_size = 0;
	buffer->inuse_size = 0;
	buffer->maxsize = maxsize;
	buffer->private = private;
	buffer->io_completed_seq = 0 ;

	return buffer;
}

/**
 *在下列情况下需要clear_data_buffer
 *1. primary变成secondary
 *2. 设备down或者模块卸载
 *3. 备机在P_DATA/P_RS_DATA之间切换
 *这些情况都不需要init sema
 */
void clear_data_buffer(struct data_buffer *buffer)
{
	unsigned long flags;
	struct bwr_data *bwr_data;
	struct bwr_data *tmp_data;

	spin_lock_irqsave(&buffer->lock, flags);
	list_for_each_entry_safe(bwr_data, tmp_data, &buffer->data_list, list) {
		list_del(&bwr_data->list);
		hlist_del_init(&bwr_data->list_hash);
		clear_bwr_data_inbuffer(bwr_data);
		bwr_data_put(bwr_data);
	}
	buffer->inuse_head = NULL;
	buffer->inuse_size = buffer->data_size = buffer->tail_seq = 0;
	buffer->io_completed_tail = NULL ; 
	buffer->io_completed_seq = 0 ; 
	init_completion(&buffer->not_full);
	//sema_init(&buffer->data_sema, 0);
        spin_unlock_irqrestore(&buffer->lock, flags);
}

void free_data_buffer(struct data_buffer *buffer)
{
	clear_data_buffer(buffer);

	free_pages_exact(buffer->hash_list, sizeof(struct hlist_head) << HASH_ENTRIES_SHIFT);
	kfree(buffer);
}

/* require buffer lock (bwr_data_seqsynced)*/
static inline int __entry_in_inuse(struct data_buffer *buffer, struct bwr_data *entry)
{
	return bwr_data_seqinbuffer(entry) && !bwr_data_seqsynced(entry);
}

static inline int __entry_in_buffer(struct data_buffer *buffer, struct bwr_data *entry)
{
	return bwr_data_inbuffer(entry) && bwr_data_seqinbuffer(entry);
}

/* read bio will search the buffer inuse, use hash version? */
struct bwr_data *get_find_data(struct data_buffer *buffer, sector_t disk_sector)
{
        unsigned long flags;
	struct bwr_data *data_iter;
	struct bwr_data *bwr_data = NULL;

	/* BUFFER_DEBUG("begin search for the buffer.search sector:%lu\n", disk_sector); */
        spin_lock_irqsave(&buffer->lock, flags);
	list_for_each_entry_reverse(data_iter, &buffer->data_list,list) {
		if(!buffer->inuse_head) {
			break;
		}
		if (data_iter->meta.dev_sector == disk_sector) {
				bwr_data = data_iter;
				bwr_data_get(bwr_data);
				break;
		}
		if (data_iter == buffer->inuse_head) 
			break;

	}
        spin_unlock_irqrestore(&buffer->lock, flags);

	return bwr_data;
}

struct bwr_data *__get_buffer_next_data(struct data_buffer *buffer, struct bwr_data *prev)
{
	struct bwr_data *bwr_data = NULL;

	if (!prev) {
		pr_err("%s null prev.\n", __FUNCTION__);
		dump_stack();
		BUG();
	}
	if (__entry_in_buffer(buffer, prev)) {
		if (prev != list_entry(buffer->data_list.prev,struct bwr_data, list)) {
			bwr_data = list_entry(prev->list.next, struct bwr_data, list);
			bwr_data_get(bwr_data);
		}
	}

	return bwr_data;
}

struct bwr_data *get_buffer_next_data(struct data_buffer *buffer, struct bwr_data *prev)
{
	unsigned long flags;
	struct bwr_data *bwr_data;

	spin_lock_irqsave(&buffer->lock, flags);
	bwr_data = __get_buffer_next_data(buffer, prev);
	spin_unlock_irqrestore(&buffer->lock, flags);
	return bwr_data;
}

struct bwr_data *get_find_data_hash(struct data_buffer *buffer, sector_t disk_sector)
{
        unsigned long flags;
        struct hlist_head *head = buffer->hash_list + data_hash(disk_sector);
	struct bwr_data *data_iter;
	struct bwr_data *bwr_data = NULL;
	sector_t io_completed_seq ;

	/* BUFFER_DEBUG("begin search for the buffer.search sector:%lu\n", disk_sector); */
        spin_lock_irqsave(&buffer->lock, flags);
	if(buffer->io_completed_tail) {
		io_completed_seq = bwr_data_seq(buffer->io_completed_tail);
	} else {
		io_completed_seq = 1;
	}
        hlist_for_each_entry(data_iter, head, list_hash) {
                /* use the whole buffer */
                if (data_iter->meta.dev_sector == disk_sector && 
				data_iter->meta.bwr_seq <= io_completed_seq ) {
			bwr_data = data_iter;
			bwr_data_get(bwr_data);
			break;
		}
	}
        spin_unlock_irqrestore(&buffer->lock, flags);

	return bwr_data;
}

static int __bwr_data_in_buffer(struct data_buffer *buffer, sector_t bwr_sector, sector_t prev_bwr_seq)
{
	struct bwr_data *head_data, *tail_data;

	if (list_empty(&buffer->data_list))
		return 0;
	head_data = list_entry(buffer->data_list.next, struct bwr_data, list);
	tail_data = list_entry(buffer->data_list.prev, struct bwr_data, list);
	if(prev_bwr_seq) {
		return (prev_bwr_seq + 1) >= head_data->meta.bwr_seq && 
			(prev_bwr_seq + 1) <= tail_data->meta.bwr_seq  ;
	}else {
		return  sector_in_area(bwr_sector, head_data->meta.bwr_sector, tail_data->meta.bwr_sector);
	}
}

struct bwr_data *get_find_data_by_bwr(struct data_buffer *buffer, sector_t bwr_sector, sector_t prev_bwr_seq)
{
	unsigned long flags;
	struct list_head *head = &buffer->data_list;
	struct bwr_data *data_iter;
	struct bwr_data *bwr_data = NULL;
	struct hadmdev *hadmdev = (struct hadmdev *)buffer->private;

	spin_lock_irqsave(&buffer->lock, flags);
	if (__bwr_data_in_buffer(buffer, bwr_sector, prev_bwr_seq)) {
		list_for_each_entry(data_iter, head, list) {
			if ((prev_bwr_seq && data_iter->meta.bwr_seq == prev_bwr_seq + 1) ||
					(!prev_bwr_seq && data_iter->meta.bwr_sector == bwr_sector)) {
				bwr_data = data_iter;
				bwr_data_get(bwr_data);
				break;
			}
		}
		if (!bwr_data) {
			pr_err("%s: BUG!!! hadm%d get bwr_data %lu failed while sector in [head, tail]\n", __FUNCTION__,
					hadmdev->minor, bwr_sector);
			BUG();
		}
	}
	spin_unlock_irqrestore(&buffer->lock, flags);
	return bwr_data;
}

struct bwr_data *get_find_data_inuse(struct data_buffer *buffer, sector_t disk_sector)
{

        return get_find_data_hash(buffer, disk_sector);

	/* FIXME why need bwr_data->list_inuse.next */
        //if (bwr_data && bwr_data->list_inuse.next)
                //return bwr_data;
}

/* return 0 if have truncated, -1 else. */
static int __buffer_trunc(struct data_buffer *buffer)
{
	struct bwr_data *bwr_data, *tail_data;
	if(list_empty(&buffer->data_list)) {
		pr_info("%s: hadm%d trunc a empty buffer\n",__FUNCTION__, get_hadmdev_minor_from_buffer(buffer));
		return -1;
		//dump_stack();
		//BUG();
	}
		
	tail_data = list_entry(buffer->data_list.prev, struct bwr_data, list);


	bwr_data = list_first_entry(&buffer->data_list, struct bwr_data, list);
	/**
	 *只有当buffer的第一个元素的seq <= io_completed_seq 才能被trunc
	 */
	if (bwr_data != buffer->inuse_head && 
			bwr_data_seq(bwr_data) <= buffer->io_completed_seq) {
		buffer->data_size--;
		if (unlikely(bwr_data == tail_data)) {
			BUFFER_DEBUG("%s warning: buffer is full, try trunc tail_data.\n", __FUNCTION__);
			buffer_set_tail_seq(buffer, bwr_data->meta.bwr_seq);
		}
		if(bwr_data == buffer->io_completed_tail) {
			buffer->io_completed_tail = NULL;
		}

		list_del_init(&bwr_data->list);
		clear_bwr_data_inbuffer(bwr_data);
		bwr_data_put(bwr_data);
		return 0;
	}else {
		BUFFER_DEBUG("%s: buffer is all in use, trunc failed. buffer first entry = %p, inuse_head = %p, io_completed_tail = %p , io_completed_seq = %llu\n",
				__FUNCTION__, bwr_data, buffer->inuse_head, buffer->io_completed_tail,
				(unsigned long long)buffer->io_completed_seq);
		BUFFER_DEBUG("%s: first entry %p ,seq %llu, sync_node_mask %llu\n",
				__FUNCTION__, bwr_data, bwr_data->meta.bwr_seq, 
				bwr_data->private ? ((struct bio_wrapper *)bwr_data->private)->sync_node_mask:0);
		return -1;
	}
}

/* FIXME: warning: need inuse size? increase?...*/
static void __buffer_inuse_add_tail(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	if (!bwr_data)
		return;
	if (! buffer->inuse_head) {
		buffer->inuse_head = bwr_data;
	}
	set_bwr_data_seqinbuffer(bwr_data);
	up(&buffer->data_sema);
}


struct bwr_data *get_head_data_inuse(struct data_buffer *buffer)
{
	unsigned long flags;
	struct bwr_data *head_data;

        spin_lock_irqsave(&buffer->lock, flags);
	head_data = buffer->inuse_head;
	if (head_data)
		bwr_data_get(head_data);
        spin_unlock_irqrestore(&buffer->lock, flags);
	return head_data;
}


/*
 * increase size before add the element,
 * guarentee buffer_add_data() success in IRQ
 */
void buffer_inuse_pre_occu(struct data_buffer *buffer)
{
        unsigned long flags;
	int ret ; 
	int inited = 0; 

try_occupy:
        spin_lock_irqsave(&buffer->lock, flags);
	if (buffer->data_size == buffer->maxsize ) {
		BUFFER_DEBUG("%s: buffer is full, try trunc data.\n", __FUNCTION__);
		ret = __buffer_trunc(buffer) ; 
		if (ret < 0) {
			spin_unlock_irqrestore(&buffer->lock, flags);
			if(!inited) {
				init_completion(&buffer->not_full);
				inited  = 1; 
			}

			if(wait_for_completion_timeout(&buffer->not_full,msecs_to_jiffies(10000)) == 0){
				pr_warn("%s: hadm%d buffer is full ,wait free space timeout\n",
						__FUNCTION__, get_hadmdev_minor_from_buffer(buffer));
				/**
				 *如果需要同步的节点非常多，可能会超时,也许需要将某些同步节点设置为ASYNC模式
				 */
				//BUG();
			}
			goto try_occupy;
		}else {
		}

	}
	buffer->data_size++;
	BUFFER_DEBUG("pre occu:data_size:%llu|maxsize:%llu.\n",
			buffer->data_size, 
			buffer->maxsize);
	spin_unlock_irqrestore(&buffer->lock, flags);
}


void buffer_add_bwr_data(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	unsigned long flags;
        struct hlist_head *hash_head;
	spin_lock_irqsave(&buffer->lock,  flags);
	list_add(&bwr_data->list, &buffer->data_list);
	hash_head  =  buffer->hash_list + data_hash(bwr_data->meta.dev_sector);
	hlist_add_head(&bwr_data->list_hash, hash_head);
	buffer->tail_seq++;
	buffer->data_size++;
	__buffer_inuse_add_tail(buffer, bwr_data);
	spin_unlock_irqrestore(&buffer->lock,  flags);


}
void buffer_add_bio_wrapper(struct bio_wrapper *bio_wrapper)
{
	struct hadmdev *hadmdev = bio_wrapper->hadmdev;
	struct data_buffer *buffer = hadmdev->buffer;
	struct bio_struct *bio_struct;
	struct bwr_data *bwr_data;
	struct page *page;
	uint64_t bwr_data_seq = 0, _bwr_seq = 0;
	int count = 0;
	if(hadmdev_error(hadmdev)){
		return;
	}
	_bwr_seq = bwr_seq(hadmdev->bwr);
	list_for_each_entry(bio_struct, &bio_wrapper->bio_list, list) {
		count++;
		bwr_data = bio_struct->private;
		page = bio_struct->bio->bi_io_vec[1].bv_page;
		get_page(page);
		bwr_data->data_page = page;
		set_page_private(page,  (unsigned long)bwr_data);
		buffer_data_add(buffer, bwr_data);
		bwr_data_seq = bwr_data_seq(bwr_data);
	}

	if(count && bwr_data_seq != _bwr_seq + count) {
		pr_warn("%s: hadm%d bwr data in buffer 's seq(%llu) is mismatch with the seq(%llu) written to primary info, count = %d\n",
				__FUNCTION__, hadmdev->minor, 
				(unsigned long long)bwr_data_seq, (unsigned long long)_bwr_seq, count);
		hadmdev_set_error(hadmdev, __BWR_ERR);
		return;

	}else{
		BUFFER_DEBUG("%s:add %d bwr data to buffer, last bwr data seq = %llu, _bwr_seq = %llu\n",
				__FUNCTION__, count,
				(unsigned long long)bwr_data_seq, (unsigned long long)_bwr_seq);
	}
	bwr_add_seq_n_tail(hadmdev->bwr, count);
	if(count) {
		complete(&hadmdev->bwr->have_snd_data);
	}
}

void buffer_set_io_completed_seq(struct data_buffer *buffer, sector_t seq)
{
	unsigned long flags;
	spin_lock_irqsave(&buffer->lock, flags);
	_buffer_set_io_completed_seq(buffer, seq);
	spin_unlock_irqrestore(&buffer->lock, flags);
}

void buffer_set_io_completed(struct bio_wrapper *bio_wrapper)
{
	struct hadmdev *hadmdev = bio_wrapper->hadmdev;
	struct data_buffer *buffer = hadmdev->buffer;
	struct bio_struct *bio_struct;
	unsigned long flags;
	BUFFER_DEBUG("%s:set io completed for bio_wrapper %p\n",
			__FUNCTION__,bio_wrapper);
	spin_lock_irqsave(&buffer->lock, flags);
	list_for_each_entry(bio_struct, &bio_wrapper->bio_list, list) {
		/**
		 *bio_struct->private 指向bwr_data，当备机处理P_RS_DATA时，因为
		 *直接写到bdev上，所以bio_struct->private == NULL时，就不处理了
		 */
		if(bio_struct->private == NULL) {
			break;
		}
		if(buffer->io_completed_tail == NULL) {
			buffer->io_completed_tail = list_entry(buffer->data_list.next, struct bwr_data, list);
		}else {
			buffer->io_completed_tail = list_entry(buffer->io_completed_tail->list.next, struct bwr_data, list) ;
		}
		BUFFER_DEBUG("%s:set io completed for bio_wrapper %p,  bio_struct %p(private %p), io_completed_tail %p, bwr_seq %llu\n",
				__FUNCTION__, 
				bio_wrapper, bio_struct, bio_struct->private, buffer->io_completed_tail,
				(unsigned long long)buffer->io_completed_tail->meta.bwr_seq);

		if (unlikely(buffer->io_completed_tail != bio_struct->private)) { 
			pr_warn("mismatch\n");
			hadmdev_set_error(hadmdev, __BWR_ERR);
			goto out;
		}
		if(unlikely(buffer->io_completed_seq &&
				       	bwr_data_seq(buffer->io_completed_tail) != 
					buffer->io_completed_seq +1)) {
			pr_warn("%s:hadm%d bwr_seq io completed seq mismatched, io_completed_tail = %llu, expected = %llu \n",
					__FUNCTION__, hadmdev->minor, 
					(unsigned long long)bwr_data_seq(buffer->io_completed_tail),
					(unsigned long long)buffer->io_completed_seq +1);
			hadmdev_set_error(hadmdev, __BWR_ERR);
			goto out;
		
		}
				
		_buffer_set_io_completed_seq(buffer, bwr_data_seq(buffer->io_completed_tail));
		complete(&buffer->not_full);

	}
out:
	spin_unlock_irqrestore(&buffer->lock, flags);
}

/**
 *FIXME 可能存在的问题，如果两个写bdev的io返回，那么在循环里获得
 *的next_entry有可能在buffer_trunc里被删除
 */
static int __buffer_inuse_del(struct data_buffer *buffer, 
		struct bwr_data *entry, 
		struct bwr_data **next_entry,
		struct bio_wrapper **completed_bio_wrapper)
{
	int count = 0;

	if(IS_ERR_OR_NULL(entry) || !bwr_data_synced(entry) ){
		return 0;
	}	
	*completed_bio_wrapper = NULL;
	*next_entry = NULL;

	if (entry == buffer->inuse_head) {
		list_for_each_entry_from(entry, &buffer->data_list, list) {
			if (!bwr_data_synced(entry))
				break;
			hlist_del_init(&entry->list_hash);
			set_bwr_data_seqsynced(entry);
			count ++;

			/**
			 *在sync模式里，当本地bdev写入数据完成后，需要清除掉对应的sync_node_mask
			 *并触发sync_mask_clear_node对应的操作
			 */
			if(entry->private) {
				/**
				 *因为sync_mask_clear_node会触发end_io操作，在end_io里，会对buffer加锁
				 *并设置io_completed_tail，所以会发生死锁，这里先将需要清理的bio_wrapper
				 *加入到队列里，然后再锁外clear
				 *使用队列的话，会使用kzalloc，导致“scheduling while atomic"的问题
				 *所以现在改用如果有completed_bio_wrapper出现，立即返回
				 */
				*completed_bio_wrapper = (struct bio_wrapper *)entry->private;
				*next_entry = list_entry(entry->list.next, struct bwr_data, list);
				break;
			}
		}
		if(*next_entry) {
		       if( &(*next_entry)->list != &buffer->data_list) {
			       buffer->inuse_head = *next_entry;
		       }else {
			       buffer->inuse_head = NULL;
			       *next_entry = NULL;
		       }
		} else if( &entry->list != &buffer->data_list) {
			buffer->inuse_head = entry; 
		}else {
			buffer->inuse_head = NULL;
		}
	}
	if(count){
		complete(&buffer->not_full);
	}
	return count;
}

int buffer_inuse_del(struct data_buffer *buffer, struct bwr_data *entry)
{
	int count, total = 0;
	struct bio_wrapper *completed_bio_wrapper;
	struct bwr_data *next_entry;
	int local_node_id = get_node_id();

        if (!entry) {
                pr_info("hadm%d try del null inuse entry.\n", get_hadmdev_minor_from_buffer(buffer));
                return -1;
        }

	/* FIXME */
	spin_lock(&buffer->lock);
	if (unlikely(!__entry_in_inuse(buffer, entry))) {
		spin_unlock(&buffer->lock);
		return -1;
	}
	set_bwr_data_synced(entry);
	while(1) {
		completed_bio_wrapper = NULL;
		next_entry = NULL;
		count = __buffer_inuse_del(buffer, entry, &next_entry, &completed_bio_wrapper);
		spin_unlock(&buffer->lock);
		total += count;
		if(count == 0 || completed_bio_wrapper ==NULL ){
			break;
		}
		entry = next_entry;
		sync_mask_clear_node(completed_bio_wrapper, local_node_id, 0);
		if(entry == NULL) {
			break;
		}
		spin_lock(&buffer->lock);
	}

	return total;
}

/* add tail */
static int __buffer_data_add(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	struct hlist_head *hash_head;
	set_bwr_data_inbuffer(bwr_data);
	list_add_tail(&bwr_data->list, &buffer->data_list);

	hash_head = buffer->hash_list + data_hash(bwr_data->meta.dev_sector);
	hlist_add_head(&bwr_data->list_hash, hash_head);

	__buffer_inuse_add_tail(buffer, bwr_data);
	return 0;
}

/*
 * 由调用者保证传进来的bwr_data是有效的，不会在此期间被删除。
 * 由于bwr_data总是先加进buffer，才被各个节点所引用，因此，在这里可以保证bwr_data
 * 有效
 */
int buffer_data_add(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	ret = __buffer_data_add(buffer, bwr_data);
        spin_unlock_irqrestore(&buffer->lock, flags);

	return ret;
}
