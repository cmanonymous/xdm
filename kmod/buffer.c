#include <linux/slab.h>
#include <linux/hash.h>
#include <linux/delay.h>

#include "buffer.h"
#include "bwr.h"
#include "utils.h"
#include "hadm_device.h"

static inline uint64_t data_hash(sector_t sector)
{
        return hash_64(sector, HASH_ENTRIES_SHIFT);
}

void dump_buffer_inuse(struct data_buffer *buffer)
{
	int p_flag = 0;
	struct bwr_data *bwr_data, *prev_data = NULL;

	pr_info("%s dump inuse buffer:\n", __FUNCTION__);
	if (buffer->inuse_head) {
		pr_info("inuse list size:%lld, (%llu:%llu).\n",
				buffer->inuse_size, bwr_data_seq(buffer->inuse_head), bwr_data_seq(buffer->tail_data));
		for (bwr_data = buffer->inuse_head;
				;
				bwr_data = list_entry(bwr_data->list.next, struct bwr_data, list)) {
			if (!prev_data) {
				printk("[BEGIN]: %llu(%lu %lu) ", bwr_data->meta.bwr_seq,
						bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
				p_flag = 1;
			} else if (bwr_data_seq(bwr_data) != bwr_data_seq(prev_data) + 1) {
				if (!p_flag)
					printk("->%llu(%lu %lu) ",
							prev_data->meta.bwr_seq, prev_data->meta.bwr_sector, prev_data->meta.dev_sector);
				printk("->%llu(%lu %lu) ", bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
				p_flag = 1;
			} else {
				if (bwr_data != buffer->tail_data && p_flag)
					printk("->...");
				p_flag = 0;
			}

			if (bwr_data == buffer->tail_data) {
				if (!p_flag)
					printk("->%llu(%lu %lu)",
							bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
				break;
			}
			prev_data = bwr_data;
		}
	}
	printk("[END]\n");
}

void dump_buffer_hash(struct hlist_head *head)
{
        struct bwr_data *bwr_data;
        struct hlist_node *node_iter;

        pr_info("%s dump hash buffer:\n", __FUNCTION__);
        hlist_for_each_entry(bwr_data, node_iter, head, list_hash) {
		printk("->%llu(%lu %lu) ", bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
        }
	pr_info("\n");
}

void dump_buffer_data(struct data_buffer *buffer)
{
	int p_flag = 0;
	struct bwr_data *bwr_data, *prev_data = NULL;

	pr_info("%s dump data buffer:\n", __FUNCTION__);
	pr_info("data size:%lld, inuse_size:%lld(%llu:%llu).\n",
			buffer->data_size, buffer->inuse_size,
			buffer->inuse_head ? bwr_data_seq(buffer->inuse_head) : 0,
			buffer->inuse_head ? bwr_data_seq(buffer->tail_data) : 0);
	if (!list_empty(&buffer->data_list)) {
		list_for_each_entry(bwr_data, &buffer->data_list, list) {
			if (!prev_data) {
				printk("[BEGIN]: %llu(%lu %lu) ", bwr_data->meta.bwr_seq,
						bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
				p_flag = 1;
			} else if (bwr_data_seq(bwr_data) != bwr_data_seq(prev_data) + 1) {
				if (!p_flag)
					printk("->%llu(%lu %lu) ",
							prev_data->meta.bwr_seq, prev_data->meta.bwr_sector, prev_data->meta.dev_sector);
				printk("->%llu(%lu %lu) ", bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
				p_flag = 1;
			} else {
				if (p_flag)
					printk("->...");
				p_flag = 0;
			}
			prev_data = bwr_data;
		}
		if (!p_flag) {
			bwr_data = list_entry(buffer->data_list.prev, struct bwr_data, list);
			printk("->%llu(%lu %lu)",
					bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
		}
		printk("[END]\n");
	}
}

int __buffer_inuse_is_full(struct data_buffer *buffer)
{
	return buffer->inuse_size == buffer->maxsize;
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

int buffer_inuse_is_full(struct data_buffer *buffer)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	ret = __buffer_inuse_is_full(buffer);
	spin_unlock_irqrestore(&buffer->lock, flags);

	return ret;
}

int buffer_inuse_is_empty(struct data_buffer *buffer)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	ret = buffer->inuse_head == NULL;
        spin_unlock_irqrestore(&buffer->lock, flags);

	return ret;
}

static inline void __buffer_inuse_size_inc(struct data_buffer *buffer)
{
	BUFFER_DEBUG("%s: inc inuse size from %lld ", __FUNCTION__, buffer->inuse_size);
	if (buffer->inuse_size++ == buffer->maxsize) {
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		BUG();
	}
	BUFFER_DEBUG("to %lld\n", buffer->inuse_size);
}

static inline void __buffer_inuse_size_add(struct data_buffer *buffer, int nr)
{
	BUFFER_DEBUG("%s: add inuse size from %lld ", __FUNCTION__, buffer->inuse_size);
	buffer->inuse_size += nr;
	if (buffer->inuse_size > buffer->maxsize) {
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		BUG();
	}
	BUFFER_DEBUG("to %lld\n", buffer->inuse_size);
}

static inline void __buffer_inuse_size_sub(struct data_buffer *buffer, int nr)
{
	if (buffer->inuse_size < nr) {
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		BUG();
	}
	if (__buffer_inuse_is_full(buffer) && nr > 0) {
		pr_info("buffer inuse size dec, notify not full.\n");
		complete(&buffer->not_full);
	}
	BUFFER_DEBUG("%s: sub inuse size from %lld ", __FUNCTION__, buffer->inuse_size);
	buffer->inuse_size -= nr;
	BUFFER_DEBUG("to %lld\n", buffer->inuse_size);
}

static inline void __buffer_inuse_size_set(struct data_buffer *buffer, int nr)
{
	if (nr > buffer->maxsize || nr < 0) {
		pr_err("%s try set buffer inuse size to %d.\n", __FUNCTION__, nr);
		return;
	}
	if (__buffer_inuse_is_full(buffer) && nr != buffer->maxsize) {
		pr_info("buffer inuse size set, notify not full.\n");
		complete(&buffer->not_full);
	}
	BUFFER_DEBUG("%s: update inuse size from %lld ", __FUNCTION__, buffer->inuse_size);
	buffer->inuse_size = nr;
	BUFFER_DEBUG("to %lld\n", buffer->inuse_size);
}

static inline void __buffer_inuse_size_dec(struct data_buffer *buffer)
{
	BUFFER_DEBUG("%s: dec inuse size from %lld ", __FUNCTION__, buffer->inuse_size);
	if (buffer->inuse_size == 0) {
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		BUG();
	}

	if (__buffer_inuse_is_full(buffer)) {
		pr_info("buffer inuse size dec, notify not full.\n");
		complete(&buffer->not_full);
	}
	buffer->inuse_size--;
	BUFFER_DEBUG("to %lld\n", buffer->inuse_size);
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
	buffer->tail_data = buffer->inuse_head = NULL;
	buffer->data_size = 0;
	buffer->inuse_size = 0;
	buffer->maxsize = maxsize;
	buffer->private = private;

	return buffer;
}

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
	buffer->inuse_head = buffer->tail_data = NULL;
	buffer->inuse_size = buffer->data_size = buffer->tail_seq = 0;
	init_completion(&buffer->not_full);
	sema_init(&buffer->data_sema, 0);
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
	if (buffer->inuse_head) {
		data_iter = buffer->tail_data;
		for(;;) {
			if (data_iter->meta.dev_sector == disk_sector) {
				bwr_data = data_iter;
				bwr_data_get(bwr_data);
				break;
			}
			if (data_iter == buffer->inuse_head)
				break;
			data_iter = list_entry(data_iter->list.prev, struct bwr_data, list);
		}
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
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		BUG();
	}
	if (__entry_in_buffer(buffer, prev)) {
		if (prev != buffer->tail_data) {
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

struct bwr_data *__get_find_data_hash(struct data_buffer *buffer, sector_t disk_sector)
{
	struct hlist_head *head = buffer->hash_list + data_hash(disk_sector);
        struct hlist_node *hash_iter;
	struct bwr_data *data_iter;
	struct bwr_data *bwr_data = NULL;

	/* BUFFER_DEBUG("begin search for the buffer.search sector:%lu\n", disk_sector); */
        hlist_for_each_entry(data_iter, hash_iter, head, list_hash) {
                /* use the whole buffer */
                if (data_iter->meta.dev_sector == disk_sector) {
			bwr_data = data_iter;
			bwr_data_get(bwr_data);
			break;
		}
	}

	return bwr_data;
}

struct bwr_data *get_find_data_hash(struct data_buffer *buffer, sector_t disk_sector)
{
	unsigned long flags;
	struct bwr_data *bwr_data = NULL;

        spin_lock_irqsave(&buffer->lock, flags);
	bwr_data = __get_find_data_hash(buffer, disk_sector);
        spin_unlock_irqrestore(&buffer->lock, flags);

	return bwr_data;
}

/* for special case while the content may overlap
 * @buffer
 * @start:	start sector to search
 * @len:	total search size. @len = HADM_SECTOR_SIZE * [1-4]
 * */
struct bwr_data **get_find_data_special(struct data_buffer *buffer,
		sector_t start, int len)
{
	int i, j;
	int count, offset;
	unsigned long flags;
	struct bwr_data *result, *find;
	struct bwr_data **rlist;
	struct bwr_data **flist;

	count = PAGE_SIZE / HADM_SECTOR_SIZE + len / HADM_SECTOR_SIZE - 1;
	flist = kzalloc(sizeof(struct bwr_data *) * count, GFP_KERNEL);
	if (!flist) {
		pr_info("%s alloc iter_result failed.\n", __func__);
		return NULL;
	}
	rlist = kzalloc(sizeof(struct bwr_data *) * len / HADM_SECTOR_SIZE,
			GFP_KERNEL);
	if (!rlist) {
		pr_info("%s: alloc result failed.\n", __func__);
		kfree(flist);
		return NULL;
	}

	//msleep(1000);
	offset = (PAGE_SIZE / HADM_SECTOR_SIZE - 1);
	spin_lock_irqsave(&buffer->lock, flags);
	for (i = 0; i < count; i++) {
		if ((start + i) < offset)
			continue;
		find = __get_find_data_hash(buffer, start + i - offset);
		flist[i] = find;
	}
	spin_unlock_irqrestore(&buffer->lock, flags);

	for (j = 0; j < len / HADM_SECTOR_SIZE; j++) {
		result = NULL;
		for (i = 0; i < PAGE_SIZE/HADM_SECTOR_SIZE; i++) {
			find = flist[j + i];
			if (find) {
				if (!result ||
				    bwr_data_seq(result) < bwr_data_seq(find))
					result = find;
			}
		}
		rlist[j] = result;
		if (result)
			bwr_data_get(result);
	}

	for (i = 0; i < count; i++) {
		if (flist[i])
			bwr_data_put(flist[i]);
	}
	kfree(flist);
	return rlist;
}

static int __bwr_data_in_buffer(struct data_buffer *buffer, sector_t bwr_sector)
{
	struct bwr_data *head_data;

	if (!buffer->tail_data)
		return 0;
	head_data = list_entry(buffer->data_list.next, struct bwr_data, list);
	return  sector_in_area(bwr_sector, head_data->meta.bwr_sector, buffer->tail_data->meta.bwr_sector);
}

struct bwr_data *get_find_data_by_bwr(struct data_buffer *buffer, sector_t bwr_sector)
{
	unsigned long flags;
	struct list_head *head = &buffer->data_list;
	struct bwr_data *data_iter;
	struct bwr_data *bwr_data = NULL;

//	BUFFER_DEBUG("begin search for the buffer.search sector:%lu\n", bwr_sector);
	spin_lock_irqsave(&buffer->lock, flags);
	if (__bwr_data_in_buffer(buffer, bwr_sector)) {
		list_for_each_entry(data_iter, head, list) {
			//BUFFER_DEBUG("iter: bwr_sector:%lu, disk_sector:%lu.\n", data_iter->meta.bwr_sector, data_iter->meta.dev_sector);
			if (data_iter->meta.bwr_sector == bwr_sector) {
				bwr_data = data_iter;
				bwr_data_get(bwr_data);
				break;
			}
		}
		if (!bwr_data) {
			pr_err("%s: BUG!!! get bwr_data %lu failed while sector in [head, tail]\n", __FUNCTION__,
					bwr_sector);
			dump_buffer_inuse(buffer);
			dump_buffer_data(buffer);
			BUG();
		}
	}
	spin_unlock_irqrestore(&buffer->lock, flags);
	return bwr_data;
}

struct bwr_data *get_find_data_inuse(struct data_buffer *buffer,
		sector_t disk_sector, int len)
{

	if (likely(len == PAGE_SIZE))
		return get_find_data_hash(buffer, disk_sector);
	else {
		int i;
		int count = len >> HADM_SECTOR_SHIFT;
		struct bwr_data *data = NULL;
		struct bwr_data **rlist;

		pr_info("%s: warning special len %d. sector:%lu.\n", __func__,
				len, disk_sector);
		rlist = get_find_data_special(buffer, disk_sector, len);
		if (!rlist)
			return NULL;
		for (i = 0; i < count; i++) {
			if (rlist[0] != rlist[i]) {
				pr_info("%s: badly! data:(%p:%lu)(%p:%lu).\n",
						__func__,
						rlist[0], rlist[0] ? rlist[0]->meta.dev_sector : -1,
						rlist[i], rlist[i] ? rlist[i]->meta.dev_sector : -1);

				goto free_list;
			}
		}
		data = rlist[0];
		if (data)
			bwr_data_get(data);
		pr_info("%s: lucky? sector:(%lu:%lu), len:%d.\n",
				__func__, disk_sector,
				data ? data->meta.dev_sector : -1, len);
free_list:
		for (i = 0; i < count; i++) {
			if (rlist[i])
				bwr_data_put(rlist[i]);
		}
		kfree(rlist);

		return data;
	}
}

/* return 0 if have truncated, -1 else. */
static int __buffer_trunc(struct data_buffer *buffer)
{
	struct bwr_data *bwr_data;

	bwr_data = list_first_entry(&buffer->data_list, struct bwr_data, list);
	if (bwr_data != buffer->inuse_head) {
		buffer->data_size--;
		list_del_init(&bwr_data->list);
		clear_bwr_data_inbuffer(bwr_data);
		if (unlikely(bwr_data == buffer->tail_data)) {
			BUFFER_DEBUG("%s warning: buffer is full, try trunc tail_data.\n", __FUNCTION__);
			buffer_set_tail_seq(buffer, bwr_data->meta.bwr_seq);
			buffer->tail_data = NULL;
		}
		BUFFER_DEBUG("%s trunc %llu(%lu:%lu)\n", __FUNCTION__,
				bwr_data_seq(bwr_data), bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector);
		bwr_data_put(bwr_data);
		return 0;
	}
	return -1;
}

static void __buffer_inuse_add_tail(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	struct hadmdev *dev;
	if (!bwr_data)
		return;
	if (bwr_data->private) {
		dev = buffer->private;
		dev->acct_info[W_BIO_FINISH]++;
		if (bwr_data_remote(bwr_data)) {
			IO_DEBUG("%s: remote write %lu finish.\n", __func__,
					bwr_data->meta.dev_sector);
			hadmdev_sbio_packet_end(dev, bwr_data->private, 0);
			//hadmdev_sbio_finish(bwr_data->private, 0) FIXME
		} else
			bio_endio(bwr_data->private, 0);
		bwr_data->private = NULL;
	}
	if (buffer->inuse_head)
		buffer->tail_data = bwr_data;
	else {
		buffer->inuse_head = buffer->tail_data = bwr_data;
	}
	set_bwr_data_seqinbuffer(bwr_data);
	up(&buffer->data_sema);
}

static int __buffer_data_seq_add(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	int count = 0;
	struct bwr_data *data_iter;
	struct hlist_head *hash_head;
	uint64_t last_seq;

	if (buffer->tail_data == NULL) {
		BUFFER_DEBUG("tail_data is NULL, take buffer->tail_seq:%llu\n", buffer->tail_seq);
		last_seq = buffer->tail_seq;
	} else
		last_seq = buffer->tail_data->meta.bwr_seq;
	if (unlikely(bwr_data_seq(bwr_data) <= last_seq)) {
		pr_err("BUG %s can not find postion to insert %llu(%lu:%lu), tail:%llu(%lu:%lu)\n",
				__FUNCTION__,
				bwr_data->meta.bwr_seq, bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector,
				buffer->tail_data ? buffer->tail_data->meta.bwr_seq : buffer->tail_seq,
				buffer->tail_data ? buffer->tail_data->meta.bwr_sector: 0,
				buffer->tail_data ? buffer->tail_data->meta.dev_sector: 0);
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		bwr_data_put(bwr_data);
		BUG();
	}

	set_bwr_data_inbuffer(bwr_data);
	if (bwr_data_seq(bwr_data) == ++last_seq) {
		if (likely(buffer->tail_data))
			list_add(&bwr_data->list, &buffer->tail_data->list);
		else
			__list_add(&bwr_data->list, &buffer->data_list, buffer->data_list.next);

		hash_head = buffer->hash_list + data_hash(bwr_data->meta.dev_sector);
		hlist_add_head(&bwr_data->list_hash, hash_head);
		__buffer_inuse_add_tail(buffer, bwr_data);
		count++;
		data_iter = bwr_data;
		list_for_each_entry_continue(data_iter, &buffer->data_list, list) {
			if (data_iter->meta.bwr_seq != ++last_seq)
				break;
			hash_head = buffer->hash_list + data_hash(data_iter->meta.dev_sector);
			hlist_add_head(&data_iter->list_hash, hash_head);
			__buffer_inuse_add_tail(buffer, data_iter);
			count++;
		}
		BUFFER_DEBUG("bufer inuse add seq. sector:%lu.\n", bwr_data->meta.dev_sector);
	} else {
		list_for_each_entry_reverse(data_iter, &buffer->data_list, list) {
			/*  tail_data == NULL; then inuse_list is empty, search the whole list.
			 *  tail_data != NULL; whether inuse_list is empty or not, reverse search until tail_data.
			 */
			if (data_iter->meta.bwr_seq < bwr_data->meta.bwr_seq) {
				list_add(&bwr_data->list, &data_iter->list);
				BUFFER_DEBUG("buffer inuse add after %llu(%lu:%lu). not-empty & not seq.\n",
						bwr_data_seq(data_iter), data_iter->meta.bwr_sector,
						data_iter->meta.dev_sector);
				return 0;
			}
		}

		/* add at first */
		BUFFER_DEBUG("buffer inuse add at head, next entry: %llu(%lu:%lu). not-empty & not seq.\n",
				bwr_data_seq(data_iter), data_iter->meta.bwr_sector,
				data_iter->meta.dev_sector);
		__list_add(&bwr_data->list, &buffer->data_list, buffer->data_list.next);
		return 0;
	}
	return count;
}

/* Note: deprecate? inuse_size, buffer_size?*/
int buffer_data_seq_add(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	ret = __buffer_data_seq_add(buffer, bwr_data);
        spin_unlock_irqrestore(&buffer->lock, flags);
	if (ret < 0)
		pr_err("%s add fail.\n", __FUNCTION__);

	return ret;
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

struct bwr_data *__get_tail_data_inuse(struct data_buffer *buffer)
{
	struct bwr_data *tail_data;
	tail_data = buffer->inuse_head ? buffer->tail_data : NULL;
	if (tail_data)
		bwr_data_get(tail_data);
	return tail_data;
}

struct bwr_data *get_tail_data_inuse(struct data_buffer *buffer)
{
	struct bwr_data *tail_data;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	tail_data = __get_tail_data_inuse(buffer);
	spin_unlock_irqrestore(&buffer->lock, flags);
	return tail_data;
}

/*
 * increase size before add the element,
 * guarentee buffer_add_data() success in IRQ
 */
void buffer_inuse_pre_occu(struct data_buffer *buffer)
{
        unsigned long flags;

try_occupy:
        spin_lock_irqsave(&buffer->lock, flags);

	if (__buffer_inuse_is_full(buffer)) {
                spin_unlock_irqrestore(&buffer->lock, flags);
		//pr_info("occu try wait.\n");
		wait_for_completion(&buffer->not_full);
		goto try_occupy;
	}

	if (buffer->data_size == buffer->maxsize) {
		BUFFER_DEBUG("%s: buffer is full, try trunc data.\n", __FUNCTION__);
		if (__buffer_trunc(buffer) < 0) {
			dump_buffer_inuse(buffer);
			dump_buffer_data(buffer);
			spin_unlock_irqrestore(&buffer->lock, flags);
			pr_err("%s BUG have no space for truncate.\n", __FUNCTION__);
			BUG();
		}
	}
	//buffer->inuse_size++;
	__buffer_inuse_size_inc(buffer);
	buffer->data_size++;
	BUFFER_DEBUG("pre occu:inuse_size:%llu|data_size:%llu.\n",
			buffer->inuse_size,
			buffer->data_size);
	spin_unlock_irqrestore(&buffer->lock, flags);
}

void buffer_inuse_del_occd(struct data_buffer *buffer)
{
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	buffer->data_size--;
	__buffer_inuse_size_dec(buffer);
//	BUFFER_DEBUG("del occu:inuse_size:%llu|data_size:%llu.\n",
//			buffer->inuse_size,
//			buffer->data_size);
        spin_unlock_irqrestore(&buffer->lock, flags);
}

int buffer_data_seq_add_occd(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
	int ret;
        unsigned long flags;

        spin_lock_irqsave(&buffer->lock, flags);
	if ((ret = __buffer_data_seq_add(buffer, bwr_data)) < 0) {
		pr_info("%s: BUG \n", __FUNCTION__);
		dump_stack();
		dump_buffer_inuse(buffer);
		BUG();
	}

	BUFFER_DEBUG("%s: buffer add occd: %llu(%lu|%lu) in %d count.\n", __FUNCTION__,
			bwr_data->meta.bwr_seq,
                        bwr_data->meta.bwr_sector, bwr_data->meta.dev_sector,
			ret);
	//dump_buffer_inuse(buffer);
	//dump_buffer_data(buffer);
        spin_unlock_irqrestore(&buffer->lock, flags);

	return ret;
}

static int __buffer_inuse_del(struct data_buffer *buffer, struct bwr_data *entry)
{
	int count = 0;

	BUFFER_DEBUG("%s try del %llu(%lu:%lu)...\n", __FUNCTION__,
			bwr_data_seq(entry), entry->meta.bwr_sector, entry->meta.dev_sector);
	set_bwr_data_synced(entry);
	if (entry == buffer->inuse_head) {
		BUFFER_DEBUG("%s entry is inuse head, forward search...\n", __FUNCTION__);
		while (entry != buffer->tail_data) {
			if (!bwr_data_synced(entry))
				break;
			hlist_del_init(&entry->list_hash);
			set_bwr_data_seqsynced(entry);
			entry = list_entry(entry->list.next, struct bwr_data, list);
		}

		BUFFER_DEBUG("%s search end at %llu(%lu:%lu)...\n", __FUNCTION__,
				bwr_data_seq(entry), entry->meta.bwr_sector, entry->meta.dev_sector);
		count = bwr_data_seq(entry) - bwr_data_seq(buffer->inuse_head);
		if (bwr_data_synced(entry)) {
			count++;
			set_bwr_data_seqsynced(entry);
			buffer->inuse_head = NULL;
			hlist_del_init(&entry->list_hash);
		} else {
			buffer->inuse_head = entry;
		}
		BUFFER_DEBUG("%s count = %d, update inuse_head to %llu(%lu:%lu).\n", __FUNCTION__,
				count,
				buffer->inuse_head ? bwr_data_seq(buffer->inuse_head) : 0,
				buffer->inuse_head ? buffer->inuse_head->meta.bwr_sector : 0,
				buffer->inuse_head ? buffer->inuse_head->meta.dev_sector: 0);
		__buffer_inuse_size_sub(buffer, count);
	}
	//dump_buffer_inuse(buffer);
	//dump_buffer_data(buffer);
	return count;
}

int buffer_inuse_del(struct data_buffer *buffer, struct bwr_data *entry)
{
	int count;
        unsigned long flags;
        sector_t disk_sector = entry->meta.dev_sector;

        if (!entry) {
                pr_info("try del null inuse entry.\n");
                return -1;
        }

	spin_lock_irqsave(&buffer->lock, flags);
	/* FIXME */
	if (likely(__entry_in_inuse(buffer, entry))) {
		count = __buffer_inuse_del(buffer, entry);
	} else {
		pr_info("BUG!!!!!!!!!!!!!!!!!!!!!!!try del non-inuse entry:%llu(%lu:%lu).\n",
				entry->meta.bwr_seq, entry->meta.bwr_sector, entry->meta.dev_sector);
		dump_buffer_inuse(buffer);
		dump_buffer_data(buffer);
		spin_unlock_irqrestore(&buffer->lock, flags);
		return -1;
                //BUG();
	}
	BUFFER_DEBUG("inuse del:disk_sector:%lu|inuse_size:%llu|data_size:%llu.\n",
                        disk_sector,
			buffer->inuse_size,
			buffer->data_size);
	spin_unlock_irqrestore(&buffer->lock, flags);
	return count;
}

/* add tail */
static int __buffer_data_add(struct data_buffer *buffer, struct bwr_data *bwr_data)
{
        struct hlist_head *hash_head;

	if (__buffer_inuse_is_full(buffer)) {
		pr_info("%s buffer is full.\n", __FUNCTION__);
		return -1;
	}

	if (buffer->data_size == buffer->maxsize) {
		BUFFER_DEBUG("%s: buffer is full, try trunc data.\n", __FUNCTION__);
		if (__buffer_trunc(buffer) < 0) {
			dump_buffer_inuse(buffer);
			dump_buffer_data(buffer);
			pr_err("%s BUG have no space for truncate.\n", __FUNCTION__);
			BUG();
		}
	}

	bwr_data_get(bwr_data);
	set_bwr_data_inbuffer(bwr_data);
	__buffer_inuse_size_inc(buffer);
	buffer->data_size++;

	if (likely(buffer->tail_data))
		list_add(&bwr_data->list, &buffer->tail_data->list);
	else
		__list_add(&bwr_data->list, &buffer->data_list, buffer->data_list.next);
	hash_head = buffer->hash_list + data_hash(bwr_data->meta.dev_sector);
	hlist_add_head(&bwr_data->list_hash, hash_head);
	__buffer_inuse_add_tail(buffer, bwr_data);

	BUFFER_DEBUG("pre occu:inuse_size:%llu|data_size:%llu.\n",
			buffer->inuse_size,
			buffer->data_size);
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
