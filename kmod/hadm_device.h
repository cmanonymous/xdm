#ifndef HADM_DEVICE_H
#define HADM_DEVICE_H

#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "hadm_acct.h"
#include "bio_helper.h"
#include "hadm_queue.h"
#include "hadm_thread.h"
#include "hadm_node.h"
#include "hadm_queue.h"

#define HADM_SECTOR_SIZE 512
#define HADM_SECTOR_SHIFT 9

#define HADMDEV_NAME "hadm"
#define HADMDEV_MODE (FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#define BWRDEV_MODE (FMODE_READ | FMODE_WRITE)

#define P_HANDLER_NUM 2
#define IO_HANDLER_NUM 5

enum {
	HADM_IO_READ,
	HADM_IO_WRITE,
	HADM_IO_DIR_NUM,
};

enum {
	P_CTRL_WORKER = 0,
	P_DATA_WORKER = 1,
	BIO_RD_HANDLER = 2,
	BIO_WR_HANDLER = 3,
	LOCAL_SYNC_HANDLER = 4,
	REMOTE_SYNC_HANDLER = 5,
	DBM_SYNC_HANDLER = 6,
	HADMDEV_THREAD_NUM = 7
};

struct hadm_perf_data {
};



enum hadmdev_state {
	__BWR_ERR,
	__BDEV_ERR,
	__OTHER_ERR
};

/*
 * hadmdev 代表一个虚拟的块设备，也就是 /dev/hadm0 这样的设备。写入它的数据将会下
 * 发到底层的设备中，比如 /dev/sdc。
 */
struct hadmdev {
	struct list_head node;
	unsigned long state;

	struct mutex lock;
	int major;
	int minor;
	char name[MAX_NAME_LEN];
	atomic_t openers;
	//unsigned long ioflags; /* hadm device io flags, >0 means io error occued. */


	struct list_head hadm_node_list;
	spinlock_t hadm_node_list_lock;
	atomic_t hadm_node_list_len;
	struct hadm_node *local; /* point to element of hadm_node_list */
	struct hadm_node *primary;
	spinlock_t primary_lock;

	struct gendisk *disk;
	struct request_queue *rq;
	struct block_device *bdev; /* storage */
	uint64_t bdev_disk_size;

	struct bwr *bwr;
	struct block_device *bwr_bdev;
	uint64_t bwr_disk_size;

	struct hadm_queue *p_receiver_queue[P_HANDLER_NUM];
	struct hadm_queue *p_sender_queue[P_HANDLER_NUM];
	struct hadm_queue *bio_wrapper_queue[HADM_IO_DIR_NUM];
	struct hadm_thread *worker_thread[HADMDEV_THREAD_NUM];
#if 0
	struct hadm_thread *p_handler_thread[P_HANDLER_NUM];
	struct hadm_thread *io_handler_thread[IO_HANDLER_NUM];
	struct hadm_thread *p_data_io_thread;
#endif
	struct data_buffer *buffer;
	/**
	 *当发生io故障时，需要清理掉bio_wrapper_queue里所有的节点，对于读操作，可以直接在endio里返回
	 *对于写操作，在同步模式下，有些io本地已经完成了但是没有收到对端的ack，这样他的bio_wrapper仍然
	 *在bio_wrapper_queue里，这个操作需要有bio_write_handler_run线程去清理。
	 *在清理之前，需要确保没有bio_wrapper已经submit，但是没有end_io，否则在end_io里调用的bio_wrapper
	 *会被清理的函数free掉。
	 *所以设定bwr_io_pending，当bio_wrapper submmit时，就增加io_pending，在end_io里，减少io_pending，
	 *只有io_pending=0，才会调用wrapper_queue_io_error()清理掉所有bio_wrapper
	 */
	atomic_t bwr_io_pending;
    atomic_t async_io_pending[2];
	uint64_t acct_info [MAX_ACCOUT_ENTRY];

	void *private;
};


extern struct hadm_thread_info hadmdev_threads[] ;

static inline void hadmdev_set_error(struct hadmdev *dev, enum hadmdev_state error)
{
	set_bit(error, &dev->state);
	pr_err("!!!Error occurs on hadm%d dev %s",
			dev->minor, 
			(error == __BDEV_ERR) ? "bdev" : 
			(error == __BWR_ERR) ? "bwr" : "other");
	dump_stack();
}

static inline int hadmdev_error(struct hadmdev *dev)
{
	return dev->state;
}

static inline void hadmdev_clear_error(struct hadmdev *dev, enum hadmdev_state error)
{
	clear_bit(error, &dev->state);
}
extern void hadmdev_list_add(struct hadmdev *dev, struct hadm_node *hadm_node);
extern void hadmdev_list_del(struct hadmdev *dev, struct hadm_node *hadm_node);

extern struct hadmdev *hadmdev_alloc(int gfp_mask);
extern int hadmdev_init(struct hadmdev *dev);
extern void hadmdev_put(struct hadmdev *dev);

extern void hadm_flush_device(struct block_device *bdev);
extern int hadm_attach_device(struct hadmdev *dev, int major, int minor,
			      char *virtual_device_name, char *low_disk_name);
extern void hadm_detach_device(struct hadmdev* dev);

extern struct hadmdev *find_hadmdev_by_minor(int minor);
extern int hadmdev_get_nr_dbm_node(struct hadmdev *dev);
extern uint32_t get_hs_nodes(struct hadmdev *dev);
extern int get_nr_primary(struct hadmdev *hadmdev);
extern int hadmdev_send_node_state(struct hadmdev *hadmdev);

extern struct hadm_node *hadmdev_get_primary(struct hadmdev *dev);
extern int hadmdev_local_primary(struct hadmdev *dev);
extern int hadmdev_set_primary(struct hadmdev *dev, struct hadm_node *primary);
extern int hadmdev_get_primary_id(struct hadmdev *dev);
extern int be_primary(int dev_id, int force);
extern int be_secondary(int dev_id, int force);

extern int all_secondary_up2date(struct hadmdev * hadmdev);
extern void set_io_fail_flag(struct block_device *bdev);
extern int io_failed(struct hadmdev *hadmdev);

#endif	/* HADM_DEVICE_H */
