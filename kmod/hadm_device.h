#ifndef HADM_DEVICE_H
#define HADM_DEVICE_H

#include <linux/genhd.h>
#include <linux/blkdev.h>

#include "hadm_acct.h"
#include "bio_helper.h"
#include "hadm_queue.h"
#include "hadm_thread.h"
#include "hadm_site.h"
#include "hadm_queue.h"
#include "hadm_packet.h"

#define HADM_SECTOR_SIZE 512
#define HADM_SECTOR_SHIFT 9

#define HADMDEV_NAME "hadm"
#define HADMDEV_MODE (FMODE_READ | FMODE_WRITE | FMODE_EXCL)
#define BWRDEV_MODE (FMODE_READ | FMODE_WRITE)

enum packet_handler_type {
	P_SITE_CTRL,
	P_SITE_DATA,
	P_NODE_CTRL,
	P_NODE_DATA,
	P_HANDLER_NUM,
};

enum hadm_io_dir {
	HADM_IO_READ,
	HADM_IO_WRITE,
	HADM_IO_DIR_NUM,
};

enum hadmdev_queue_type {
	/* general queue */
	SITE_CTRL_Q,
	SITE_DATA_Q,
	NODE_CTRL_Q,
	NODE_DATA_Q,

	/* slaver primary */
	SBIO_Q,

	/* master primary */
	RD_WRAPPER_Q,
	WR_WRAPPER_Q,
	SLAVER_SBIO_Q,

	HADMDEV_QUEUE_MAX,
};

enum hadmdev_thread_type {
	/* general thread (site node recv handler) */
	SITE_CTRL_WORKER,
	SITE_DATA_WORKER,
	NODE_CTRL_WORKER,
	NODE_DATA_WORKER,

	/* master & primary thread */
	BIO_RD_HANDLER,
	BIO_WR_HANDLER,
	SLAVER_BIO_HANDLER,
	LOCAL_SYNC_HANDLER,
	REMOTE_SYNC_HANDLER,
	DBM_SYNC_HANDLER,
	DBM_FLUSH_HANDLER,

	HADMDEV_THREAD_MAX,
};

struct hadm_perf_data {
};


#define BWR_FAILED_BIT	0
#define BDEV_FAILED_BIT 1

enum hadmdev_state {
	__DEV_DOWN,
	__DEV_ERR,	/* I/O error occured */
};


/*
 * hadmdev 代表一个虚拟的块设备，也就是 /dev/hadm0 这样的设备。写入它的数据将会下
 * 发到底层的设备中，比如 /dev/sdc。
 */
struct hadmdev {
	atomic_t openers;
	struct mutex lock;
	unsigned long state;
	unsigned long ioflags; /* hadm device io flags, >0 means io error occued. */
	struct list_head node;

	/* static info */
	int major;
	int minor;
	char name[MAX_NAME_LEN];

	/* storage */
	struct gendisk *disk;
	struct request_queue *rq;
	struct block_device *bdev; /* storage */
	uint64_t bdev_disk_size;

	/* bwr */
	struct bwr *bwr;
	struct block_device *bwr_bdev;
	uint64_t bwr_disk_size;

	/* runsite */
	struct list_head hadm_site_list;
	spinlock_t hadm_site_list_lock;
	atomic_t hadm_site_list_len;
	struct hadm_site *local_site; /* point to element of hadm_site_list */
	struct hadm_site *primary;
	spinlock_t primary_lock;

	/* runnode */
	struct list_head hadm_node_list;
	spinlock_t hadm_node_list_lock;
	atomic_t hadm_node_list_len;
	struct hadm_node *local_node;
	struct hadm_node *master;
	spinlock_t master_lock;

	/* threads & queues */
	struct hadm_thread *threads[HADMDEV_THREAD_MAX];
	struct hadm_queue *queues[HADMDEV_QUEUE_MAX];

	struct data_buffer *buffer;

	uint64_t acct_info [MAX_ACCOUT_ENTRY];
	void *private;
};

static inline int hadmdev_error(struct hadmdev *dev)
{
	return test_bit(__DEV_ERR, &dev->state);
}

static inline void hadmdev_set_error(struct hadmdev *dev)
{
	set_bit(__DEV_ERR, &dev->state);
}

static inline void hadmdev_clear_error(struct hadmdev *dev)
{
	clear_bit(__DEV_ERR, &dev->state);
}

extern int hadmdev_alloc_threads(struct hadmdev *dev);
extern void hadmdev_stop_threads(struct hadmdev *dev);
extern void hadmdev_free_threads(struct hadmdev *dev);
extern void hadmdev_start_io_threads(struct hadmdev *dev);
extern void hadmdev_stop_io_threads(struct hadmdev *dev);
extern int hadmdev_alloc_queues(struct hadmdev *dev);
extern void hadmdev_freeze_queues(struct hadmdev *dev);
extern void hadmdev_free_queues(struct hadmdev *dev);
extern void hadmdev_free_disk(struct hadmdev *dev);

extern struct hadmdev *hadmdev_alloc(int gfp_mask);
extern int hadmdev_init(struct hadmdev *dev);
extern void hadmdev_put(struct hadmdev *dev);
extern void hadmdev_free(struct hadmdev *dev);

extern void hadmdev_site_add(struct hadmdev *dev, struct hadm_site *hadm_site);
extern void hadmdev_site_del(struct hadmdev *dev, struct hadm_site *hadm_site);
struct config;
extern int hadmdev_create_site_list(struct hadmdev *dev, struct config *cfg);
extern int hadmdev_site_list_init(struct hadmdev *dev);
extern void hadmdev_site_list_clear(struct hadmdev *dev);

extern void hadmdev_node_add(struct hadmdev *dev, struct hadm_node *hadm_node);
extern void hadmdev_node_del(struct hadmdev *dev, struct hadm_node *hadm_node);
extern struct hadm_node *hadmdev_node_find(struct hadmdev *dev, int id);
extern unsigned long hadmdev_get_connect_nodes(struct hadmdev *dev);
extern void hadmdev_node_connect(struct hadmdev *dev, struct hadm_node *node);
extern void hadmdev_node_disconnect(struct hadmdev *dev, struct hadm_node *node);
extern void hadmdev_node_list_clear(struct hadmdev *dev);
struct site_config;
extern int hadmdev_create_node_list(struct hadmdev *, struct site_config *);
extern void hadmdev_disconnect_all(struct hadmdev *dev);
extern int hadmdev_set_master(struct hadmdev *, struct hadm_node *);
extern int hadmdev_set_slaver_master(struct hadmdev *, struct hadm_node *);
extern struct hadm_node *hadmdev_get_master(struct hadmdev *dev);
extern int hadmdev_local_master(struct hadmdev *dev);
extern int hadmdev_stop_site_all(struct hadmdev *dev);
extern int hadmdev_clean_site_pack(struct hadmdev *dev);

extern void hadmdev_wait_io_finish(struct hadmdev *dev);

extern void hadm_flush_device(struct block_device *bdev);
extern int hadm_attach_device(struct hadmdev *dev, int major, int minor,
			      char *virtual_device_name, char *low_disk_name);
extern void hadm_detach_device(struct hadmdev* dev);
extern int hadmdev_opened(struct hadmdev *dev);

extern int hadmdev_do_slaver_primary(struct hadmdev *dev);
extern int hadmdev_do_slaver_secondary(struct hadmdev *dev);

extern int hadmdev_packet_handler_type(int linktype, struct packet *pack);

extern struct hadmdev *find_hadmdev_by_minor(int minor);
extern int hadmdev_get_nr_dbm_node(struct hadmdev *dev);
extern int get_nr_primary(struct hadmdev *hadmdev);
extern int hadmdev_send_node_state_request(struct hadmdev *dev,
		struct hadm_node *node);
extern int hadmdev_send_node_state(struct hadmdev *dev, struct hadm_node *node);
extern int hadmdev_send_site_state(struct hadmdev *hadmdev);
extern int hadmdev_send_primary_notify(struct hadmdev *dev);
extern int hadmdev_send_master_notify(struct hadmdev *dev);
extern int hadmdev_send_slaver_notify(struct hadmdev *dev);

extern struct hdpacket *hadmdev_create_site_state_packet(struct hadmdev *hadmdev);

extern struct hadm_site *hadmdev_get_primary(struct hadmdev *dev);
extern int hadmdev_set_primary(struct hadmdev *dev, struct hadm_site *primary);
extern int hadmdev_local_primary(struct hadmdev *dev);
extern int hadmdev_get_primary_id(struct hadmdev *dev);

extern int all_secondary_up2date(struct hadmdev * hadmdev);
extern void set_io_fail_flag(struct block_device *bdev);
extern int io_failed(struct hadmdev *hadmdev);

int hadmdev_sbio_add(struct hadmdev *dev, struct sbio *sbio);
struct sbio *hadmdev_sbio_search(struct hadmdev *dev, sector_t dev_sector);
struct sbio *hadmdev_sbio_search_pop(struct hadmdev *dev, sector_t dev_sector);
int hadmdev_sbio_send(struct hadmdev *dev, struct sbio *sbio);
int hadmdev_sbio_clear(struct hadmdev *dev);
int __hadmdev_sbio_list_submit(struct hadmdev *dev);
int hadmdev_sbio_list_send(struct hadmdev *dev);
void hadmdev_sbio_packet_end(struct hadmdev *dev,
		struct hdpacket *sbio_pack, int err);

#endif	/* HADM_DEVICE_H */
