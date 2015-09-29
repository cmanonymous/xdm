#ifndef __DEVICE_H__
#define __DEVICE_H__

/* device: 运行 kmod 的节点，不是设备。是的，这个名字取得不好，历史遗留问题…… */
struct device {
	int id;
	struct daemon *daemon;
	int dfd;
	struct event *data_event;
	event_handler data_handler;
	int mfd;
	struct event *meta_event;
	event_handler meta_handler;
	struct queue *data_q;
	struct queue *meta_q;
	struct thread *data_worker;
	struct thread *meta_worker;
	pthread_spinlock_t spinlock;
};

struct device_list {
	int max_num;
	int dev_num;
	int local_idx;
	struct device **devs;
};

struct device *alloc_device();

void free_device(struct device *dev);

struct device *make_device(int id);

void dev_set_daemon(struct device *dev, struct daemon *daemon);

int dev_put_data_packet_force(struct device *dev, struct packet *pkt,
		cb_fn *callback, void *data);

int dev_put_data_packet(struct device *dev, struct packet *pkt);

struct packet *dev_get_data_packet(struct device *dev);

int dev_put_meta_packet(struct device *dev, struct packet *pkt);

struct packet *dev_get_meta_packet(struct device *dev);

void dev_del_data_event(struct device *dev);

void dev_del_meta_event(struct device *dev);

struct device_list *init_device_list(struct daemon *daemon, struct config *cfg);
struct device *find_device(struct device_list *dev_list, int dev_id);
int device_is_target(struct device *dev, int node_to);
int device_want_recv(struct device *dev);
int device_disconnect(struct device *dev);

void pr_device(struct device *dev);
void pr_device_list(struct device_list *dev_list);

#endif // __DEVICE_H__
