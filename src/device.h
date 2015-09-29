#ifndef __DEVICE_H__
#define __DEVICE_H__

struct device {
	struct daemon *daemon;
	int dfd;
	struct event *data_event;
	event_handler data_handler;
	int mfd;
	struct event *meta_event;
	event_handler meta_handler;
	struct queue *data_q;
	struct queue *meta_q;
	struct queue *work_q;
	struct thread *data_worker;
	struct thread *meta_worker;
	struct thread *worker;
	pthread_spinlock_t spinlock;
};

struct device_list {
	int dev_num;
	struct device **devs;
};

struct device *alloc_device();

void free_device(struct device *dev);

struct device *make_device();
struct device *init_device(struct daemon *daemon, struct config *cfg);

void dev_set_daemon(struct device *dev, struct daemon *daemon);


int dev_put_work_packet(struct device *dev, struct packet *pkt);

struct packet *dev_get_work_packet(struct device *dev);

int dev_put_data_packet(struct device *dev, struct packet *pkt);

struct packet *dev_get_data_packet(struct device *dev);

int dev_put_meta_packet(struct device *dev, struct packet *pkt);

struct packet *dev_get_meta_packet(struct device *dev);

void dev_del_data_event(struct device *dev);

void dev_del_meta_event(struct device *dev);

#endif // __DEVICE_H__
