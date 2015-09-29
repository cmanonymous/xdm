#ifndef __DEVICE_WORKER_H__
#define __DEVICE_WORKER_H__

struct device_packet_handler {
	int (*action)(struct device *dev, struct packet *orig_pkt);
};

int device_worker_function(void *data);

int device_data_worker_function(void *data);

int device_meta_worker_function(void *data);

int device_data_packet_handler(struct device *dev, struct packet *orig_pkt);

int device_meta_packet_handler(struct device *dev, struct packet *orig_pkt);

int w_dev_data_common_action(struct device *dev, struct packet *orig_pkt);

int w_dev_meta_common_action(struct device *dev, struct packet *orig_pkt);

#endif // __DEVICE_WORKER_H__
