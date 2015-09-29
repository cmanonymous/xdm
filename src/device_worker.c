#include "common.h"

int device_data_worker_function(void *data)
{
	struct thread *thr;
	struct device *dev;
	struct packet *pkt;
	int ret;

	thr = (struct thread *)data;
	dev = (struct device *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = dev_get_data_packet(dev);

		if(pkt == NULL) {
			continue;
		}

		while(dev->dfd < 0) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

		ret = packet_send(dev->dfd, pkt);
		if(ret <= 0) {
			log_error(">>>>>>> failed to send data packet to kmod:%d, ret = %d",  dev->id, ret);
			log_packet_header(pkt, packet_log_error);
			//dev_del_data_event(dev);
		}

		free_packet(pkt);
	}

	return 0;
}

int device_meta_worker_function(void *data)
{
	struct thread *thr;
	struct device *dev;
	struct packet *pkt;
	int ret;

	thr = (struct thread *)data;
	dev = (struct device *)thr->data;

	while(thr->state == THREAD_RUN) {
		pkt = dev_get_meta_packet(dev);

		if(pkt == NULL) {
			continue;
		}

		while(dev->mfd < 0) {
			sleep(CONNECT_TIMER_TIMEOUT);
		}

		ret = packet_send(dev->mfd, pkt);
		if(ret <= 0) {
			log_error(">>>>>>> failed to send meta packet to kmod:%d, ret = %d", dev->id, ret);
			log_packet_header(pkt, packet_log_error);
			//dev_del_meta_event(dev);
		}

		free_packet(pkt);
	}

	return 0;
}
