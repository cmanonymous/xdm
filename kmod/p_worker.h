#ifndef __P_WORKER_H
#define __P_WORKER_H 1
#include "hadm_queue.h"
#include "hadm_packet.h"

enum hs_flag_bits {
	__hs_ok,
	__hs_splitbrain,
	__hs_fullsync,
	__hs_dbm,
	__hs_sethead,
	__hs_setbm,
	__hs_nr_bits,
};

#define HS_OK		(1 << __hs_ok)
#define HS_SPLITBRAIN	(1 << __hs_splitbrain)
#define HS_FULLSYNC	(1 << __hs_fullsync)
#define HS_DBM		(1 << __hs_dbm)
#define HS_SETHEAD	(1 << __hs_sethead)
#define HS_SETBM	(1 << __hs_setbm)

typedef int (*cmd_handler_t)(void*);
typedef int (*device_packet_handler_t)(struct hadmdev*, struct hdpacket*);

struct packet_handler {
	cmd_handler_t func;
};

struct device_handler {
	device_packet_handler_t func;
};

extern int p_ctrl_sender_run(void *arg);
extern int p_data_sender_run(void *arg);
extern int cmd_sender_run(void *arg);
extern int p_ctrl_receiver_run(void *arg);
extern int p_data_receiver_run(void *arg);
extern int cmd_receiver_run(void *arg);
extern int site_ctrl_worker(void *arg);
extern int site_data_worker(void *arg);
extern int node_ctrl_worker(void *arg);
extern int node_data_worker(void *arg);
extern int cmd_worker_run(void *arg);
extern int sbio_worker(void *arg);
extern int dbm_flusher(void *arg);
extern void hadm_pack_queue_clean(struct hadm_queue *queue);
extern struct cmd_pack_node *
cmd_pack_node_create(struct packet *pack, struct socket *sock);
extern void cmd_pack_node_free(struct cmd_pack_node  *node);

extern struct device_handler *get_site_ctrl_handler(void);
extern struct device_handler *get_site_data_handler(void);
extern struct device_handler *get_node_ctrl_handler(void);
extern struct device_handler *get_node_data_handler(void);

extern struct packet_handler *get_cmd_handler(void);

extern int create_dbm_sync_thread(uint8_t dbm_type,struct hadm_site *hadm_site);
extern int send_startrep(int dev_id, uint32_t node_id);

struct hadm_site;
extern void hadm_pack_queue_clean_for_host(struct hadm_queue *queue, struct hadm_site *host);

#endif
