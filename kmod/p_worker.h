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

struct hadm_pack_node {
	struct list_head q_node;
	atomic_t refcnt;
	struct packet *pack;
	struct socket *sock;
};

typedef int (*packet_handler_t)(void *);

struct packet_handler {
	packet_handler_t func;
};

extern int p_ctrl_sender_run(void *arg);
extern int p_data_sender_run(void *arg);
extern int cmd_sender_run(void *arg);
extern int p_ctrl_receiver_run(void *arg);
extern int p_data_receiver_run(void *arg);
extern int cmd_receiver_run(void *arg);
extern int p_ctrl_worker_run(void *arg);
extern int p_data_worker_run(void *arg);
extern int cmd_worker_run(void *arg);
extern uint32_t hadm_pack_queue_clean(struct hadm_queue *queue);
extern struct hadm_pack_node *hadm_pack_node_create(struct packet *pack,struct socket *sock);
extern packet_handler_t get_ctrl_worker_handler(int type);
extern packet_handler_t get_data_worker_handler(int type);
extern packet_handler_t get_cmd_worker_handler(int type);

extern int create_dbm_sync_thread(uint8_t dbm_type,struct hadm_node *hadm_node);
extern int send_startrep(int dev_id, struct hadm_node *node);

struct hadm_node;
extern void hadm_pack_queue_clean_for_host(struct hadm_queue *queue, struct hadm_node *host);
extern void hadm_pack_node_free(struct hadm_pack_node *node);
extern void hadm_pack_node_get(struct hadm_pack_node  *node);
extern struct hadm_pack_node *gen_data_ack_pack_node(struct hadm_pack_node *node, int errcode);

#endif
