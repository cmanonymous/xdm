#ifndef HADM_H
#define HADM_H

#include <linux/module.h>
#include <linux/spinlock.h>

struct hadmdev;
struct hadm_node;
struct receiver_thread;
struct sender_thread;
struct cmd_worker_thread;

struct hadm_struct {
	int local_node_id;	//proxy server id
	int local_kmod_id;	//local node kmod id
	int major;
	int state;

	struct list_head dev_list;
	rwlock_t dev_list_lock;
	atomic_t dev_list_len;

	atomic_t config_count;
	int cmd_port;
	struct socket *cmd_server_sock;
	struct hadm_thread *cmd_worker;

	struct hadm_net *data_net;
	struct hadm_net *ctrl_net;
	struct hadm_thread *p_receiver[P_TYPE_NUM];
	struct hadm_thread *p_sender[P_TYPE_NUM];
	struct hadm_queue *cmd_receiver_queue;
	struct hadm_queue *cmd_sender_queue;
	atomic_t sender_queue_size[P_TYPE_NUM];
	wait_queue_head_t queue_event;

	struct proc_dir_entry *proc_dir;
};

extern struct hadm_struct *g_hadm;

extern struct hadm_struct *hadm_alloc(const char *hadm_server_ipaddr,
				      const int hadm_server_port, int gfp_mask);
extern void hadm_put(struct hadm_struct *hadm);
extern int hadm_init(struct hadm_struct *hadm, const int hadm_local_id,
		     const int hadm_cmd_port, int gfp_mask);
extern int hadm_reconfig(struct hadm_struct *hadm, char *serverip, char *serverport,
		int local_node_id, int local_kmod_id);

static inline int get_kmod_id(void)
{
	return g_hadm->local_kmod_id;
}

extern void hadm_list_add(struct hadm_struct *hadm, struct hadmdev *dev);
extern void hadm_list_del(struct hadm_struct *hadm, struct hadmdev *dev);
extern int hadm_devs_empty(struct hadm_struct *hadm);
extern int hadm_get_config_count(struct hadm_struct *hadm);
extern void hadm_inc_config_count(struct hadm_struct *hadm);

#endif	/* HADM_H */
