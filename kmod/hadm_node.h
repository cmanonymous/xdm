#ifndef HADM_NODE_H
#define HADM_NODE_H

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/list.h>

struct hadmdev;
struct dbm;

#define VALID_NODE(node_id) (0 <= (node_id) && (node_id) < MAX_NODES)

#define DEVICE_HANDSHAKE_FAIL (-1)
#define DEVICE_NOT_HANDSHAKE (0)
#define DEVICE_HANDSHAKE_SUCCESS (1)

enum {
	S_HANDSHAKE,
	S_INVALID,
	S_ROLE,
	S_DEV_STATE,
	S_CSTATE,
	S_NSTATE,
	S_BWR_SIZE,
	S_DSTATE,
	S_DATA_STATE,
	S_SND_HEAD,
};

enum {
	PRIMARY_STATE,
	SECONDARY_STATE,
};

struct hadm_node_state {
	spinlock_t lock;

	int invalid;
	int handshake;
	int role;
	int dev_state;
	int c_state;
	int d_state;
	int n_state;
	int data_state;

	/* in logic order, node_head <= snd_ack_head <= snd_head */
	uint64_t node_head;	/* for status display */
	uint64_t node_seq; /**seq for node**/
	uint64_t snd_ack_head;
	uint64_t snd_head;
	uint64_t tail;		/* for status display */
	struct bwr_data *snd_head_data;

	uint64_t bwr_seq;
	uint64_t uuid;

	uint64_t dbm_set;
	uint64_t bwr_size;	/* [head, tail) */
	uint64_t in_sync;	/* [head, snd_head] */
	uint64_t in_network;	/* [snd_ack_head, snd_head] */
	uint64_t in_buffer;	/* [head, snd_ack_head] */
	struct hadm_node *node;	/* point back */
};

extern void hadm_node_state_dump(struct hadm_node_state *state);
extern struct hadm_node_state *hadm_node_state_alloc(int gfp_mask);
extern void hadm_node_state_free(struct hadm_node_state *state);
extern void hadm_node_state_pack(struct node_state_packet *ns_pack, struct hadm_node_state *state);
extern void hadm_node_state_unpack(struct hadm_node_state *state, struct node_state_packet *ns_pack);
extern struct node_state_packet *node_state_packet_entry(struct packet *pack, uint32_t node_id);
extern int hadm_node_state_is_invalid(struct hadm_node_state *state);
extern void hadm_node_state_set_invalid(struct hadm_node_state *state, int invalid);
extern void hadm_node_send_head_data_set(struct hadm_node *runnode, struct bwr_data *bwr_data);
extern void hadm_node_send_head_data_update(struct hadm_node *runnode);
extern void __hadm_node_send_head_inc(struct hadm_node *node, sector_t bwr_sector);
extern void hadm_node_send_head_inc(struct hadm_node *node, sector_t bwr_sector);
extern void hadm_node_net_head_inc(struct hadm_node *node, sector_t bwr_sector, sector_t bwr_seq);
extern void snd_head_condition_update(struct hadm_node *node, int field, int status);
extern void hadm_node_reset_send_head(struct hadm_node *node);
extern int hadm_node_test_and_set(struct hadm_node *node, int which, int field, int test_val, int val);
extern uint64_t gen_sync_node_mask(struct hadmdev *hadmdev);

extern void disconnect_node(struct hadm_node *node);

extern void __hadm_node_reset_send_head(struct hadm_node *node);

//FIXME Do we really need those stuff?
struct hadm_node_conf {
	uint8_t protocol;
	uint8_t real_protocol;
	char hostname[MAX_NAME_LEN];
	char ipaddr[MAX_IPADDR_LEN];
	char disk[MAX_NAME_LEN];
	char bwr_disk[MAX_NAME_LEN];
};

struct hadm_node {
	struct list_head node;
	uint32_t id;
	uint32_t kmod_id;
	struct hadm_node_conf conf;
	struct hadm_node_state p_state; /* primary state */
	struct hadm_node_state s_state; /* secondary state */
	char dbm_name[MAX_NAME_LEN];
	struct dbm *dbm;
	struct hadmdev *hadmdev; /* point back */
	struct hadm_thread *delta_sync;
};


extern void hadm_node_free(struct hadm_node *node);
extern struct hadm_node *hadm_node_alloc(int nr);
extern struct hadm_node *hadm_node_create(struct hadmdev *dev, uint32_t node_id,
		uint32_t kmod_id, uint8_t protocol);
extern int __hadm_node_test_and_set(struct hadm_node_state *state, int field, int test_val, int val);
extern void __hadm_node_set(struct hadm_node_state *state, int field, int val);
extern uint64_t __hadm_node_get(struct hadm_node_state *state, int field);
extern void hadm_node_set(struct hadm_node *node, int which, int field, int val);
extern uint64_t hadm_node_get(struct hadm_node *node, int which, int field);
extern int hadm_node_next_cstate(struct hadm_node *node);
extern void hadm_node_become_inconsitent(struct hadm_node *node);

extern struct hadm_node *find_hadm_node_by_id(struct hadmdev *dev, uint32_t node_id);
#endif	/* HADM_NODE_H */
