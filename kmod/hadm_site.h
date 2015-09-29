#ifndef HADM_SITE_H
#define HADM_SITE_H

#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/list.h>

struct hadmdev;
struct dbm;

#define VALID_SITE(node_id) (0 <= (node_id) && (node_id) < MAX_NODES)

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

struct hadm_site_state {
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
	uint64_t site_head;	/* for status display */
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
	struct hadm_site *site;	/* point back */
};

struct hdpacket;
extern void hadm_site_state_dump(struct hadm_site_state *state);
extern struct hadm_site_state *hadm_site_state_alloc(int gfp_mask);
extern void hadm_site_state_free(struct hadm_site_state *state);
extern void hadm_site_state_pack(struct site_state_packet *ns_pack, struct hadm_site_state *state);
extern void hadm_site_state_unpack(struct hadm_site_state *state, struct site_state_packet *ns_pack);
extern struct site_state_packet *site_state_packet_entry(struct hdpacket *pack, uint32_t site_id);
extern int hadm_site_state_is_invalid(struct hadm_site_state *state);
extern void hadm_site_state_set_invalid(struct hadm_site_state *state, int invalid);
extern void hadm_site_send_head_data_set(struct hadm_site *runsite, struct bwr_data *bwr_data);
extern void hadm_site_send_head_data_update(struct hadm_site *runsite);
extern void __hadm_site_send_head_inc(struct hadm_site *site);
extern void hadm_site_send_head_inc(struct hadm_site *site);
extern void hadm_site_net_head_inc(struct hadm_site *site);
extern void snd_head_condition_update(struct hadm_site *site, int field, int status);
extern void hadm_site_reset_send_head(struct hadm_site *site);
extern int hadm_site_test_and_set(struct hadm_site *site, int which, int field, int test_val, int val);

extern void disconnect_site(struct hadm_site *site);

extern void __hadm_site_reset_send_head(struct hadm_site *site);
extern void hadm_site_reset_send_head(struct hadm_site *site);

struct hadm_site_conf {
	uint8_t protocol;
	uint8_t real_protocol;
	char name[MAX_NAME_LEN];
	char ipaddr[MAX_IPADDR_LEN];
	char disk[MAX_NAME_LEN];
	char bwr_disk[MAX_NAME_LEN];
};

struct hadm_site {
	struct list_head site;
	uint32_t id;
	struct hadm_site_conf conf;
	struct hadm_site_state p_state; /* primary state */
	struct hadm_site_state s_state; /* secondary state */
	struct dbm *dbm;
	struct hadmdev *hadmdev; /* point back */
	struct hadm_thread *delta_sync;
};


extern void hadm_site_free(struct hadm_site *site);
extern struct hadm_site *hadm_site_alloc(int nr);
extern struct hadm_site *hadm_site_create(int id, int proto, char *disk_name,
		char *bwr_name);

extern int __hadm_site_test_and_set(struct hadm_site_state *state, int field,
		int test_val, int val);
extern void __hadm_site_set(struct hadm_site_state *state, int field, int val);
extern int __hadm_site_get(struct hadm_site_state *state, int field);
extern void hadm_site_set(struct hadm_site *site, int which, int field, int val);
extern int hadm_site_get(struct hadm_site *site, int which, int field);
extern int hadm_site_next_cstate(struct hadm_site *site);
extern void hadm_site_become_inconsitent(struct hadm_site *site);

extern struct hadm_site *find_hadm_site_by_id(struct hadmdev *dev, uint32_t site_id);

#endif	/* HADM_SITE_H */
