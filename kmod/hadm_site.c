#include <linux/module.h>
#include <linux/slab.h>

#include "hadm_def.h"
#include "hadm_struct.h"
#include "hadm_config.h"
#include "hadm_site.h"
#include "hadm_device.h"
#include "dbm.h"
#include "buffer.h"
#include "bwr.h"
#include "p_worker.h"

#define NOT_USE_PACKET_NAME
#define NOT_USE_PROTO_NAME
#include "../include/common_string.h"

extern struct hadm_struct *g_hadm;

struct hadm_site *find_hadm_site_by_id(struct hadmdev *dev, uint32_t site_id)
{
	struct hadm_site *hadm_site;

	list_for_each_entry(hadm_site, &dev->hadm_site_list, site) {
		if (hadm_site->id == site_id)
			return hadm_site;
	}

	return NULL;
}

struct site_state_packet *site_state_packet_entry(struct hdpacket *pack,
						  uint32_t site_id)
{
	struct site_state_packet *ns_pack;
	int i;

	ns_pack = (struct site_state_packet *)pack->data->buff;
	for (i = 0; i < pack->head.site_state_num; i++) {
		if (ns_pack->id == site_id)
			return ns_pack;
		ns_pack += 1;
	}

	return NULL;
}

void hadm_site_conf_free(struct hadm_site_conf *conf)
{
	kfree(conf);
}

struct hadm_site_conf *hadm_site_conf_alloc(void)
{
	struct hadm_site_conf *conf;

	conf = kzalloc(sizeof(struct hadm_site_conf), GFP_KERNEL);

	return conf;
}

void hadm_site_conf_init(struct hadm_site_conf *conf,
			 uint8_t protocol, char *name, char *ipaddr,
			 char *disk, char *bwr_disk)
{
	conf->protocol = protocol;
	snprintf(conf->name, MAX_NAME_LEN, "%s", name);
	snprintf(conf->ipaddr, MAX_IPADDR_LEN, "%s", ipaddr);
	snprintf(conf->disk, MAX_NAME_LEN, "%s", disk);
	snprintf(conf->bwr_disk, MAX_NAME_LEN, "%s", bwr_disk);
}

struct hadm_site_conf *hadm_site_conf_create(uint8_t protocol,
					     char *hostname, char *ipaddr,
					     char *disk, char *bwr_disk)
{
	struct hadm_site_conf *conf;

	conf = hadm_site_conf_alloc();
	if (conf)
		hadm_site_conf_init(conf, protocol, hostname, ipaddr, disk, bwr_disk);

	return conf;
}

void hadm_site_state_dump(struct hadm_site_state *state)
{
	pr_info("++++++++ %s ++++++++\n", __FUNCTION__);
	pr_info("%d|%s|%s|%s|%s|%s\n",
		state->site->id,
		role_name[state->role],
		dev_state_name[state->dev_state],
		cstate_name[state->c_state],
		dstate_name[state->d_state],
		nstate_name[state->n_state]);
	pr_info("-------- %s --------\n", __FUNCTION__);
}

void hadm_site_state_free(struct hadm_site_state *state)
{
	if (state != NULL && !IS_ERR(state)) {
		if (state->snd_head_data)
			bwr_data_put(state->snd_head_data);
		kfree(state);
	}
}

struct hadm_site_state *hadm_site_state_alloc(int gfp_mask)
{
	struct hadm_site_state *state;

	state = kzalloc(sizeof(*state), gfp_mask);
	if (state == NULL) {
		pr_err("hadm_site_state_alloc: no memory\n");
		return ERR_PTR(-ENOMEM);
	}

	return state;
}

void hadm_site_state_init(struct hadm_site_state *state)
{
	spin_lock_init(&state->lock);
	state->role = R_SECONDARY;
	state->dev_state = DEV_DOWN;
	state->handshake = HS_FAIL;

	state->data_state = DATA_CONSISTENT;
	state->c_state = C_STOPPED;
	state->d_state = D_CONSISTENT;
	state->n_state = N_DISCONNECT;
	state->snd_head_data = NULL;

	state->invalid = 1;
}

/* 都没加锁，允许读到过时的信息吗？如果允许，那么对于head > tail等情况也要在显示的时候加以注意 */
void hadm_site_state_pack(struct site_state_packet *ns_pack, struct hadm_site_state *state)
{
	struct bwr* bwr = state->site->hadmdev->bwr;
	int primary_id, local_site_id;

	local_site_id = get_site_id();
	primary_id = hadmdev_get_primary_id(state->site->hadmdev);

	ns_pack->id = state->site->id;
	ns_pack->role = state->role;
	ns_pack->protocol = state->site->conf.real_protocol;

	ns_pack->dev_state = state->dev_state;
	ns_pack->data_state = state->data_state;
	ns_pack->c_state = state->c_state;
	ns_pack->n_state = state->n_state;

	ns_pack->snd_head = state->snd_head;
	ns_pack->snd_ack_head = state->snd_ack_head;
	if (ns_pack->id == local_site_id) {
		ns_pack->disk_state = bwr->mem_meta.disk_state;
		ns_pack->dbm_set = state->dbm_set;
	} else
		ns_pack->dbm_set = atomic_read(&state->site->dbm->nr_bit);

	/* accepted primary */
	if (primary_id != INVALID_ID && primary_id != local_site_id) {
		ns_pack->site_head = state->site_head;
		ns_pack->tail = state->tail;
	} else {
		ns_pack->site_head = bwr->mem_meta.head[ns_pack->id];
		ns_pack->tail = bwr->mem_meta.tail;
	}
}

void hadm_site_state_unpack(struct hadm_site_state *state, struct site_state_packet *ns_pack)
{
	state->site->id = ns_pack->id;
	state->role = ns_pack->role;
	state->site->conf.real_protocol = ns_pack->protocol;

	state->dev_state = ns_pack->dev_state;
	state->data_state = ns_pack->data_state;
	state->c_state = ns_pack->c_state;
	state->n_state = ns_pack->n_state;

	state->site_head = ns_pack->site_head;
	state->snd_ack_head = ns_pack->snd_ack_head;
	state->snd_head = ns_pack->snd_head;
	state->tail = ns_pack->tail;

	/* NOTE: how to set site_head/tail? */
	state->dbm_set = ns_pack->dbm_set;
}

int hadm_site_next_cstate(struct hadm_site *site)
{
	return 0;
}

void hadm_site_become_inconsitent(struct hadm_site *site)
{
	unsigned long flags;

	spin_lock_irqsave(&site->s_state.lock, flags);
	if (__hadm_site_get(&site->s_state, S_DSTATE) != D_INCONSISTENT) {
		__hadm_site_set(&site->s_state, S_DATA_STATE, DATA_DBM);
		__hadm_site_set(&site->s_state, S_CSTATE, C_STOPPED);
		__hadm_site_set(&site->s_state, S_DSTATE, D_INCONSISTENT);
		__hadm_site_reset_send_head(site); /* atomic reset & set DATA_DBM */

		site->dbm->dsi.flags = 1;
		if (atomic_read(&site->dbm->dsi.count)) {
			/* FIXME */
			pr_err("%s: still have unfinished dsi?\n", __func__);
			atomic_set(&site->dbm->dsi.count, 0);
		}

		pr_info("after set state site:%d, cstate:%d, dstate:%d\n",
				site->id,
				__hadm_site_get(&site->s_state, S_CSTATE),
				__hadm_site_get(&site->s_state, S_DSTATE));

	}
	spin_unlock_irqrestore(&site->s_state.lock, flags);
}

void hadm_site_free(struct hadm_site *site)
{
	if (site == NULL || IS_ERR(site))
		return;
	if (site->id != get_site_id())
		free_dbm(site->dbm);
	kfree(site);
}

struct hadm_site *hadm_site_alloc(int gfp_mask)
{
	struct hadm_site *site;

	site = kzalloc(sizeof(*site), gfp_mask);
	if (!site)
		return NULL;

	INIT_LIST_HEAD(&site->site);
	site->conf.real_protocol = PROTO_ASYNC;
	hadm_site_state_init(&site->s_state);
	hadm_site_state_init(&site->p_state);
	site->s_state.site = site;
	site->p_state.site = site;

	return site;
}

void hadm_site_init(struct hadm_site *site, struct hadmdev *dev,
		    uint32_t site_id, uint8_t protocol,
		    char *disk_name, char *bwr_name, char *dbm)
{
	site->id = site_id;
	site->hadmdev = dev;

	site->conf.protocol = protocol;
	site->conf.real_protocol = PROTO_ASYNC;
	pr_info("init site %d, protocol:%u, real_protocol:%u.\n",
			site->id, site->conf.protocol, site->conf.real_protocol);
	snprintf(site->conf.disk, MAX_NAME_LEN, "%s", disk_name);
	snprintf(site->conf.bwr_disk, MAX_NAME_LEN, "%s", bwr_name);

	site->s_state.site = site;
	site->p_state.site = site;
	site->delta_sync=NULL;
}

struct hadm_site *hadm_site_create(int id, int proto, char *disk_name,
		char *bwr_name)
{
	struct hadm_site *site;
	struct hadm_site_conf *conf;

	site = hadm_site_alloc(GFP_KERNEL);
	if (!site)
		return NULL;
	site->id = id;
	conf = &site->conf;
	conf->protocol = proto;
	strncpy(conf->disk, disk_name, sizeof(conf->disk));
	strncpy(conf->bwr_disk, bwr_name, sizeof(conf->bwr_disk));

	return site;
}

void cstate_debug(int site_id, int cstate_old, int cstate_new)
{
	if (cstate_old != cstate_new) {
		pr_info("site %d cstate change(%s -> %s)\n",
			site_id, cstate_name[cstate_old], cstate_name[cstate_new]);
		/* dump_stack(); */
	}
}

void __hadm_site_set(struct hadm_site_state *state, int field, int val)
{
	switch (field) {
	case S_INVALID:
		state->invalid = val;
		break;
	case S_HANDSHAKE:
		state->handshake = val;
		break;
	case S_DSTATE:
		state->d_state = val;
		break;
	case S_DEV_STATE:
		state->dev_state = val;
		break;
	case S_ROLE:
		state->role = val;
		break;
	case S_CSTATE:
		cstate_debug(state->site->id, state->c_state, val);
		state->c_state = val;
		break;
	case S_NSTATE:
		state->n_state = val;
		break;
	case S_BWR_SIZE:
		state->bwr_size = val;
		break;
	case S_SND_HEAD:
		state->snd_head = val;
		break;
	case S_DATA_STATE:
		state->data_state = val;
		break;
	default:
		break;
	}
}

void hadm_site_set(struct hadm_site *site, int which, int field, int val)
{
	struct hadm_site_state *state;
	unsigned long flags;

	state = (which == PRIMARY_STATE) ? &site->p_state : &site->s_state;
	if(IS_ERR_OR_NULL(state)) {
		BUG();
	}

	spin_lock_irqsave(&state->lock, flags);
	__hadm_site_set(state, field, val);
	spin_unlock_irqrestore(&state->lock, flags);
}

int __hadm_site_test_and_set(struct hadm_site_state *state, int field, int test_val, int val)
{
	int ret = 0, *field_val = NULL;

	switch (field) {
	case S_HANDSHAKE:
		field_val = &state->handshake;
		break;
	case S_CSTATE:
		field_val = &state->c_state;
		break;
	case S_DATA_STATE:
		field_val = &state->data_state;
		break;
	case S_DSTATE:
		field_val = &state->d_state;
		break;
	case S_NSTATE:
		field_val = &state->n_state;
		break;
	case S_ROLE:
		field_val = &state->role;
		break;
	case S_DEV_STATE:
		field_val = &state->dev_state;
		break;
	default:
		pr_warning("no field %d\n", field);
		break;
	}

	if (field_val && *field_val == test_val) {
		*field_val = val;
		ret = 1;
	}

	return ret;
}

int hadm_site_test_and_set(struct hadm_site *site, int which, int field, int test_val, int val)
{
	int ret = 0;
	unsigned long flags;
	struct hadm_site_state *state;

	state = (which == PRIMARY_STATE) ? &site->p_state : &site->s_state;

	spin_lock_irqsave(&state->lock, flags);
	__hadm_site_test_and_set(state, field, test_val, val);
	spin_unlock_irqrestore(&state->lock, flags);

	return ret;
}

int __hadm_site_get(struct hadm_site_state *state, int field)
{
	int val = 0;

	switch (field) {
	case S_INVALID:
		val = state->invalid;
		break;
	case S_HANDSHAKE:
		val = state->handshake;
		break;
	case S_DEV_STATE:
		val = state->dev_state;
		break;
	case S_ROLE:
		val = state->role;
		break;
	case S_CSTATE:
		val = state->c_state;
		break;
	case S_DSTATE:
		val = state->d_state;
		break;
	case S_DATA_STATE:
		val = state->data_state;
		break;
	case S_NSTATE:
		val = state->n_state;
		break;
	case S_BWR_SIZE:
		val = state->bwr_size;
		break;
	case S_SND_HEAD:
		val = state->snd_head;
		break;
	default:
		val = 0;
		break;
	}

	return val;
}

int hadm_site_get(struct hadm_site *site, int which, int field)
{
	struct hadm_site_state *state;
	unsigned long flags;
	int val = 0;

	state = (which == PRIMARY_STATE) ? &site->p_state : &site->s_state;

	spin_lock_irqsave(&state->lock, flags);
	val = __hadm_site_get(state, field);
	spin_unlock_irqrestore(&state->lock, flags);

	return val;
}

int hadm_site_bit_to_num(uint32_t site_id)
{
	int i;

	for (i = 0; i < MAX_NODES; i++) {
		if (site_id == (1<<i))
			return i;
	}

	return -1;
}

void hadm_site_net_head_inc(struct hadm_site *site)
{
	unsigned long flags;
	sector_t tail;
	struct bwr *bwr = site->hadmdev->bwr;

	read_lock_irqsave(&bwr->lock, flags);
	tail = bwr->mem_meta.tail;
	read_unlock_irqrestore(&bwr->lock, flags);

	site->s_state.snd_ack_head = bwr_next_sector(bwr, site->s_state.snd_ack_head);
	if (site->s_state.snd_ack_head == tail && site->conf.real_protocol == PROTO_SYNC) {
		spin_lock(&bwr->sync_site_mask_lock);
		bwr->sync_site_mask &= ~(1UL << site->id);
		if (!bwr->sync_site_mask)
			complete(&bwr->sync_site_finish);
		spin_unlock(&bwr->sync_site_mask_lock);
	}
}

void hadm_site_send_head_data_set(struct hadm_site *runsite, struct bwr_data *bwr_data)
{
	if (runsite->s_state.snd_head_data)
		bwr_data_put(runsite->s_state.snd_head_data);
	if (bwr_data) {
		bwr_data_get(bwr_data);
	}
	runsite->s_state.snd_head_data = bwr_data;
}

void hadm_site_send_head_data_update(struct hadm_site *runsite)
{
	struct bwr_data *head_data = runsite->s_state.snd_head_data;
	struct data_buffer *buffer = runsite->hadmdev->buffer;

	if (head_data) {
		head_data = get_buffer_next_data(buffer, head_data);
		bwr_data_put(runsite->s_state.snd_head_data);
		runsite->s_state.snd_head_data = head_data;
	}
}

void __hadm_site_send_head_inc(struct hadm_site *site)
{
	struct bwr *bwr = site->hadmdev->bwr;
	site->s_state.snd_head = bwr->start_sector + (site->s_state.snd_head - bwr->start_sector + BWR_ALIGN_SECTOR) % bwr->max_size;
}

void hadm_site_send_head_inc(struct hadm_site *site)
{
	unsigned long flags;

	spin_lock_irqsave(&site->s_state.lock, flags);
	__hadm_site_send_head_inc(site);
	spin_unlock_irqrestore(&site->s_state.lock, flags);
}

void snd_head_condition_update(struct hadm_site *site, int field, int status)
{
	unsigned long flags;
	spin_lock_irqsave(&site->s_state.lock, flags);
	if (__hadm_site_get(&site->s_state, field) == status) {
		__hadm_site_send_head_inc(site);
		site->s_state.snd_ack_head=site->s_state.snd_head;
		spin_unlock_irqrestore(&site->s_state.lock, flags);
		hadm_site_send_head_data_update(site);
	} else
		spin_unlock_irqrestore(&site->s_state.lock, flags);
}

void __hadm_site_reset_send_head(struct hadm_site *site)
{
	site->s_state.snd_ack_head = site->s_state.snd_head = site->hadmdev->bwr->mem_meta.head[site->id];
//	if (site->s_state.snd_head_data)
//		bwr_data_put(site->s_state.snd_head_data);
//	site->s_state.snd_head_data = NULL;
}

void hadm_site_reset_send_head(struct hadm_site *site)
{
	unsigned long flags;
	spin_lock_irqsave(&site->s_state.lock, flags);
	pr_info("before reset, snd_head:%llu, site_head:%llu.\n", site->s_state.snd_head, site->hadmdev->bwr->mem_meta.head[site->id]);
	site->s_state.snd_ack_head = site->s_state.snd_head = site->hadmdev->bwr->mem_meta.head[site->id];
	pr_info("after reset, snd_head:%llu, site_head:%llu.\n", site->s_state.snd_head, site->hadmdev->bwr->mem_meta.head[site->id]);
	spin_unlock_irqrestore(&site->s_state.lock, flags);
}

void disconnect_site(struct hadm_site *site)
{
	unsigned long flags;
	struct bwr *bwr;
	int nstate;
	int handshake;
	int primary_id;

	primary_id = hadmdev_get_primary_id(site->hadmdev);
	spin_lock_irqsave(&site->s_state.lock, flags);
	nstate = __hadm_site_get(&site->s_state, S_NSTATE);
	if (nstate != N_DISCONNECT) {
		pr_info("pre disconnect, state changed...");
		if (get_site_id() == primary_id) {
			pr_info("primary site: reset peer site info.\n");
			__hadm_site_reset_send_head(site);
			__hadm_site_set(&site->s_state, S_NSTATE, N_DISCONNECT);
			__hadm_site_set(&site->s_state, S_HANDSHAKE, HS_FAIL);
			__hadm_site_set(&site->s_state, S_CSTATE, C_STOPPED);
			spin_unlock_irqrestore(&site->s_state.lock, flags);

			bwr = site->hadmdev->bwr;
			if (site->conf.protocol == PROTO_SYNC) {
				pr_info("site %d disconnect, tp change to %d.\n", site->id, PROTO_ASYNC);
				site->conf.real_protocol = PROTO_ASYNC;
				spin_lock(&bwr->sync_site_mask_lock);
				if (bwr->sync_site_mask) {
					bwr->sync_site_mask &= ~(1UL << site->id);
					if (!bwr->sync_site_mask)
						complete(&bwr->sync_site_finish);
				}
				spin_unlock(&bwr->sync_site_mask_lock);
			}
		} else {
			pr_info("secondary site: reset peer site info.\n");
			if (primary_id == site->id) {
				pr_info("peer is primary, clean primary info.\n");
				__hadm_site_set(&site->s_state, S_ROLE, R_SECONDARY);
				hadmdev_set_primary(site->hadmdev, NULL);
			}
			__hadm_site_set(&site->s_state, S_NSTATE, N_DISCONNECT);
			__hadm_site_set(&site->s_state, S_CSTATE, C_STOPPED);
			handshake = __hadm_site_get(&site->s_state, S_HANDSHAKE);
			if (handshake == HS_SUCCESS) {
				pr_info("site %d disconnect, reset handshake\n",
						site->id);
				__hadm_site_set(&site->s_state, S_HANDSHAKE, HS_FAIL);
			}
			spin_unlock_irqrestore(&site->s_state.lock, flags);
		}
		hadm_pack_queue_clean_for_host(g_hadm->p_sender_queue[P_DATA_TYPE], site);
		hadm_pack_queue_clean_for_host(site->hadmdev->queues[SITE_DATA_Q], site);
	} else
		spin_unlock_irqrestore(&site->s_state.lock, flags);
}
