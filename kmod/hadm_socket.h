#ifndef HADM_SOCKET_H
#define HADM_SOCKET_H

#include <linux/module.h>
#include <linux/socket.h>
#include <linux/net.h>

#include "hadm_def.h"

struct hadm_net_conf {
	char ipaddr[MAX_IP_SIZE];
	uint32_t port;
};

enum {
	NET_CONNECTED = 0,
	NET_DISCONNECTED = 1,
	NET_WAIT_CONNECT = 2,
	NET_CLOSED = 3
};

struct hadm_net {
	uint8_t cstate;
	uint8_t connect_type;
	atomic_t refcnt;
	struct mutex cstate_lock;
	struct socket *sock;

	char conf_path[MAX_PATH_SIZE];
	int connect_interval;
	struct completion ev_conn;
	struct hadm_net_conf *conf;

};

#ifdef NET_DEBUG
#define __hadm_net_set_state(net, state) do { \
	pr_info("%s: set net %p 's state from %d to %d\n",  __FUNCTION__, net,  net->cstate , state); \
	net->cstate = state; \
	}while(0)
#else 
#define __hadm_net_set_state(net, state) do { \
	net->cstate = state; \
	}while(0)
#endif

extern int hadm_socket_set_timeout(struct socket *sock,int timeout);
extern struct socket *hadm_socket_connect(char *ip, uint16_t port);
extern struct socket *hadm_socket_listen(uint16_t port);
extern int hadm_socket_send(struct socket *sock, void *data, size_t size);
extern void hadm_socket_close(struct socket *sock);
extern void hadm_socket_release(struct socket *sock);
extern int hadm_socket_receive(struct socket *c_sock, char *buf, size_t buflen);
extern int hadm_net_closed(struct hadm_net *net);
extern int hadm_net_connected(struct hadm_net *net);

extern struct hadm_net *hadm_net_create(const char *ipaddr, const int port, int gfp_mask);
extern void hadm_net_shutdown(struct hadm_net *net, enum sock_shutdown_cmd how);
extern void hadm_net_close(struct hadm_net *net);
extern void hadm_net_release(struct hadm_net *net);
extern int hadm_net_send(struct hadm_net *net, void *data, size_t size);
extern int hadm_net_receive(struct hadm_net *net, char *buf, size_t buflen);

extern struct hadm_net *find_hadm_net_by_type(int type);

extern int hadm_socket_has_connected(struct hadm_net *net);
extern int hadm_connect_server(void *arg);

static inline int hadm_net_get_state(struct hadm_net *net)
{
	int cstate;
	if(IS_ERR_OR_NULL(net)) {
		return NET_CLOSED;
	}
	mutex_lock(&net->cstate_lock);
	cstate = net->cstate ; 
	if(cstate != NET_CLOSED && IS_ERR_OR_NULL(net->sock)){
		cstate = NET_DISCONNECTED;
	}
	mutex_unlock(&net->cstate_lock);
	return cstate;
}


static inline void hadm_net_set_socket(struct hadm_net *net, struct socket *sock)
{
	mutex_lock(&net->cstate_lock);
	BUG_ON(atomic_read(&net->refcnt));
	atomic_inc(&net->refcnt);
	net->sock = sock;
	mutex_unlock(&net->cstate_lock);
}

static inline int hadm_net_socket_released(struct hadm_net *net)
{
	int ret;

	mutex_lock(&net->cstate_lock);
	ret = net->sock == NULL;
	mutex_unlock(&net->cstate_lock);

	return ret;
}

static inline int get_hadm_net_socket(struct hadm_net *net)
{
	int ret = 0;

	mutex_lock(&net->cstate_lock);
	if (atomic_read(&net->refcnt) == 0) {
		ret = -1;
	} else {
		atomic_inc(&net->refcnt);
	}
	mutex_unlock(&net->cstate_lock);

	return ret;
}

static inline void hadm_net_close_socket(struct hadm_net *net)
{
	mutex_lock(&net->cstate_lock);
	if(net->cstate != NET_CLOSED) {
		__hadm_net_set_state(net, NET_DISCONNECTED);
		BUG_ON(!atomic_read(&net->refcnt));
		if(net->sock) {
			if (atomic_dec_and_test(&net->refcnt)) {
				hadm_socket_close(net->sock);
				hadm_socket_release(net->sock);
				net->sock = NULL;
			}
		}
	}
	mutex_unlock(&net->cstate_lock);
}

#endif	/* HADM_SOCKET_H */
