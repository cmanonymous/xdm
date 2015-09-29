#define pr_fmt(fmt) "hadm_socket: " fmt

#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>

#include "hadm_def.h"
#include "hadm_socket.h"
#include "hadm_device.h"
#include "hadm_site.h"
#include "hadm_packet.h"
#include "hadm_struct.h"

/* FIXME: why need this? */
int hadm_socket_set_timeout(struct socket *sock,int timeout)
{
        struct timeval t = { timeout, 0 };
	int ret=0;
	return 0;
        ret=kernel_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (void *)&t, sizeof(t))  +
		kernel_setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (void *)&t, sizeof(t));
	if(0) {
		if((unsigned long)sock==(unsigned long)g_hadm->ctrl_net->sock){
			pr_info("set ctrl net timeout to %d,ret=%d\n",timeout,ret);
		} else if((unsigned long)sock==(unsigned long)g_hadm->data_net->sock) {
			pr_info("set data net timeout to %d,ret=%d\n",timeout,ret);
		} else {
			pr_info("set cmd net timeout to %d,ret=%d\n",timeout,ret);
		}
	}
	return ret;
}

struct socket *hadm_socket_connect(char *ip, uint16_t port)
{
	int ret;
	struct socket *c_sock;
	struct sockaddr_in s_addr;

	ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &c_sock);
	if (ret || !c_sock)
		return ret ? ERR_PTR(ret) : c_sock;
	hadm_socket_set_timeout(c_sock,5);
	memset(&s_addr, 0, sizeof(s_addr));
	s_addr.sin_family = PF_INET;
	s_addr.sin_port = htons(port);
	s_addr.sin_addr.s_addr = in_aton(ip);

	ret = kernel_connect(c_sock, (struct sockaddr *)&s_addr, sizeof(struct sockaddr), 0);
	if (ret < 0) {
		sock_release(c_sock);
		return ERR_PTR(ret);
	}

	return c_sock;
}

int hadm_socket_receive(struct socket *c_sock, char *buf, size_t buflen)
{
	int ret = 0;
	size_t nbytes_rcv = 0;
	struct kvec vec;
	struct msghdr msg;

	vec.iov_base = buf, vec.iov_len = buflen;
	/* msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL; */
	msg.msg_flags = MSG_NOSIGNAL;

	//hadm_socket_set_timeout(c_sock,5);
	while (nbytes_rcv < buflen) {
		ret = kernel_recvmsg(c_sock, &msg, &vec, 1, (buflen - nbytes_rcv), msg.msg_flags);
#if 1
		if (ret == -EAGAIN) {
			pr_info("read again\n");
			continue;
		}
#endif
		if (ret < 0) {
			pr_debug("ret: %d, nbytes_rcv: %lu\n", ret, nbytes_rcv);
			return ret;
		} else if (ret == 0) {
			return -ENOTCONN;
		}
		nbytes_rcv += ret;
		pr_debug("ret: %d, nbytes_rcv: %lu, buflen: %lu\n", ret, nbytes_rcv, buflen);
	}

	return nbytes_rcv;
}

int hadm_socket_recvv(struct socket *sock, struct kvec *vec, int count, size_t size)
{
	int ret;
	int remain;
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };

	remain = size;
	while (remain > 0) {
		ret = kernel_recvmsg(sock, &msg, vec,
				count, remain, msg.msg_flags);
		if (ret == -EAGAIN) {
			pr_err("%s: return EAGAIN\n", __FUNCTION__);
			continue;
		}
		if (ret < 0) {
			pr_err("%s: return %d.(count:%d|size:%ld|remain:%d\n",
					__func__, ret, count, size, remain);
			return ret;
		} else if (ret == 0)
			return -ENOTCONN;

		remain -= ret;
	}

	return size;
}

int hadm_net_receive(struct hadm_net *net, char *buf, size_t buflen)
{
	int ret;

	if (net->sock == NULL || IS_ERR(net->sock)) {
		ret = -ENOTCONN;
		goto done;
	}
	ret = hadm_socket_receive(net->sock, buf, buflen);

done:
	return ret;
}

int hadm_socket_send(struct socket *sock, void *data, size_t size)
{
	struct kvec vec;
	struct msghdr msg;
	size_t sent = 0;
	int ret = 0;

	vec.iov_base = data, vec.iov_len = size;
	/* msg.msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL; */
	msg.msg_flags = MSG_NOSIGNAL;

	do {
		ret = kernel_sendmsg(sock, &msg, &vec, 1, size);
		if (ret == -EAGAIN) {
			pr_debug("hadm_socket_send return EAGAIN, send again\n");
			continue;
		}
		if (ret <= 0) {
			pr_debug("hadm_socket_send return %d\n", ret);
			return ret;
		}
		sent += ret;
		vec.iov_base += ret;
		vec.iov_len -= ret;
	} while (sent < size);

	return sent;
}

int hadm_socket_sendv(struct socket *sock, struct kvec *vec, int count,
		int size)
{
	int i;
	int ret;
	int remain;
	int vec_idx;
	struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };

	vec_idx = 0;
	remain = size;
	while (remain > 0) {
		//ret = kernel_sendmsg(sock, &msg, vec, count, (size - sent));
		ret = kernel_sendmsg(sock, &msg, &vec[vec_idx],
				count - vec_idx, remain);
		if (ret == -EAGAIN) {
			pr_err("%s: return EAGAIN\n", __FUNCTION__);
			continue;
		}
		if (ret <= 0) {
			pr_err("%s: return %d\n", __FUNCTION__, ret);
			return ret;
		}

		remain -= ret;

		for (i = vec_idx; i < count; i++) {
			if (ret >= vec[i].iov_len) {
				ret -= vec[i].iov_len;
			} else {
				vec[i].iov_len -= ret;
				vec[i].iov_base += ret;
				vec_idx = i;
				break;
			}
		}
	}

	return size;
}

/*
int hadm_net_send(struct hadm_net *net, void *data, size_t size)
{
	int sent = 0;

	if (!hadm_socket_has_connected(net)) {
		sent = -ENOTCONN;
		goto done;
	}
	sent = hadm_socket_send(net->sock, data, size);

done:
	return sent;
}
*/

struct socket *hadm_socket_listen(uint16_t port)
{
	int ret, backlog = 5, opt = 1;
	struct socket *sock;
	struct sockaddr_in addr;

	ret = sock_create_kern(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
	if (ret || IS_ERR(sock))
		return ret ? ERR_PTR(ret) : sock;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = PF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);
	hadm_socket_set_timeout(sock,5);
	kernel_setsockopt(sock, SOL_SOCKET, SO_REUSEADDR,
			(char *)&opt, sizeof(opt));
	ret = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr));
	if (ret < 0)
		return ERR_PTR(ret);

	ret = kernel_listen(sock, backlog);
	if (ret < 0)
		return ERR_PTR(ret);

	return sock;
}

struct hadm_net *hadm_net_create(int gfp_mask)
{
	struct hadm_net *net;

	net = kzalloc(sizeof(*net), gfp_mask);
	if (net == NULL)
		return ERR_PTR(-ENOMEM);
	net->sock = NULL;
	net->connect_type = 0;

	net->cstate = NET_DISCONNECTED;
	mutex_init(&net->cstate_lock);
	atomic_set(&net->refcnt, 0);

	net->conf = kzalloc(sizeof(struct hadm_net_conf), gfp_mask);
	if (net->conf == NULL) {
		kfree(net);
		return ERR_PTR(-ENOMEM);
	}
	strcpy(net->conf->ipaddr, "127.0.0.1");
	net->conf->port = DATA_PORT;

	return net;
}

void hadm_net_shutdown(struct hadm_net *net, enum sock_shutdown_cmd how)
{
        int connected;

        connected = hadm_socket_has_connected(net);
        if (!connected)
                return;

	kernel_sock_shutdown(net->sock, how);

	mutex_lock(&net->cstate_lock);
	net->cstate = NET_CLOSED;
	mutex_unlock(&net->cstate_lock);
}

int hadm_net_closed(struct hadm_net *net)
{
	int ret;

	mutex_lock(&net->cstate_lock);
	ret = net->cstate == NET_CLOSED;
	mutex_unlock(&net->cstate_lock);

	return ret;
}

void hadm_socket_close(struct socket *sock)
{
	kernel_sock_shutdown(sock, SHUT_RDWR);
}

void hadm_socket_release(struct socket *sock)
{
	sock_release(sock);
}

struct hadm_net *find_hadm_net_by_type(int type)
{
	struct hadm_net *hadm_net;

	switch(type) {
	case P_CTRL_TYPE:
		hadm_net = g_hadm->ctrl_net;
		break;
	case P_DATA_TYPE:
		hadm_net = g_hadm->data_net;
		break;
	case P_CMD_TYPE:
	default:
		hadm_net = NULL;
		break;
		//hadm_net = ERR_PTR(-EINVAL);
	}

	return hadm_net;
}

void hadm_net_close(struct hadm_net *net)
{
	mutex_lock(&net->cstate_lock);
	net->cstate = NET_DISCONNECTED;
	if (net->sock != NULL && !IS_ERR(net->sock)) {
		kernel_sock_shutdown(net->sock, SHUT_RDWR);
		sock_release(net->sock);
		net->sock = NULL;
	}
	mutex_unlock(&net->cstate_lock);
}

void hadm_net_release(struct hadm_net *net)
{
	if (net != NULL && !IS_ERR(net)) {
		hadm_net_close(net);
		kfree(net->conf);
		kfree(net);
	}
}

int hadm_socket_has_connected(struct hadm_net *net)
{
	int connected;

	if (net == NULL || IS_ERR(net))
		return 0;

	mutex_lock(&net->cstate_lock);
	connected = (net->cstate == NET_CONNECTED) && net->sock != NULL && !IS_ERR(net->sock);
	mutex_unlock(&net->cstate_lock);

	return connected;
}

static int hadm_do_handshake(struct hadm_net *net)
{
	int ret = 0;
	struct packet pkt_buf;
	size_t pack_size = sizeof(pkt_buf);

	memset(&pkt_buf, 0, sizeof(pkt_buf));
	pkt_buf.len = 0;
	pkt_buf.type = net->connect_type;

	mutex_lock(&net->cstate_lock);

	ret = hadm_socket_send(net->sock, (char *)&pkt_buf, pack_size);
	if ((size_t)ret != pack_size) {
		dump_packet("hadm_do_handshake", &pkt_buf);
		ret = -1;
		goto done;
	}
	pr_info("hadm_do_handshake: send packet type %d\n", pkt_buf.type);

	ret = hadm_socket_receive(net->sock, (char *)&pkt_buf, pack_size);
	if (ret != pack_size) {
		//dump_packet("hadm_do_handshake", &pkt_buf);
		ret = -1;
		goto done;
	}
	pr_info("hadm_do_handshake: recv packet type %d\n", pkt_buf.type);

	if (net->connect_type == P_KERN_HANDSHAKE_D && pkt_buf.type != P_KERN_HANDSHAKE_D_ACK) {
		pr_err("hadm_do_handshke: no data ACK receive\n");
		dump_packet("hadm_do_handshake", &pkt_buf);
		ret = -1;
		goto done;
	}
	if (net->connect_type == P_KERN_HANDSHAKE_M && pkt_buf.type != P_KERN_HANDSHAKE_M_ACK) {
		pr_err("hadm_do_handshake: no meta ACK receive\n");
		dump_packet("hadm_do_handshake", &pkt_buf);
		ret = -1;
		goto done;
	}

	net->cstate = NET_CONNECTED;
done:
	mutex_unlock(&net->cstate_lock);
	return ret;
}

/* FIXME error code */
int hadm_connect_server(void *arg)
{
	struct hadm_net *net;
	struct socket *sock;

	net = (struct hadm_net *)arg;

	if (!hadm_net_socket_released(net)) {
		pr_debug("%s sock not release. wait.\n", __FUNCTION__);
		return -ENOTCONN;
	}
	sock = hadm_socket_connect(net->conf->ipaddr, net->conf->port);
	if (IS_ERR(sock)) {
		pr_debug("%s: connect to server failed.%ld.\n", __FUNCTION__, PTR_ERR(sock));
		return PTR_ERR(sock);
	}
	hadm_net_set_socket(net, sock);
	if (hadm_do_handshake(net) < 0) {
		pr_debug("%s connect server, handshake faild.\n", __FUNCTION__);
		hadm_net_close_socket(net);
		return -ENOTCONN;
	}

	return 0;
}
