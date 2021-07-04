/*
 * Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2 or the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#include "spdk/stdinc.h"
#include <rte_config.h>
#include <rte_mbuf.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include "spdk/log.h"
#include "spdk/sock.h"
#include "spdk/string.h"
#include "spdk/env.h"
#include "spdk/config.h"
#include "spdk_internal/sock.h"
#include "spdk_internal/event.h"
#include "nvmf_internal.h"
#include "chtcp_ucompat.h"
#include "t4_regs_values.h"
#include "t4_regs.h"
#include "t4_hw.h"
#include "t4fw_interface.h"
#include "chtcp_umain.h"
#include "chtcp_ioctl.h"
#include "chtcp_ucm.h"
#include "chtcp_usge.h"

struct chtcp_root g_chtcp_root;

static void chtcp_destroy_reactor_mempool(void);
static void chtcp_tid_fini(void);
static void chtcp_fini_adapters(void);
static void chtcp_free_reactor_priv_data(void);
static ssize_t __chtcp_sock_writev(struct spdk_sock *_sock, struct iovec *iov,
				  int iovcnt);
static void chtcp_fini_all_queues(void);

#define __chtcp_listen_sock(lcsk) (struct chtcp_listen_sock *)lcsk
#define __chtcp_sock(sock) (struct chtcp_sock *)sock
#define __chtcp_group_impl(group) (struct chtcp_sock_group_impl *)group

struct chtcp_sge_ofld_rxq *
chtcp_get_rxq(struct chtcp_uadapter *adap, u32 port_id, u32 reactor_id)
{
	return &adap->rxq[(port_id * g_chtcp_root.nreactors) + reactor_id];
}

struct chtcp_sge_ofld_txq *
chtcp_get_txq(struct chtcp_uadapter *adap, u32 port_id, u32 reactor_id)
{
	return &adap->txq[(port_id * g_chtcp_root.nreactors) + reactor_id];
}

static int 
chtcp_server_close_req(struct chtcp_listen_sock *lcsk)
{

	struct chtcp_free_server_info srv_info;
	struct spdk_reactor *reactor;
	struct chtcp_sge_ofld_rxq *rxq;
	u32 lcore, r_id;
	int rc;

	lcore = rte_lcore_id();
	reactor = spdk_reactor_get(lcore);
	assert(reactor != NULL);

	r_id = reactor->r_index;
	rxq = chtcp_get_rxq(lcsk->adap, lcsk->port_id, r_id);

	srv_info.rss_qid = rxq->rspq.abs_id;
	srv_info.stid = lcsk->stid;
	rc = ioctl(lcsk->adap->dev_fd, CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ_CMD,
		   &srv_info);
	if (rc < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
				"CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ: %d\n",
				lcsk->adap->pci_devname, rte_lcore_id(), rc);
	}
	return rc;
}

static void 
chtcp_abort_conn(void *arg1, void *arg2)
{
	struct chtcp_sock *csk = __chtcp_sock(arg1);

	if ((csk->state == CHTCP_CSK_STATE_ESTABLISHED) ||
	    (csk->state == CHTCP_CSK_STATE_CLOSING))
		chtcp_send_abort_req(csk, true);
}

int 
chtcp_cleanup_conn(void *ctx)
{
	struct chtcp_listen_sock *lcsk = __chtcp_listen_sock(ctx);
	struct chtcp_sock *csk, *tmp;
	struct spdk_reactor *reactor;
	u32 current_core;

	if (rte_atomic32_read(&lcsk->conn_count) == 0) {
		chtcp_server_close_req(lcsk);
		spdk_poller_unregister(&lcsk->cleanup_poller);
		return 0;
	}

	if (TAILQ_EMPTY(&lcsk->acsk_list))
		return 0;

	current_core = spdk_env_get_current_core();

	TAILQ_FOREACH_SAFE(csk, &lcsk->acsk_list, acsk_link, tmp) {
		reactor = csk->pg->thread->reactor;
		assert(reactor != NULL);
		if (current_core == reactor->lcore)
			continue;
		TAILQ_REMOVE(&lcsk->acsk_list, csk, acsk_link);
		spdk_event_call(spdk_event_allocate(reactor->lcore,
				chtcp_abort_conn, csk, NULL));
	}

	TAILQ_FOREACH_SAFE(csk, &lcsk->acsk_list, acsk_link, tmp) {
		reactor = csk->pg->thread->reactor;
		assert(reactor != NULL);
		if (current_core == reactor->lcore) {
			TAILQ_REMOVE(&lcsk->acsk_list, csk, acsk_link);
			if ((csk->state == CHTCP_CSK_STATE_ESTABLISHED) ||
	    		    (csk->state == CHTCP_CSK_STATE_CLOSING))
				chtcp_send_abort_req(csk, true);
		}
	}

	return 0;
}

static int
chtcp_sock_flush(struct spdk_sock *_sock)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	struct spdk_sock_request *req;

	if (_sock->cb_cnt > 0) {
		return 0;
	}

	req = TAILQ_FIRST(&_sock->queued_reqs);
	while (req) {
		if (csk->state != CHTCP_CSK_STATE_ESTABLISHED) {
			errno = EPIPE;
			return -1;
		}

		if (!(csk->flags & CHTCP_CSK_FLAG_FORCE_FLUSH) && 
		    (csk->flags & CHTCP_CSK_FLAG_NO_WR_CREDIT))
			return 0;

		if (req->nvmf_req) {
			struct spdk_nvmf_request *nvmf_req = req->nvmf_req;
			u32 i;
			
			for (i = 0; i < nvmf_req->iovcnt; i++) {
				struct rte_mbuf *mbuf = nvmf_req->mbuf[i];

				chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_TX_DATA);
				chtcp_queue_tx_mbuf(csk, mbuf);

				nvmf_req->iov[i].iov_base = NULL;
				nvmf_req->buffers[i] = NULL;
				nvmf_req->mbuf[i] = NULL;				
			}

			nvmf_req->iovcnt = 0;
		} else {
#define CHTCP_MAX_TX_IOVCNT 32
			struct iovec iovs[CHTCP_MAX_TX_IOVCNT];
			u32 offset = req->internal.offset;
			u32 len = 0;
			ssize_t rc;
			int iovcnt = 0;
			int i;
			
			for (i = 0; i < req->iovcnt; i++) {
				if (offset >= SPDK_SOCK_REQUEST_IOV(req, i)->iov_len) {
					offset -= SPDK_SOCK_REQUEST_IOV(req, i)->iov_len;
					continue;
				}

				iovs[iovcnt].iov_base = SPDK_SOCK_REQUEST_IOV(req, i)->iov_base + offset;
				iovs[iovcnt].iov_len = SPDK_SOCK_REQUEST_IOV(req, i)->iov_len - offset;
				len += iovs[iovcnt].iov_len;
				offset = 0;
				iovcnt++;

				if (unlikely(iovcnt >= CHTCP_MAX_TX_IOVCNT))
					break;
			}

			rc = __chtcp_sock_writev(_sock, iovs, iovcnt);
			if (rc <= 0)
				return rc;

			if ((rc < len) || (i < req->iovcnt)) {
				req->internal.offset += rc;
				return 0;
			}
		}

		spdk_sock_request_pend(_sock, req);
		if (spdk_sock_request_put(_sock, req, 0))
			return 0;

		req = TAILQ_FIRST(&_sock->queued_reqs);
	}

	return 0;
}

void
chtcp_remove_tid(struct tid_info *t, u32 chan, u32 tid,
		  unsigned short family)
{
	if (t->tid_tab[tid - t->tid_base]) {
		t->tid_tab[tid - t->tid_base] = NULL;
		rte_atomic32_dec(&t->conns_in_use);

		if (family == AF_INET6)
			rte_atomic32_sub(&t->tids_in_use, 2);
		else
			rte_atomic32_dec(&t->tids_in_use);
	}

}

static int
chtcp_sock_getaddr_port(struct sockaddr_storage *sa, char *addr, int len,
			uint16_t *port)
{
	const char *result = NULL;

	if (sa->ss_family == AF_INET) {
		result = inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
				   addr, len);
		if (!result)
			return -1;
		if (port)
			*port = rte_be_to_cpu_16(((struct sockaddr_in *)sa)->sin_port);
		return 0;
	} else if (sa->ss_family == AF_INET6) {
		result = inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
				   addr, len);
		if (!result)
			return -1;
		if (port)
			*port = rte_be_to_cpu_16(((struct sockaddr_in6 *)sa)->sin6_port);
		return 0;
	}

	return -1;
}

static int
chtcp_sock_getaddr(struct spdk_sock *_sock, char *saddr, int slen, 
		   uint16_t *sport, char *caddr, int clen, uint16_t *cport)
{
	struct chtcp_sock *csk;
	struct sockaddr_storage *sa;
	int rc;

	if (_sock->is_listen) {
		struct chtcp_listen_sock *lcsk = __chtcp_listen_sock(_sock);

		SPDK_ERRLOG("%s core[%d]: %s called for lcsk\n",
			     lcsk->adap->pci_devname, rte_lcore_id(), __func__);
		return -1;
	}

	csk = __chtcp_sock(_sock);
	assert(csk != NULL);

	if ((saddr == NULL) || (caddr == NULL))
		return -1;

	sa = &csk->local_addr;

	rc = chtcp_sock_getaddr_port(sa, saddr, slen, sport);
	if (rc) {
		SPDK_ERRLOG("%s core[%d]: get saddr failed (errno=%d)\n", 
			csk->adap->pci_devname, rte_lcore_id(), errno);
		return -1;
	}

	sa = &csk->remote_addr;

	rc = chtcp_sock_getaddr_port(sa, caddr, clen, cport);
	if (rc) {
		SPDK_ERRLOG("%s core[%d]: get caddr failed (errno=%d)\n", 
			csk->adap->pci_devname, rte_lcore_id(), errno);
		return -1;
	}

	return 0;
}

static struct spdk_sock *
chtcp_sock_listen(const char *ip_info, int port, struct spdk_sock_opts *opts)
{
	struct chtcp_listener_address *addr;
	struct chtcp_listen_sock *lcsk;
	struct chtcp_create_server_info s_info;
	struct chtcp_uadapter *adap = NULL;
	struct spdk_reactor *reactor;
	struct chtcp_sge_ofld_rxq *rxq;
	unsigned lcore;
	u32 i, p_id, r_id;
	s32 ret;
	u8 is_ipv4;
	const char *ip;

	if (!ip_info)
		return NULL;

	addr = (struct chtcp_listener_address *)ip_info;
	ip = (const char *)addr->traddr;

	memset(&s_info, 0, sizeof(s_info));
	if (inet_pton(AF_INET, ip, &s_info.u.in.addr.ip_addr[0])) {
		if (addr->adrfam == SPDK_NVMF_ADRFAM_IPV4) {
			s_info.u.in.is_ipv4 = 1;
			is_ipv4 = 1;
		}
		else
			return NULL;
	} else if (inet_pton(AF_INET6, ip, &s_info.u.in.addr.ip_addr[0])) {
			if (addr->adrfam == SPDK_NVMF_ADRFAM_IPV6) {
				s_info.u.in.is_ipv4 = 0;
				is_ipv4 = 0;
			}
			else
				return NULL;
	} else {
		SPDK_ERRLOG("IP address with invalid format\n");
		return NULL;
	}

	lcsk = rte_calloc_socket("server_sock", 1, sizeof(*lcsk),
				RTE_CACHE_LINE_SIZE,
				rte_socket_id());
	if (!lcsk) {
		SPDK_ERRLOG("sock allocation failed\n");
		return NULL;
	}

	s_info.u.in.addr.tcp_port = port;
	lcore = rte_lcore_id();
	reactor = spdk_reactor_get(lcore);
	assert(reactor != NULL);
	r_id = reactor->r_index;
	for (i = 0; i < g_chtcp_root.num_adapter; i++) {
		adap = g_chtcp_root.adapter[i];
		for (p_id = 0; p_id < adap->nports; p_id++) {
			rxq = chtcp_get_rxq(adap, p_id, r_id);
			s_info.u.in.rss_iq[p_id] = rxq->rspq.abs_id;
		}
		ret = ioctl(adap->dev_fd, CHTCP_IOCTL_CPL_PASS_OPEN_CMD, &s_info);
		if (ret < 0) {
			SPDK_DEBUGLOG(chtcp, "%s core[%d]: ioctl failed for"
				    "CHTCP_IOCTL_CPL_PASS_OPEN:%d\n",
				     adap->pci_devname, rte_lcore_id(), ret);
			adap = NULL;
			continue;
		} else if (ret == 0) {
			SPDK_DEBUGLOG(chtcp, "success: CHTCP_IOCTL_CPL_PASS_OPEN "
					"ioctl: %d\n",ret);
			break;
		}
	}

	if (!adap) {
		SPDK_ERRLOG("Unable to create the server for IP: %s Port: %u\n",
			     ip, port);
		rte_free(lcsk);
		return NULL;
	}

	SPDK_NOTICELOG("%s :success server creation with stid: %u\n",
		      adap->pci_devname, s_info.u.out.stid);
	
	lcsk->port = (struct spdk_nvmf_tcp_port *)addr->port;
	lcsk->is_ipv4 = is_ipv4;
	rte_atomic32_inc(&adap->server_count);
	lcsk->adap = adap;
	lcsk->port_id = s_info.u.out.port_id;
	lcsk->stid = s_info.u.out.stid;
	lcsk->base.is_listen = true;
	lcsk->state = CHTCP_LCSK_STATE_PASS_OPEN;
	rte_atomic32_init(&lcsk->conn_count);
	TAILQ_INIT(&lcsk->acsk_list);
	rte_spinlock_init(&lcsk->acsk_lock);
	rte_spinlock_lock(&adap->lcsk_lock);
	TAILQ_INSERT_TAIL(&adap->lcsk_list, lcsk, lcsk_link);
	rte_spinlock_unlock(&adap->lcsk_lock);
	return &lcsk->base;
}

static struct spdk_sock *
chtcp_sock_connect(const char *ip, int port, struct spdk_sock_opts *opts)
{
	return NULL;
}

static struct spdk_sock *
chtcp_sock_accept(struct spdk_sock *_sock)
{
	struct chtcp_listen_sock *lcsk = __chtcp_listen_sock(_sock);
	struct chtcp_sock *csk;

	rte_spinlock_lock(&lcsk->acsk_lock);
	csk = TAILQ_FIRST(&lcsk->acsk_list);
	if (csk) {
		TAILQ_REMOVE(&lcsk->acsk_list, csk, acsk_link);
		rte_spinlock_unlock(&lcsk->acsk_lock);
		return &csk->base;
	}
	rte_spinlock_unlock(&lcsk->acsk_lock);

	return NULL;
}

static int
chtcp_sock_close(struct spdk_sock *_sock)
{
	if (_sock->is_listen) {
		struct chtcp_listen_sock *lcsk;
		lcsk = __chtcp_listen_sock(_sock);
		return chtcp_listen_sock_close(lcsk);
	} else {
		struct chtcp_sock *c_sock;
		c_sock = __chtcp_sock(_sock);
		return chtcp_client_sock_close(c_sock);
	}
}

static u32 
chtcp_copy_mbuf(struct chtcp_sock *csk, struct rte_mbuf *mbuf, void *buf,
		size_t len)
{
	void *data;
	u32 copy_len;

	copy_len = RTE_MIN(mbuf->data_len, len);
	data = rte_pktmbuf_mtod(mbuf, void *);

	rte_memcpy(buf, data, copy_len);
	rte_pktmbuf_adj(mbuf, copy_len);

	return copy_len;
}

static ssize_t
chtcp_sock_recv(struct spdk_sock *_sock, void *buf, size_t len)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	struct chtcp_mbuf_private *priv_data;
	struct chtcp_mbuf_private *tpriv;
	struct rte_mbuf *mbuf; 
	u32 len_copied = 0, rx_bytes = 0;

	TAILQ_FOREACH_SAFE(priv_data, &csk->recvq, link, tpriv){
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data);
		if (chtcp_test_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_DISCONNECT)) {
			if (!len_copied) {
				errno = ECONNRESET;
				TAILQ_REMOVE(&csk->recvq, priv_data, link);
				rte_pktmbuf_free(mbuf);
				return 0;
			} else {
				return rx_bytes;
			}
		}

		if (len <= rx_bytes)
			break;
		len_copied = chtcp_copy_mbuf(csk, mbuf, buf + rx_bytes,
					     len - rx_bytes);
		rx_bytes += len_copied;
		if (!mbuf->pkt_len) {
			TAILQ_REMOVE(&csk->recvq, priv_data, link);
			rte_pktmbuf_free(mbuf);
		}
	}

	if (!rx_bytes) {
		errno = EAGAIN;
		return -1;
	}

	return rx_bytes;
}

static ssize_t
chtcp_sock_readv(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	ssize_t rc, rx_bytes = 0;
	int i; 

	for (i = 0; i < iovcnt; i++) {
		rc = chtcp_sock_recv(_sock, iov[i].iov_base, iov[i].iov_len);
		if (!rc) 
			return rc;
		else if (rc < 0) {
			if (rx_bytes)
				return rx_bytes;
			else
				return rc;
		}

		rx_bytes += rc;
	}

	return rx_bytes;
}

static ssize_t
__chtcp_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	u32 tx_bytes = 0;
	u32 offset = 0;
	int i = 0;

	while (i < iovcnt) {
		struct rte_mbuf *mbuf;
		u32 mbuf_rem_dlen;

		mbuf = chtcp_alloc_tx_mbuf(csk);
		if (!mbuf) {
			SPDK_DEBUGLOG(chtcp, "failed rte_pktmbuf_alloc\n");
			break;
		}

		mbuf_rem_dlen = mbuf->data_len;

		while (i < iovcnt) {
			void *data;
			u32 len;

			if (!mbuf_rem_dlen)
				break;

			len = RTE_MIN(iov[i].iov_len - offset, mbuf_rem_dlen);

			data = rte_pktmbuf_mtod_offset(mbuf, void *,
						       mbuf->data_len - mbuf_rem_dlen);
			rte_memcpy(data, iov[i].iov_base + offset, len);

			offset += len;
			mbuf_rem_dlen -= len;
			tx_bytes += len;

			if (offset == iov[i].iov_len) {
				offset = 0;
				i++;
			}
		}

		mbuf->data_len -= mbuf_rem_dlen;
		mbuf->pkt_len = mbuf->data_len;

		chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_TX_DATA);
		chtcp_queue_tx_mbuf(csk, mbuf);
	}

	return tx_bytes;
}

static ssize_t
chtcp_sock_writev(struct spdk_sock *_sock, struct iovec *iov, int iovcnt)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	int rc;

	if (csk->state != CHTCP_CSK_STATE_ESTABLISHED) {
		errno = EPIPE;
		return -1;
	}

	csk->flags |= CHTCP_CSK_FLAG_FORCE_FLUSH;
 
	rc = chtcp_sock_flush(_sock);
	csk->flags &= ~CHTCP_CSK_FLAG_FORCE_FLUSH;
	if (rc < 0)
		return rc;

	if (!TAILQ_EMPTY(&_sock->queued_reqs)) {
		errno = EAGAIN;
		return -1;
	}

	return __chtcp_sock_writev(_sock, iov, iovcnt);
}

static void
chtcp_sock_writev_async(struct spdk_sock *sock,
			struct spdk_sock_request *req)
{
	int rc;

	spdk_sock_request_queue(sock, req);

	rc = chtcp_sock_flush(sock);
	if (rc)
		spdk_sock_abort_requests(sock);
}

static int
chtcp_sock_set_recvlowat(struct spdk_sock *_sock, int nbytes)
{
	return 0;
}

static int
chtcp_sock_set_recvbuf(struct spdk_sock *_sock, int sz)
{
	return 0;
}

static int
chtcp_sock_set_sendbuf(struct spdk_sock *_sock, int sz)
{
	return 0;
}

static bool
chtcp_sock_is_ipv6(struct spdk_sock *_sock)
{
	if (_sock->is_listen) {
		struct chtcp_listen_sock *lcsk = __chtcp_listen_sock(_sock);

		assert(lcsk != NULL);
		return !(lcsk->is_ipv4);
	} else {
		struct chtcp_sock *csk = __chtcp_sock(_sock);
		struct sockaddr_storage *sa;

		assert(csk != NULL);
		sa = &csk->local_addr;
		return (sa->ss_family == AF_INET6);
	}
}

static bool
chtcp_sock_is_ipv4(struct spdk_sock *_sock)
{
	if (_sock->is_listen) {
		struct chtcp_listen_sock *lcsk = __chtcp_listen_sock(_sock);

		assert(lcsk != NULL);
		return lcsk->is_ipv4;
	} else {
		struct chtcp_sock *csk = __chtcp_sock(_sock);
		struct sockaddr_storage *sa;

		assert(csk != NULL);
		sa = &csk->local_addr;
		return (sa->ss_family == AF_INET);
	}
}

static bool
chtcp_sock_is_connected(struct spdk_sock *_sock)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	
	assert(csk != NULL);

	return (csk->state == CHTCP_CSK_STATE_ESTABLISHED);
}

static int
chtcp_get_listen_sock_state(struct spdk_sock *_sock)
{
	if (_sock->is_listen) {
		struct chtcp_listen_sock *lcsk;
		lcsk = __chtcp_listen_sock(_sock);
		return lcsk->state;
	}

	return -EINVAL;
}

static int
chtcp_sock_get_tx_buffers(struct spdk_sock *_sock, void **m, u32 n)
{
	struct chtcp_sock *csk = __chtcp_sock(_sock);
	struct rte_mbuf **mbufs = (struct rte_mbuf **)m;
	u32 i;
	int ret;

	ret = rte_pktmbuf_alloc_bulk(csk->tx_mbuf_pool, mbufs, n);
	if (unlikely(ret != 0)) {
		SPDK_DEBUGLOG(chtcp, "%s core[%d]: failed to allocate send mbuf entries in bulk\n",
			      csk->adap->pci_devname, rte_lcore_id());
		return ret;
	}

	for (i = 0; i < n; i++) {
		struct rte_mbuf *mbuf = (struct rte_mbuf *)mbufs[i];
		struct chtcp_mbuf_private *priv_data = CHTCP_MBUF_TO_PRIV(mbuf);

		memset(priv_data, 0, sizeof(struct chtcp_mbuf_private));

		rte_mbuf_refcnt_set(mbuf, 1);
		mbuf->data_off = RTE_PKTMBUF_HEADROOM +
				 sizeof(union nvme_tcp_pdu_hdr);
		mbuf->data_len = mbuf->buf_len - mbuf->data_off;
		mbuf->pkt_len = mbuf->data_len;
	}

	return ret;
}

static int
chtcp_sock_get_placement_id(struct spdk_sock *_sock, int *placement_id)
{
	return -1;
}

static struct spdk_sock_group_impl *
chtcp_sock_group_impl_create(void)
{
	struct chtcp_sock_group_impl *group_impl;

	group_impl = calloc(1, sizeof(*group_impl));
	if (group_impl == NULL) {
		SPDK_ERRLOG("group_impl allocation failed\n");
		return NULL;
	}

	return &group_impl->base;
}

static int
chtcp_sock_group_impl_add_sock(struct spdk_sock_group_impl *_group,
			       struct spdk_sock *_sock)
{
	return 0;
}

static int
chtcp_sock_group_impl_remove_sock(struct spdk_sock_group_impl *_group, 
				       struct spdk_sock *_sock)
{
	struct chtcp_sock_group_impl *group = __chtcp_group_impl(_group);

	if (group->next_sock == _sock)
		group->next_sock = NULL;

	spdk_sock_abort_requests(_sock);

	return 0;
}

static int
chtcp_sock_group_impl_poll(struct spdk_sock_group_impl *_group, int max_events,
			   struct spdk_sock **socks)
{
	struct chtcp_sock_group_impl *group = __chtcp_group_impl(_group);
	int nevents = 0;
	struct spdk_sock *sock, *tmp_sock;
	struct chtcp_sock *csk;
	int rc;

	TAILQ_FOREACH_SAFE(sock, &_group->socks, link, tmp_sock) {
		rc = chtcp_sock_flush(sock);
		if (rc)
			spdk_sock_abort_requests(sock);
	}

	sock = group->next_sock;
	if (!sock)
		sock = TAILQ_FIRST(&group->base.socks);

	while (sock) {
		csk = __chtcp_sock(sock);
		if (!TAILQ_EMPTY(&csk->recvq)) {
			socks[nevents++] = sock; 
			if (nevents >= max_events) {
				sock = TAILQ_NEXT(sock, link);
				break;
			}
		}
		sock = TAILQ_NEXT(sock, link);
	}

	group->next_sock = sock;
	
	return nevents;
}

static int
chtcp_sock_group_impl_close(struct spdk_sock_group_impl *_group)
{
	return 0;
}

static int
chtcp_get_poll_group(struct spdk_sock *sock,
		     struct spdk_nvmf_poll_group **pg)
{
	struct chtcp_sock *csk = __chtcp_sock(sock);

	*pg = csk->pg;

	return 0;
}

static void __iomem *
chtcp_mmap_bar2(int32_t fd, u64 bar2_length)
{
	void *bar2 = NULL;

	bar2 = mmap(NULL, bar2_length, PROT_WRITE, MAP_SHARED, fd, 0);
	bar2 = (bar2 == MAP_FAILED) ? NULL: bar2;
	if (!bar2) {
        	SPDK_ERRLOG("mmap failed with %d\n", errno);
	        return NULL;
	}

       return bar2;
}

static int 
chtcp_init_adapters(void)
{
	struct chtcp_adapter_info adap_info;
	struct chtcp_uadapter *adap;
	char cdevname[20] = {'\0'};
	u32 minor;
	int fd, ret;

	g_chtcp_root.num_adapter = 0;

	for (minor = 0 ; minor < CHTCP_MAX_ADAPTER_NUM; minor++) {
		ret = snprintf(cdevname, sizeof(cdevname),
			       "/dev/chtcp-%u", minor);
		if ( ret < 0 ) {
			SPDK_ERRLOG("snprintf:failed to format dev node "
				"name\n");
			return ret;
		} else
			ret = 0;

		fd = open(cdevname, O_RDWR);
		if (fd < 0) {
			ret = -errno;
			if (ret == -EPERM) {
				SPDK_ERRLOG("chtcp device file already opened\n");
				return ret;
			}
			continue;
		}

		memset(&adap_info, 0, sizeof(adap_info));
		ret = ioctl(fd, CHTCP_IOCTL_GET_DEV_INFO_CMD, &adap_info);
		if (ret < 0) {
			SPDK_ERRLOG("ioctl failed for "
				    "CHTCP_IOCTL_GET_DEV_INFO: %d", ret);
			goto close_fd;
		}

		adap = rte_zmalloc("chtcp_init_adapters",
				    sizeof(struct chtcp_uadapter),
				    RTE_CACHE_LINE_SIZE);
		if (!adap) {
			SPDK_ERRLOG("failed to allocate memory\n");
			ret = -ENOMEM;
			goto close_fd;
		}

		adap->nports = adap_info.nports;
		adap->bar2 = chtcp_mmap_bar2(fd, adap_info.bar2_length);
		if (!adap->bar2) {
			SPDK_ERRLOG("mapping bar address failed\n");
			ret = -ENOMEM;
			goto free_adap;
		}
		adap->bar2_length = adap_info.bar2_length;
		strcpy(adap->pci_devname, adap_info.pci_devname);
		adap->pf = adap_info.pf;
		adap->sge.stat_len = adap_info.stat_len;
		adap->sge.pktshift = adap_info.pktshift;
		adap->sge.fl_starve_thres = adap_info.fl_starve_thres;
		adap->sge.fl_align = adap_info.fl_align;
		adap->sge.fl_buf_idx = adap_info.fl_buf_idx;
		adap->sge.fl_buf_size = adap_info.fl_buf_size;
		adap->sge_fl_db = adap_info.sge_fl_db;
		adap->wr_cred = adap_info.wr_cred;
		adap->adapter_type = adap_info.adapter_type;
		rte_memcpy(adap->mtus, adap_info.mtus, sizeof(adap->mtus));

		adap->dev_fd = fd;
		adap->adap_idx = g_chtcp_root.num_adapter;
		rte_atomic32_init(&adap->server_count);
		rte_spinlock_init(&adap->lcsk_lock);
		TAILQ_INIT(&adap->lcsk_list);
		g_chtcp_root.adapter[g_chtcp_root.num_adapter] = adap;
		g_chtcp_root.num_adapter++;
	}

	if (!g_chtcp_root.num_adapter) {
		SPDK_WARNLOG("No chelsio adapter found\n");
		return -ENODEV;
	}

	return 0;

free_adap:
	rte_free(adap);
close_fd:
	close(fd);
	return ret;
}

static int
tid_init(struct tid_info *t)
{
	u32 size;

	size = (t->ntids * sizeof(*t->tid_tab)) +
	       (t->nstids * sizeof(*t->stid_tab));

	t->tid_tab = rte_zmalloc("tid_init", size, RTE_CACHE_LINE_SIZE);
	if (!t->tid_tab)
		return -ENOMEM;

	rte_atomic32_init(&t->tids_in_use);
	rte_atomic32_set(&t->tids_in_use, 0);
	rte_atomic32_init(&t->conns_in_use);
	rte_atomic32_set(&t->conns_in_use, 0);

	return 0;
}

static int 
chtcp_tid_init(void)
{
	struct chtcp_tid_info tid_info;
	struct chtcp_uadapter *adap;
	u32 i;
	int rc = 0;

	for (i = 0; i < g_chtcp_root.num_adapter; i++) {
		adap = g_chtcp_root.adapter[i];
		rc = ioctl(adap->dev_fd, CHTCP_IOCTL_GET_TID_INFO_CMD,
			   &tid_info);
		if (rc < 0) {
			SPDK_ERRLOG("%s core[%d]: ioctl failed for"
				    "CHTCP_IOCTL_GET_TID_INFO: %d\n", 
				    adap->pci_devname, rte_lcore_id(), rc);
			goto out;
		}
		adap->tids.ntids = tid_info.ntids;
		adap->tids.nstids = tid_info.nstids;
		adap->tids.tid_base = tid_info.tid_base;
		adap->tids.stid_base = tid_info.stid_base;
		if (tid_init(&adap->tids) < 0) {
			SPDK_ERRLOG("%s core[%d]: could not allocate TID table, "
				    "continuing\n", adap->pci_devname, rte_lcore_id());
		}
	}
out:
	return rc;
}

static u32 
chtcp_get_total_ports(void)
{
	u32 i, total_ports = 0;

	for (i = 0; i < g_chtcp_root.num_adapter; i++)
		total_ports += g_chtcp_root.adapter[i]->nports;

	return total_ports;
}

static int 
chtcp_create_reactor_mempool(void)
{
	struct chtcp_uadapter *adap;
	u32 i, nports, nreactors, tx_buf_size;
	u32 tx_nmbuf, fl_nmbuf;
	u32 fl_align, fl_buf_size;
	u32 socket_id;
	struct spdk_reactor *reactor;
	char name[64];
	
        if (!g_chtcp_root.num_adapter) {
		SPDK_ERRLOG("num_adapter %u\n", g_chtcp_root.num_adapter);
		return -EINVAL;
	}

	adap = g_chtcp_root.adapter[0];
	fl_align = adap->sge.fl_align;
	fl_buf_size = adap->sge.fl_buf_size;

        for (i = 1; i < g_chtcp_root.num_adapter; i++) {
		adap = g_chtcp_root.adapter[i];

		if (adap->sge.fl_align != fl_align) {
			SPDK_ERRLOG("\"%s\" fl align does not match %u, %u\n",
			g_chtcp_root.adapter[i]->pci_devname, 
			g_chtcp_root.adapter[i]->sge.fl_align, fl_align);
                	return -EINVAL;  
		}

		if (adap->sge.fl_buf_size != fl_buf_size) {
			SPDK_ERRLOG("\"%s\" fl buf size does not match %u, %u\n",
			g_chtcp_root.adapter[i]->pci_devname, 
			g_chtcp_root.adapter[i]->sge.fl_buf_size, fl_buf_size);
                	return -EINVAL;  
		}
	}

	g_chtcp_root.tx_mbuf_pool = rte_calloc("tx_mempool", g_chtcp_root.nreactors,
					     sizeof(void *),
					     RTE_CACHE_LINE_SIZE);
	if (!g_chtcp_root.tx_mbuf_pool) {
		SPDK_ERRLOG("Failed to allocate memory: TX MBUF POOL \n");
		return -ENOMEM;
	}

	g_chtcp_root.fl_mbuf_pool = rte_calloc("fl_mempool", g_chtcp_root.nreactors,
					     sizeof(void *),
					     RTE_CACHE_LINE_SIZE);
	if (!g_chtcp_root.fl_mbuf_pool) {
		SPDK_ERRLOG("Failed to allocate memory: FL MBUF POOL\n");
		rte_free(g_chtcp_root.tx_mbuf_pool);
		g_chtcp_root.tx_mbuf_pool = NULL;
		return -ENOMEM;
	}

	nports = chtcp_get_total_ports();
	tx_nmbuf = nports * 256;
	fl_nmbuf = nports * 512;
	tx_buf_size = RTE_PKTMBUF_HEADROOM + sizeof(union nvme_tcp_pdu_hdr) +
		      NVMF_DATA_BUFFER_ALIGNMENT +
		      SPDK_NVMF_TCP_DEFAULT_IO_UNIT_SIZE + SPDK_NVME_TCP_DIGEST_LEN;
	for (i = 0; i < g_chtcp_root.nreactors; i++) {
		snprintf(name, sizeof(name), "chtcp_tx_mbuf_pool_%d", i);
		reactor = g_chtcp_root.reactors[i];
		socket_id = rte_lcore_to_socket_id(reactor->lcore);
		g_chtcp_root.tx_mbuf_pool[i] =
			rte_pktmbuf_pool_create(name, tx_nmbuf, 0,
						RTE_ALIGN(sizeof(struct chtcp_mbuf_private),
							  RTE_MBUF_PRIV_ALIGN),
						tx_buf_size, socket_id);
		if (g_chtcp_root.tx_mbuf_pool[i] == NULL) {
			SPDK_ERRLOG("core[%d]: failed rte_pktmbuf_pool_create"
				    " for tx\n", reactor->lcore); 
			goto err;
		}

		snprintf(name, sizeof(name), "chtcp_fl_mbuf_pool_%d", i);
		g_chtcp_root.fl_mbuf_pool[i] =
			rte_pktmbuf_pool_create(name, fl_nmbuf, 0,
						RTE_ALIGN(sizeof(struct chtcp_mbuf_private),
							  RTE_MBUF_PRIV_ALIGN),
						RTE_PKTMBUF_HEADROOM +
						fl_align + fl_buf_size,
						socket_id);
		if (g_chtcp_root.fl_mbuf_pool[i] == NULL) {
			rte_mempool_free(g_chtcp_root.tx_mbuf_pool[i]);
			SPDK_ERRLOG("core[%d]: failed rte_pktmbuf_pool_create"
				    " for rx\n", reactor->lcore);
			goto err;
		}
	}

	return 0;

err:
	nreactors = i;
	for (i = 0; i < nreactors; i++) {
		rte_mempool_free(g_chtcp_root.tx_mbuf_pool[i]);
		rte_mempool_free(g_chtcp_root.fl_mbuf_pool[i]);
	}

	rte_free(g_chtcp_root.tx_mbuf_pool);
	g_chtcp_root.tx_mbuf_pool = NULL;
	rte_free(g_chtcp_root.fl_mbuf_pool);
	g_chtcp_root.fl_mbuf_pool = NULL;

	return -ENOMEM;
}

static void
chtcp_usge_ofld_queues_release(struct chtcp_uadapter *adap, u32 nports,
			      u32 nreactors)
{
	struct chtcp_sge_ofld_txq *txq;
	struct chtcp_sge_ofld_rxq *rxq;
	u32 p_id, r_id;

	for (p_id = 0; p_id < nports; p_id++) {
		for (r_id = 0; r_id < nreactors; r_id++) {
			txq = chtcp_get_txq(adap, p_id, r_id);
			chtcp_usge_ofld_txq_release(adap, txq);

			rxq = chtcp_get_rxq(adap, p_id, r_id);
			chtcp_usge_ofld_rxq_release(adap, rxq);
		}
	}

	rte_free(adap->txq);
	adap->txq = NULL;

	rte_free(adap->rxq);
	adap->rxq = NULL;
}

static int 
chtcp_init_adapter_queues(struct chtcp_uadapter *adap)
{
	struct chtcp_sge_ofld_txq *txq;
	struct chtcp_sge_ofld_rxq *rxq;
	u32 p_id, r_id;
	int ret = 0;

	adap->txq = rte_calloc("txq",adap->nports * g_chtcp_root.nreactors,
				sizeof(struct chtcp_sge_ofld_txq),
				RTE_CACHE_LINE_SIZE);

	adap->rxq = rte_calloc("rxq", adap->nports * g_chtcp_root.nreactors,
				sizeof(struct chtcp_sge_ofld_rxq),
				RTE_CACHE_LINE_SIZE);

	for (p_id = 0; p_id < adap->nports; p_id++) {
		for (r_id = 0; r_id < g_chtcp_root.nreactors; r_id++) {
			txq = chtcp_get_txq(adap, p_id, r_id);
			txq->q.size = 4096;
			txq->q.port_id = p_id;
			txq->adap = adap;
			txq->reactor_id = r_id;
			ret = chtcp_usge_alloc_ofld_txq(adap, txq);
			if (ret) {
				SPDK_ERRLOG("%s core[%d]: alloc ofld txq failed: %d",
					adap->pci_devname, rte_lcore_id(), ret);
				goto err;
			}

			rxq = chtcp_get_rxq(adap, p_id, r_id);
			rxq->rspq.size = 4096;
			rxq->rspq.iqe_len = 64;
			rxq->rspq.port_id = p_id;
			rxq->fl.size = 72;
			rxq->adap = adap;
			rxq->reactor_id = r_id;
			ret = chtcp_usge_alloc_ofld_rxq(adap,
					g_chtcp_root.fl_mbuf_pool[r_id], rxq);
			if (ret) {
				chtcp_usge_ofld_txq_release(adap, txq);
				SPDK_ERRLOG("%s core[%d]: alloc ofld rxq failed: %d\n",
					adap->pci_devname, rte_lcore_id(), ret);
				goto err;
			}
		}
	}

	return 0;
err:
	chtcp_usge_ofld_queues_release(adap, p_id, r_id);

	return ret;
}

static int 
chtcp_init_all_queues(void)
{
	struct chtcp_uadapter *adap;
	int ret, i;

	for (i = 0 ; i < g_chtcp_root.num_adapter ; i++) {
		adap = g_chtcp_root.adapter[i];
		ret = chtcp_init_adapter_queues(adap);
		if (ret) {
			SPDK_ERRLOG("%s core[%d]: chtcp_init_adapter_queues failed: "
				"%d\n", adap->pci_devname, rte_lcore_id(), ret);
			return ret;
		}
	}

	return 0;
}

void 
chtcp_handle_poller_register(void *arg1, void *arg2)
{
	spdk_poller_fn fn = (spdk_poller_fn)arg1;
	struct spdk_reactor *reactor = (struct spdk_reactor *)arg2;

	u32 i = reactor->lcore;

	g_chtcp_root.poller[i] = spdk_poller_register(fn, reactor, 0);
	rte_atomic32_inc(&g_chtcp_root.poller_count);

	return;
}

static int
chtcp_poller_register(void)
{
	struct spdk_reactor *reactor;
	u32 i;

	g_chtcp_root.poller = rte_calloc("chtcp_poller_cb", g_chtcp_root.nreactors,
					   sizeof(void *),
					   RTE_CACHE_LINE_SIZE);

	if (g_chtcp_root.poller == NULL) {
		SPDK_ERRLOG("Failed to allocate memory \n");
		return -ENOMEM;
	}

	rte_atomic32_init(&g_chtcp_root.poller_count);

	SPDK_ENV_FOREACH_CORE(i) {
		reactor = spdk_reactor_get(i);
		if (reactor == NULL)
			continue;

		spdk_event_call(spdk_event_allocate(reactor->lcore,
				chtcp_handle_poller_register,
				chtcp_poller_cb, reactor));
	}

	return 0;
}

static void
chtcp_free_reactor_priv_data(void)
{
	u32 i;
	struct spdk_reactor *reactor;

	SPDK_ENV_FOREACH_CORE(i) {
		reactor  = spdk_reactor_get(i);
		if (reactor == NULL)
			continue;

		rte_free(reactor->priv_data);
	}

	return;
}

static int chtcp_module_version_check(void)
{
	char *ver_file_name = "/sys/module/chtcp/version";
	char ver[256];
	int ret = 0;
	int fd;
	u32 bytes_read;

	fd = open(ver_file_name, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		SPDK_ERRLOG("Failed to open file: %s: %s\n", ver_file_name,
			    strerror(-ret)); 
		return ret;
	}

	bytes_read = read(fd, ver, 256); 	
	ver[bytes_read - 1] = '\0'; /* bytes_read - 1 char is '\n' change it to '\0' */
	if (strcmp(ver, CHTCP_MODULE_VERSION)) {
		/*chtcp driver version mismatch */
		SPDK_ERRLOG("chtcp driver version mismatch: required %s: "
			    "found %s\n", CHTCP_MODULE_VERSION, ver);
		return -EINVAL; 
	}

	return 0;
}

static int chtcp_refcnt_check(void)
{
	char *file_name = "/sys/module/chtcp/refcnt";
	char refcnt_str[3];
	u32 bytes_read;
	int fd, ret;

	fd = open(file_name, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		SPDK_ERRLOG("Failed to open file: %s: %s\n", file_name,
			    strerror(-ret));
		return ret;
	}

	bytes_read = read(fd, refcnt_str, 3);
	if (!bytes_read) {
		ret = -errno;
		SPDK_ERRLOG("Failed to open file: %s: %s\n", file_name,
			    strerror(-ret));
		return ret;
	}
	refcnt_str[bytes_read - 1] = '\0';  /* replace '\n' with '\0' */

	if (atoi(refcnt_str) > 0) {
		/* don't allow device file open more than 1 time */
		SPDK_ERRLOG("chtcp device file is already opened\n");
		return -EPERM;
	}

	return 0;
}

static int 
chtcp_reactor_init(void)
{
	u32 i, index = 0;
	int ret = 0;
	struct spdk_reactor *reactor;

#if defined(DEBUG) || defined(SPDK_CONFIG_DEBUG)
	SPDK_NOTICELOG(" *** Currently running in debug mode *** \n");
#endif

	ret = chtcp_module_version_check();
	if (ret)
		return ret;

	ret = chtcp_refcnt_check();
	if (ret)
		return ret;

	SPDK_ENV_FOREACH_CORE(i) {
		reactor  = spdk_reactor_get(i);
		if ( reactor == NULL )
			continue;

		reactor->r_index  = index;
		reactor->priv_data = rte_calloc("chtcp_reactor_init", 1,
						sizeof(struct chtcp_reactor),
						RTE_CACHE_LINE_SIZE);
		if (reactor->priv_data == NULL) {
			SPDK_ERRLOG("Failed to allocate Memory\n");
			ret = -ENOMEM;
			goto out;
		}
		TAILQ_INIT(&CHTCP_GET_CH_REACTOR(reactor)->acsk_req_list);
		g_chtcp_root.reactors[index] = reactor;
		index++;
	}

	g_chtcp_root.nreactors = index;
	
	ret = chtcp_init_adapters();
	if (ret < 0) {
		SPDK_ERRLOG("chtcp_init_adapters failed: %d\n", ret);
		goto adap_fini;
	}

	ret = chtcp_tid_init();
	if (ret < 0) {
		SPDK_ERRLOG("chtcp_tid_init failed : %d\n", ret);
		goto adap_fini;
	}

	ret = chtcp_create_reactor_mempool();
	if (ret < 0) {
                SPDK_ERRLOG("chtcp_create_reactor_mempool failed : %d\n", ret);
                goto adap_fini;
        }

	ret = chtcp_init_all_queues();
	if (ret) {
		SPDK_ERRLOG("chtcp_init_all_queues failed: %d\n", ret);	
		goto destroy_mempool;
	}	

	ret = chtcp_poller_register();
	if (ret) {
		SPDK_ERRLOG("chtcp_poller_register failed: %d\n", ret);
		goto fini_all_queues;
	}

	return 0;

fini_all_queues:
	chtcp_fini_all_queues();
destroy_mempool:
	chtcp_destroy_reactor_mempool();
	chtcp_tid_fini();
adap_fini:
	chtcp_fini_adapters();
	chtcp_free_reactor_priv_data();
out:
	return ret;
}

static void 
chtcp_wait_for_all_serverfree(void)
{
	struct chtcp_uadapter *adap;
	struct chtcp_listen_sock *lcsk;
	struct spdk_reactor *reactor;
	u32 current_core;
	int i;

	current_core = spdk_env_get_current_core();
	reactor = spdk_reactor_get(current_core);

	for (i = 0 ; i < g_chtcp_root.num_adapter ; i++) {
		adap = g_chtcp_root.adapter[i];
		while (rte_atomic32_read(&adap->server_count)) {

			rte_spinlock_lock(&adap->lcsk_lock);
			TAILQ_FOREACH(lcsk, &adap->lcsk_list, lcsk_link)
				chtcp_cleanup_conn(lcsk);
			rte_spinlock_unlock(&adap->lcsk_lock);

			assert(reactor != NULL);
			chtcp_poller_cb(reactor);
		}
	}

	return;
}

void 
chtcp_handle_poller_unregister(void *arg1, void *arg2)
{
	struct spdk_reactor *reactor = (struct spdk_reactor *)arg1;
	struct spdk_poller *poller;
	u32 i = reactor->lcore;

	poller = g_chtcp_root.poller[i];
	spdk_poller_unregister(&poller);

	if (rte_atomic32_read(&g_chtcp_root.poller_count) != 0)
		rte_atomic32_dec(&g_chtcp_root.poller_count);

	return;
}

static void 
chtcp_poller_unregister(void)
{
	u32 current_core, i;
	struct spdk_reactor *reactor;

	current_core = spdk_env_get_current_core();
	SPDK_ENV_FOREACH_CORE(i) {
		if (i != current_core) {
			reactor = spdk_reactor_get(i);
			if (reactor == NULL)
				continue;
			spdk_event_call(spdk_event_allocate(reactor->lcore,
					chtcp_handle_poller_unregister,
					reactor, NULL));
		}
	}

	reactor = spdk_reactor_get(current_core);
	assert(reactor != NULL);
	chtcp_handle_poller_unregister(reactor, NULL);

	while(rte_atomic32_read(&g_chtcp_root.poller_count));

	rte_free(g_chtcp_root.poller);

	return;
}

static void 
chtcp_fini_all_queues(void)
{
	struct chtcp_uadapter *adap;
	u32 i;

	for (i = 0 ; i < g_chtcp_root.num_adapter ; i++) {
		adap = g_chtcp_root.adapter[i];
		chtcp_usge_ofld_queues_release(adap, adap->nports,
					       g_chtcp_root.nreactors);
	}
}

static void 
chtcp_destroy_reactor_mempool(void)
{
	u32 r;

	for (r = 0; r < g_chtcp_root.nreactors; r++) {
		rte_mempool_free(g_chtcp_root.tx_mbuf_pool[r]);
		rte_mempool_free(g_chtcp_root.fl_mbuf_pool[r]);
	}

	rte_free(g_chtcp_root.tx_mbuf_pool);
	g_chtcp_root.tx_mbuf_pool = NULL;
	rte_free(g_chtcp_root.fl_mbuf_pool);
	g_chtcp_root.fl_mbuf_pool = NULL;

	return;
}

static void 
chtcp_tid_free(struct tid_info *t)
{
	if(t->tid_tab)
		rte_free(t->tid_tab);

	memset(t, 0, sizeof(struct tid_info));
}

static void 
chtcp_tid_fini(void)
{
	struct chtcp_uadapter *adap;
	u32 i;

	for (i = 0; i < g_chtcp_root.num_adapter; i++) {
		adap = g_chtcp_root.adapter[i];
		chtcp_tid_free(&adap->tids);
	}

	return;
}

static void 
chtcp_unmmap_bar2(struct chtcp_uadapter *adap)
{
	int rc = 0;

	rc = munmap(adap->bar2, adap->bar2_length);
	if (rc < 0)
		perror("munmap");
	return;
}

static void 
chtcp_fini_adapters(void)
{
	struct chtcp_uadapter *adap;
	u32 adap_num = g_chtcp_root.num_adapter;
	u32 i;

	for (i = 0; i < adap_num; i++ ) {
		adap = g_chtcp_root.adapter[i];

		if (adap == NULL)
			continue;

		g_chtcp_root.num_adapter--;
		g_chtcp_root.adapter[i] = NULL;
		chtcp_unmmap_bar2(adap);
		close(adap->dev_fd);
		rte_free(adap);
	}
}


static void 
chtcp_free_reactor_priv(void)
{
	struct spdk_reactor *reactor;
	u32 i;

	SPDK_ENV_FOREACH_CORE(i) {
		reactor  = spdk_reactor_get(i);
		if ( reactor == NULL )
			continue;

		if (reactor->priv_data)
			rte_free(reactor->priv_data);
	}
}

static void 
chtcp_reactor_fini(void)
{
	chtcp_wait_for_all_serverfree();
	chtcp_poller_unregister();
	chtcp_fini_all_queues();
	chtcp_destroy_reactor_mempool();
	chtcp_tid_fini();
	chtcp_fini_adapters();
	chtcp_free_reactor_priv();
}

static struct spdk_net_impl g_chtcp_net_impl = {
	.name			= "chtcp",
	.getaddr		= chtcp_sock_getaddr,
	.connect		= chtcp_sock_connect,
	.listen			= chtcp_sock_listen,
	.accept			= chtcp_sock_accept,
	.close			= chtcp_sock_close,
	.recv			= chtcp_sock_recv,
	.readv			= chtcp_sock_readv,
	.writev			= chtcp_sock_writev,
	.writev_async		= chtcp_sock_writev_async,
	.flush			= chtcp_sock_flush,
	.set_recvlowat		= chtcp_sock_set_recvlowat,
	.set_recvbuf		= chtcp_sock_set_recvbuf,
	.set_sendbuf		= chtcp_sock_set_sendbuf,
	.is_ipv6		= chtcp_sock_is_ipv6,
	.is_ipv4		= chtcp_sock_is_ipv4,
	.is_connected		= chtcp_sock_is_connected,
	.get_tx_buffers		= chtcp_sock_get_tx_buffers,
	.get_placement_id	= chtcp_sock_get_placement_id,
	.group_impl_create	= chtcp_sock_group_impl_create,
	.group_impl_add_sock	= chtcp_sock_group_impl_add_sock,
	.group_impl_remove_sock = chtcp_sock_group_impl_remove_sock,
	.group_impl_poll	= chtcp_sock_group_impl_poll,
	.group_impl_close	= chtcp_sock_group_impl_close,
	.get_sock_poll_group	= chtcp_get_poll_group,
	.get_listen_sock_state	= chtcp_get_listen_sock_state,
	.reactor_init           = chtcp_reactor_init,
	.reactor_fini           = chtcp_reactor_fini
};

SPDK_NET_IMPL_REGISTER(chtcp, &g_chtcp_net_impl, DEFAULT_SOCK_PRIORITY);
SPDK_LOG_REGISTER_COMPONENT(chtcp)
