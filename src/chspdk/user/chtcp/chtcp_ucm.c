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
#include <sys/ioctl.h>

#include <rte_memzone.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_ether.h>

#include <linux/ipv6.h>
#include <linux/ip.h>

#include "spdk/log.h"
#include "spdk_internal/event.h"
#include "spdk/nvmf.h"
#include "spdk/nvmf_transport.h"
#include "nvmf_internal.h"
#include "event_nvmf.h"

#include "chtcp_ucompat.h"

#include "t4_regs.h"
#include "t4_regs_values.h"
#include "t4_hw.h"
#include "t4_msg.h"
#include "t4fw_interface.h"

#include "chtcp_umain.h"
#include "chtcp_ioctl.h"
#include "chtcp_ucm.h"


extern struct chtcp_root g_chtcp_root;

/* Aquire list lock before calling __chtcp_get_listen_sock() */
static struct chtcp_listen_sock *
__chtcp_get_lcsk(struct chtcp_uadapter *adap,  u32 stid)
{
	struct chtcp_listen_sock *lcsk;

	TAILQ_FOREACH(lcsk, &adap->lcsk_list, lcsk_link){
		if (stid == lcsk->stid) {
			return lcsk;
		}
	}

	return NULL;
}

void chtcp_free_lcsk(struct chtcp_listen_sock *lcsk)
{
	struct chtcp_uadapter *adap = lcsk->adap;

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: lcsk %p state %d stid %u\n", 
		      adap->pci_devname, rte_lcore_id(), lcsk,
		      lcsk->state, lcsk->stid);

	TAILQ_REMOVE(&adap->lcsk_list, lcsk, lcsk_link);

	rte_free(lcsk);
}

int
chtcp_handle_close_listsrv_rpl(struct chtcp_uadapter *adap, const void *rsp)
{
	struct cpl_close_listsvr_rpl *rpl = (struct cpl_close_listsvr_rpl *)rsp;
	struct chtcp_listen_sock *lcsk;
	u32 stid = GET_TID(rpl);
	int ret = 0;

	rte_spinlock_lock(&adap->lcsk_lock);
	lcsk = __chtcp_get_lcsk(adap, stid);
	if (!lcsk) {
		SPDK_ERRLOG("%s core[%d]: __chtcp_get_lcsk failed\n", 
			adap->pci_devname, rte_lcore_id());
		rte_spinlock_unlock(&adap->lcsk_lock);
		return -EINVAL;
	}

	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL_CMD,
		    &stid);
	if (ret < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
			"CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL: %d\n",
			adap->pci_devname, rte_lcore_id(), ret);
	}

	chtcp_free_lcsk(lcsk);
	rte_atomic32_dec(&adap->server_count);

	rte_spinlock_unlock(&adap->lcsk_lock);

	return ret;
}

static unsigned int
chtcp_compare_transport(struct spdk_nvmf_transport_poll_group *tgroup)
{
	struct spdk_nvmf_transport *transport = tgroup->transport;
	int type = transport->ops->type;

	if (type == SPDK_NVME_TRANSPORT_TCP)
		return 1;

	return 0;
}

static struct spdk_sock_group_impl *
chtcp_get_sock_group(struct spdk_nvmf_poll_group *pg)
{
	struct spdk_nvmf_transport_poll_group *tgroup;
	struct spdk_nvmf_tcp_poll_group *tcpgroup;
	struct spdk_sock_group	*sock_group;

	TAILQ_FOREACH(tgroup, &pg->tgroups, link) {
               if (!chtcp_compare_transport(tgroup))
                       continue;
               tcpgroup = SPDK_CONTAINEROF(tgroup,
                                       struct spdk_nvmf_tcp_poll_group,
                                       group);
               sock_group = tcpgroup->sock_group;
               if (STAILQ_EMPTY(&sock_group->group_impls)) {
                       SPDK_ERRLOG("sock group impl list is empty\n");
                       return NULL;
               }
               /*
		* Since we only support one transport at any time,
		* we're returning the first element in the group.
		*/
               return STAILQ_FIRST(&sock_group->group_impls);
	}
	return NULL;
}

static int 
chtcp_reserve_csk_mbuf(struct chtcp_sock *csk)
{
	struct rte_mbuf *mbuf;
	u32 len, flowclen;
	u32 i;

#define FLOWC_WR_NPARAMS_MIN 	9
#define FLOWC_WR_NPARAMS_MAX 	11
	flowclen = offsetof(struct fw_flowc_wr,
			    mnemval[FLOWC_WR_NPARAMS_MAX]);

	len = RTE_MAX(sizeof(struct cpl_abort_req),
		      sizeof(struct cpl_abort_rpl));

	len = RTE_MAX(sizeof(struct cpl_close_con_req), len);
	len = RTE_MAX(len, flowclen);
	len = RTE_ALIGN(len, 16);

	/* 2 extra for CHTCP_MBUF_FLAG_DISCONNECT during peer_close and
	 * abort_req_rss */

	for (i = 0; i < 6; i++) {
		mbuf = chtcp_alloc_tx_mbuf(csk);
		if (!mbuf) {
			SPDK_DEBUGLOG(chtcp, "%s core[%d]: failed rte_pktmbuf_alloc \n",
				      csk->adap->pci_devname, rte_lcore_id());
			CHTCP_PURGE_MBUF_Q(&csk->res_mbufq, link);
			return -ENOMEM;
		}
		CHTCP_QUEUE_MBUF(&csk->res_mbufq, mbuf, link);
	}

	return 0;
}

static void 
chtcp_purge_all_csk_mbuf_queues(struct chtcp_sock *csk)
{
	CHTCP_PURGE_MBUF_Q(&csk->recvq, link);
	CHTCP_PURGE_MBUF_Q(&csk->sendq, link);
	CHTCP_PURGE_MBUF_Q(&csk->res_mbufq, link);
	CHTCP_PURGE_MBUF_Q(&csk->wr_ack_mbufq, ack_link);
}

static void 
chtcp_free_csk(struct chtcp_sock *csk)
{
	struct chtcp_uadapter *adap = csk->adap;
	struct chtcp_listen_sock *lcsk;
	int rc = 0;

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: csk %p state %d tid %u stid %u\n", 
		csk->adap->pci_devname, rte_lcore_id(), csk, csk->state, 
		csk->tid, csk->stid);

	chtcp_remove_tid(&adap->tids, 0, csk->tid, csk->local_addr.ss_family);
	rc = ioctl(adap->dev_fd, CHTCP_IOCTL_FREE_SOCK_CMD, &csk->tid);
	if (rc < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for"
			    "CHTCP_IOCTL_FREE_SOCK_CMD: %d\n",
			     adap->pci_devname, rte_lcore_id(), rc);
	}
	
	chtcp_purge_all_csk_mbuf_queues(csk);
	
	rte_spinlock_lock(&adap->lcsk_lock);
	lcsk = __chtcp_get_lcsk(adap, csk->stid);
	rte_atomic32_dec(&lcsk->conn_count);
	rte_spinlock_unlock(&adap->lcsk_lock);

	rte_free(csk);
}

void
check_for_arp_failure(struct chtcp_sock_list *sock_list)
{
        struct chtcp_sock *csk;
        struct chtcp_sock *tcsk;
        struct chtcp_arp_info arp_info;
        int rc;

        TAILQ_FOREACH_SAFE(csk, sock_list, acsk_link, tcsk) {
                memset(&arp_info, 0, sizeof(arp_info));
                arp_info.u.tid = csk->tid;
                rc = ioctl(csk->adap->dev_fd, CHTCP_IOCTL_CHECK_ARP_FAILURE_CMD,
                           &arp_info);
                if (rc) {
                        SPDK_WARNLOG("%s core[%d]: ioctl failed\n",
                                csk->adap->pci_devname, rte_lcore_id());
                        continue;
                }

                if (arp_info.u.arp_failed) {
                        SPDK_DEBUGLOG(chtcp, "%s core[%d]: arp failed for tid %u\n",
                                csk->adap->pci_devname, rte_lcore_id(), csk->tid);
                        TAILQ_REMOVE(sock_list, csk, acsk_link);
			chtcp_free_csk(csk);
                }
        }
}

int 
chtcp_handle_abort_rpl_rss(struct chtcp_uadapter *adap, const void *cpl)
{
	struct cpl_abort_rpl_rss *rpl = (struct cpl_abort_rpl_rss*)cpl;
	struct chtcp_sock *csk;
	u32 tid = GET_TID(rpl);

	csk = chtcp_lookup_tid(&adap->tids, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
				adap->pci_devname, rte_lcore_id(), tid);
		return -EFAULT;
	}

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: csk %p; tid %u; state %d\n",
	       adap->pci_devname, rte_lcore_id(), csk, tid, csk->state);

	switch (csk->state) {
	case CHTCP_CSK_STATE_ABORTING:
		csk->state = CHTCP_CSK_STATE_DEAD;

		if (csk->flags & CHTCP_CSK_FLAG_APP_CLOSE)
			chtcp_free_csk(csk);
		break;
	default:
		SPDK_WARNLOG("%s core[%d]: cpl_abort_rpl_rss in state %d\n",
				adap->pci_devname, rte_lcore_id(), csk->state);
		assert(0);
	}

	return 0;
}

/* Returns whether a CPL status conveys negative advice. */
static bool chtcp_is_neg_adv(u32 status)
{
	return ((status == CPL_ERR_RTX_NEG_ADVICE) ||
		(status == CPL_ERR_PERSIST_NEG_ADVICE) ||
		(status == CPL_ERR_KEEPALV_NEG_ADVICE));
}

int 
chtcp_handle_abort_req_rss(struct chtcp_uadapter *adap, const void *cpl)
{
	struct cpl_abort_req_rss *req = (struct cpl_abort_req_rss *)cpl;
	struct chtcp_sock *csk;
	struct spdk_reactor *reactor;
	u32 tid = GET_TID(req);
	bool release = false;
	bool q_mbuf = false;
	struct rte_mbuf *mbuf;

	csk = chtcp_lookup_tid(&adap->tids, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
			adap->pci_devname, rte_lcore_id(), tid);
		return -EFAULT;
	}

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: csk %p; tid %u; state %d\n",
	       adap->pci_devname, rte_lcore_id(), csk, tid, csk->state);

	if (chtcp_is_neg_adv(req->status)) {
		SPDK_DEBUGLOG(chtcp, "%s core[%d]: got neg advise %d "
			      "on tid %u\n", adap->pci_devname, rte_lcore_id(),
			      req->status, tid);
		goto out;
	}

	if (csk->state == CHTCP_CSK_STATE_CONNECTING) {
		reactor = spdk_reactor_get(rte_lcore_id());
		TAILQ_REMOVE(&CHTCP_GET_CH_REACTOR(reactor)->acsk_req_list,
			     csk, acsk_link);
	}

	switch (csk->state) {
	case CHTCP_CSK_STATE_CONNECTING:
	case CHTCP_CSK_STATE_MORIBUND:
		csk->state = CHTCP_CSK_STATE_DEAD;
		release = true;
		break;
	case CHTCP_CSK_STATE_ESTABLISHED:
		csk->state = CHTCP_CSK_STATE_DEAD;
		q_mbuf = true;
		break;
	case CHTCP_CSK_STATE_CLOSING:
		csk->state = CHTCP_CSK_STATE_DEAD;
		if (csk->flags & CHTCP_CSK_FLAG_APP_CLOSE)
			release = true;
		break;
	case CHTCP_CSK_STATE_ABORTING:
		break;
	default:
		SPDK_ERRLOG("%s core[%d]: cpl_abort_req_rss in bad state %d\n",
			adap->pci_devname, rte_lcore_id(), csk->state);
		csk->state = CHTCP_CSK_STATE_DEAD;
		assert(0);
	}

	CHTCP_PURGE_MBUF_Q(&csk->sendq, link);

	chtcp_send_abort_rpl(csk);

	if (q_mbuf) {
		mbuf = chtcp_alloc_mbuf_res(csk, 0);
		chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_DISCONNECT);
		CHTCP_QUEUE_MBUF(&csk->recvq, mbuf, link);
		return 0;
	}

	if (release)
		chtcp_free_csk(csk);

out:
	return 0;
}

#define INIT_TP_WR(w, tid) do { \
        (w)->wr.wr_hi = rte_cpu_to_be_32(V_FW_WR_OP(FW_TP_WR) | \
                              V_FW_WR_IMMDLEN(sizeof(*w) - sizeof(w->wr))); \
        (w)->wr.wr_mid = rte_cpu_to_be_32(V_FW_WR_LEN16(SPDK_CEIL_DIV(sizeof(*w), 16)) | \
                               V_FW_WR_FLOWID(tid)); \
        (w)->wr.wr_lo = rte_cpu_to_be_64(0); \
} while (0)

int 
chtcp_send_abort_rpl(struct chtcp_sock *csk)
{
	struct rte_mbuf *mbuf;
	struct cpl_abort_rpl *rpl;
	u32 len = RTE_ALIGN(sizeof(struct cpl_abort_rpl), 16);

	if (!(csk->flags & CHTCP_CSK_FLAG_FLOWC_SENT)) {
		csk->flags |= CHTCP_CSK_FLAG_FLOWC_SENT;
		mbuf = chtcp_get_flowc_mbuf(csk);
		chtcp_ofld_queue_xmit(csk->txq, mbuf);
	}

	mbuf = chtcp_alloc_mbuf_res(csk, len);

	rpl = rte_pktmbuf_mtod(mbuf, struct cpl_abort_rpl *);
	memset(rpl, 0, len);

	INIT_TP_WR(rpl, csk->tid);
	OPCODE_TID(rpl) = rte_cpu_to_be_32(MK_OPCODE_TID(CPL_ABORT_RPL,
					   csk->tid));
	rpl->cmd = CPL_ABORT_NO_RST;

	chtcp_ofld_queue_xmit(csk->txq, mbuf);

	return 0;
}

int 
chtcp_send_abort_req(struct chtcp_sock *csk, bool reset)
{
	struct rte_mbuf *mbuf;
	struct cpl_abort_req *req;
	u32 len = RTE_ALIGN(sizeof(struct cpl_abort_req), 16);

	csk->state = CHTCP_CSK_STATE_ABORTING;

	CHTCP_PURGE_MBUF_Q(&csk->sendq, link);

	if (!(csk->flags & CHTCP_CSK_FLAG_FLOWC_SENT)) {
		csk->flags |= CHTCP_CSK_FLAG_FLOWC_SENT;
		mbuf = chtcp_get_flowc_mbuf(csk);
		chtcp_ofld_queue_xmit(csk->txq, mbuf);
	}

	mbuf = chtcp_alloc_mbuf_res(csk, len);

	req = rte_pktmbuf_mtod(mbuf, struct cpl_abort_req *);
	memset(req, 0, len);

	INIT_TP_WR(req, csk->tid);
	OPCODE_TID(req) = rte_cpu_to_be_32(MK_OPCODE_TID(CPL_ABORT_REQ,
				      csk->tid));
	if (reset)
		req->cmd = CPL_ABORT_SEND_RST;
	else
		req->cmd = CPL_ABORT_NO_RST;

	chtcp_ofld_queue_xmit(csk->txq, mbuf);

	return 0;
}

static void 
chtcp_cleanup_server(struct chtcp_uadapter *adap, struct chtcp_listen_sock *lcsk,
		     struct spdk_nvmf_tcp_port *ports)
{
	struct spdk_nvmf_tcp_transport  *ttransport;
	const struct spdk_nvme_transport_id *trid;
	struct spdk_nvmf_transport *transport;
	struct spdk_nvmf_listener *listener;
	void *cb_arg;
	int ret;

	TAILQ_REMOVE(&adap->lcsk_list, lcsk, lcsk_link);

	ret = ioctl(adap->dev_fd, CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL_CMD,
		    &lcsk->stid);
	if (ret < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
			"CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL: %d\n",
			adap->pci_devname, rte_lcore_id(), ret);
	}

	rte_atomic32_dec(&adap->server_count);
	rte_free(lcsk);

	cb_arg = ports->cb_arg;
	trid = ports->trid;
	ttransport = ports->transport;
	transport = &ports->transport->transport;
	TAILQ_REMOVE(&ttransport->ports, ports, link);
	free(ports);
	listener = nvmf_transport_find_listener(transport, trid);
	/*listener should be valid*/
	TAILQ_REMOVE(&transport->listeners, listener, link);
	free(listener);

	chspdk_nvmf_subsystem_add_listener(cb_arg, -EINVAL);
}

int
chtcp_handle_pass_open_rpl(struct chtcp_uadapter *adap, const void *rsp)
{
	struct cpl_pass_open_rpl *rpl = (struct cpl_pass_open_rpl *)rsp;
	struct chtcp_listen_sock *lcsk;
	struct spdk_nvmf_tcp_port *ports;

	u32 stid = GET_TID(rpl);
	int ret = 0;

	rte_spinlock_lock(&adap->lcsk_lock);
	lcsk = __chtcp_get_lcsk(adap, stid);

	ports = lcsk->port;
	if (rpl->status) {
		chtcp_cleanup_server(adap, lcsk, ports);
		ret = -EINVAL;
	} else {
		lcsk->state = CHTCP_LCSK_STATE_LISTEN;
		SPDK_NOTICELOG("*** NVMe/TCP Target Listening on %s port %s ***\n",
				ports->trid->traddr, ports->trid->trsvcid);
		chspdk_nvmf_subsystem_add_listener(ports->cb_arg, 0);
	}

	rte_spinlock_unlock(&adap->lcsk_lock);
	return ret;
}

int 
chtcp_handle_close_con_rpl(struct chtcp_uadapter *adap, const void *cpl)
{
	struct cpl_close_con_rpl *rpl = (struct cpl_close_con_rpl *)cpl;
	struct chtcp_sock *csk;
	u32 tid = GET_TID(rpl);

	csk = chtcp_lookup_tid(&adap->tids, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
			adap->pci_devname, rte_lcore_id(), tid);
		return -EFAULT;
	}

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: csk %p; tid %u; state %d\n",
	       adap->pci_devname, rte_lcore_id(), csk, tid, csk->state);

	switch (csk->state) {
	case CHTCP_CSK_STATE_CLOSING:
		csk->state = CHTCP_CSK_STATE_MORIBUND;
		break;
	case CHTCP_CSK_STATE_MORIBUND:
		csk->state = CHTCP_CSK_STATE_DEAD;
		chtcp_free_csk(csk);
		break;
	case CHTCP_CSK_STATE_ABORTING:
	case CHTCP_CSK_STATE_DEAD:
		break;
	default:
		SPDK_ERRLOG("%s core[%d]: cpl_close_con_rpl in bad state %d\n",
			adap->pci_devname, rte_lcore_id(), csk->state);
		assert(0);
        }

	return 0;
}

int 
chtcp_send_close_con_req(struct chtcp_sock *csk)
{
	struct rte_mbuf *mbuf;
	struct cpl_close_con_req *req;
	u32 len = RTE_ALIGN(sizeof(struct cpl_close_con_req), 16);

	mbuf = chtcp_alloc_mbuf_res(csk, len);

	req = rte_pktmbuf_mtod(mbuf, struct cpl_close_con_req *);
	memset(req, 0, len);

	INIT_TP_WR(req, csk->tid);
	OPCODE_TID(req) = rte_cpu_to_be_32(MK_OPCODE_TID(CPL_CLOSE_CON_REQ,
                                                    csk->tid));
	req->rsvd = 0;

	return chtcp_queue_tx_mbuf(csk, mbuf);
}

int 
chtcp_handle_peer_close(struct chtcp_uadapter *adap, const void *cpl)
{
	struct cpl_peer_close *pclose = (struct cpl_peer_close *)cpl;
	struct chtcp_sock *csk;
	u32 tid = GET_TID(pclose);
	struct rte_mbuf *mbuf;

	csk = chtcp_lookup_tid(&adap->tids, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
			adap->pci_devname, rte_lcore_id(), tid);
		return -EFAULT;
	}

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: csk %p; tid %u; state %d\n",
	       adap->pci_devname, rte_lcore_id(), csk, tid, csk->state);

	switch (csk->state) {
		case CHTCP_CSK_STATE_ESTABLISHED:
			csk->state = CHTCP_CSK_STATE_CLOSING;
			mbuf = chtcp_alloc_mbuf_res(csk, 0);
			chtcp_set_mbuf_flag(mbuf, CHTCP_MBUF_FLAG_DISCONNECT);
			CHTCP_QUEUE_MBUF(&csk->recvq, mbuf, link);
			break;
		case CHTCP_CSK_STATE_CLOSING:
			csk->state = CHTCP_CSK_STATE_MORIBUND;
			break;
		case CHTCP_CSK_STATE_MORIBUND:
			csk->state = CHTCP_CSK_STATE_DEAD;
			chtcp_free_csk(csk);
			break;
		case CHTCP_CSK_STATE_ABORTING:
			break;
		default:
			SPDK_ERRLOG("%s core[%d]: cpl_peer_close in bad state %d\n",
				adap->pci_devname, rte_lcore_id(), csk->state);
			assert(0);
	}

	return 0;
}

static u32
chtcp_tx_flowc_wr_credits(struct chtcp_sock *csk, u32 *nparamsp,
			  u32 *flowclenp)
{
	u32 nparams, flowclen16, flowclen;

	nparams = FLOWC_WR_NPARAMS_MIN;

	if (csk->snd_wscale)
		nparams++;

	flowclen = offsetof(struct fw_flowc_wr, mnemval[nparams]);
	flowclen16 = SPDK_CEIL_DIV(flowclen, 16);
	flowclen = flowclen16 * 16;
	/*
	 * Return the number of 16-byte credits used by the flowc request.
	 * Pass back the nparams and actual flowc length if requested.
	 */
	if (nparamsp)
		*nparamsp = nparams;
	if (flowclenp)
		*flowclenp = flowclen;
	return flowclen16;
}

struct rte_mbuf * 
chtcp_get_flowc_mbuf(struct chtcp_sock *csk)
{
	struct chtcp_uadapter *adap = csk->adap;
	struct fw_flowc_wr *flowc;
	u32 nparams, fw_wr_credits, flowclen;
	struct rte_mbuf *mbuf;
	u32 index;

	fw_wr_credits = chtcp_tx_flowc_wr_credits(csk, &nparams, &flowclen);

	mbuf = chtcp_alloc_mbuf_res(csk, flowclen);

	flowc = rte_pktmbuf_mtod(mbuf, struct fw_flowc_wr *);
	memset(flowc, 0, flowclen);

	flowc->op_to_nparams = rte_cpu_to_be_32(V_FW_WR_OP(FW_FLOWC_WR) |
					   V_FW_FLOWC_WR_NPARAMS(nparams) |
					   V_FW_WR_COMPL(0));
	flowc->flowid_len16 = rte_cpu_to_be_32(V_FW_WR_LEN16(fw_wr_credits) |
					  V_FW_WR_FLOWID(csk->tid));
	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_PFNVFN;
	flowc->mnemval[0].val = rte_cpu_to_be_32(V_FW_PFVF_CMD_PFN
					    (adap->pf));
	flowc->mnemval[1].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[1].val = rte_cpu_to_be_32(csk->tx_chan);
	flowc->mnemval[2].mnemonic = FW_FLOWC_MNEM_PORT;
	flowc->mnemval[2].val = rte_cpu_to_be_32(csk->tx_chan);
	flowc->mnemval[3].mnemonic = FW_FLOWC_MNEM_IQID;
	flowc->mnemval[3].val = rte_cpu_to_be_32(csk->rss_qid);
	flowc->mnemval[4].mnemonic = FW_FLOWC_MNEM_SNDNXT;
	flowc->mnemval[4].val = rte_cpu_to_be_32(csk->snd_nxt);
	flowc->mnemval[5].mnemonic = FW_FLOWC_MNEM_RCVNXT;
	flowc->mnemval[5].val = rte_cpu_to_be_32(csk->rcv_nxt);
	flowc->mnemval[6].mnemonic = FW_FLOWC_MNEM_SNDBUF;
	flowc->mnemval[6].val = rte_cpu_to_be_32(csk->snd_win);
	flowc->mnemval[7].mnemonic = FW_FLOWC_MNEM_MSS;
	flowc->mnemval[7].val = rte_cpu_to_be_32(csk->emss);
	flowc->mnemval[8].mnemonic = FW_FLOWC_MNEM_TXDATAPLEN_MAX;
	flowc->mnemval[8].val = rte_cpu_to_be_32(65535);

	index = 9;

	if (csk->snd_wscale) {
		flowc->mnemval[index].mnemonic = FW_FLOWC_MNEM_RCV_SCALE;
		flowc->mnemval[index].val = rte_cpu_to_be_32(csk->snd_wscale);
		index++;
	}

	SPDK_DEBUGLOG(chtcp, "%s: csk %p; tx_chan = %u; rss_qid = %u; snd_seq = %u;"
	       " rcv_seq = %u; snd_win = %u; emss = %u\n",
	       __func__, csk, csk->tx_chan, csk->rss_qid, csk->snd_nxt,
	       csk->rcv_nxt, csk->snd_win, csk->emss);

	return mbuf;
}

static void 
chtcp_set_emss(struct chtcp_sock *csk, u16 opt)
{
	struct chtcp_uadapter *adap = csk->adap;

	csk->emss = adap->mtus[G_TCPOPT_MSS(opt)] -
			((csk->remote_addr.ss_family == AF_INET) ?
			 sizeof(struct iphdr) : sizeof(struct ipv6hdr)) -
			sizeof(struct tcphdr);
	csk->mss = csk->emss;
	if (G_TCPOPT_TSTAMP(opt))
		csk->emss -= RTE_ALIGN(TCPOLEN_TIMESTAMP, 4);
	if (csk->emss < 128)
		csk->emss = 128;
	if (csk->emss & 7)
		SPDK_DEBUGLOG(chtcp, "%s core[%d]: misaligned mtu idx %u mss %u emss=%u\n",
			      csk->adap->pci_devname, rte_lcore_id(),
			      G_TCPOPT_MSS(opt), csk->mss, csk->emss);
}

int 
chtcp_handle_pass_establish(struct chtcp_uadapter *adap, const void *cpl)
{
	struct cpl_pass_establish *rpl = (struct cpl_pass_establish *)cpl;
	u32 tid = GET_TID(rpl);
	u32 stid = G_PASS_OPEN_TID(rte_be_to_cpu_32(rpl->tos_stid));
	struct chtcp_sock *csk;
	struct chtcp_listen_sock *lcsk;
	struct spdk_reactor *reactor;
	struct tid_info *t = &adap->tids;
	u16 tcp_opt = rte_be_to_cpu_16(rpl->tcp_opt);
	u32 snd_isn = rte_be_to_cpu_32(rpl->snd_isn);
	u32 rcv_isn = rte_be_to_cpu_32(rpl->rcv_isn);

	csk = chtcp_lookup_tid(t, tid);
	if (unlikely(!csk)) {
		SPDK_ERRLOG("%s core[%d]: can't find connection for tid %u.\n",
			adap->pci_devname, rte_lcore_id(), tid);
		goto rel_skb;
	}

	assert(csk->state == CHTCP_CSK_STATE_CONNECTING);

	reactor = spdk_reactor_get(rte_lcore_id());
	TAILQ_REMOVE(&CHTCP_GET_CH_REACTOR(reactor)->acsk_req_list,
		     csk, acsk_link);

	csk->write_seq = snd_isn;
	csk->snd_una = snd_isn;
	csk->snd_nxt = snd_isn;
	csk->rcv_nxt = rcv_isn;
	csk->snd_wscale = G_TCPOPT_SND_WSCALE(tcp_opt);
	chtcp_set_emss(csk, tcp_opt);
	csk->state = CHTCP_CSK_STATE_ESTABLISHED;

	rte_spinlock_lock(&adap->lcsk_lock);
	lcsk = __chtcp_get_lcsk(adap, stid);
	rte_spinlock_lock(&lcsk->acsk_lock);
	TAILQ_INSERT_TAIL(&lcsk->acsk_list, csk, acsk_link);
	rte_spinlock_unlock(&lcsk->acsk_lock);
	rte_spinlock_unlock(&adap->lcsk_lock);

	SPDK_DEBUGLOG(chtcp, "%s core[%d]: function stid %u tid %u\n", 
		adap->pci_devname, rte_lcore_id(), stid, tid);
	return 0;
rel_skb:
	return -EINVAL;
}

static void 
chtcp_pass_accept_req_cb(void *arg1, void *arg2)
{
	struct chtcp_uadapter *adap = (struct chtcp_uadapter *)arg1;
	struct rte_mbuf *mbuf = (struct rte_mbuf *)arg2;
	struct cpl_pass_accept_req *req =
		rte_pktmbuf_mtod(mbuf, struct cpl_pass_accept_req *);
	u32 stid = G_PASS_OPEN_TID(rte_be_to_cpu_32(req->tos_stid));
	u32 tid = GET_TID(req);
	u16 port_id = G_SYN_INTF(rte_be_to_cpu_16(req->l2info));
	struct spdk_reactor *reactor;
	struct chtcp_sock *csk;
	struct chtcp_conn_info cci;
	struct chtcp_sge_ofld_rxq *rxq;
	int rc = 0;

	if (mbuf->port != port_id) {
		SPDK_ERRLOG("%s core[%d]: Port interface mismatched\n",
			    adap->pci_devname, rte_lcore_id());
		goto out;
	}
	csk = rte_calloc_socket("conn_sock", 1, sizeof(struct chtcp_sock),
				RTE_CACHE_LINE_SIZE, rte_socket_id());
	if (!csk) {
		SPDK_ERRLOG("%s core[%d]: failed to allocate csk\n",
			adap->pci_devname, rte_lcore_id());
		goto out;
	}

	csk->adap = adap;
	csk->pg = CHTCP_MBUF_TO_PRIV(mbuf)->pg;
	csk->group_impl = (struct chtcp_sock_group_impl *)chtcp_get_sock_group(csk->pg);
	reactor = csk->pg->thread->reactor;

	assert(reactor == spdk_reactor_get(rte_lcore_id()));

	csk->tx_mbuf_pool = g_chtcp_root.tx_mbuf_pool[reactor->r_index];
	csk->state = CHTCP_CSK_STATE_CONNECTING;
	csk->port_id = port_id;
	rxq = chtcp_get_rxq(adap, csk->port_id, reactor->r_index);

	TAILQ_INIT(&csk->recvq);
	TAILQ_INIT(&csk->sendq);
	TAILQ_INIT(&csk->res_mbufq);
	TAILQ_INIT(&csk->wr_ack_mbufq);

	if (chtcp_reserve_csk_mbuf(csk)) {
		SPDK_ERRLOG("%s core[%d]: Failed to alloc reserve mbuf\n",
			    adap->pci_devname, rte_lcore_id());
		goto free_csk;
	}

	memset(&cci, 0, sizeof(cci));
	cci.res = rte_calloc(NULL, 1, mbuf->pkt_len, RTE_CACHE_LINE_SIZE);
	if (!cci.res) {
		SPDK_ERRLOG("%s core[%d]: failed to allocate memory cci.res\n",
			adap->pci_devname, rte_lcore_id());
		goto mbuf_purge;
	}

	rte_memcpy(cci.res, req , mbuf->pkt_len);
	cci.u.in.pkt_len = mbuf->pkt_len;
	cci.u.in.rss_qid = rxq->rspq.abs_id;
	cci.u.in.tid	= tid;
	cci.u.in.port_id = port_id;
	rc = ioctl(adap->dev_fd, CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ_CMD, &cci);
	if (rc < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
			    "CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ: %d\n",
			    adap->pci_devname, rte_lcore_id(), rc);
		goto fail;
	}
	csk->stid = stid;
	csk->tid = tid;
	csk->wr_cred = adap->wr_cred -
			SPDK_CEIL_DIV(sizeof(struct cpl_abort_req), 16);
	csk->wr_max_cred = csk->wr_cred;
	csk->wr_una_cred = 0;
	csk->tx_chan = cci.u.out.tx_chan;
	csk->snd_win = cci.u.out.snd_win;
	csk->rcv_win = cci.u.out.rcv_win;
	if (cci.u.out.is_ipv4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&csk->local_addr;

		sin->sin_family = AF_INET;
		sin->sin_port = cci.u.out.local_addr.tcp_port;
		sin->sin_addr.s_addr = *(__be32 *)cci.u.out.local_addr.ip_addr;

		sin = (struct sockaddr_in *)&csk->remote_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = cci.u.out.remote_addr.tcp_port;
		sin->sin_addr.s_addr = *(__be32 *)cci.u.out.remote_addr.ip_addr;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
					     &csk->local_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = cci.u.out.local_addr.tcp_port;
		memcpy(sin6->sin6_addr.s6_addr, cci.u.out.local_addr.ip_addr,
		       sizeof(cci.u.out.local_addr.ip_addr));

		sin6 = (struct sockaddr_in6 *)&csk->remote_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = cci.u.out.remote_addr.tcp_port;
		memcpy(sin6->sin6_addr.s6_addr, cci.u.out.remote_addr.ip_addr,
		       sizeof(cci.u.out.remote_addr.ip_addr));
	}
	csk->rss_qid = rxq->rspq.abs_id;
	csk->txq = chtcp_get_txq(adap, csk->port_id, reactor->r_index);

	chtcp_insert_tid(&adap->tids , csk, tid,
		((struct sockaddr_in *)&csk->local_addr)->sin_family);

	TAILQ_INSERT_TAIL(&(CHTCP_GET_CH_REACTOR(reactor)->acsk_req_list),
			    csk, acsk_link);

	rte_free(cci.res);
	goto mbuf_free;

fail:
	rte_free(cci.res);
mbuf_purge:
	CHTCP_PURGE_MBUF_Q(&csk->res_mbufq, link);
free_csk:
	rte_free(csk);
out:
	if (ioctl(adap->dev_fd, CHTCP_IOCTL_RELEASE_TID_CMD, &tid) < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
			    "CHTCP_IOCTL_RELEASE_TID_CMD\n",
			    adap->pci_devname, rte_lcore_id());
	}
mbuf_free:
	rte_pktmbuf_free(mbuf);

	return;
}

int 
chtcp_handle_pass_accept_req(struct chtcp_sge_ofld_rxq *rxq,
			     struct chtcp_mbuf_q  *mbufq)
{
	struct chtcp_uadapter *adap = rxq->adap;
	struct rte_mbuf *mbuf = CHTCP_MBUF_Q_FIRST(mbufq);
	struct cpl_pass_accept_req *req =
			rte_pktmbuf_mtod(mbuf, struct cpl_pass_accept_req *);

	struct spdk_nvmf_poll_group *pg;
	struct spdk_reactor *reactor;
	u32 stid = G_PASS_OPEN_TID(rte_be_to_cpu_32(req->tos_stid));
	u32 tid = GET_TID(req);
	u32 current_core = spdk_env_get_current_core();
	struct chtcp_listen_sock *lcsk;
	struct chtcp_mbuf_private *priv_data;

	if ((CHTCP_MBUF_TO_PRIV(mbuf)->nmbuf) > 1) {
		SPDK_ERRLOG("%s core[%d]: nmbuf's in "
			"CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ: %d \n",
			adap->pci_devname, rte_lcore_id(), 
			CHTCP_MBUF_TO_PRIV(mbuf)->nmbuf);
		goto out;
	}

	rte_spinlock_lock(&adap->lcsk_lock);
	lcsk = __chtcp_get_lcsk(adap, stid);
	if (lcsk->state == CHTCP_LCSK_STATE_CLOSE_LISTSRV) {
		rte_spinlock_unlock(&adap->lcsk_lock);
		goto out;
	}

	rte_atomic32_inc(&lcsk->conn_count);
	rte_spinlock_unlock(&adap->lcsk_lock);
	pg = spdk_nvmf_get_round_robin_poll_group(g_spdk_nvmf_tgt);
	CHTCP_MBUF_TO_PRIV(mbuf)->pg = pg;
	reactor = pg->thread->reactor;

	/* mbufq is local var in chtcp_process_responses so dont pass mbufq 
	 * in event that will cause out of scope.
	 * pass head of mbufq
	 */
	if (current_core == reactor->lcore)
		chtcp_pass_accept_req_cb(adap, mbuf);
	else
		spdk_event_call(spdk_event_allocate(reactor->lcore,
				chtcp_pass_accept_req_cb, adap, mbuf));

	return 0;
out:
	if (ioctl(adap->dev_fd, CHTCP_IOCTL_RELEASE_TID_CMD, &tid) < 0) {
		SPDK_ERRLOG("%s core[%d]: ioctl failed for "
			    "CHTCP_IOCTL_RELEASE_TID_CMD\n",
			    adap->pci_devname, rte_lcore_id());
	}

	TAILQ_FOREACH(priv_data, mbufq, link) {
		TAILQ_REMOVE(mbufq, priv_data, link);
		mbuf = CHTCP_PRIV_TO_MBUF(priv_data);
		rte_pktmbuf_free(mbuf);
	}
	
	return 0;
}

int
chtcp_listen_sock_close(struct chtcp_listen_sock *lcsk)
{
        SPDK_DEBUGLOG(chtcp, "%s core[%d]: server sock %p state %u stid %u\n",
		      lcsk->adap->pci_devname, rte_lcore_id(), lcsk, lcsk->state,
		      lcsk->stid);

	lcsk->state = CHTCP_LCSK_STATE_CLOSE_LISTSRV;
	lcsk->cleanup_poller = spdk_poller_register(chtcp_cleanup_conn, lcsk, 0);

        return 0;
}

int
chtcp_client_sock_close(struct chtcp_sock *csk)
{
        SPDK_DEBUGLOG(chtcp, "%s core[%d]: state %d\n",
               csk->adap->pci_devname, rte_lcore_id(), csk->state);

        csk->flags |= CHTCP_CSK_FLAG_APP_CLOSE;

        switch (csk->state) {
        case CHTCP_CSK_STATE_ESTABLISHED:
		csk->state = CHTCP_CSK_STATE_CLOSING;
		chtcp_send_close_con_req(csk);
                break;
        case CHTCP_CSK_STATE_CLOSING:
                csk->state = CHTCP_CSK_STATE_MORIBUND;
                chtcp_send_close_con_req(csk);
                break;
	case CHTCP_CSK_STATE_ABORTING:
		break;
        case CHTCP_CSK_STATE_DEAD:
        	chtcp_free_csk(csk);
                break;
        default:
                SPDK_ERRLOG("%s core[%d]: csk %p; state %d\n",
                            csk->adap->pci_devname, rte_lcore_id(),
			    csk, csk->state);
		assert(0);
        }


        return 0;
}
