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
#include <linux/net.h>
#include <linux/inet.h>
#include <net/tcp.h>
#include "common.h"
#include "cxgb4_ofld.h"
#include "chtcp_kmain.h"
#include "chtcp_ioctl.h"
#include "chtcp_kcm.h"
#include "t4_msg.h"
#include "clip_tbl.h"

static int chtcp_release_tid(struct chtcp_kadapter *dev, u32 tid);

static int chtcp_inaddr_any(struct sockaddr_storage *sockaddr)
{
	u16 ss_family = sockaddr->ss_family;
	int ret = -1;

	if (ss_family == AF_INET) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)sockaddr;
		ret = (sin->sin_addr.s_addr == cpu_to_be32(INADDR_ANY)) ? 1 : 0;
	}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6;
		int addr_type;

		sin6 = (struct sockaddr_in6 *)sockaddr;
		addr_type = ipv6_addr_type((const struct in6_addr *)
				&sin6->sin6_addr);
		ret = (addr_type == IPV6_ADDR_ANY) ? 1 : 0;
	}
#endif

	return ret;
}

static struct net_device *chtcp_get_real_dev(struct net_device *ndev)
{
	if (ndev->priv_flags & IFF_BONDING) {
		pr_err("Bond devices are not supported. Interface:%s\n",
			ndev->name);
		return NULL;
	}

	if (is_vlan_dev(ndev))
		return vlan_dev_real_dev(ndev);

	return ndev;
}

static struct net_device *chtcp_ipv4_netdev(__be32 saddr)
{
	struct net_device *ndev;

	ndev = __ip_dev_find(&init_net, saddr, false);
	if (!ndev)
		return NULL;

	return chtcp_get_real_dev(ndev);
}

static struct net_device *chtcp_ipv6_netdev(struct in6_addr *addr6)
{
	struct net_device *ndev = NULL;
	bool found = false;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	for_each_netdev_rcu(&init_net, ndev) {
		if (ipv6_chk_addr(&init_net, addr6, ndev, 1)) {
			found = true;
			break;
		}
	}
#endif

	if (!found)
		return NULL;

	return chtcp_get_real_dev(ndev);
}

static struct net_device *
chtcp_find_np_device(struct chtcp_kadapter *dev,
		     struct sockaddr_storage *sockaddr, u16 ss_family)
{
	struct net_device *ndev = NULL;

	if (ss_family == AF_INET) {
		struct sockaddr_in *sin;

		sin = (struct sockaddr_in *)sockaddr;
		ndev = 	chtcp_ipv4_netdev(sin->sin_addr.s_addr);

	} else if (ss_family == AF_INET6){
		struct sockaddr_in6 *sin6;

		sin6 = (struct sockaddr_in6 *)sockaddr;
		ndev = chtcp_ipv6_netdev(&sin6->sin6_addr);
	}

	return ndev;
}

static int chtcp_find_device(struct chtcp_kadapter *dev,
			     struct net_device *ndev, u8 *port_id)
{
	u8 i;
	struct cxgb4_lld_info *lldi = &dev->lldi;

	for (i = 0; i < lldi->nports ; i++) {
		if (lldi->ports[i] == ndev) {
			if (port_id)
				*port_id = i;
			return i;
		}
	}

	return -1;
}

static int chtcp_create_server4(struct chtcp_kadapter *dev,
		struct net_device *ndev, int stid,
		struct sockaddr_storage *sockaddr, u16 rss_iq)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)sockaddr;
	struct port_info *p_info;
	int ret = 0;

	p_info = netdev_priv(ndev);
	ret = __cxgb4_create_server(ndev, stid, sin->sin_addr.s_addr,
				    sin->sin_port, 0, rss_iq,
				    &p_info->tx_chan);
	if (!ret) {
		pr_info("created server4: stid %d laddr %pI4 lport %d\n",
			stid, &sin->sin_addr, cpu_to_be16(sin->sin_port));
	}
	if (ret) {
		pr_err("create server failed err %d stid %d laddr %pI4 lport %d\n",
			ret, stid, &sin->sin_addr, cpu_to_be16(sin->sin_port));
		ret = -ENOMEM;
	}
	return ret;
}

static int chtcp_create_server6(struct chtcp_kadapter *dev,
		struct net_device *ndev, int stid,
		struct sockaddr_storage *sockaddr, u16 rss_iq)
{
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sockaddr;
	struct port_info *p_info;
	int ret;

	pr_debug("%s: dev = %s; stid = %d; sin6_port = %u\n",
		__func__, ndev->name, stid, sin6->sin6_port);

	p_info = netdev_priv(ndev);
	ret = __cxgb4_create_server6(ndev, stid, &sin6->sin6_addr,
				     sin6->sin6_port, rss_iq,
				     &p_info->tx_chan);
	if (!ret) {
		pr_info("created server6: stid %d laddr %pI6 lport %d\n",
			stid, sin6->sin6_addr.s6_addr,
			cpu_to_be16(sin6->sin6_port));
	}
	if (ret) {
		pr_err("create server6 err %d stid %d laddr %pI6 lport %d\n",
			ret, stid, sin6->sin6_addr.s6_addr,
			cpu_to_be16(sin6->sin6_port));
		ret = -ENOMEM;
	}

	return 0;
}

static int
chtcp_setup_cdev_np(struct chtcp_kadapter *dev,
		    struct sockaddr_storage *sockaddr,
		    struct chtcp_create_server_info *serv_info)
{
	struct net_device *ndev = NULL;
	int stid, port;
	u16 ss_family = sockaddr->ss_family;
	int ret = 0;
	u16 rss_iq;

	ndev = chtcp_find_np_device(dev, sockaddr, ss_family);
	if (!ndev) {
		pr_err("%s: unable to get network device\n",
			pci_name(dev->lldi.pdev));
		return -ENODEV;
	}
	port = chtcp_find_device(dev, ndev, NULL);
	if (port < 0) {
		pr_err("%s: failed to match network device\n",
			pci_name(dev->lldi.pdev));
		return -ENXIO;
	}

	rss_iq = serv_info->u.in.rss_iq[port];

	stid = cxgb4_alloc_stid(dev->lldi.tids, ss_family, dev);
	if (stid < 0) {
		pr_err("failed to allocate stid\n");
		return -ENOMEM;
	}
	if (ss_family == AF_INET)
		ret = chtcp_create_server4(dev, ndev, stid, sockaddr, rss_iq);
	else
		ret = chtcp_create_server6(dev, ndev, stid, sockaddr, rss_iq);

	if (ret < 0) {
		cxgb4_free_stid(dev->lldi.tids, stid, ss_family);
		goto out;
	}

	serv_info->u.out.port_id = port;
	serv_info->u.out.stid = stid;
	serv_info->u.out.ss_family = ss_family;
out:
	return ret;
}

int chtcp_handle_pass_open_req(struct chtcp_kadapter *dev,
			       void __user *useraddr)
{
	struct chtcp_create_server_info s_info;
	struct chtcp_klisten_sock *lcsk;
	struct sockaddr_storage addr;
	int rc = 0;

	rc = copy_from_user(&s_info, useraddr, sizeof(s_info));
	if (rc)
		return -EFAULT;

	lcsk = kzalloc(sizeof(struct chtcp_klisten_sock), GFP_KERNEL);
	if (!lcsk) {
		pr_err("%s: failed to allocated memory for lcsk\n", __func__);
		return -ENOMEM;
	}

	memset(&addr, 0, sizeof(addr));
	if (s_info.u.in.is_ipv4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
		sin->sin_family = AF_INET;
		sin->sin_port = cpu_to_be16(s_info.u.in.addr.tcp_port);
		sin->sin_addr.s_addr = *(__be32 *)s_info.u.in.addr.ip_addr;
	}else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = cpu_to_be16(s_info.u.in.addr.tcp_port);
		memcpy(sin6->sin6_addr.s6_addr, s_info.u.in.addr.ip_addr,
		       sizeof(s_info.u.in.addr.ip_addr));
	}

	rc = chtcp_inaddr_any(&addr);
	if (rc)
		return -ENOTSUPP; /* IPV6 kernel config disabled */

	rc = chtcp_setup_cdev_np(dev, &addr, &s_info);
	if (rc < 0) {
		pr_err("%s: failed to create server\n", pci_name(dev->lldi.pdev));
		return rc;
	}

	pr_info("%s: server created successfully, stid: %u, port iface: %u\n",
		 pci_name(dev->lldi.pdev), s_info.u.out.stid, s_info.u.out.port_id);

	if (copy_to_user(useraddr, &s_info, sizeof(s_info))) {
		rc = -EFAULT;
		goto out;
	}

	lcsk->port_id = s_info.u.out.port_id;
	lcsk->stid = s_info.u.out.stid;
	lcsk->ss_family = s_info.u.out.ss_family;

	INIT_LIST_HEAD(&lcsk->acsk_list);
	mutex_init(&lcsk->acsk_lock);

	mutex_lock(&dev->lcsk_lock);
	list_add_tail(&lcsk->lcsk_link, &dev->lcsk_list);
	mutex_unlock(&dev->lcsk_lock);
	return 0;

out:
	return rc;
}

static struct chtcp_klisten_sock *
chtcp_get_klisten_sock(struct chtcp_kadapter *dev, u32 stid)
{
	struct chtcp_klisten_sock *lcsk, *tmp;

	list_for_each_entry_safe(lcsk, tmp, &dev->lcsk_list, lcsk_link) {
		if (lcsk->stid == stid) {
			return lcsk;
		}
	}

	return NULL;
}

int chtcp_remove_server(struct chtcp_kadapter *dev,
			struct chtcp_klisten_sock *lcsk, u16 rss_qid)
{
	u32 stid = lcsk->stid;
 	u32 port_id = lcsk->port_id;
	u16 ss_family = lcsk->ss_family;
 	struct net_device *ndev = dev->lldi.ports[port_id];
 	int ret = 0;

	if (!ndev) {
		pr_err("Invalid net device\n");
		return -ENODEV;
	}

	ret = cxgb4_remove_server(ndev, stid, rss_qid, ss_family == PF_INET6);
	if (!ret) {
		pr_info("%s: server removed successfully stid: %u\n",
			pci_name(dev->lldi.pdev), stid);
	} else if (ret) {
		pr_err("%s: failed to destory server tid: %u\n",
			pci_name(dev->lldi.pdev), stid);
		ret = -ENOMEM;
	}
	return ret;
}

int chtcp_handle_close_listsrv_req(struct chtcp_kadapter *dev,
				   void __user *useraddr)
{
	struct chtcp_free_server_info s_info;
	struct chtcp_klisten_sock *lcsk;
	int rc = 0;

	rc = copy_from_user(&s_info, useraddr, sizeof(s_info));
	if (rc)
		return -EFAULT;

	mutex_lock(&dev->lcsk_lock);
	lcsk = chtcp_get_klisten_sock(dev, s_info.stid); 
	if (!lcsk) {
		pr_err("Error: No listen sock found with stid %u\n",
		       s_info.stid);
		mutex_unlock(&dev->lcsk_lock);
		return -EFAULT;
	}

	rc = chtcp_remove_server(dev, lcsk, s_info.rss_qid);
	mutex_unlock(&dev->lcsk_lock);

	return rc;
}

static void
chtcp_get_tuple_info(struct cpl_pass_accept_req *req,
		     enum chip_type adapter_type, u32 *iptype,
		     __u8 *local_ip, __u8 *peer_ip,
		     __be16 *local_port, __be16 *peer_port)
{
	u32 eth_len = is_t5(adapter_type) ?
			G_ETH_HDR_LEN(be32_to_cpu(req->hdr_len)) :
			G_T6_ETH_HDR_LEN(be32_to_cpu(req->hdr_len));
	u32 ip_len = is_t5(adapter_type) ?
			G_IP_HDR_LEN(be32_to_cpu(req->hdr_len)) :
			G_T6_IP_HDR_LEN(be32_to_cpu(req->hdr_len));
	struct iphdr *ip = (struct iphdr *)((u8 *)(req + 1) + eth_len);
	struct ipv6hdr *ip6 = (struct ipv6hdr *)((u8 *)(req + 1) + eth_len);
	struct tcphdr *tcp = (struct tcphdr *)
                               ((u8 *)(req + 1) + eth_len + ip_len);
	if (ip->version == 4) {
		pr_debug("%s saddr 0x%x daddr 0x%x sport %u dport %u\n",
			 __func__, be32_to_cpu(ip->saddr), be32_to_cpu(ip->daddr),
			 be16_to_cpu(tcp->source), be16_to_cpu(tcp->dest));

		*iptype = 4;
		memcpy(peer_ip, &ip->saddr, 4);
		memcpy(local_ip, &ip->daddr, 4);
	} else {
		pr_debug("%s saddr %pI6 daddr %pI6 sport %u dport %u\n",
			  __func__, ip6->saddr.s6_addr, ip6->daddr.s6_addr,
			  be16_to_cpu(tcp->source), be16_to_cpu(tcp->dest));
		*iptype = 6;
		memcpy(peer_ip, ip6->saddr.s6_addr, 16);
		memcpy(local_ip, ip6->daddr.s6_addr, 16);
	}
	*peer_port = tcp->source;
	*local_port = tcp->dest;
}

static int
chtcp_our_interface(struct chtcp_kadapter *dev, struct net_device *egress_dev)
{
	u8 i;
	egress_dev = chtcp_get_real_dev(egress_dev);
	for (i = 0; i < dev->lldi.nports; i++)
		if (dev->lldi.ports[i] == egress_dev)
			return 1;
	return 0;
}

static struct dst_entry *
chtcp_find_route(struct chtcp_kadapter *dev, __be32 local_ip,
		 __be32 peer_ip, __be16 local_port,
		 __be16 peer_port, u8 tos, struct net_device *ndev)
{
	struct rtable *rt;
	struct flowi4 fl4;
	struct neighbour *n;

	rt = ip_route_output_ports(&init_net, &fl4, NULL, peer_ip,
				   local_ip, peer_port, local_port,
				   IPPROTO_TCP, tos, ndev->ifindex);
	if (IS_ERR(rt))
		return NULL;
	n = dst_neigh_lookup(&rt->dst, &peer_ip);
	if(!n)
		return NULL;
	if ((ndev != n->dev) ||
	    (!chtcp_our_interface(dev, n->dev) &&
	     !(n->dev->flags & IFF_LOOPBACK))) {
		neigh_release(n);
		dst_release(&rt->dst);
		return NULL;
	}
	neigh_release(n);
	return &rt->dst;
}

static struct dst_entry *
chtcp_find_route6(struct chtcp_kadapter *dev, __u8 *local_ip, __u8 *peer_ip,
		  __be16 local_port, __be16 peer_port, u8 tos,
		  struct net_device *ndev)
{
	struct dst_entry *dst = NULL;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (IS_ENABLED(CONFIG_IPV6)) {
		struct flowi6 fl6;

		memset(&fl6, 0, sizeof(fl6));
		memcpy(&fl6.daddr, peer_ip, 16);
		memcpy(&fl6.saddr, local_ip, 16);
		fl6.flowi6_oif = ndev->ifindex;
		dst = ip6_route_output(&init_net, NULL, &fl6);
		if (dst->error ||
		    (ndev != ip6_dst_idev(dst)->dev) ||
		    (!chtcp_our_interface(dev, ip6_dst_idev(dst)->dev) &&
		     !(ip6_dst_idev(dst)->dev->flags & IFF_LOOPBACK))) {
			dst_release(dst);
			return NULL;
		}
	}
#endif
	return dst;
}

static unsigned int chtcp_snd_win = 128 * 1024;
module_param(chtcp_snd_win, uint, S_IRUGO);
MODULE_PARM_DESC(chtcp_snd_win, "TCP send window in bytes (default = 128KB)");

static unsigned int chtcp_rcv_win = 128 * 1024;
module_param(chtcp_rcv_win, uint, S_IRUGO);
MODULE_PARM_DESC(chtcp_rcv_win, "TCP receive window in bytes (default = 128KB)");

static void
chtcp_set_tcp_window(struct chtcp_sock_info *csk_info)
{

	csk_info->snd_win = min(chtcp_snd_win, 512U * 1024);
	csk_info->rcv_win = min3(chtcp_rcv_win, M_RCV_BUFSIZ << 10,
				 512U * 1024);

	pr_debug("%s snd_win %d rcv_win %d\n",
		 __func__, csk_info->snd_win, csk_info->rcv_win);
}

static int
chtcp_offload_init(struct chtcp_sock_info *csk_info, int iptype, __u8 *peer_ip,
		    u16 local_port, struct dst_entry *dst,
		    struct chtcp_kadapter *cdev)
{
	struct neighbour *n;
	struct net_device *ndev;
	u16 port_id;
	struct port_info *pi;
	int ret;

	n = dst_neigh_lookup(dst, peer_ip);
	if (!n)
		return -ENODEV;
	rcu_read_lock();
	if (!(n->nud_state & NUD_VALID))
		neigh_event_send(n, NULL);

	ret = -ENOMEM;
	ndev = chtcp_get_real_dev(n->dev);
	if (!ndev) {
		ret = -ENODEV;
		goto out;
	}
	csk_info->l2t = cxgb4_l2t_get(cdev->lldi.l2t, n, ndev, 0);
	if (!csk_info->l2t)
		goto out;
	port_id = cxgb4_port_idx(ndev);
	csk_info->mtu = dst_mtu(dst);
	csk_info->tx_chan = cxgb4_port_chan(ndev);
	csk_info->rx_chan = cxgb4_port_e2cchan(ndev);
	pi = (struct port_info *)netdev_priv(ndev);
	csk_info->smac_idx = pi->smt_idx;
	csk_info->ctrlq_idx = cxgb4_port_idx(ndev);
	csk_info->port_id = port_id;
	chtcp_set_tcp_window(csk_info);
	ret = 0;
out:
	rcu_read_unlock();
	neigh_release(n);
	return ret;
}

static void
chtcp_best_mtu(struct chtcp_sock_info *csk_info, unsigned int *idx, int use_ts)
{
	const struct chtcp_kadapter *cdev = csk_info->com.dev;
	const struct cxgb4_lld_info *lldi = &cdev->lldi;
	const unsigned short *mtus = csk_info->com.dev->lldi.mtus;
	bool ipv6 = csk_info->com.remote_addr.ss_family == AF_INET;
	unsigned short hdr_size = (ipv6 ? sizeof(struct ipv6hdr) :
				sizeof(struct iphdr)) +
				sizeof(struct tcphdr) +
				(use_ts ? round_up(TCPOLEN_TIMESTAMP, 4) : 0);
	unsigned short data_size = csk_info->mtu - hdr_size;
	unsigned short data_align_size = 8;
	if (CHELSIO_CHIP_VERSION(lldi->adapter_type) > CHELSIO_T5)
		data_align_size = 1;
	cxgb4_best_aligned_mtu(mtus, hdr_size, data_size, data_align_size, idx);
}

static u32 chtcp_compute_wscale(u32 win)
{
	u32 wscale = 0;

	while (wscale < 14 && (65535 << wscale) < win)
		wscale++;

	return wscale;
}

static void chtcp_pass_accept_rpl_arp_failure(void *handle, struct sk_buff *skb)
{
	struct chtcp_ksock *csk = (struct chtcp_ksock *)handle;

	pr_err("debug: %s: WARN: arp failed tid %u\n", __func__, csk->tid);
	atomic_set(&csk->arp_failed, 1);
}

static int
chtcp_pass_accept_rpl(struct chtcp_sock_info *csk_info,
		      struct cpl_pass_accept_req *req)
{
	struct sk_buff *skb;
	const struct tcphdr *tcph;
	struct cxgb4_lld_info *lldi = &csk_info->com.dev->lldi;
	struct cpl_t5_pass_accept_rpl *rpl5;
	u32 len = roundup(sizeof(*rpl5), 16);
	u32 mtu_idx;
	u64 opt0;
	u32 opt2, hlen;
	u32 wscale;
	u32 win;
	int ret = 0;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb) {
		pr_err("failed to allocate skb\n");
		return -ENOMEM;
	}
	rpl5 = (struct cpl_t5_pass_accept_rpl *)__skb_put(skb, len);
	memset(rpl5, 0, len);

	INIT_TP_WR(rpl5, csk_info->tid);
	OPCODE_TID(rpl5) = cpu_to_be32(MK_OPCODE_TID(CPL_PASS_ACCEPT_RPL,
				       csk_info->tid));
	chtcp_best_mtu(csk_info, &mtu_idx, req->tcpopt.tstamp);
	wscale = chtcp_compute_wscale(csk_info->rcv_win);
	win = csk_info->rcv_win >> 10;
	if (win > M_RCV_BUFSIZ)
		win = M_RCV_BUFSIZ;
	opt0 =  F_TCAM_BYPASS |
		V_WND_SCALE(wscale) |
		V_MSS_IDX(mtu_idx) |
		V_L2T_IDX(csk_info->l2t->idx) |
		V_TX_CHAN(csk_info->tx_chan) |
		V_SMAC_SEL(csk_info->smac_idx) |
		V_DSCP(csk_info->tos >> 2) |
		V_ULP_MODE(ULP_MODE_TCPDDP) |
		V_RCV_BUFSIZ(win);

	opt2 = V_RX_CHANNEL(csk_info->rx_chan) |
		F_RSS_QUEUE_VALID | V_RSS_QUEUE(csk_info->rss_qid);

	opt2 |= F_RX_FC_DISABLE;

	if (req->tcpopt.tstamp)
		opt2 |= F_TSTAMPS_EN;

	if (req->tcpopt.sack)
		opt2 |= F_SACK_EN;

	if (wscale)
		opt2 |= F_WND_SCALE_EN;

	hlen = be32_to_cpu(req->hdr_len);

	if (is_t5(lldi->adapter_type))
		tcph = (const void *)(req + 1) + G_ETH_HDR_LEN(hlen) +
			G_IP_HDR_LEN(hlen);
	else
		tcph = (const void *)(req + 1) + G_T6_ETH_HDR_LEN(hlen) +
			G_T6_IP_HDR_LEN(hlen);
	if (tcph->ece && tcph->cwr)
		opt2 |= V_CCTRL_ECN(1);

	opt2 |= V_CONG_CNTRL(CONG_ALG_NEWRENO);
	opt2 |= F_T5_ISS;
	rpl5->iss = cpu_to_be32((prandom_u32() & ~7UL) - 1);
	opt2 |= F_T5_OPT_2_VALID;
	rpl5->opt0 = cpu_to_be64(opt0);
	rpl5->opt2 = cpu_to_be32(opt2);
	set_wr_txq(skb, CPL_PRIORITY_SETUP, csk_info->ctrlq_idx);
	t4_set_arp_err_handler(skb, csk_info, chtcp_pass_accept_rpl_arp_failure);
	ret = cxgb4_l2t_send(csk_info->com.dev->lldi.ports[0], skb,
			     csk_info->l2t);
	if (net_xmit_eval(ret) != NET_XMIT_SUCCESS) {
		kfree_skb(skb) ;
		ret = -EINVAL;
	}
	return ret;
}

struct net_device *
chtcp_get_ipv4_netdev(__be32 saddr)
{
	struct net_device *ndev = NULL;
	ndev = __ip_dev_find(&init_net, saddr, false);

	return ndev;
}

struct net_device *
chtcp_get_ipv6_netdev(struct in6_addr *addr6)
{
	struct net_device *ndev = NULL;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	for_each_netdev_rcu(&init_net, ndev) {
		if (ipv6_chk_addr(&init_net, addr6, ndev, 1))
			break;
	}
#endif

	return ndev;
}

static struct net_device *
chtcp_find_ndev(struct chtcp_kadapter *dev, u8 *saddr, u16 ss_family,
		u16 port_id)
{
	struct net_device *ndev = NULL;

	if (ss_family == AF_INET)
		ndev = chtcp_get_ipv4_netdev(*(__be32 *)saddr);
	else {
		struct sockaddr_in6 sin6;

		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		memcpy(&sin6.sin6_addr.s6_addr, saddr, 16);
		ndev = chtcp_get_ipv6_netdev(&sin6.sin6_addr);
	}

	if (!ndev) {
		pr_err("failed to find the network device\n");
		return NULL;
	}

	if (ndev->priv_flags & IFF_BONDING) {
		pr_err("Bond devices are not supported. Interface:%s\n",
			ndev->name);
		return NULL;
	}

	if (is_vlan_dev(ndev)) {
		struct net_device *real = vlan_dev_real_dev(ndev);

		if (real == dev->lldi.ports[port_id])
			return ndev;
	} else {
		if (ndev == dev->lldi.ports[port_id])
			return ndev;
	}

	return NULL;
}

static int
chtcp_pass_accept_req(struct chtcp_kadapter *dev,
		      struct chtcp_conn_info *conn_info)
{
	struct chtcp_klisten_sock *lcsk;
	struct cpl_pass_accept_req *req;
	struct tid_info *t = dev->lldi.tids;
	struct chtcp_ksock *csk;
	struct net_device *ndev;
	struct chtcp_sock_info csk_info;
	void *mbuf;
	u32 stid, tid;
	u16 peer_mss;
	struct dst_entry *dst;
	__u8 local_ip[16], peer_ip[16];
	__be16 local_port, peer_port;
	u16 hdrs;
	u32 iptype;
	int rc = 0;

	mbuf = kzalloc(conn_info->u.in.pkt_len, GFP_KERNEL);
	if (!mbuf) {
		pr_err("Memory allocation failed\n");
		rc = -ENOMEM;
		goto reject;
	}
	rc = copy_from_user(mbuf, conn_info->res, conn_info->u.in.pkt_len);
	if (rc) {
		pr_err("Failed to copy user data\n");
		rc = -EFAULT;
		goto out;
	}

	req = (struct cpl_pass_accept_req *)mbuf;
	stid = G_PASS_OPEN_TID(be32_to_cpu(req->tos_stid));
	tid = GET_TID(req);
	peer_mss = be16_to_cpu(req->tcpopt.mss);

	
	chtcp_get_tuple_info(req, dev->lldi.adapter_type, &iptype,
			     local_ip, peer_ip, &local_port, &peer_port);
	if (iptype == 4)  {
		pr_info("%s: tid %u laddr %pI4 raddr %pI4 "
			"lport %d rport %d peer_mss %u\n",
			pci_name(dev->lldi.pdev), tid, local_ip,
			peer_ip, be16_to_cpu(local_port),
			be16_to_cpu(peer_port), peer_mss);
		ndev = chtcp_find_ndev(dev, local_ip, AF_INET,
					     conn_info->u.in.port_id);
		if (!ndev) {
			pr_err("%s: failed to find ndev for ip %pI4\n",
				pci_name(dev->lldi.pdev), local_ip);
			goto out;
		}

		dst = chtcp_find_route(dev, *(__be32 *)local_ip,
				*(__be32 *)peer_ip,
				local_port, peer_port,
				G_PASS_OPEN_TOS(be32_to_cpu(req->tos_stid)),
				ndev);
	} else {
		pr_info("%s: tid %u laddr %pI6 raddr %pI6 "
			"lport %d rport %d peer_mss %u\n",
			pci_name(dev->lldi.pdev), tid, local_ip, peer_ip,
			be16_to_cpu(local_port),
			be16_to_cpu(peer_port), peer_mss);
		ndev = chtcp_find_ndev(dev, local_ip, AF_INET6,
				       conn_info->u.in.port_id);
		if (!ndev) {
			pr_err("%s: failed to find ndev for ip %pI4\n",
				pci_name(dev->lldi.pdev), local_ip);
			goto out;
		}

		dst = chtcp_find_route6(dev, local_ip, peer_ip,
					local_port, peer_port,
					G_PASS_OPEN_TOS(be32_to_cpu(req->tos_stid)),
					ndev);
	}
	if (!dst) {
		pr_err("%s - failed to find dst entry!\n",
			__func__);
		rc = -EHOSTUNREACH;
		goto out;
	}
	csk = kzalloc(sizeof(struct chtcp_ksock), GFP_KERNEL);
	if (!csk) {
		dst_release(dst);
		rc = -ENOMEM;
		goto out;
	}

	rc = chtcp_offload_init(&csk_info, iptype, peer_ip,
				be16_to_cpu(local_port), dst, dev);
	if (rc) {
		pr_err("%s - failed to allocate l2t entry!\n",
			__func__);
		dst_release(dst);
		kfree(csk);
		goto out;
	}
	hdrs = (iptype == 4 ? sizeof(struct iphdr) : sizeof(struct ipv6hdr)) +
		sizeof(struct tcphdr) + (req->tcpopt.tstamp ? 12 : 0);

	if (peer_mss && (csk_info.mtu > (peer_mss + hdrs)))
		csk_info.mtu = peer_mss + hdrs;
	atomic_set(&csk->arp_failed, 0);
	csk_info.com.dev = dev;
	csk_info.tos = G_PASS_OPEN_TOS(be32_to_cpu(req->tos_stid));
	csk_info.dst = dst;
	csk_info.tid = tid;
	csk_info.wr_cred = dev->lldi.wr_cred -
			    DIV_ROUND_UP(sizeof(struct cpl_abort_req), 16);
	csk_info.wr_max_cred = csk_info.wr_cred;
	csk_info.wr_una_cred = 0;
	csk_info.rss_qid = conn_info->u.in.rss_qid;
	if (iptype == 4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&csk_info.com.local_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = local_port;
		sin->sin_addr.s_addr = *(__be32 *)local_ip;
		sin = (struct sockaddr_in *)&csk_info.com.remote_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = peer_port;
		sin->sin_addr.s_addr = *(__be32 *)peer_ip;

		conn_info->u.out.is_ipv4 = 1;
		conn_info->u.out.local_addr.tcp_port = local_port;
		memcpy(conn_info->u.out.local_addr.ip_addr, local_ip,
		       sizeof(conn_info->u.out.local_addr.ip_addr));
		conn_info->u.out.remote_addr.tcp_port = peer_port;
		memcpy(conn_info->u.out.remote_addr.ip_addr, peer_ip,
		       sizeof(conn_info->u.out.remote_addr.ip_addr));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
					    &csk_info.com.local_addr;
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port = local_port;
		memcpy(sin6->sin6_addr.s6_addr, local_ip, 16);
		cxgb4_clip_get(dev->lldi.ports[0],
				(const u32 *)&sin6->sin6_addr.s6_addr,
				1);
		sin6 = (struct sockaddr_in6 *)&csk_info.com.remote_addr;
		sin6->sin6_family = PF_INET6;
		sin6->sin6_port = peer_port;
		memcpy(sin6->sin6_addr.s6_addr, peer_ip, 16);

		conn_info->u.out.is_ipv4 = 0;
		conn_info->u.out.local_addr.tcp_port = local_port;
		memcpy(conn_info->u.out.local_addr.ip_addr, local_ip,
		       sizeof(conn_info->u.out.local_addr.ip_addr));
		conn_info->u.out.remote_addr.tcp_port = peer_port;
		memcpy(conn_info->u.out.remote_addr.ip_addr, peer_ip,
		       sizeof(conn_info->u.out.remote_addr.ip_addr));
	}

	csk->dev = csk_info.com.dev;
	csk->local_addr = csk_info.com.local_addr;
	csk->l2t = csk_info.l2t;
	csk->dst = csk_info.dst;
	csk->tid = csk_info.tid;
	if (iptype == 4)
		cxgb4_insert_tid(t, csk, tid,
				((struct sockaddr_in*)&csk->local_addr)->sin_family);
	else
		cxgb4_insert_tid(t, csk, tid,
				((struct sockaddr_in6 *)&csk->local_addr)->sin6_family);

	rc = chtcp_pass_accept_rpl(&csk_info, req);
	if (rc < 0) {
		chtcp_free_kcsk(dev, tid);
		kfree(mbuf);
		return rc;
	}
	conn_info->u.out.tx_chan = csk_info.tx_chan;
	conn_info->u.out.snd_win = csk_info.snd_win;
	conn_info->u.out.rcv_win = csk_info.rcv_win;
	mutex_lock(&dev->lcsk_lock);
	lcsk = chtcp_get_klisten_sock(dev, stid); 
	if (!lcsk) {
		pr_err("Error: No listen sock found with stid %u\n", stid);
		mutex_unlock(&dev->lcsk_lock);
		goto out;
	}

	mutex_lock(&lcsk->acsk_lock);
	list_add_tail(&csk->acsk_link, &lcsk->acsk_list);
	mutex_unlock(&lcsk->acsk_lock);
	mutex_unlock(&dev->lcsk_lock);
	kfree(mbuf);

	return rc;
out:
	kfree(mbuf);
reject:
	chtcp_release_tid(dev, conn_info->u.in.tid);
	return rc;
}

int chtcp_handle_pass_accept_req(struct chtcp_kadapter *dev,
				 void __user *useraddr)
{
	struct chtcp_conn_info conn_info;
	int rc = 0;

	rc = copy_from_user(&conn_info, useraddr, sizeof(conn_info));
	if (rc)
		return -EFAULT;

	rc = chtcp_pass_accept_req(dev, &conn_info);
	if (rc < 0)
		return rc;

	if (copy_to_user(useraddr, &conn_info, sizeof(conn_info)))
		return -EFAULT;

	return rc;
}

int chtcp_handle_close_listsrv_rpl(struct chtcp_kadapter *dev, u32 stid)
{
	struct chtcp_klisten_sock *lcsk;
	int rc = 0;
	u16 ss_family;

	mutex_lock(&dev->lcsk_lock);
	lcsk = chtcp_get_klisten_sock(dev, stid); 
	if (!lcsk) {
		pr_err("Error: No listen sock found with stid %u\n", stid);
		mutex_unlock(&dev->lcsk_lock);
		return -EFAULT;
	}
	ss_family = lcsk->ss_family;
	list_del(&lcsk->lcsk_link);
	kfree(lcsk);
	mutex_unlock(&dev->lcsk_lock);

	cxgb4_free_stid(dev->lldi.tids, stid, ss_family);
	return rc;
}

void chtcp_free_kcsk(struct chtcp_kadapter *dev, u32 tid)
{
	struct chtcp_ksock *csk;

	csk = lookup_tid(dev->lldi.tids, tid);
	if (unlikely(!csk)) {
		pr_err("%s: can't find connection for tid %u.\n",
			pci_name(dev->lldi.pdev), tid);
		return;
	}

	if (csk->tid != tid) {
		pr_err("%s: WARNING: %s: csk->tid %u != tid %u\n",
			pci_name(dev->lldi.pdev), __func__, csk->tid, tid);
		return;
	}

	if (csk->local_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)
			&csk->local_addr;
		cxgb4_clip_release(dev->lldi.ports[0],
				(const u32 *)
				&sin6->sin6_addr.s6_addr, 1);
	}

	cxgb4_remove_tid(dev->lldi.tids, 0, tid,
			 csk->local_addr.ss_family);

	dst_release(csk->dst);
	cxgb4_l2t_release(csk->l2t);
	list_del(&csk->acsk_link);

	kfree(csk);
}

int chtcp_handle_free_sock(struct chtcp_kadapter *dev, void __user *useraddr)
{
	int rc = 0;
	u32 tid;

	rc = copy_from_user(&tid, useraddr, sizeof(u32));
	if(rc)
		return -EFAULT;
	chtcp_free_kcsk(dev, tid);

	return rc;
}

static int chtcp_release_tid(struct chtcp_kadapter *dev, u32 tid)
{
	struct cpl_tid_release *req;
	u32 len = roundup(sizeof(*req), 16);
	struct sk_buff *skb;
	int ret = 0;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	req = (struct cpl_tid_release *)__skb_put(skb, len);
	memset(req, 0, len);
	INIT_TP_WR(req, tid);
	OPCODE_TID(req) = cpu_to_be32(MK_OPCODE_TID(
			CPL_TID_RELEASE, tid));

	set_wr_txq(skb, CPL_PRIORITY_SETUP, 0);
	ret = cxgb4_ofld_send(dev->lldi.ports[0], skb);
	if (ret < 0)
		kfree_skb(skb);

	return ret < 0 ? ret : 0;
}

int chtcp_handle_release_tid(struct chtcp_kadapter *dev, void __user *useraddr)
{
	int rc = 0;
	u32 tid;

	rc = copy_from_user(&tid, useraddr, sizeof(tid));
	if (rc)
		return -EFAULT;
	rc = chtcp_release_tid(dev, tid);
	return rc;
}

static bool check_arp_failure(struct chtcp_kadapter *dev, u32 tid)
{
	struct chtcp_ksock *csk;

	csk = lookup_tid(dev->lldi.tids, tid);
	if (unlikely(!csk)) {
		pr_err("%s: WARNING: can't find connection for tid %u.\n",
			pci_name(dev->lldi.pdev), tid);
		WARN_ON(1);
		return false;
	}

	if (csk->tid != tid) {
		pr_err("%s: WARNING: %s: csk->tid %u != tid %u\n",
			pci_name(dev->lldi.pdev), __func__, csk->tid, tid);
		WARN_ON(1);
		return false;
	}

	if (atomic_read(&csk->arp_failed))
		return true;

	return false;
}

int chtcp_handle_arp_failure(struct chtcp_kadapter *dev, void __user *useraddr)
{
	struct chtcp_arp_info arp_info;
	int rc = 0;

	rc = copy_from_user(&arp_info, useraddr, sizeof(struct chtcp_arp_info));
	if(rc)
		return -EFAULT;
	arp_info.u.arp_failed = check_arp_failure(dev, arp_info.u.tid);
	if (copy_to_user(useraddr, &arp_info, sizeof(struct chtcp_arp_info)))
		return -EFAULT;

	return rc;
}
