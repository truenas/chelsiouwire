/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Divy Le Ray (divy@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "defs.h"
#include <linux/toedev.h>
#include <linux/if_vlan.h>

#include "tom.h"
#include "cpl_io_state.h"
#include "t4_msg.h"
#include "cxgb4_ctl_defs.h"
#include "t4fw_interface.h"
#include "t4_ma_failover.h"
#include "t4_tcb.h"

#include <net/bonding.h>

/* Adapted from drivers/net/bonding/bond_3ad.c:__get_bond_by_port() */
static inline struct bonding *toe_bond_get_bond_by_port(struct port *port)
{
	if (port->slave == NULL)
		return NULL;

	return bond_get_bond_by_slave(port->slave);
}

static inline int total_ports(struct toedev *tdev)
{
	struct adap_ports *port_info = TOM_DATA(tdev)->ports;

	return port_info->nports;
}

static inline int lookup_port(struct net_device *slave_dev)
{
	int i, port = -1;
	struct toedev *tdev;
	struct adap_ports *port_info;
	struct net_device *root_dev;

	if (slave_dev->priv_flags & IFF_802_1Q_VLAN) {
		root_dev = vlan_dev_real_dev(slave_dev);
	} else
		root_dev = slave_dev;

	tdev = TOEDEV(root_dev);
	port_info = TOM_DATA(tdev)->ports;

	for (i = 0; i < port_info->nports; i++) {
		if (root_dev != port_info->lldevs[i])
			continue;

		port = i;
		break;
	}
	return port;
}

static inline int lld_evt(int event)
{
	return event + FAILOVER_ACTIVE_SLAVE;
}

int failover_smac_update(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct toedev *tdev = cplios->toedev;
	struct tom_data *d = TOM_DATA(tdev);
	struct adap_ports *port_info = d->ports;
	struct cxgb4_lld_info *lldi = d->lldi;
	struct l2t_entry *e = cplios->l2t_entry;
	unsigned short chan;
	struct port_info *pi;

	if (cplios->tx_c_chan == e->lport)
		return -EINVAL;

	/* Update the SMT table index */
	pi = (struct port_info *)netdev_priv(port_info->lldevs[e->lport]);
	cplios->smac_idx = pi->smt_idx;
	t4_set_tcb_field(sk, W_TCB_SMAC_SEL, V_TCB_SMAC_SEL(M_TCB_SMAC_SEL),
				V_TCB_SMAC_SEL(cplios->smac_idx));

	/* Update TX modulation queue */
	chan = cxgb4_port_chan(tdev->lldev[e->lport]);
	t4_set_tcb_field(sk, W_TCB_T_FLAGS, V_TF_TX_QUEUE(M_TF_TX_QUEUE),
				V_TF_TX_QUEUE(lldi->tx_modq[chan]));
	return 0;
}

/* Assumes initial Flowc WR has already been sent
 * so that SOCK_OFFLOADED and CPLIOS_TX_DATA_SENT
 * flags set
 */
int send_failover_flowc_wr(struct sock *sk)
{
	struct cpl_io_state *cplios = CPL_IO_STATE(sk);
	struct sk_buff *skb;
	struct l2t_entry *e;
	int flowclen16, flowclen;
	int nparams = 1;

	struct flowc_packed {
		struct fw_flowc_wr fc;
		struct fw_flowc_mnemval mnem[1];
		} __packed sflowc;

	struct fw_flowc_wr *flowc = &sflowc.fc;

	e = cplios->l2t_entry;
	if (cplios->tx_c_chan == e->lport)
		return -EINVAL;

	/*
	 * No need to carry out channel change and avoid sending
	 * corresponding flowc-wr when in post ESTABLISHED state.
	 */
	if (sk->sk_state >= TCP_FIN_WAIT1)
		return 0;

	/* Make assumption explicit that initial FlowC WR always
	 * needs to be sent before TX channel update.
	 */
	if (unlikely(!cplios_flag(sk, CPLIOS_TX_DATA_SENT))) {
		netdev_err(cplios->egress_dev, " TX channel update without CPLIOS_TX_DATA_SENT flag set\n");
		WARN_ON_ONCE(1);
	}

	/*
	 * Determine the number of parameters we're going to send and the
	 * consequent size of the Work Request.
	 */
	flowclen = failover_flowc_wr_len;
	flowclen16 = DIV_ROUND_UP(flowclen, 16);
	flowclen = flowclen16 * 16;

	memset(flowc, 0, flowclen);

	cplios->tx_c_chan = e->lport;

	/*
	 * Initialize the FlowC Work Request.
	 */
	flowc->op_to_nparams =
		htonl(V_FW_WR_OP(FW_FLOWC_WR) | V_FW_WR_COMPL(1) |
		      V_FW_FLOWC_WR_NPARAMS(nparams));
	flowc->flowid_len16 =
		htonl(V_FW_WR_LEN16(flowclen16) |
		      V_FW_WR_FLOWID(cplios->tid));

	flowc->mnemval[0].mnemonic = FW_FLOWC_MNEM_CH;
	flowc->mnemval[0].val = htonl(cplios->tx_c_chan);

	if (!cxgb4_immdata_send(cplios->egress_dev, cplios->txq_idx,
				flowc, flowclen))
		goto setflags;

	skb = alloc_ctrl_skb(cplios->txdata_skb_cache, flowclen);
	if (!skb)
		return -ENOMEM;

	memcpy(__skb_put(skb, flowclen), flowc, flowclen);
	set_queue(skb, (cplios->txq_idx << 1) | CPL_PRIORITY_DATA, sk);
	cxgb4_ofld_send(cplios->egress_dev, skb);

setflags:
	cplios->wr_nondata += flowclen16;
	cplios_set_flag(cplios, CPLIOS_TX_WAIT_IDLE);
	cplios_set_flag(cplios, CPLIOS_TX_FAILOVER);
	return 0;
}

static int t4_switch_channel_idr(int id, void *p, void *data)
{
	struct sock *sk = p;
	struct tcp_sock *tp;
	struct cpl_io_state *cplios;

	if (!sk)
		return 0;

	sock_hold(sk);
	bh_lock_sock(sk);
	cplios = CPL_IO_STATE(sk);
	tp = tcp_sk(sk);

	if (cplios_flag(sk, CPLIOS_ABORT_REQ_RCVD) ||
		cplios_flag(sk, CPLIOS_ABORT_RPL_PENDING) ||
		cplios_flag(sk, CPLIOS_TX_FAILOVER))
			goto unlock;

	if (!cplios_flag(sk, CPLIOS_TX_DATA_SENT)) {
		int flowclen16;

		/* do not send first FlowC if sk_state != TCP_ESTABLISHED */
		if (sk->sk_state != TCP_ESTABLISHED)
			goto unlock;

		flowclen16 = send_tx_flowc_wr(sk, 1, tp->snd_nxt,
						  tp->rcv_nxt);
		if (flowclen16 < 0)
			BUG_ON(1);
		cplios->wr_credits -= flowclen16;
		cplios->wr_unacked += flowclen16;
		cplios->wr_nondata += flowclen16;
		cplios_set_flag(cplios, CPLIOS_TX_DATA_SENT);
	}
	if (!failover_smac_update(sk)) {
		cplios_set_flag(cplios, CPLIOS_TX_FAILOVER);

		if (send_failover_flowc_wr(sk) < 0)
			goto unlock;
	}
unlock:
	bh_unlock_sock(sk);
	sock_put(sk);

	return 0;
}

void t4_switch_channel(struct toedev *tdev)
{
	struct tom_data *td = TOM_DATA(tdev);

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	spin_lock(&td->idr_lock);
	idr_for_each(&td->hwtid_idr, t4_switch_channel_idr, NULL);
	spin_unlock(&td->idr_lock);
#else
	unsigned long index;
	struct sock *sk;

	xa_for_each(&td->hwtid_idr, index, sk) {
		t4_switch_channel_idr(index, sk, NULL);
	}
#endif
}

extern void t4_rst_all_active_opens(struct tom_data *td, struct net_device *netdev, int context);
extern void act_open_req_arp_failure(struct tom_data *td, struct sk_buff *skb);
extern unsigned int t4_rst_all_conn(struct toedev *tdev, struct net_device *egress_dev,
				    bool release_ofld_res);

/* Called under bonding locks (bond_mii_monitor) */
void t4_failover(struct toedev *tdev, struct net_device *bond_dev,
		 struct net_device *slave_dev, int event, struct net_device *last_dev)
{
	struct bond_ports bond_ports;
	struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
	struct slave *slave = NULL;
	int port_idx,  idx = 0;
	struct list_head *bond_list_iter __attribute__((unused));
	struct port *port;

	local_bh_disable();
	bond_ports.slave_dev = slave_dev;

	if (last_dev && last_dev->priv_flags & IFF_802_1Q_VLAN)
		last_dev =  vlan_dev_real_dev(last_dev);
	if (slave_dev && slave_dev->priv_flags & IFF_802_1Q_VLAN)
		slave_dev =  vlan_dev_real_dev(slave_dev);

	if (lld_evt(event) == FAILOVER_BOND_DOWN || lld_evt(event) == FAILOVER_BOND_UP) {

		bond_for_each_slave(bond, slave, bond_list_iter) {
			bond_ports.port = lookup_port(slave->dev);
			tdev->ctl(tdev, lld_evt(event), &bond_ports);
		}
		local_bh_enable();
		return;
	}

	if (!slave_dev) { /* bond release all */
		local_bh_enable();
		return;
	}

	/*
 	 * If last slave is getting removed, terminate all active open
 	 * connections running over bond interface
 	 */
	if (event == TOE_RELEASE && bond->slave_cnt == 1) {
		t4_rst_all_conn(tdev, slave_dev, false);
		local_bh_enable();
		return;
	}

	switch (bond->params.mode) {
	case BOND_MODE_ACTIVEBACKUP:

		port_idx = lookup_port(slave_dev);
		bond_ports.port = port_idx;
		bond_ports.nports = 0;

		bond_for_each_slave(bond, slave, bond_list_iter) {
			if (slave->dev != slave_dev) {
				bond_ports.ports[idx++] =
					lookup_port(slave->dev);
				bond_ports.nports++;
			}
		}


		if (last_dev) {
			if (TOEDEV (last_dev) != TOEDEV (slave_dev)) {
				t4_toe_ma_failover (slave_dev, last_dev,
						    lld_evt(event), &bond_ports);
				break;
			}
		}

		/* Change channel only when new active slave is selected */
		if (event == TOE_ACTIVE_SLAVE) {
			tdev->ctl (tdev, lld_evt (event), &bond_ports);
			t4_switch_channel(tdev);
		}
		break;

	case BOND_MODE_8023AD:
		if (event == TOE_ACTIVE_SLAVE) {
			local_bh_enable();
			return;
		}

                port_idx = lookup_port(slave_dev);
                bond_ports.port = port_idx;
                bond_ports.nports = 0;

		bond_for_each_slave(bond, slave, bond_list_iter) {
			port = &(SLAVE_AD_INFO_COMPAT(slave))->port;
			if (port->slave->dev != slave_dev &&
				bond_is_active_slave(port->slave)) {
				bond_ports.ports[idx++] =
					lookup_port(port->slave->dev);
				bond_ports.nports++;
			}
		}
		tdev->ctl(tdev, lld_evt(event), &bond_ports);
		t4_switch_channel(tdev);
		break;
	case BOND_MODE_ROUNDROBIN:
	case BOND_MODE_XOR:
		port_idx = lookup_port(slave_dev);
    		bond_ports.port = port_idx;
    		bond_ports.nports = 0;
    
    		bond_for_each_slave(bond, slave, bond_list_iter) {
    			if (slave->dev != slave_dev){
    				bond_ports.ports[idx++] =
    					lookup_port(slave->dev);
    				bond_ports.nports++;
    			}
    		}
    		tdev->ctl(tdev, lld_evt(event), &bond_ports);
		t4_switch_channel(tdev);
    		break;
	}
	local_bh_enable();
	return;
}

void t4_update_master_devs(struct toedev *tdev)
{
	int i;

	rcu_read_lock();
	for (i = 0; i < tdev->nlldev; i++) {
		struct net_device *dev = tdev->lldev[i];

		if (dev->flags & IFF_SLAVE) {
			struct net_device *bond_dev = netdev_master_upper_dev_get_rcu(dev);
			struct bonding *bond = (struct bonding *)netdev_priv(bond_dev);
			struct toedev *slave_tdev = NULL;
			struct slave *slave;
			int ofld_cnt = 0;
			struct list_head *bond_list_iter __attribute__((unused));

			if (netdev_is_offload(bond_dev))
				continue;

			bond_for_each_slave_rcu(bond, slave, bond_list_iter) {
				ofld_cnt += !!netdev_is_offload(slave->dev);

				if (!slave_tdev)
					slave_tdev = TOEDEV(slave->dev);
				else if (slave_tdev != TOEDEV(slave->dev)) {
					slave_tdev = NULL;
					break;
				}
			}

			if (ofld_cnt == bond->slave_cnt && slave_tdev)
				netdev_set_offload(bond_dev);
		}
	}
	rcu_read_unlock();
}
