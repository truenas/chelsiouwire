/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#include "common.h"
#include "t4_regs.h"
#include "t4_tcb.h"
#include "l2t.h"
#include "t4fw_interface.h"
#include "smt.h"
#include "clip_tbl.h"
#include "cxgb4_filter.h"
#include "t4_linux_fs.h"

extern unsigned int use_ddr_filters;
/*-------------------------- Forward declarations ---------------------------*/
static inline int ehash_filter_locks_alloc(struct filter_hashinfo *hashinfo);
static int validate_filter(struct net_device *dev,
			   struct ch_filter_specification *fs);
static void mk_act_open_req6(struct filter_entry *f, struct sk_buff *skb,
			     unsigned int qid_filterid, struct adapter *adap);
static void mk_act_open_req(struct filter_entry *f, struct sk_buff *skb,
			    unsigned int qid_filterid, struct adapter *adap);
static inline void mk_set_tcb_field_ulp(struct filter_entry *f,
					struct cpl_set_tcb_field *req,
					unsigned int word,
					u64 mask, u64 val, u8 cookie,
					int no_reply);
static void set_tcb_tflag(struct adapter *adap , struct filter_entry *f,
		   unsigned int ftid, unsigned int bit_pos,
		   unsigned int val, int no_reply);
static u64 hash_filter_ntuple(struct ch_filter_specification *fs,
			      struct net_device *dev);
static unsigned int get_filter_steerq(struct net_device *dev,
				      struct ch_filter_specification *fs);
static int del_filter_wr(struct adapter *adapter, int fidx, gfp_t gfp_mask);
static int cxgb4_del_hash_filter(struct net_device *dev, int filter_id,
			  struct filter_ctx *ctx, gfp_t flags);
static void set_tcb_field(struct adapter *adap, struct filter_entry *f,
		   unsigned int ftid,  u16 word, u64 mask, u64 val,
		   int no_reply);

static inline int ehash_filter_locks_alloc(struct filter_hashinfo *hashinfo)
{
	unsigned int i, size = 256;
#if defined(CONFIG_PROVE_LOCKING)
	unsigned int nr_pcpus = 2;
#else
	unsigned int nr_pcpus = num_possible_cpus();
#endif
	if (nr_pcpus >= 4)
		size = 512;
	if (nr_pcpus >= 8)
		size = 1024;
	if (nr_pcpus >= 16)
		size = 2048;
	if (nr_pcpus >= 32)
		size = 4096;
	if (sizeof(spinlock_t) != 0) {
#ifdef CONFIG_NUMA
		if (size * sizeof(spinlock_t) > PAGE_SIZE)
			hashinfo->ehash_filter_locks =
				vmalloc(size * sizeof(spinlock_t));
		else
#endif
		hashinfo->ehash_filter_locks =
				kmalloc(size * sizeof(spinlock_t),
			GFP_KERNEL);
		if (!hashinfo->ehash_filter_locks)
			return -ENOMEM;
		for (i = 0; i < size; i++)
			spin_lock_init(&hashinfo->ehash_filter_locks[i]);
	}
	hashinfo->ehash_filter_locks_mask = size - 1;
	return 0;
}

static int cxgb4_set_hash_filter(struct net_device *dev, int filter_id,
			  struct ch_filter_specification *fs,
			  struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	struct port_info *pi = netdev_priv(dev);
	struct tid_info *t = &adapter->tids;
	const struct hlist_nulls_node *node;
	struct filter_ehash_bucket *head;
	struct filter_entry *f = NULL;
	struct sk_buff *skb;
	unsigned int hash;
	unsigned int slot;
	unsigned int iq;
	int atid, size;
	int ret = 0;
	u32 iconf;

	ret = validate_filter(dev, fs);
	if (ret)
		return ret;
	iq = get_filter_steerq(dev, fs);
	if (iq < 0)
		return iq;

	/* lookup for an existing entry if its a T6 */
	if (is_t6(adapter->params.chip)) {
		if (fs->type) {
			const struct in6_addr *laddr = (struct in6_addr *)fs->val.lip;
			const struct in6_addr *faddr = (struct in6_addr *)fs->val.fip;
			u32 lhash, fhash;
			u32 ports = (((u32)fs->val.lport) << 16) |
				    (__force u32)fs->val.fport;

			lhash = (__force u32)laddr->s6_addr32[3];
			fhash = __ipv6_addr_jhash(faddr, 0);
			hash = jhash_3words(lhash, fhash, ports,
					    hash_filter_ntuple(fs, dev) &
					    0xFFFFFFFF);
		} else {
			u32 lip = fs->val.lip[0] |
				fs->val.lip[1]<<8 |
				fs->val.lip[2]<<16 |
				fs->val.lip[3]<<24;
			u32 fip = fs->val.fip[0] |
				fs->val.fip[1]<<8 |
				fs->val.fip[2]<<16 |
				fs->val.fip[3]<<24;

			hash = jhash_3words((__force __u32)lip,
					   (__force __u32)fip,
					   ((__u32) fs->val.lport) << 16 |
					   (__force __u32)fs->val.fport,
					   hash_filter_ntuple(fs, dev) &
					   0xFFFFFFFF);
		}

		if (fs->val.proto == IPPROTO_UDP) {
			slot = hash & adapter->filter_udphash.ehash_mask;
			head = &adapter->filter_udphash.ehash[slot];
		} else {
			slot = hash & adapter->filter_tcphash.ehash_mask;
			head = &adapter->filter_tcphash.ehash[slot];
		}

		rcu_read_lock();
begin:
		hlist_nulls_for_each_entry_rcu(f, node, &head->chain, filter_nulls_node) {
			u8 lip = memcmp(f->fs.val.lip, fs->val.lip,
					sizeof(fs->val.lip));
			u8 fip = memcmp(f->fs.val.fip, fs->val.fip,
					sizeof(fs->val.fip));

			if ((f->filter_hash == hash) &&
			    (f->fs.val.lport == fs->val.lport) &&
			    (f->fs.val.fport == fs->val.fport) &&
			    !lip && !fip) {
				rcu_read_unlock();
				return -EEXIST;
			}
		}
		/*
		 * if the nulls value we got at the end of this lookup is
		 * not the expected one, we must restart lookup.
		 * We probably met an item that was moved to another chain.
		 */
		if (get_nulls_value(node) != slot)
			goto begin;

		rcu_read_unlock();
	}

	f = kzalloc(sizeof(*f), flags);
	if (f == NULL)
		goto out_err;


	f->fs = *fs;
	f->ctx = ctx;
	f->dev = dev;
	f->fs.iq = iq;

	/*
	 * If the new filter requires loopback Destination MAC and/or VLAN
	 * rewriting then we need to allocate a Layer 2 Table (L2T) entry for
	 * the filter.
	 */
	if (f->fs.newdmac || ((f->fs.newvlan == VLAN_INSERT) ||
	    (f->fs.newvlan == VLAN_REWRITE))) {
		/* allocate L2T entry for new filter */
		f->l2t = t4_l2t_alloc_switching(adapter, f->fs.vlan,
						f->fs.eport, f->fs.dmac);
		if (f->l2t == NULL) {
			ret = -ENOMEM;
			goto out_err;
		}
	}

	/*
	 * If the new filter requires loopback Source MAC rewriting then
	 * we need to allocate a SMT entry for the filter.
	 */
	if (f->fs.newsmac) {
		f->smt = cxgb4_smt_alloc_switching(f->dev, f->fs.smac);
		if (!f->smt) {
			ret = -EAGAIN;
			goto free_l2t;
		}
		f->smtidx = f->smt->hw_idx;
	}

	atid = cxgb4_alloc_atid(t, f);
	if (atid < 0)
		goto free_smt;

	iconf = adapter->params.tp.ingress_config;
	if (iconf & F_VNIC) {
		f->fs.val.ovlan = (fs->val.pf << 13) | fs->val.vf;
		f->fs.mask.ovlan = (fs->mask.pf << 13) | fs->mask.vf;
		f->fs.val.ovlan_vld = fs->val.pfvf_vld;
		f->fs.mask.ovlan_vld = fs->mask.pfvf_vld;
	} else if (iconf & F_USE_ENC_IDX) {
		if (f->fs.val.encap_vld) {
			struct port_info *pi = netdev_priv(f->dev);
			/* allocate MPS TCAM entry */
			ret = cxgb_alloc_encap_mac_filt(adapter, pi->viid,
						      f->fs.val.encap_inner_mac,
						      f->fs.mask.encap_inner_mac,
						      f->fs.val.vni, f->fs.mask.vni,
						      0, f->fs.val.encap_lookup, 1);
			if (ret < 0)
				goto free_atid;

			f->fs.val.ovlan = ret;
			f->fs.mask.ovlan = 0xffff;
			f->fs.val.ovlan_vld = 1;
			f->fs.mask.ovlan_vld = 1;
		}
	}

	if (f->fs.type) {
		/* Issue a cxgb4_clip_get() only if we have non-zero IPv6
		 * address
		 */
		if (ipv6_addr_type((const struct in6_addr *)fs->val.lip) !=
		    IPV6_ADDR_ANY) {
			struct ch_filter_specification *fs = &f->fs;

			ret = cxgb4_clip_get_filter(f->dev,
						    (const u32 *)&fs->val.lip,
						    (const u32 *)&fs->mask.lip,
						    1);
			if (ret)
				goto free_mps;
		}

		if (is_t5(adapter->params.chip))
			size = sizeof(struct cpl_t5_act_open_req6);
		else
			size = sizeof(struct cpl_t6_act_open_req6);
		skb = alloc_skb(size, flags);
		if (!skb) {
			ret = -ENOMEM;
			goto free_clip;
		}

		mk_act_open_req6(f, skb,
				 ((adapter->sge.fw_evtq.abs_id<<14)|atid),
				 adapter);
	} else {
		if (is_t5(adapter->params.chip))
			size = sizeof(struct cpl_t5_act_open_req);
		else
			size = sizeof(struct cpl_t6_act_open_req);
		skb = alloc_skb(size, flags);
		if (!skb) {
			ret = -ENOMEM;
			goto free_mps;
		}

		mk_act_open_req(f, skb,
				((adapter->sge.fw_evtq.abs_id<<14)|atid),
				adapter);
	}

	f->pending = 1;
	set_wr_txq(skb, CPL_PRIORITY_SETUP, f->fs.val.iport & 0x3);
	t4_ofld_send(adapter, skb);
	return 0;

free_clip:
	if (ipv6_addr_type((const struct in6_addr *)fs->val.lip) !=
	    IPV6_ADDR_ANY)
		cxgb4_clip_release_filter(f->dev, (const u32 *)&f->fs.val.lip,
					  (const u32 *)&f->fs.mask.lip, 1);

free_mps:
	if (f->fs.val.encap_vld && f->fs.val.ovlan_vld)
		cxgb_free_encap_mac_filt(adapter, pi->viid,
					 f->fs.val.ovlan & 0x1ff, 1);

free_atid:
	cxgb4_free_atid(t, atid);

free_smt:
	if (f->smt) {
		cxgb4_smt_release(f->smt);
		f->smt = NULL;
	}

free_l2t:
	if (f->l2t) {
		cxgb4_l2t_release(f->l2t);
		f->l2t = NULL;
	}

out_err:
	kfree(f);
	return ret;
}

static int validate_filter(struct net_device *dev,
			   struct ch_filter_specification *fs)
{
	struct adapter *adapter = netdev2adap(dev);
	u32 fconf, f_mask, iconf;

	/*
	 * Check for unconfigured fields being used.
	 */
	fconf = adapter->params.tp.vlan_pri_map;
	f_mask = adapter->params.tp.filter_mask;
	iconf = adapter->params.tp.ingress_config;

	#define S(_field) \
		(fs->val._field || fs->mask._field)

	/* if cap is maskless then validate filter_mask else filter_mode */
	#define U(_mask, _field) \
		(!((fs->cap ? f_mask : fconf) & (_mask)) && S(_field))

	if (U(F_FCOE, fcoe) || U(F_PORT, iport) || U(F_TOS, tos) ||
	    U(F_ETHERTYPE, ethtype) || U(F_MACMATCH, macidx) ||
	    U(F_MPSHITTYPE, matchtype) || U(F_FRAGMENTATION, frag) ||
	    U(F_PROTOCOL, proto) ||
	    U(F_VNIC_ID, pfvf_vld) ||
	    U(F_VNIC_ID, ovlan_vld) ||
	    U(F_VNIC_ID, encap_vld) ||
	    U(F_VLAN, ivlan_vld))
		return -EOPNOTSUPP;

	/*
	 * T4 inconveniently uses the same W_FT_VNIC_ID bits for both the Outer
	 * VLAN Tag and PF/VF/VFvld fields based on F_VNIC being set
	 * in TP_INGRESS_CONFIG.  Hense the somewhat crazy checks
	 * below.  Additionally, since the T4 firmware interface also
	 * carries that overlap, we need to translate any PF/VF
	 * specification into that internal format below.
	 */
	if ((S(pfvf_vld) && S(ovlan_vld)) ||
	    (S(pfvf_vld) && S(encap_vld)) ||
	    (S(ovlan_vld) && S(encap_vld)))
		return -EOPNOTSUPP;
	if ((S(pfvf_vld) && !(iconf & F_VNIC)) ||
	    (S(ovlan_vld) && (iconf & F_VNIC)))
		return -EOPNOTSUPP;
	if (fs->val.pf > 0x7 || fs->val.vf > 0x7f)
		return -ERANGE;
	fs->mask.pf &= 0x7;
	fs->mask.vf &= 0x7f;

	#undef S
	#undef U

	/*
	 * If the user is requesting that the filter action loop
	 * matching packets back out one of our ports, make sure that
	 * the egress port is in range.
	 */
	if (fs->action == FILTER_SWITCH &&
	    fs->eport >= adapter->params.nports) {
	    	/* in t6, loopback channel is supported, which starts from 4
 		 * (NUM_UP_TSCH_CHANNEL_INSTANCES), in that case egress
	    	 * port can be 0-1 or 4-5.
	    	 */
		if(CHELSIO_CHIP_VERSION(adapter->params.chip) > CHELSIO_T5) {
			if ((fs->eport >= adapter->params.nports &&
			     fs->eport < NUM_UP_TSCH_CHANNEL_INSTANCES) ||
			    (fs->eport >= (adapter->params.nports + 
			    		   NUM_UP_TSCH_CHANNEL_INSTANCES)))
				return -ERANGE;
		} else {
			return -ERANGE;
		}
	}


	/*
	 * Don't allow various trivially obvious bogus out-of-range
	 * values ...
	 */
	if (fs->val.iport >= adapter->params.nports)
		return -ERANGE;

	/*
	 * T4 doesn't support removing VLAN Tags for loop back
	 * filters. Also, swapmac and NAT are not supported on T4.
	 */
	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    (fs->newvlan == VLAN_REMOVE ||
	     fs->newvlan == VLAN_REWRITE))
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->swapmac)
		return -EOPNOTSUPP;

	if (is_t4(adapter->params.chip) &&
	    fs->action == FILTER_SWITCH &&
	    fs->nat_mode)
		return -EOPNOTSUPP;

	if (fs->val.encap_vld &&
	    CHELSIO_CHIP_VERSION(adapter->params.chip) < CHELSIO_T6)
		return -EOPNOTSUPP;

	if (fs->drop_encap_hdr &&
	    CHELSIO_CHIP_VERSION(adapter->params.chip) < CHELSIO_T6)
		return -EOPNOTSUPP;

	return 0;
}

static void mk_act_open_req6(struct filter_entry *f, struct sk_buff *skb,
			     unsigned int qid_filterid, struct adapter *adap)
{
	struct cpl_act_open_req6 *req = NULL;
	struct cpl_t5_act_open_req6 *t5req = NULL;
	struct cpl_t6_act_open_req6 *t6req = NULL;

	switch (CHELSIO_CHIP_VERSION(adap->params.chip)) {
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req6 *)__skb_put(skb,
								sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		req = (struct cpl_act_open_req6 *)t5req;
		break;
	case CHELSIO_T6:
		t6req = (struct cpl_t6_act_open_req6 *)__skb_put(skb,
								sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req6 *)t6req;
		t5req = (struct cpl_t5_act_open_req6 *)t6req;
		break;
	default:
		pr_err("%s: unsupported chip type!\n", __func__);
		return;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ6, qid_filterid));
	req->local_port = cpu_to_be16(f->fs.val.lport);
	req->peer_port = cpu_to_be16(f->fs.val.fport);
	req->local_ip_hi = *(__be64 *)(&f->fs.val.lip);
	req->local_ip_lo = *(((__be64 *)&f->fs.val.lip) + 1);
	req->peer_ip_hi = *(__be64 *)(&f->fs.val.fip);
	req->peer_ip_lo = *(((__be64 *)&f->fs.val.fip) + 1);
	req->opt0 = cpu_to_be64(V_NAGLE(f->fs.newvlan == VLAN_REMOVE ||
					f->fs.newvlan == VLAN_REWRITE) |
				V_DELACK(f->fs.hitcnts) |
				V_KEEP_ALIVE(f->fs.drop_encap_hdr) |
				V_L2T_IDX(f->l2t ? f->l2t->idx : 0) |
				V_SMAC_SEL((cxgb4_port_viid(f->dev) &
					0x7F) << 1) |
				V_TX_CHAN(f->fs.eport & 
					(NUM_UP_TSCH_CHANNEL_INSTANCES - 1)) |
				V_NO_CONG(f->fs.rpttid) |
				V_ULP_MODE(f->fs.nat_mode ?
					   ULP_MODE_TCPDDP : ULP_MODE_NONE) |
				F_TCAM_BYPASS |
				F_NON_OFFLOAD);

	if (is_t5(adap->params.chip)) {
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(hash_filter_ntuple(&f->fs, f->dev)));
		t5req->opt2 = htonl(F_RSS_QUEUE_VALID |
				    V_RSS_QUEUE(f->fs.iq) |
				    V_TX_QUEUE(f->fs.nat_mode) |
				    V_WND_SCALE_EN(f->fs.nat_flag_chk) |
				    V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) |
				    F_T5_OPT_2_VALID |
				    V_RX_CHANNEL(cxgb4_port_e2cchan(f->dev)) |
				    V_SACK_EN(f->fs.swapmac) |
				    V_PACE((f->fs.maskhash) |
					    ((f->fs.dirsteerhash) << 1)));
	} else {
		t6req->params = cpu_to_be64(V_FILTER_TUPLE(hash_filter_ntuple(&f->fs, f->dev)));
		t6req->opt2 = htonl(F_RSS_QUEUE_VALID |
				    V_RSS_QUEUE(f->fs.iq) |
				    V_TX_QUEUE(f->fs.nat_mode) |
				    V_WND_SCALE_EN(f->fs.nat_flag_chk) |
				    V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) |
				    F_T5_OPT_2_VALID |
				    V_RX_CHANNEL(cxgb4_port_e2cchan(f->dev)) |
				    V_SACK_EN(f->fs.swapmac) |
				    V_PACE((f->fs.maskhash) |
					    ((f->fs.dirsteerhash) << 1)));
	}
}

static void mk_act_open_req(struct filter_entry *f, struct sk_buff *skb,
			    unsigned int qid_filterid, struct adapter *adap)
{
	struct cpl_act_open_req *req = NULL;
	struct cpl_t5_act_open_req *t5req = NULL;
	struct cpl_t6_act_open_req *t6req = NULL;

	switch (CHELSIO_CHIP_VERSION(adap->params.chip)) {
	case CHELSIO_T5:
		t5req = (struct cpl_t5_act_open_req *)__skb_put(skb,
								sizeof(*t5req));
		INIT_TP_WR(t5req, 0);
		req = (struct cpl_act_open_req *)t5req;
		break;
	case CHELSIO_T6:
		t6req = (struct cpl_t6_act_open_req *)__skb_put(skb,
								sizeof(*t6req));
		INIT_TP_WR(t6req, 0);
		req = (struct cpl_act_open_req *)t6req;
		t5req = (struct cpl_t5_act_open_req *)t6req;
		break;
	default:
		pr_err("%s: unsupported chip type!\n", __func__);
		return;
	}

	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_ACT_OPEN_REQ, qid_filterid));
	req->local_port = cpu_to_be16(f->fs.val.lport);
	req->peer_port = cpu_to_be16(f->fs.val.fport);
	req->local_ip = f->fs.val.lip[0] | f->fs.val.lip[1]<<8 |
			f->fs.val.lip[2]<<16 | f->fs.val.lip[3]<<24;
	req->peer_ip = f->fs.val.fip[0] | f->fs.val.fip[1]<<8 |
			f->fs.val.fip[2]<<16 | f->fs.val.fip[3]<<24;
	req->opt0 = cpu_to_be64(V_NAGLE(f->fs.newvlan == VLAN_REMOVE ||
					f->fs.newvlan == VLAN_REWRITE) |
				V_DELACK(f->fs.hitcnts) |
				V_KEEP_ALIVE(f->fs.drop_encap_hdr) |
				V_L2T_IDX(f->l2t ? f->l2t->idx : 0) |
				V_SMAC_SEL((cxgb4_port_viid(f->dev) &
					0x7F) << 1) |
				V_TX_CHAN(f->fs.eport & 
					(NUM_UP_TSCH_CHANNEL_INSTANCES - 1)) |
				V_NO_CONG(f->fs.rpttid) |
				V_ULP_MODE(f->fs.nat_mode ?
					   ULP_MODE_TCPDDP : ULP_MODE_NONE) |
				F_TCAM_BYPASS | F_NON_OFFLOAD);

	if (is_t5(adap->params.chip)) {
		t5req->params = cpu_to_be64(V_FILTER_TUPLE(hash_filter_ntuple(&f->fs, f->dev)));
		t5req->opt2 = htonl(F_RSS_QUEUE_VALID |
				    V_RSS_QUEUE(f->fs.iq) |
				    V_TX_QUEUE(f->fs.nat_mode) |
				    V_WND_SCALE_EN(f->fs.nat_flag_chk) |
				    V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) |
				    F_T5_OPT_2_VALID |
				    V_RX_CHANNEL(cxgb4_port_e2cchan(f->dev)) |
				    V_SACK_EN(f->fs.swapmac) |
				    V_PACE((f->fs.maskhash) |
					    ((f->fs.dirsteerhash) << 1)));
	} else {
		t6req->params = cpu_to_be64(V_FILTER_TUPLE(hash_filter_ntuple(&f->fs, f->dev)));
		t6req->opt2 = htonl(F_RSS_QUEUE_VALID |
				    V_RSS_QUEUE(f->fs.iq) |
				    V_TX_QUEUE(f->fs.nat_mode) |
				    V_WND_SCALE_EN(f->fs.nat_flag_chk) |
				    V_RX_FC_DISABLE(f->fs.nat_seq_chk ? 1 : 0) |
				    F_T5_OPT_2_VALID |
				    V_RX_CHANNEL(cxgb4_port_e2cchan(f->dev)) |
				    V_SACK_EN(f->fs.swapmac) |
				    V_PACE((f->fs.maskhash) |
					    ((f->fs.dirsteerhash) << 1)));

	}
}

/*
 * Build a CPL_SET_TCB_FIELD message as payload of a ULP_TX_PKT command.
 */
static inline void mk_set_tcb_field_ulp(struct filter_entry *f,
					struct cpl_set_tcb_field *req,
					unsigned int word,
					u64 mask, u64 val, u8 cookie,
					int no_reply)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*req), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*req) - sizeof(struct work_request_hdr));
	OPCODE_TID(req) = htonl(MK_OPCODE_TID(CPL_SET_TCB_FIELD, f->tid));
	req->reply_ctrl = htons(V_NO_REPLY(no_reply) | V_REPLY_CHAN(0) |
				V_QUEUENO(0));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(cookie));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);
	sc = (struct ulptx_idata *)(req + 1);
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_NOOP));
	sc->len = htonl(0);
}

/*
 * Set one of the t_flags bits in the TCB.
 */
static void set_tcb_tflag(struct adapter *adap , struct filter_entry *f,
		   unsigned int ftid, unsigned int bit_pos,
		   unsigned int val, int no_reply)
{
	set_tcb_field(adap, f, ftid,  W_TCB_T_FLAGS, 1ULL << bit_pos,
		      (unsigned long long)val << bit_pos, no_reply);
}

static u64 hash_filter_ntuple(struct ch_filter_specification *fs,
			      struct net_device *dev)
{
	struct adapter *adap = netdev2adap(dev);
	struct tp_params *tp = &adap->params.tp;
	u64 ntuple = 0;

	/*
	 * Initialize each of the fields which we care about which are present
	 * in the Compressed Filter Tuple.
	 */
	if (tp->vlan_shift >= 0 && fs->mask.ivlan)
		ntuple |= (F_FT_VLAN_VLD | fs->val.ivlan) << tp->vlan_shift;

	if (tp->port_shift >= 0 && fs->mask.iport)
		ntuple |= (u64)fs->val.iport << tp->port_shift;

	if (tp->protocol_shift >= 0) {
		if (!fs->val.proto)
			ntuple |= (u64)IPPROTO_TCP << tp->protocol_shift;
		else
			ntuple |= (u64)fs->val.proto << tp->protocol_shift;
	}

	if (tp->tos_shift >= 0 && fs->mask.tos)
		ntuple |= (u64)(fs->val.tos) << tp->tos_shift;

	if (tp->vnic_shift >= 0) {
		if ((adap->params.tp.ingress_config & F_USE_ENC_IDX) &&
		    (fs->mask.encap_vld))
			ntuple |= (u64)((fs->val.encap_vld << 16) |
					(fs->val.encap_matchtype << 9) |
					(fs->val.ovlan)) << tp->vnic_shift;
		else if ((adap->params.tp.ingress_config & F_VNIC) &&
			 (fs->mask.pfvf_vld))
			ntuple |= (u64)((fs->val.pfvf_vld << 16) |
					(fs->val.pf << 13) |
					(fs->val.vf)) << tp->vnic_shift;
		else
			ntuple |= (u64)((fs->val.ovlan_vld << 16) |
					(fs->val.ovlan)) << tp->vnic_shift;
	}

	if (tp->macmatch_shift >= 0 && fs->mask.macidx)
		ntuple |= (u64)(fs->val.macidx) << tp->macmatch_shift;

	if (tp->ethertype_shift >= 0 && fs->mask.ethtype)
		ntuple |= (u64)(fs->val.ethtype) << tp->ethertype_shift;

	if (tp->matchtype_shift >= 0 && fs->mask.matchtype)
		ntuple |= (u64)(fs->val.matchtype) << tp->matchtype_shift;

	if (tp->frag_shift >= 0 && fs->mask.frag)
		ntuple |= (u64)(fs->val.frag) << tp->frag_shift;

	if (tp->fcoe_shift >= 0 && fs->mask.fcoe)
		ntuple |= (u64)(fs->val.fcoe) << tp->fcoe_shift;

	return ntuple;
}

static unsigned int get_filter_steerq(struct net_device *dev,
				      struct ch_filter_specification *fs)
{
	struct adapter *adapter = netdev2adap(dev);
	unsigned int iq;

	/*
	 * If the user has requested steering matching Ingress Packets
	 * to a specific Queue Set, we need to make sure it's in range
	 * for the port and map that into the Absolute Queue ID of the
	 * Queue Set's Response Queue.
	 */
	if (!fs->dirsteer) {
		if (fs->iq)
			return -EINVAL;
		iq = 0;
	} else {
		struct port_info *pi = netdev_priv(dev);

		/*
		 * If the iq id is greater than the number of qsets,
		 * then assume it is an absolute qid.
		 */
		if (fs->iq < pi->nqsets)
			iq = adapter->sge.ethrxq[pi->first_qset +
						 fs->iq].rspq.abs_id;
		else
			iq = fs->iq;
	}

	return iq;
}

/*
 * Delete the filter at the specified index (if valid).  The checks for all
 * the common problems with doing this like the filter being locked, currently
 * pending in another operation, etc.
 */
int delete_filter(struct adapter *adapter, unsigned int fidx, gfp_t gfp_mask)
{
	struct filter_entry *f;
	int ret;
	unsigned int max_fidx;

	max_fidx = adapter->tids.nftids + adapter->tids.nsftids +
		   adapter->tids.nhpftids;
	if (fidx >= max_fidx)
		return -E2BIG;

	f = &adapter->tids.ftid_tab[fidx];
	ret = writable_filter(f);
	if (ret)
		return ret;
	if (f->valid)
		return del_filter_wr(adapter, fidx, gfp_mask);

	return 0;
}

/*
 * Retrieve the packet count for the specified filter.
 */
int cxgb4_get_filter_count(struct adapter *adapter, unsigned int fidx,
			   u64 *c, int hash, bool get_byte)
{
	struct filter_entry *f;
	unsigned int tcb_base, tcbaddr;
	int ret;

	tcb_base = t4_read_reg(adapter, A_TP_CMM_TCB_BASE);
	if (is_hashfilter(adapter) && hash) {
		if ((fidx - adapter->tids.tid_base) < adapter->tids.ntids) {
			f = adapter->tids.tid_tab[fidx -
						  adapter->tids.tid_base];
			if (!f)
				return -EINVAL;

			if (is_t5(adapter->params.chip)) {
				if (get_byte)
					*c = f->byte_counter;
				else
					*c = f->pkt_counter;
				return 0;
			} else {
				tcbaddr = tcb_base + (fidx * TCB_SIZE);
				goto get_count;
			}
		} else
			return -E2BIG;
	} else {
		if ((fidx != (adapter->tids.nftids + adapter->tids.nsftids +
			      adapter->tids.nhpftids - 1))
				&& (fidx >= adapter->tids.nftids +
				adapter->tids.nhpftids))
			return -E2BIG;

		f = &adapter->tids.ftid_tab[fidx];
		if (!f->valid)
			return -EINVAL;

		tcbaddr = tcb_base + f->tid * TCB_SIZE;
	}

	f = &adapter->tids.ftid_tab[fidx];
	if (!f->valid)
		return -EINVAL;

get_count:
	if (is_t4(adapter->params.chip)) {
		/*
		 * For T4, the Filter Packet Hit Count is maintained as a
		 * 64-bit Big Endian value in the TCB fields
		 * {t_rtt_ts_recent_age, t_rtseq_recent} ...  For insanely
		 * crazy (and completely unknown) reasons, the format in
		 * memory is swizzled/mapped in a manner such that instead
		 * of having this 64-bit counter show up at offset 24
		 * ((W_TCB_T_RTT_TS_RECENT_AGE == 6) * sizeof(u32)), it
		 * actually shows up at offset 16.  After more than an hour
		 * trying to untangle things so it could be properly coded
		 * and documented here, it's simply not worth the effort.
		 * So we use an incredibly gross "4" constant instead of
		 * W_TCB_T_RTT_TS_RECENT_AGE.
		 */
		if (get_byte) {
			unsigned int word_offset = 4;
			__be64 be64_byte_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_byte_count), &be64_byte_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_byte_count);
		} else {
			unsigned int word_offset = 4;
			__be64 be64_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_count), (__be32 *)&be64_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_count);
		}
	} else {
		/*
		 * For T5, the Filter Packet Hit Count is maintained as a
		 * 32-bit Big Endian value in the TCB field {timestamp}.
		 * Similar to the craziness above, instead of the filter hit
		 * count showing up at offset 20 ((W_TCB_TIMESTAMP == 5) *
		 * sizeof(u32)), it actually shows up at offset 24.  Whacky.
		 */
		if (get_byte) {
			unsigned int word_offset = 4;
			__be64 be64_byte_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be64_byte_count), &be64_byte_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = be64_to_cpu(be64_byte_count);
		} else {
			unsigned int word_offset = 6;
			__be32 be32_count;

			spin_lock(&adapter->win0_lock);
			ret = t4_memory_rw(adapter, MEMWIN_NIC, MEM_EDC0,
					   tcbaddr + (word_offset * sizeof(__be32)),
					   sizeof(be32_count), &be32_count,
					   T4_MEMORY_READ);
			spin_unlock(&adapter->win0_lock);
			if (ret < 0)
				return ret;
			*c = (u64)be32_to_cpu(be32_count);
		}
	}

	return 0;
}

int cxgb4_get_filter_counters(struct net_device *dev, unsigned int fidx,
			      u64 *hitcnt, u64 *bytecnt, int hash)
{
	struct adapter *adapter = netdev2adap(dev);
	int ret;

	ret = cxgb4_get_filter_count(adapter, fidx, hitcnt, hash, false);
	if (ret < 0)
		goto out;
	ret = cxgb4_get_filter_count(adapter, fidx, bytecnt, hash, true);

out:
	return ret;
}
EXPORT_SYMBOL(cxgb4_get_filter_counters);

static int cxgb4_set_ftid(struct tid_info *t, int fidx, int family,
			  unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);

	if (test_bit(fidx, t->ftid_bmap)) {
		spin_unlock_bh(&t->ftid_lock);
		return -EBUSY;
	}

	if (family == PF_INET)
		__set_bit(fidx, t->ftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_allocate_region(t->ftid_bmap, fidx, 2);
		else
			bitmap_allocate_region(t->ftid_bmap, fidx, 1);
	}

	spin_unlock_bh(&t->ftid_lock);
	return 0;
}

static int cxgb4_set_hpftid(struct tid_info *t, int fidx, int family,
			    unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);

	if (test_bit(fidx, t->hpftid_bmap)) {
		spin_unlock_bh(&t->ftid_lock);
		return -EBUSY;
	}

	if (family == PF_INET)
		__set_bit(fidx, t->hpftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_allocate_region(t->hpftid_bmap, fidx, 2);
		else
			bitmap_allocate_region(t->hpftid_bmap, fidx, 1);
	}

	spin_unlock_bh(&t->ftid_lock);
	return 0;
}

void cxgb4_clear_ftid(struct tid_info *t, int fidx, int family,
		      unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET)
		__clear_bit(fidx, t->ftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_release_region(t->ftid_bmap, fidx, 2);
		else
			bitmap_release_region(t->ftid_bmap, fidx, 1);
	}
	spin_unlock_bh(&t->ftid_lock);
}
EXPORT_SYMBOL(cxgb4_clear_ftid);

void cxgb4_clear_hpftid(struct tid_info *t, int fidx, int family,
			unsigned int chip_ver)
{
	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET)
		__clear_bit(fidx, t->hpftid_bmap);
	else {
		if (chip_ver < CHELSIO_T6)
			bitmap_release_region(t->hpftid_bmap, fidx, 2);
		else
			bitmap_release_region(t->hpftid_bmap, fidx, 1);
	}
	spin_unlock_bh(&t->ftid_lock);
}
EXPORT_SYMBOL(cxgb4_clear_hpftid);

int cxgb4_get_free_ftid(struct net_device *dev, int family, int prio)
{
	struct adapter *adap = netdev2adap(dev);
	struct tid_info *t = &adap->tids;
	int ftid;

	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET) {
		if (is_t6(adap->params.chip) && prio) {
			ftid = find_first_zero_bit(t->hpftid_bmap, t->nhpftids);
			if (ftid >= t->nhpftids)
				ftid = -1;
		} else {
			ftid = find_first_zero_bit(t->ftid_bmap, t->nftids);
			if (ftid >= t->nftids) {
				ftid = -1;
				goto out;
			}
			ftid += t->nhpftids;
		}
	} else {
		if (is_t6(adap->params.chip) && prio) {
			ftid = bitmap_find_free_region(t->hpftid_bmap,
						       t->nhpftids, 1);
			if (ftid < 0) {
				ftid = -1;
				goto out;
			}
			bitmap_release_region(t->hpftid_bmap, ftid, 1);
		} else {
			if (is_t6(adap->params.chip)) {
				ftid = bitmap_find_free_region(t->ftid_bmap,
							       t->nftids, 1);
				if (ftid < 0) {
					ftid = -1;
					goto out;
				}
				bitmap_release_region(t->ftid_bmap, ftid, 1);
			} else {
				ftid = bitmap_find_free_region(t->ftid_bmap,
							       t->nftids, 2);
				if (ftid < 0) {
					ftid = -1;
					goto out;
				}
				bitmap_release_region(t->ftid_bmap, ftid, 2);
			}
			ftid += t->nhpftids;
		}
	}

out:
	spin_unlock_bh(&t->ftid_lock);
	return ftid;

}
EXPORT_SYMBOL(cxgb4_get_free_ftid);

/*
 * Delete the filter at a specified index.
 */
static int del_filter_wr(struct adapter *adapter, int fidx, gfp_t gfp_mask)
{
	struct filter_entry *f = &adapter->tids.ftid_tab[fidx];
	struct sk_buff *skb;
	struct fw_filter_wr *fwr;
	unsigned int len;

	len = sizeof(*fwr);

	if (gfp_mask & GFP_ATOMIC) {
		skb = alloc_skb(len, GFP_ATOMIC);
		if (!skb)
			return -ENOMEM;
	} else
		skb = alloc_skb(len, gfp_mask | __GFP_NOFAIL);
	fwr = (struct fw_filter_wr *)__skb_put(skb, len);
	t4_mk_filtdelwr(f->tid, fwr, f->fs.type, adapter->sge.fw_evtq.abs_id);

	/*
	 * Mark the filter as "pending" and ship off the Filter Work Request.
	 * When we get the Work Request Reply we'll clear the pending status.
	 */
	f->pending = 1;
	t4_mgmt_tx(adapter, skb);
	return 0;
}
/*
 * Filter Table.
 */

static void filters_show_ipaddr(struct seq_file *seq,
				int type, u8 *addr, u8 *addrm)
{
	int noctets, octet;

	seq_puts(seq, " ");
	if (type == 0) {
		noctets = 4;
		seq_printf(seq, "%48s", " ");
	} else
		noctets = 16;

	for (octet = 0; octet < noctets; octet++)
		seq_printf(seq, "%02x", addr[octet]);
	seq_puts(seq, "/");
	for (octet = 0; octet < noctets; octet++)
		seq_printf(seq, "%02x", addrm[octet]);
}

static void filters_display(struct seq_file *seq, unsigned int fidx,
			    struct filter_entry *f, int hash)
{
	struct adapter *adapter = seq->private;
	u32 fconf = adapter->params.tp.vlan_pri_map;
	u32 tpiconf = adapter->params.tp.ingress_config;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);
	int i;

	/*
	 * Filter index.
	 */
	if (f->fs.type)
		seq_printf(seq, "%4d ..%4d%c%c", fidx,
			   chip_ver < CHELSIO_T6 ? fidx+3 : fidx+1,
			   (!f->locked  ? ' ' : '!'),
			   (!f->pending ? ' ' : (!f->valid ? '+' : '-')));
	else
		seq_printf(seq, "%4d       %c%c", fidx,
			   (!f->locked  ? ' ' : '!'),
			   (!f->pending ? ' ' : (!f->valid ? '+' : '-')));

	if (f->fs.hitcnts) {
		u64 hitcnt;
		int ret;

		ret = cxgb4_get_filter_count(adapter, fidx, &hitcnt, hash, false);
		if (ret)
			seq_printf(seq, " %20s", "hits={ERROR}");
		else
			seq_printf(seq, " %20llu", hitcnt);

		ret = cxgb4_get_filter_count(adapter, fidx, &hitcnt, hash,
				             true);
		if (ret)
			seq_printf(seq, " %20s", "bytes={ERROR}");
		else
			seq_printf(seq, " %20llu", hitcnt);
	} else {
		seq_printf(seq, " %20s", "Disabled");
		seq_printf(seq, " %20s", "Disabled");
	}

	/*
	 * Compressed header portion of filter.
	 */
	for (i = S_FT_FIRST; i <= S_FT_LAST; i++) {
		switch (fconf & (1 << i)) {
		case 0:
			/* compressed filter field not enabled */
			break;

		case F_FCOE:
			seq_printf(seq, "  %1d/%1d",
				   f->fs.val.fcoe, f->fs.mask.fcoe);
			break;

		case F_PORT:
			seq_printf(seq, "  %1d/%1d",
				   f->fs.val.iport, f->fs.mask.iport);
			break;

		case F_VNIC_ID:
			if (tpiconf & F_USE_ENC_IDX)
				seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
					   f->fs.val.ovlan_vld,
					   (f->fs.val.ovlan >> 9) & 0x7,
					   f->fs.val.ovlan & 0x1ff,
					   f->fs.mask.ovlan_vld,
					   (f->fs.mask.ovlan >> 9) & 0x7,
					   f->fs.mask.ovlan & 0x1ff);

			else if (tpiconf & F_VNIC)
				seq_printf(seq, " %1d:%1x:%02x/%1d:%1x:%02x",
					   f->fs.val.ovlan_vld,
					   (f->fs.val.ovlan >> 13) & 0x7,
					   f->fs.val.ovlan & 0x7f,
					   f->fs.mask.ovlan_vld,
					   (f->fs.mask.ovlan >> 13) & 0x7,
					   f->fs.mask.ovlan & 0x7f);
			else
				seq_printf(seq, " %1d:%04x/%1d:%04x",
					   f->fs.val.ovlan_vld,
					   f->fs.val.ovlan,
					   f->fs.mask.ovlan_vld,
					   f->fs.mask.ovlan);
			break;

		case F_VLAN:
			seq_printf(seq, " %1d:%04x/%1d:%04x",
				   f->fs.val.ivlan_vld,
				   f->fs.val.ivlan,
				   f->fs.mask.ivlan_vld,
				   f->fs.mask.ivlan);
			break;

		case F_TOS:
			seq_printf(seq, " %02x/%02x",
				   f->fs.val.tos, f->fs.mask.tos);
			break;

		case F_PROTOCOL:
			seq_printf(seq, " %02x/%02x",
				   f->fs.val.proto, f->fs.mask.proto);
			break;

		case F_ETHERTYPE:
			seq_printf(seq, " %04x/%04x",
				   f->fs.val.ethtype, f->fs.mask.ethtype);
			break;

		case F_MACMATCH:
			seq_printf(seq, " %03x/%03x",
				   f->fs.val.macidx, f->fs.mask.macidx);
			break;

		case F_MPSHITTYPE:
			seq_printf(seq, " %1x/%1x",
				   f->fs.val.matchtype,
				   f->fs.mask.matchtype);
			break;

		case F_FRAGMENTATION:
			seq_printf(seq, "  %1d/%1d",
				   f->fs.val.frag, f->fs.mask.frag);
			break;
		}
	}

	/*
	 * Fixed portion of filter.
	 */
	filters_show_ipaddr(seq, f->fs.type,
			    f->fs.val.lip, f->fs.mask.lip);
	filters_show_ipaddr(seq, f->fs.type,
			    f->fs.val.fip, f->fs.mask.fip);
	seq_printf(seq, " %04x/%04x %04x/%04x",
		   f->fs.val.lport, f->fs.mask.lport,
		   f->fs.val.fport, f->fs.mask.fport);

	/*
	 * Variable length filter action.
	 */
	if (f->fs.action == FILTER_DROP)
		seq_puts(seq, " Drop");
	else if (f->fs.action == FILTER_SWITCH) {
		seq_printf(seq, " Switch: port=%d", f->fs.eport);
		if (f->fs.newdmac)
			seq_printf(seq,
				   ", dmac=%02x:%02x:%02x:%02x:%02x:%02x"
				   ", l2tidx=%d",
				   f->fs.dmac[0], f->fs.dmac[1],
				   f->fs.dmac[2], f->fs.dmac[3],
				   f->fs.dmac[4], f->fs.dmac[5],
				   f->l2t->idx);
		if (f->fs.newsmac)
			seq_printf(seq,
				   ", smac=%02x:%02x:%02x:%02x:%02x:%02x"
				   ", smtidx=%d",
				   f->fs.smac[0], f->fs.smac[1],
				   f->fs.smac[2], f->fs.smac[3],
				   f->fs.smac[4], f->fs.smac[5],
				   f->smtidx);
		if (f->fs.newvlan == VLAN_REMOVE)
			seq_printf(seq, ", vlan=none");
		else if (f->fs.newvlan == VLAN_INSERT)
			seq_printf(seq, ", vlan=insert(%x)",
					f->fs.vlan);
		else if (f->fs.newvlan == VLAN_REWRITE)
			seq_printf(seq, ", vlan=rewrite(%x)",
					f->fs.vlan);
	} else {
		seq_puts(seq, " Pass: Q=");
		if (f->fs.dirsteer == 0) {
			seq_puts(seq, "RSS");
			if (f->fs.maskhash)
				seq_puts(seq, "(TCB=hash)");
		} else {
			seq_printf(seq, "%d", f->fs.iq);
			if (f->fs.dirsteerhash == 0)
				seq_puts(seq, "(QID)");
			else
				seq_puts(seq, "(hash)");
		}
	}
	if (f->fs.prio)
		seq_puts(seq, " Prio");
	if (f->fs.rpttid)
		seq_puts(seq, " RptTID");
	seq_puts(seq, "\n");
}

static int filters_show(struct seq_file *seq, void *v)
{
	struct adapter *adapter = seq->private;
	u32 fconf = adapter->params.tp.vlan_pri_map;
	u32 tpiconf = adapter->params.tp.ingress_config;
	int i;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "[[Legend: "
			 "'!' => locked; "
			 "'+' => pending set; "
			 "'-' => pending clear]]\n");
		seq_puts(seq, " Idx                          Hits");
		seq_puts(seq, "            Hit-Bytes");
		for (i = S_FT_FIRST; i <= S_FT_LAST; i++) {
			switch (fconf & (1 << i)) {
			case 0:
				/* compressed filter field not enabled */
				break;

			case F_FCOE:
				seq_puts(seq, " FCoE");
				break;

			case F_PORT:
				seq_puts(seq, " Port");
				break;

			case F_VNIC_ID:
				if (tpiconf & F_USE_ENC_IDX)
					seq_puts(seq, "    vld:MPS:Id");
				else if(tpiconf & F_VNIC)
					seq_puts(seq, "   VFvld:PF:VF");
				else
					seq_puts(seq, "     vld:oVLAN");
				break;

			case F_VLAN:
				seq_puts(seq, "     vld:iVLAN");
				break;

			case F_TOS:
				seq_puts(seq, "   TOS");
				break;

			case F_PROTOCOL:
				seq_puts(seq, "  Prot");
				break;

			case F_ETHERTYPE:
				seq_puts(seq, "   EthType");
				break;

			case F_MACMATCH:
				seq_puts(seq, "  MACIdx");
				break;

			case F_MPSHITTYPE:
				seq_puts(seq, " MPS");
				break;

			case F_FRAGMENTATION:
				seq_puts(seq, " Frag");
				break;
			}
		}
		seq_printf(seq, " %65s %65s %9s %9s %s\n",
			   "LIP", "FIP", "LPORT", "FPORT", "Action");
	} else {
		int fidx = (uintptr_t)v - 2;
		struct filter_entry *f = &adapter->tids.ftid_tab[fidx];

		/* if this entry isn't filled in just return */
		if (!f->valid && !f->pending)
			return 0;

		filters_display(seq, fidx, f, 0);
	}
	return 0;
}

static inline void *filters_get_idx(struct adapter *adapter, loff_t pos)
{
	if (pos > (adapter->tids.nftids + adapter->tids.nsftids +
		   adapter->tids.nhpftids))
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

static void *filters_start(struct seq_file *seq, loff_t *pos)
{
	struct adapter *adapter = seq->private;

	return (*pos
		? filters_get_idx(adapter, *pos)
		: SEQ_START_TOKEN);
}

static void *filters_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct adapter *adapter = seq->private;

	(*pos)++;
	return filters_get_idx(adapter, *pos);
}

static void filters_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations filters_seq_ops = {
	.start = filters_start,
	.next  = filters_next,
	.stop  = filters_stop,
	.show  = filters_show
};

int filters_open(struct inode *inode, struct file *file)
{
	struct adapter *adapter = inode->i_private;
	int res;

	res = seq_open(file, &filters_seq_ops);
	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = adapter;
	}
	return res;
}

const struct file_operations filters_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = filters_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

static int hash_filters_show(struct seq_file *seq, void *v)
{
	struct adapter *adapter = seq->private;
	u32 fconf = adapter->params.tp.vlan_pri_map;
	u32 tpiconf = adapter->params.tp.ingress_config;
	int i;

	if (v == SEQ_START_TOKEN) {
		seq_puts(seq, "[[Legend: "
			 "'!' => locked; "
			 "'+' => pending set; "
			 "'-' => pending clear]]\n");
		seq_puts(seq, " Idx                          Hits");
		seq_puts(seq, "            Hit-Bytes");
		for (i = S_FT_FIRST; i <= S_FT_LAST; i++) {
			switch (fconf & (1 << i)) {
			case 0:
				/* compressed filter field not enabled */
				break;

			case F_FCOE:
				seq_puts(seq, " FCoE");
				break;

			case F_PORT:
				seq_puts(seq, " Port");
				break;

			case F_VNIC_ID:
				if (tpiconf & F_USE_ENC_IDX)
					seq_puts(seq, "    vld:MPS:Id");
				else if(tpiconf & F_VNIC)
					seq_puts(seq, "   VFvld:PF:VF");
				else
					seq_puts(seq, "     vld:oVLAN");
				break;

			case F_VLAN:
				seq_puts(seq, "     vld:iVLAN");
				break;

			case F_TOS:
				seq_puts(seq, "   TOS");
				break;

			case F_PROTOCOL:
				seq_puts(seq, "  Prot");
				break;

			case F_ETHERTYPE:
				seq_puts(seq, "   EthType");
				break;

			case F_MACMATCH:
				seq_puts(seq, "  MACIdx");
				break;

			case F_MPSHITTYPE:
				seq_puts(seq, " MPS");
				break;

			case F_FRAGMENTATION:
				seq_puts(seq, " Frag");
				break;
			}
		}
		seq_printf(seq, " %65s %65s %9s %9s %s\n",
			   "LIP", "FIP", "LPORT", "FPORT", "Action");
	} else {
		struct filter_entry *f;
		spinlock_t *lock;
		int fidx = (uintptr_t)v - 2;

		if (is_hashfilter(adapter)) {
			f = adapter->tids.tid_tab[fidx];
			if (!f)
				return 0;
		} else
			return 0;

		if (f->fs.val.proto == IPPROTO_UDP)
			lock = &adapter->filter_udphash.ehash_filter_locks[f->filter_hash &
				adapter->filter_udphash.ehash_filter_locks_mask];
		else
			lock = &adapter->filter_tcphash.ehash_filter_locks[f->filter_hash &
				adapter->filter_tcphash.ehash_filter_locks_mask];
		spin_lock_bh(lock);
		/* if this entry isn't filled in just return */
		if (!f->valid) {
			spin_unlock_bh(lock);
			return 0;
		}

		filters_display(seq, fidx + adapter->tids.tid_base, f, 1);
		spin_unlock_bh(lock);
	}
	return 0;
}

static inline void *hash_filters_get_idx(struct adapter *adapter, loff_t pos)
{
	if (is_hashfilter(adapter)) {
		if (pos > (adapter->tids.ntids))
			return NULL;
	} else
		return NULL;

	return (void *)(uintptr_t)(pos + 1);
}

static void *hash_filters_start(struct seq_file *seq, loff_t *pos)
{
	struct adapter *adapter = seq->private;

	return (*pos
		? hash_filters_get_idx(adapter, *pos)
		: SEQ_START_TOKEN);
}

static void *hash_filters_next(struct seq_file *seq, void *v, loff_t *pos)
{
	struct adapter *adapter = seq->private;

	(*pos)++;
	return hash_filters_get_idx(adapter, *pos);
}

static void hash_filters_stop(struct seq_file *seq, void *v)
{
}

static const struct seq_operations hash_filters_seq_ops = {
	.start = hash_filters_start,
	.next  = hash_filters_next,
	.stop  = hash_filters_stop,
	.show  = hash_filters_show
};

static int hash_filters_open(struct inode *inode, struct file *file)
{
	struct adapter *adapter = inode->i_private;
	int res;

	res = seq_open(file, &hash_filters_seq_ops);
	if (!res) {
		struct seq_file *seq = file->private_data;

		seq->private = adapter;
	}
	return res;
}

const struct file_operations hash_filters_debugfs_fops = {
	.owner   = THIS_MODULE,
	.open    = hash_filters_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
};

/*
 * Send a Work Request to write the filter at a specified index.  We construct
 * a Firmware Filter Work Request to have the work done and put the indicated
 * filter into "pending" mode which will prevent any further actions against
 * it till we get a reply from the firmware on the completion status of the
 * request.
 */
int set_filter_wr(struct adapter *adapter, int fidx, gfp_t gfp_mask)
{
	struct filter_entry *f = &adapter->tids.ftid_tab[fidx];
	struct sk_buff *skb;
	struct fw_filter2_wr *fwr;
	int ret;

	if (gfp_mask & GFP_ATOMIC) {
		skb = alloc_skb(sizeof(*fwr), GFP_ATOMIC);
		if (!skb) {
			ret = -ENOMEM;
			goto out;
		}
	} else
		skb = alloc_skb(sizeof(*fwr), gfp_mask | __GFP_NOFAIL);
	fwr = (struct fw_filter2_wr *)__skb_put(skb, sizeof(*fwr));
	memset(fwr, 0, sizeof(*fwr));

	/*
	 * If the new filter requires loopback Destination MAC and/or VLAN
	 * rewriting then we need to allocate a Layer 2 Table (L2T) entry for
	 * the filter.
	 */
	if (f->fs.newdmac || f->fs.newvlan) {
		/* allocate L2T entry for new filter */
		f->l2t = t4_l2t_alloc_switching(adapter, f->fs.vlan,
						f->fs.eport, f->fs.dmac);
		if (f->l2t == NULL) {
			ret = -ENOMEM;
			goto error;
		}
	}

	/*
	 * If the new filter requires loopback Source MAC rewriting then
	 * we need to allocate a SMT entry for the filter.
	 */
	if (f->fs.newsmac) {
		f->smt = cxgb4_smt_alloc_switching(f->dev, f->fs.smac);
		if (!f->smt) {
			if (f->l2t) {
				cxgb4_l2t_release(f->l2t);
				f->l2t = NULL;
			}
			ret = -ENOMEM;
			goto error;
		}
		f->smtidx = f->smt->hw_idx;
	}

	/*
	 * It would be nice to put most of the following in t4_hw.c but most
	 * of the work is translating the cxgbtool ch_filter_specification
	 * into the Work Request and the definition of that structure is
	 * currently in cxgbtool.h which isn't appropriate to pull into the
	 * common code.  We may eventually try to come up with a more neutral
	 * filter specification structure but for now it's easiest to simply
	 * put this fairly direct code in line ...
	 */
	if (adapter->params.filter2_wr_support)
		fwr->op_pkd = htonl(V_FW_WR_OP(FW_FILTER2_WR));
	else
		fwr->op_pkd = htonl(V_FW_WR_OP(FW_FILTER_WR));
	fwr->len16_pkd = htonl(V_FW_WR_LEN16(sizeof(*fwr)/16));
	fwr->tid_to_iq =
		htonl(V_FW_FILTER_WR_TID(f->tid) |
		      V_FW_FILTER_WR_RQTYPE(f->fs.type) |
		      V_FW_FILTER_WR_NOREPLY(0) |
		      V_FW_FILTER_WR_IQ(f->fs.iq));
	fwr->del_filter_to_l2tix =
		htonl(V_FW_FILTER_WR_RPTTID(f->fs.rpttid) |
		      V_FW_FILTER_WR_DROP(f->fs.action == FILTER_DROP) |
		      V_FW_FILTER_WR_DIRSTEER(f->fs.dirsteer) |
		      V_FW_FILTER_WR_MASKHASH(f->fs.maskhash) |
		      V_FW_FILTER_WR_DIRSTEERHASH(f->fs.dirsteerhash) |
		      V_FW_FILTER_WR_LPBK(f->fs.action == FILTER_SWITCH) |
		      V_FW_FILTER2_WR_TX_LOOP(f->fs.eport >= 
					 NUM_UP_TSCH_CHANNEL_INSTANCES) |
		      V_FW_FILTER2_WR_DROP_ENCAP(f->fs.drop_encap_hdr) |
		      V_FW_FILTER_WR_DMAC(f->fs.newdmac) |
		      V_FW_FILTER_WR_SMAC(f->fs.newsmac) |
		      V_FW_FILTER_WR_INSVLAN(f->fs.newvlan == VLAN_INSERT ||
					     f->fs.newvlan == VLAN_REWRITE) |
		      V_FW_FILTER_WR_RMVLAN(f->fs.newvlan == VLAN_REMOVE ||
					    f->fs.newvlan == VLAN_REWRITE) |
		      V_FW_FILTER_WR_HITCNTS(f->fs.hitcnts) |
		      V_FW_FILTER_WR_TXCHAN(f->fs.eport & 
					(NUM_UP_TSCH_CHANNEL_INSTANCES - 1)) |
		      V_FW_FILTER_WR_PRIO(f->fs.prio) |
		      V_FW_FILTER_WR_L2TIX(f->l2t ? f->l2t->idx : 0));
	fwr->ethtype = htons(f->fs.val.ethtype);
	fwr->ethtypem = htons(f->fs.mask.ethtype);
	fwr->frag_to_ovlan_vldm =
		     (V_FW_FILTER_WR_FRAG(f->fs.val.frag) |
		      V_FW_FILTER_WR_FRAGM(f->fs.mask.frag) |
		      V_FW_FILTER_WR_IVLAN_VLD(f->fs.val.ivlan_vld) |
		      V_FW_FILTER_WR_OVLAN_VLD(f->fs.val.ovlan_vld) |
		      V_FW_FILTER_WR_IVLAN_VLDM(f->fs.mask.ivlan_vld) |
		      V_FW_FILTER_WR_OVLAN_VLDM(f->fs.mask.ovlan_vld));
	fwr->smac_sel = f->smtidx;
	fwr->rx_chan_rx_rpl_iq =
		htons(V_FW_FILTER_WR_RX_CHAN(
			cxgb4_port_e2cchan(adapter->port[0])) |
		      V_FW_FILTER_WR_RX_RPL_IQ(adapter->sge.fw_evtq.abs_id));
	fwr->maci_to_matchtypem =
		htonl(V_FW_FILTER_WR_MACI(f->fs.val.macidx) |
		      V_FW_FILTER_WR_MACIM(f->fs.mask.macidx) |
		      V_FW_FILTER_WR_FCOE(f->fs.val.fcoe) |
		      V_FW_FILTER_WR_FCOEM(f->fs.mask.fcoe) |
		      V_FW_FILTER_WR_PORT(f->fs.val.iport) |
		      V_FW_FILTER_WR_PORTM(f->fs.mask.iport) |
		      V_FW_FILTER_WR_MATCHTYPE(f->fs.val.matchtype) |
		      V_FW_FILTER_WR_MATCHTYPEM(f->fs.mask.matchtype));
	fwr->ptcl = f->fs.val.proto;
	fwr->ptclm = f->fs.mask.proto;
	fwr->ttyp = f->fs.val.tos;
	fwr->ttypm = f->fs.mask.tos;
	fwr->ivlan = htons(f->fs.val.ivlan);
	fwr->ivlanm = htons(f->fs.mask.ivlan);
	fwr->ovlan = htons(f->fs.val.ovlan);
	fwr->ovlanm = htons(f->fs.mask.ovlan);
	memcpy(fwr->lip, f->fs.val.lip, sizeof(fwr->lip));
	memcpy(fwr->lipm, f->fs.mask.lip, sizeof(fwr->lipm));
	memcpy(fwr->fip, f->fs.val.fip, sizeof(fwr->fip));
	memcpy(fwr->fipm, f->fs.mask.fip, sizeof(fwr->fipm));
	fwr->lp = htons(f->fs.val.lport);
	fwr->lpm = htons(f->fs.mask.lport);
	fwr->fp = htons(f->fs.val.fport);
	fwr->fpm = htons(f->fs.mask.fport);

	if (adapter->params.filter2_wr_support) {
		fwr->filter_type_swapmac =
			 V_FW_FILTER2_WR_SWAPMAC(f->fs.swapmac);
		fwr->natmode_to_ulp_type =
			V_FW_FILTER2_WR_ULP_TYPE(f->fs.nat_mode ?
						 ULP_MODE_TCPDDP :
						 ULP_MODE_NONE) |
			V_FW_FILTER2_WR_NATFLAGCHECK(f->fs.nat_flag_chk) |
			V_FW_FILTER2_WR_NATMODE(f->fs.nat_mode);
		memcpy(fwr->newlip, f->fs.nat_lip, sizeof(fwr->newlip));
		memcpy(fwr->newfip, f->fs.nat_fip, sizeof(fwr->newfip));
		fwr->newlport = htons(f->fs.nat_lport);
		fwr->newfport = htons(f->fs.nat_fport);
		fwr->natseqcheck = htonl(f->fs.nat_seq_chk);
	}

	/*
	 * Mark the filter as "pending" and ship off the Filter Work Request.
	 * When we get the Work Request Reply we'll clear the pending status.
	 */
	f->pending = 1;

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	t4_ofld_send(adapter, skb);
	return 0;

error:
	dev_kfree_skb(skb);
out:
	return ret;
}

/* Allocate a normal filter TID */
int cxgb4_alloc_ftid(struct tid_info *t, int family, unsigned int chip_ver)
{
	int ftid;

	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET) {
		ftid = find_first_zero_bit(t->ftid_bmap, t->nftids);
		if (ftid < t->nftids)
			__set_bit(ftid, t->ftid_bmap);
		else
			ftid = -1;
	} else {
		if (chip_ver < CHELSIO_T6)
			ftid = bitmap_find_free_region(t->ftid_bmap, t->nftids,
						       2);
		else
			ftid = bitmap_find_free_region(t->ftid_bmap, t->nftids,
						       1);
		if (ftid < 0)
			ftid = -1;
	}

	spin_unlock_bh(&t->ftid_lock);
	return ftid;
}
EXPORT_SYMBOL(cxgb4_alloc_ftid);

/* Allocate a hi priority filter TID */
int cxgb4_alloc_hpftid(struct tid_info *t, int family, unsigned int chip_ver)
{
	int ftid;

	spin_lock_bh(&t->ftid_lock);
	if (family == PF_INET) {
		ftid = find_first_zero_bit(t->hpftid_bmap, t->nhpftids);
		if (ftid < t->nhpftids)
			__set_bit(ftid, t->hpftid_bmap);
		else
			ftid = -1;
	} else {
		if (chip_ver < CHELSIO_T6)
			ftid = bitmap_find_free_region(t->hpftid_bmap,
						       t->nhpftids, 2);
		else
			ftid = bitmap_find_free_region(t->hpftid_bmap,
						       t->nhpftids, 1);
		if (ftid < 0)
			ftid = -1;
	}

	spin_unlock_bh(&t->ftid_lock);
	return ftid;
}
EXPORT_SYMBOL(cxgb4_alloc_hpftid);

/*
 * Check a Chelsio Filter Request for validity, convert it into our internal
 * format and send it to the hardware.  Return 0 on success, an error number
 * otherwise.  We attach any provided filter operation context to the internal
 * filter specification in order to facilitate signaling completion of the
 * operation.  The RTNL must be held when calling this function.
 */
int cxgb4_set_filter(struct net_device *dev, int filter_id,
		     struct ch_filter_specification *fs,
		     struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	u32 iconf;
	unsigned int fidx, iq, fid_bit = 0;
	struct filter_entry *f;
	int ret;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	if (fs->cap) {
		if (is_hashfilter(adapter))
			return cxgb4_set_hash_filter(dev, filter_id, fs, ctx,
						     flags);
		pr_err("%s: Attempt to use maskless filter in non hash-filter "
		       "configuration; mod-param use_ddr_filters = %d\n",
		       __func__, use_ddr_filters);
		return -EINVAL;
	}

	if ((filter_id != (adapter->tids.nftids + adapter->tids.nsftids +
			   adapter->tids.nhpftids - 1)) &&
			(filter_id >= adapter->tids.nftids +
			 adapter->tids.nhpftids))
		return -E2BIG;

	ret = validate_filter(dev, fs);
	if (ret)
		return ret;

	iq = get_filter_steerq(dev, fs);
	if (iq < 0)
		return iq;

	/*
	 * IPv6 filters occupy four slots and must be aligned on
	 * four-slot boundaries.  IPv4 filters only occupy a single
	 * slot and have no alignment requirements but writing a new
	 * IPv4 filter into the middle of an existing IPv6 filter
	 * requires clearing the old IPv6 filter.
	 */
	if (fs->type == 0) { /* IPv4 */
		/*
		 * For T6, If our IPv4 filter isn't being written to a
		 * multiple of two filter index and there's an IPv6
		 * filter at the multiple of 2 base slot, then we need
		 * to delete that IPv6 filter ...
		 * For adapters below T6, IPv6 filter occupies 4 entries.
		 * Hence we need to delete the filter in multiple of 4 slot.
		 */
		if (chip_ver < CHELSIO_T6)
			fidx = filter_id & ~0x3;
		else
			fidx = filter_id & ~0x1;

		if (fidx != filter_id &&
		    adapter->tids.ftid_tab[fidx].fs.type) {
			f = &adapter->tids.ftid_tab[fidx];
			if (f->valid) {
				pr_err("%s: IPv6 filter present at index %d. "
				       "Please remove IPv6 filter first.\n",
				       __func__, filter_id);
				return -EBUSY;
			}
		}
	} else { /* IPv6 */
		if (chip_ver < CHELSIO_T6) {
			/*
			 * Ensure that the IPv6 filter is aligned on a
			 * multiple of 4 boundary.
			 */
			if (filter_id & 0x3)
				return -EINVAL;

			/*
			 * Check all except the base overlapping IPv4 filter
			 * slots.
			 */
			for (fidx = filter_id+1; fidx < filter_id+4; fidx++) {
				f = &adapter->tids.ftid_tab[fidx];
				if (f->valid) {
					pr_err("%s: IPv6 filter requires 4 indices."
					       "IPv4 filter already present at %d. "
					       "Please remove IPv4 filter first.\n",
					       __func__, fidx);
					return -EBUSY;
				}
			}
		} else {
			/*
			 * For T6, CLIP being enabled, IPv6 filter would occupy
			 * 2 entries.
			 */
			if (filter_id & 0x1)
				return -EINVAL;

			/*
			 * Check overlapping IPv4 filter slot
			 */
			fidx = filter_id + 1;
			f = &adapter->tids.ftid_tab[fidx];
			if (f->valid) {
				pr_err("%s: IPv6 filter requires 2 indices."
				       "IPv4 filter already present at %d. "
				       "Please remove IPv4 filter first.\n",
				       __func__, fidx);
				return -EBUSY;
			}
		}
	}

	/*
	 * Check to make sure that provided filter index is not
	 * already in use by someone else
	 */
	f = &adapter->tids.ftid_tab[filter_id];
	if (f->valid)
		return -EBUSY;

	/* Hi priority filter index should be from 0 to nhpftids - 1 and
	 * normal priority filter index should be from nhpftids to
	 * nhpftids + nftids - 1.
	 */
	if ((chip_ver > CHELSIO_T5) && fs->prio) {
		if (filter_id >= adapter->tids.nhpftids)
			return -EINVAL;
		fidx = filter_id + adapter->tids.hpftid_base;
	} else {
		if ((chip_ver > CHELSIO_T5) &&
		    (filter_id < adapter->tids.nhpftids))
			return -EINVAL;
		fidx = filter_id - adapter->tids.nhpftids +
		       adapter->tids.ftid_base;
	}

	if ((chip_ver > CHELSIO_T5) && fs->prio) {
		ret = cxgb4_set_hpftid(&adapter->tids, filter_id,
				       fs->type ? PF_INET6 : PF_INET, chip_ver);
	} else {
		fid_bit = filter_id - adapter->tids.nhpftids;
		ret = cxgb4_set_ftid(&adapter->tids, fid_bit,
				     fs->type ? PF_INET6 : PF_INET, chip_ver);
	}
	if (ret)
		return ret;

	/*
	 * Check to make sure the filter requested is writable ...
	 */
	ret = writable_filter(f);
	if (ret)
		goto free_tid;

	/*
	 * Clear out any old resources being used by the filter before
	 * we start constructing the new filter.
	 */
	if (f->valid)
		clear_filter(adapter, f);

	/* Issue a cxgb4_clip_get() only if we have non-zero IPv6 address
	 */
	if ((chip_ver == CHELSIO_T6) && fs->type &&
	    ipv6_addr_type((const struct in6_addr *)fs->val.lip) !=
		IPV6_ADDR_ANY) {
		ret = cxgb4_clip_get_filter(dev, (const u32 *)&fs->val.lip,
					    (const u32 *)&fs->mask.lip, 1);
		if (ret)
			goto free_tid;
	}

	/*
	 * Convert the filter specification into our internal format.
	 * We copy the PF/VF specification into the Outer VLAN field
	 * here so the rest of the code -- including the interface to
	 * the firmware -- doesn't have to constantly do these checks.
	 */
	f->fs = *fs;
	f->fs.iq = iq;
	f->dev = dev;

	iconf = adapter->params.tp.ingress_config;
	if (iconf & F_VNIC) {
		f->fs.val.ovlan = (fs->val.pf << 13) | fs->val.vf;
		f->fs.mask.ovlan = (fs->mask.pf << 13) | fs->mask.vf;
		f->fs.val.ovlan_vld = fs->val.pfvf_vld;
		f->fs.mask.ovlan_vld = fs->mask.pfvf_vld;
	} else if (iconf & F_USE_ENC_IDX) {
		if (f->fs.val.encap_vld) {
			struct port_info *pi = netdev_priv(f->dev);
			/* allocate MPS TCAM entry */
			ret = cxgb_alloc_encap_mac_filt(adapter, pi->viid,
						      f->fs.val.encap_inner_mac,
						      f->fs.mask.encap_inner_mac,
						      f->fs.val.vni,
						      f->fs.mask.vni, 0,
						      f->fs.val.encap_lookup, 1);
			if (ret < 0)
				goto free_clip;

			f->fs.val.ovlan = (fs->val.encap_matchtype << 9) | ret;
			f->fs.mask.ovlan = (fs->mask.encap_matchtype << 9) |
					   0x1ff;
			f->fs.val.ovlan_vld = 1;
			f->fs.mask.ovlan_vld = 1;
		}
	}

	/*
	 * Attempt to set the filter.  If we don't succeed, we clear
	 * it and return the failure.
	 */
	f->ctx = ctx;
	f->tid = fidx; /* Save the actual tid */
	ret = set_filter_wr(adapter, filter_id, GFP_KERNEL);
	if (ret) {
		if ((chip_ver > CHELSIO_T5) && f->fs.prio) {
			fid_bit = f->tid - adapter->tids.hpftid_base;
			cxgb4_clear_hpftid(&adapter->tids, fid_bit,
					   fs->type ? PF_INET6 : PF_INET,
					   chip_ver);
		} else {
			fid_bit = f->tid - adapter->tids.ftid_base;
			cxgb4_clear_ftid(&adapter->tids, fid_bit,
					 fs->type ? PF_INET6 : PF_INET,
					 chip_ver);
		}
		clear_filter(adapter, f);
	}

	return ret;

free_clip:
	if ((chip_ver == CHELSIO_T6) && f->fs.type &&
	    ipv6_addr_type((const struct in6_addr *)fs->val.lip) !=
		IPV6_ADDR_ANY)
		cxgb4_clip_release_filter(f->dev, (const u32 *)&f->fs.val.lip,
					  (const u32 *)&f->fs.mask.lip, 1);
free_tid:
	if ((chip_ver > CHELSIO_T5) && f->fs.prio)
		cxgb4_clear_hpftid(&adapter->tids, filter_id,
				   fs->type ? PF_INET6 : PF_INET, chip_ver);
	else
		cxgb4_clear_ftid(&adapter->tids, fid_bit,
				 fs->type ? PF_INET6 : PF_INET, chip_ver);

	return ret;

}
EXPORT_SYMBOL(cxgb4_set_filter);

/*
 * Build a CPL_ABORT_REQ message as payload of a ULP_TX_PKT command.
 */
static void mk_abort_req_ulp(struct cpl_abort_req *abort_req,
			     unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_req;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_req), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_req) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_req) = htonl(MK_OPCODE_TID(CPL_ABORT_REQ, tid));
	abort_req->rsvd0 = htonl(0);
	abort_req->rsvd1 = 0;
	abort_req->cmd = CPL_ABORT_NO_RST;
}

static void mk_abort_rpl_ulp(struct cpl_abort_rpl *abort_rpl,
			     unsigned int tid)
{
	struct ulp_txpkt *txpkt = (struct ulp_txpkt *)abort_rpl;
	struct ulptx_idata *sc = (struct ulptx_idata *)(txpkt + 1);

	txpkt->cmd_dest = htonl(V_ULPTX_CMD(ULP_TX_PKT) | V_ULP_TXPKT_DEST(0));
	txpkt->len = htonl(DIV_ROUND_UP(sizeof(*abort_rpl), 16));
	sc->cmd_more = htonl(V_ULPTX_CMD(ULP_TX_SC_IMM));
	sc->len = htonl(sizeof(*abort_rpl) - sizeof(struct work_request_hdr));
	OPCODE_TID(abort_rpl) = htonl(MK_OPCODE_TID(CPL_ABORT_RPL, tid));
	abort_rpl->rsvd0 = htonl(0);
	abort_rpl->rsvd1 = 0;
	abort_rpl->cmd = CPL_ABORT_NO_RST;
}



/*
 * Check a delete filter request for validity and send it to the hardware.
 * Return 0 on success, an error number otherwise.  We attach any provided
 * filter operation context to the internal filter specification in order to
 * facilitate signaling completion of the operation.  The RTNL must be held
 * when calling this function.
 */
int cxgb4_del_filter(struct net_device *dev, int filter_id,
		     struct ch_filter_specification *fs,
		     struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	struct filter_entry *f;
	int ret;
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adapter->params.chip);

	/*
	 * Make sure this is a valid filter and that we can delete it.
	 */
	if (fs && fs->cap) {
		if (is_hashfilter(adapter))
			return cxgb4_del_hash_filter(dev, filter_id, ctx,
						     flags);
		pr_err("%s: Attempt to use maskless filter in non hash-filter "
		       "configuration; mod-param use_ddr_filters = %d\n",
		       __func__, use_ddr_filters);
		return -EINVAL;
	}

	if ((filter_id != (adapter->tids.nftids + adapter->tids.nsftids +
			   adapter->tids.nhpftids - 1))
			&& (filter_id >= adapter->tids.nftids +
			    adapter->tids.nhpftids))
		return -E2BIG;

	f = &adapter->tids.ftid_tab[filter_id];
	ret = writable_filter(f);
	if (ret)
		return ret;

	if (f->valid) {
		f->ctx = ctx;
		if ((chip_ver > CHELSIO_T5) && f->fs.prio)
			cxgb4_clear_hpftid(&adapter->tids,
					   f->tid - adapter->tids.hpftid_base,
					   f->fs.type ? PF_INET6 : PF_INET,
					   chip_ver);
		else
			cxgb4_clear_ftid(&adapter->tids,
					 f->tid - adapter->tids.ftid_base,
					 f->fs.type ? PF_INET6 : PF_INET,
					 chip_ver);
		return del_filter_wr(adapter, filter_id, GFP_KERNEL);
	}

	/*
	 * If the caller has passed in a Completion Context then we need to
	 * mark it as a successful completion so they don't stall waiting
	 * for it.
	 */
	if (ctx) {
		ctx->result = 0;
		complete(&ctx->completion);
	}
	return 0;
}
EXPORT_SYMBOL(cxgb4_del_filter);

void clear_all_filters(struct adapter *adapter)
{
	unsigned int i;

	if (adapter->tids.ftid_tab) {
		struct filter_entry *f = &adapter->tids.ftid_tab[0];

		for (i = 0; i < (adapter->tids.nftids +
				 adapter->tids.nsftids +
				 adapter->tids.nhpftids); i++, f++)
			if (f->valid || f->pending)
				clear_filter(adapter, f);
	}

	if (is_hashfilter(adapter) && adapter->tids.tid_tab) {
		unsigned int sb = adapter->tids.stid_base;

		if (sb) {
			for (i = 0; i < sb; i++) {
				struct filter_entry *f = (struct filter_entry *)
					adapter->tids.tid_tab[i];

				if (f && (f->valid || f->pending))
					kfree(f);
			}

			for (i = adapter->tids.hash_base;
					i <= adapter->tids.ntids; i++) {
				struct filter_entry *f = (struct filter_entry *)
					adapter->tids.tid_tab[i];

				if (f && (f->valid || f->pending))
					kfree(f);
			}
		}
	}
}

void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags)
{
	unsigned int i;
	u32 srv_idx_reg;

	if (adapter->tids.ftid_tab) {
		struct filter_entry *f = &adapter->tids.ftid_tab[0];

		for (i = 0; i < (adapter->tids.nftids +
				 adapter->tids.nsftids +
				 adapter->tids.nhpftids); i++, f++)
			if (f->valid)
				clear_filter(adapter, f);
	}

	if (CHELSIO_CHIP_VERSION(adapter->params.chip) <= CHELSIO_T5)
		srv_idx_reg = A_LE_DB_SERVER_INDEX;
	else
		srv_idx_reg = A_LE_DB_SRVR_START_INDEX;
	if (is_hashfilter(adapter) && adapter->tids.tid_tab) {
		unsigned int sb = t4_read_reg(adapter, srv_idx_reg) / 4;

		if (sb) {
			for (i = 0; i < sb; i++) {
				struct filter_entry *f = (struct filter_entry *)
					adapter->tids.tid_tab[i];

				if (f && f->valid)
					cxgb4_del_hash_filter(adapter->port[0],
								f->tid, NULL,
								flags);
			}

			for (i = adapter->tids.hash_base;
				i <= adapter->tids.ntids; i++) {
				struct filter_entry *f = (struct filter_entry *)
						adapter->tids.tid_tab[i];

				if (f && f->valid)
					cxgb4_del_hash_filter(adapter->port[0],
								f->tid, NULL,
								flags);
			}
		}
	}
}
EXPORT_SYMBOL(cxgb4_flush_all_filters);

static int cxgb4_del_hash_filter(struct net_device *dev, int filter_id,
			  struct filter_ctx *ctx, gfp_t flags)
{
	struct adapter *adapter = netdev2adap(dev);
	struct tid_info *t = &adapter->tids;
	struct filter_entry *f;
	int ret;

	CH_MSG(adapter, INFO, HW,
		"%s: filter_id = %d ; nftids = %d\n",
		__func__, filter_id, adapter->tids.nftids);

	if (unlikely(tid_out_of_range(t, filter_id))) {
		CH_ERR(adapter, "%s: hash filter TID %u too large\n",
			__func__, filter_id);
		return -E2BIG;
	}

	f = lookup_tid(t, filter_id);
	if (!f) {
		CH_ERR(adapter, "%s: no filter entry for filter_id = %d",
			__func__, filter_id);
		return -EINVAL;
	}

	ret = writable_filter(f);
	if (ret)
		return ret;

	if (f->valid) {
		unsigned int wrlen;
		struct sk_buff *skb;
		struct work_request_hdr *wr;
		struct ulptx_idata *aligner;
		struct cpl_set_tcb_field *req;
		struct cpl_abort_req *abort_req;
		struct cpl_abort_rpl *abort_rpl;

		f->ctx = ctx;
		f->pending = 1;

		wrlen = roundup(sizeof(*wr) + (sizeof(*req) + sizeof(*aligner))
				+ sizeof(*abort_req) + sizeof(*abort_rpl), 16);
		skb = alloc_skb(wrlen, flags);
		if (!skb) {
			CH_ERR(adapter, "%s: could not allocate skb ..\n",
				__func__);
			goto out_err;
		}

		set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
		req = (struct cpl_set_tcb_field *)__skb_put(skb, wrlen);
		INIT_ULPTX_WR(req, wrlen, 0, 0);
		wr = (struct work_request_hdr *)req;
		wr++;
		req = (struct cpl_set_tcb_field *)wr;
		mk_set_tcb_field_ulp(f, req, W_TCB_RSS_INFO,
					V_TCB_RSS_INFO(M_TCB_RSS_INFO),
					V_TCB_RSS_INFO(
					adapter->sge.fw_evtq.abs_id), 0, 1);
		aligner = (struct ulptx_idata *)(req + 1);
		abort_req = (struct cpl_abort_req *)(aligner + 1);
		mk_abort_req_ulp(abort_req, f->tid);
		abort_rpl = (struct cpl_abort_rpl *)(abort_req + 1);
		mk_abort_rpl_ulp(abort_rpl, f->tid);
		t4_ofld_send(adapter, skb);

		return 0;
	}
	return 0;

out_err:
	return -ENOMEM;
}

/*
 * Clear a filter and release any of its resources that we own.  This also
 * clears the filter's "pending" status.
 */
void clear_filter(struct adapter *adap, struct filter_entry *f)
{
	struct port_info *pi = netdev_priv(f->dev);
	unsigned int chip_ver = CHELSIO_CHIP_VERSION(adap->params.chip);

	/*
	 * If the filter has loopback rewriteing rules then we'll need to free
	 * any existing Layer Two Table (L2T) entries of the filter rule.  The
	 * firmware will handle freeing up any Source MAC Table (SMT) entries
	 * used for rewriting Source MAC Addresses in loopback rules.
	 */
	if (f->l2t)
		cxgb4_l2t_release(f->l2t);

	if (f->smt)
		cxgb4_smt_release(f->smt);

	if (f->fs.val.encap_vld && f->fs.val.ovlan_vld)
		cxgb_free_encap_mac_filt(adap, pi->viid,
					 f->fs.val.ovlan & 0x1ff, 0);

	if ((chip_ver == CHELSIO_T6) && f->fs.type)
		cxgb4_clip_release_filter(f->dev, (const u32 *)&f->fs.val.lip,
					  (const u32 *)&f->fs.mask.lip, 1);

	/*
	 * The zeroing of the filter rule below clears the filter valid,
	 * pending, locked flags, l2t pointer, etc. so it's all we need for
	 * this operation.
	 */
	memset(f, 0, sizeof(*f));
}


int init_hash_filter(struct adapter *adap)
{
	unsigned int hash_size = 512 * 1024;
	unsigned int n_user_filters;
	unsigned int user_filter_perc;
	int i, ret;
	u32 params[7], val[7];

	/* On T6, if hash filter is enabled with or without ofld enabled, verify
	 * necessary register configs and warn the user in case of improper
	 * config.
	 */
	if (is_t6(adap->params.chip)) {
		if (is_offload(adap)) {
			if (!(t4_read_reg(adap, A_TP_GLOBAL_CONFIG)
			    & F_ACTIVEFILTERCOUNTS))
				pr_warn("%s: Invalid hash filter + ofld" 
					" config\n", __func__);
		} else {
			if (G_TCAM_ACTV_HIT(
				t4_read_reg(adap, A_LE_DB_RSP_CODE_0)) != 4)
				pr_warn("%s: Invalid hash filter config\n",
					__func__);

			if (G_HASH_ACTV_HIT(
				t4_read_reg(adap, A_LE_DB_RSP_CODE_1)) != 4)
				pr_warn("%s: Invalid hash filter config\n",
					__func__);
		}
	}


#define FW_PARAM_DEV(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_DEV) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_DEV_##param))

#define FW_PARAM_PFVF(param) \
	(V_FW_PARAMS_MNEM(FW_PARAMS_MNEM_PFVF) | \
	V_FW_PARAMS_PARAM_X(FW_PARAMS_PARAM_PFVF_##param)|  \
	V_FW_PARAMS_PARAM_Y(0) | \
	V_FW_PARAMS_PARAM_Z(0))

#define MAX_ATIDS 8192U

	params[0] = FW_PARAM_DEV(NTID);
	params[1] = FW_PARAM_PFVF(SERVER_START);
	params[2] = FW_PARAM_PFVF(SERVER_END);
	params[3] = FW_PARAM_PFVF(TDDP_START);
	params[4] = FW_PARAM_PFVF(TDDP_END);
	params[5] = FW_PARAM_DEV(FLOWC_BUFFIFO_SZ);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 6,
			      params, val);
	if (ret < 0)
		return ret;
	adap->tids.ntids = val[0];
	adap->tids.natids = min(adap->tids.ntids / 2, MAX_ATIDS);
	adap->tids.stid_base = val[1];
	adap->tids.nstids = val[2] - val[1] + 1;

	user_filter_perc = 100;
	n_user_filters = mult_frac(adap->tids.nftids,
				   user_filter_perc,
				   100);
	adap->tids.sftid_base = adap->tids.ftid_base + n_user_filters;
	adap->tids.nsftids = adap->tids.nftids - n_user_filters;
	adap->tids.nftids = adap->tids.sftid_base -
			     adap->tids.ftid_base;

	adap->filter_tcphash.ehash_mask = adap->filter_udphash.ehash_mask =
						hash_size - 1;
	adap->filter_tcphash.ehash = t4_alloc_mem(hash_size *
					  sizeof(struct filter_ehash_bucket));

	if (!adap->filter_tcphash.ehash) {
		pr_err("%s: No mem for filter_tcphash.ehash ..\n",
			__func__);
		return -ENOMEM;
	}

	if (ehash_filter_locks_alloc(&adap->filter_tcphash)) {
		pr_err("%s: Failed to alloc locks for filter_tcphash ..\n",
			__func__);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}


	adap->filter_udphash.ehash = t4_alloc_mem(hash_size *
					sizeof(struct filter_ehash_bucket));

	if (!adap->filter_udphash.ehash) {
		pr_err("%s: No mem for filter_udphash.ehash ..\n",
			__func__);
		ehash_filter_locks_free(&adap->filter_tcphash);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}

	if (ehash_filter_locks_alloc(&adap->filter_udphash)) {
		pr_err("%s: Failed to alloc locks for filter_udphash ..\n",
			__func__);
		t4_free_mem(adap->filter_udphash.ehash);
		ehash_filter_locks_free(&adap->filter_tcphash);
		t4_free_mem(adap->filter_tcphash.ehash);
		return -ENOMEM;
	}

	for (i = 0; i <= adap->filter_tcphash.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&adap->filter_tcphash.ehash[i].chain, i);


	for (i = 0; i <= adap->filter_udphash.ehash_mask; i++)
		INIT_HLIST_NULLS_HEAD(&adap->filter_udphash.ehash[i].chain, i);

	adap->vres.ddp.start = val[3];
	adap->vres.ddp.size = val[4] - val[3] + 1;
	adap->params.ofldq_wr_cred = val[5];

	params[0] = FW_PARAM_PFVF(ETHOFLD_START);
	params[1] = FW_PARAM_PFVF(ETHOFLD_END);
	ret = t4_query_params(adap, adap->mbox, adap->pf, 0, 2, params, val);
	if ((val[0] != val[1]) && (ret >= 0)) {
		adap->tids.uotid_base = val[0];
		adap->tids.nuotids = val[1] - val[0] + 1;
	}

	adap->params.hash_filter = 1;
	return 0;
}

/*
 * Handle a filter write/deletion reply.
 */
void filter_rpl(struct adapter *adap, const struct cpl_set_tcb_rpl *rpl)
{
	unsigned int tid = GET_TID(rpl);
	struct filter_entry *f = NULL;
	int idx, max_fidx = adap->tids.nftids + adap->tids.nsftids +
			    adap->tids.nhpftids;

	/* Get the corresponding filter entry for this tid */
	if (adap->tids.ftid_tab) {
		/* Check this in hi-prio filter region */
		idx = tid - adap->tids.hpftid_base;
		if (idx < adap->tids.nhpftids) {
			f = &adap->tids.ftid_tab[idx];
			if (f->tid != tid)
				return;
		} else {
			/* Check this in normal filter region */
			idx = tid - adap->tids.ftid_base + adap->tids.nhpftids;
			if (idx >= max_fidx)
				return;
			f = &adap->tids.ftid_tab[idx];
			if (f->tid != tid)
				return;
		}
	}

	/* We found the filter entry for this tid */
	if (f) {
		unsigned int ret = G_COOKIE(rpl->cookie);
		struct filter_ctx *ctx;

		/*
		 * Pull off any filter operation context attached to the
		 * filter.
		 */
		ctx = f->ctx;
		f->ctx = NULL;

		if (ret == FW_FILTER_WR_FLT_DELETED) {
			/*
			 * Clear the filter when we get confirmation from the
			 * hardware that the filter has been deleted.
			 */
			clear_filter(adap, f);
			if (ctx)
				ctx->result = 0;
		} else if (ret == FW_FILTER_WR_FLT_ADDED) {
			f->pending = 0;  /* asynchronous setup completed */
			f->valid = 1;
			if (ctx) {
				ctx->result = 0;
				ctx->tid = idx;
			}
		} else {
			/*
			 * Something went wrong.  Issue a warning about the
			 * problem and clear everything out.
			 */
			CH_ERR(adap, "filter %u setup failed with error %u\n",
			       idx, ret);
			clear_filter(adap, f);
			if (ctx)
				ctx->result = -EINVAL;
		}
		if (ctx)
			complete(&ctx->completion);
	}
}

void hash_del_filter_rpl(struct adapter *adap,
				const struct cpl_abort_rpl_rss *rpl)
{
	struct tid_info *t = &adap->tids;
	unsigned int tid = GET_TID(rpl);
	unsigned int status = rpl->status;
	struct filter_entry *f;
	struct filter_ctx *ctx = NULL;
	struct port_info *pi;
	spinlock_t *lock;

	CH_MSG(adap, INFO, HW,
	       "%s: status = %u; tid = %u\n", __func__, status, tid);

	f = lookup_tid(t, tid);
	if (!f) {
		CH_WARN_RATELIMIT(adap,
			"%s:could not find filter entry", __func__);
		return;
	}

	ctx = f->ctx;
	f->ctx = NULL;
	pi = netdev_priv(f->dev);

	if (f->fs.val.proto == IPPROTO_UDP)
		lock = &adap->filter_udphash.ehash_filter_locks[f->filter_hash &
			adap->filter_udphash.ehash_filter_locks_mask];
	else
		lock = &adap->filter_tcphash.ehash_filter_locks[f->filter_hash &
			adap->filter_tcphash.ehash_filter_locks_mask];
	spin_lock_bh(lock);
	f->valid = 0;
	/* remove hash entry */
	hlist_nulls_del_init_rcu(&f->filter_nulls_node);

	if (f->l2t)
		cxgb4_l2t_release(f->l2t);

	if (f->smt)
		cxgb4_smt_release(f->smt);
	spin_unlock_bh(lock);

	if (f->fs.type)
		cxgb4_clip_release_filter(f->dev, (const u32 *)&f->fs.val.lip,
					  (const u32 *)&f->fs.mask.lip, 1);

	if (f->fs.val.encap_vld && f->fs.val.ovlan_vld)
		cxgb_free_encap_mac_filt(adap, pi->viid,
					 f->fs.val.ovlan & 0x1ff, 0);

	cxgb4_remove_tid(t, 0, tid, 0);
	kfree(f);

	if (ctx) {
		ctx->result = 0;
		complete(&ctx->completion);
	}
}

unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
			  const __u16 lport, const __be32 faddr,
			  const __be16 fport)
{
	static u32 inet_ehash_secret __read_mostly;

	net_get_random_once(&inet_ehash_secret, sizeof(inet_ehash_secret));

	return __inet_ehashfn(laddr, lport, faddr, fport,
			      inet_ehash_secret + net_hash_mix(net));
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
unsigned int t4_inet6_ehashfn(struct net *net,
			      const struct in6_addr *laddr,
			      const u16 lport,
			      const struct in6_addr *faddr,
			      const __be16 fport)
{
	static u32 inet6_ehash_secret __read_mostly;
	static u32 ipv6_hash_secret __read_mostly;

	u32 lhash, fhash;

	net_get_random_once(&inet6_ehash_secret, sizeof(inet6_ehash_secret));
	net_get_random_once(&ipv6_hash_secret, sizeof(ipv6_hash_secret));

	lhash = (__force u32)laddr->s6_addr32[3];
	fhash = __ipv6_addr_jhash(faddr, ipv6_hash_secret);

	return __inet6_ehashfn(lhash, lport, fhash, fport,
			       inet6_ehash_secret + net_hash_mix(net));
}
#else
unsigned int t4_inet6_ehashfn(struct net *net,
			      const struct in6_addr *laddr,
			      const u16 lport,
			      const struct in6_addr *faddr,
			      const __be16 fport)
{
	return 0;
}
#endif

static void set_tcb_field(struct adapter *adap, struct filter_entry *f,
		   unsigned int ftid,  u16 word, u64 mask, u64 val,
		   int no_reply)
{
	struct sk_buff *skb;
	struct cpl_set_tcb_field *req;

	skb = alloc_skb(sizeof(struct cpl_set_tcb_field), GFP_ATOMIC);
	BUG_ON(!skb);

	req = (struct cpl_set_tcb_field *)__skb_put(skb, sizeof(*req));
	memset(req, 0, sizeof(*req));
	INIT_TP_WR_MIT_CPL(req, CPL_SET_TCB_FIELD, ftid);
	req->reply_ctrl = htons(V_REPLY_CHAN(0) |
				V_QUEUENO(adap->sge.fw_evtq.abs_id) |
				V_NO_REPLY(no_reply));
	req->word_cookie = htons(V_WORD(word) | V_COOKIE(ftid));
	req->mask = cpu_to_be64(mask);
	req->val = cpu_to_be64(val);

	set_wr_txq(skb, CPL_PRIORITY_CONTROL, f->fs.val.iport & 0x3);
	t4_ofld_send(adap, skb);
}

static void set_nat_params(struct adapter *adap, struct filter_entry *f,
			   unsigned int tid, bool dip, bool sip,
			   bool dp, bool sp)
{
	if (dip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW,
				      WORD_MASK, f->fs.nat_lip[15] |
				      f->fs.nat_lip[14] << 8 |
				      f->fs.nat_lip[13] << 16 |
				      f->fs.nat_lip[12] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 1,
				      WORD_MASK, f->fs.nat_lip[11] |
				      f->fs.nat_lip[10] << 8 |
				      f->fs.nat_lip[9] << 16 |
				      f->fs.nat_lip[8] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 2,
				      WORD_MASK, f->fs.nat_lip[7] |
				      f->fs.nat_lip[6] << 8 |
				      f->fs.nat_lip[5] << 16 |
				      f->fs.nat_lip[4] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_SND_UNA_RAW + 3,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      f->fs.nat_lip[0] << 24, 1);
		} else {
			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG3_LEN_RAW,
				      WORD_MASK, f->fs.nat_lip[3] |
				      f->fs.nat_lip[2] << 8 |
				      f->fs.nat_lip[1] << 16 |
				      f->fs.nat_lip[0] << 24, 1);
		}
	}

	if (sip) {
		if (f->fs.type) {
			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW,
				      WORD_MASK, f->fs.nat_fip[15] |
				      f->fs.nat_fip[14] << 8 |
				      f->fs.nat_fip[13] << 16 |
				      f->fs.nat_fip[12] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 1,
				      WORD_MASK, f->fs.nat_fip[11] |
				      f->fs.nat_fip[10] << 8 |
				      f->fs.nat_fip[9] << 16 |
				      f->fs.nat_fip[8] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 2,
				      WORD_MASK, f->fs.nat_fip[7] |
				      f->fs.nat_fip[6] << 8 |
				      f->fs.nat_fip[5] << 16 |
				      f->fs.nat_fip[4] << 24, 1);

			set_tcb_field(adap, f, tid, W_TCB_RX_FRAG2_PTR_RAW + 3,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      f->fs.nat_fip[0] << 24, 1);

		} else {
			set_tcb_field(adap, f, tid,
				      W_TCB_RX_FRAG3_START_IDX_OFFSET_RAW,
				      WORD_MASK, f->fs.nat_fip[3] |
				      f->fs.nat_fip[2] << 8 |
				      f->fs.nat_fip[1] << 16 |
				      f->fs.nat_fip[0] << 24, 1);
		}
	}

	set_tcb_field(adap, f, tid, W_TCB_PDU_HDR_LEN, WORD_MASK,
		      (dp ? f->fs.nat_lport : 0) |
		      (sp ? f->fs.nat_fport << 16 : 0), 1);
}

void hash_filter_rpl(struct adapter *adap,
			    const struct cpl_act_open_rpl *rpl)
{
	struct tid_info *t = &adap->tids;
	unsigned int tid = GET_TID(rpl);
	unsigned int ftid = G_TID_TID(G_AOPEN_ATID(ntohl(rpl->atid_status)));
	unsigned int status  = G_AOPEN_STATUS(ntohl(rpl->atid_status));
	struct filter_entry *f;
	struct filter_ctx *ctx = NULL;

	CH_MSG(adap, INFO, HW,
	       "%s: tid = %u; atid = %u; status = %u\n",
	       __func__, tid, ftid, status);

#ifdef CONFIG_PO_FCOE
	/* ATID is 14 bit value [0..13], MAX_ATIDS is 8192
	 * ATID needs max 13 bits [0..12], using 13th bit in
	 * ATID for FCoE CPL_ACT_OPEN_REQ.
	 */
	if (ftid & BIT(CXGB_FCOE_ATID)) {
		cxgb_fcoe_cpl_act_open_rpl(adap, ftid, tid, status);
		return;
	}
#endif

	f = lookup_atid(t, ftid);
	if (!f) {
		CH_WARN_RATELIMIT(adap, "%s:could not find filter entry",
			__func__);
		return;
	}

	ctx = f->ctx;
	f->ctx = NULL;

	switch (status) {
	case CPL_ERR_NONE:
		{
			struct filter_ehash_bucket *head;
			struct hlist_nulls_head *list;
			spinlock_t *lock;

			/* hash 4-tuple and add filter entry */
			if (f->fs.type) {
				if (is_t5(adap->params.chip)) {
					f->filter_hash = t4_inet6_ehashfn(dev_net(f->dev),
							(struct in6_addr *)f->fs.val.lip,
							f->fs.val.lport,
							(struct in6_addr *)f->fs.val.fip,
							f->fs.val.fport);
				} else {
					const struct in6_addr *laddr = (struct in6_addr *)f->fs.val.lip;
					const struct in6_addr *faddr = (struct in6_addr *)f->fs.val.fip;
				        u32 lhash, fhash;
					u32 ports = (((u32)f->fs.val.lport) << 16) |
						    (__force u32)f->fs.val.fport;

					lhash = (__force u32)laddr->s6_addr32[3];
					fhash = __ipv6_addr_jhash(faddr, 0);
					f->filter_hash = jhash_3words(lhash, fhash, ports,
								      hash_filter_ntuple(&f->fs, f->dev) &
								      0xFFFFFFFF);
				}
			} else {
				u32 lip = f->fs.val.lip[0] |
					  f->fs.val.lip[1]<<8 |
					  f->fs.val.lip[2]<<16 |
					  f->fs.val.lip[3]<<24;
				u32 fip = f->fs.val.fip[0] |
					  f->fs.val.fip[1]<<8 |
					  f->fs.val.fip[2]<<16 |
					  f->fs.val.fip[3]<<24;

				if (is_t5(adap->params.chip))
					f->filter_hash = inet_ehashfn(dev_net(f->dev),
								      lip,
								      f->fs.val.lport,
								      fip,
								      f->fs.val.fport);
				else
					f->filter_hash = jhash_3words((__force __u32)lip,
								      (__force __u32)fip,
								      ((__u32)f->fs.val.lport) << 16 |
								       (__force __u32)f->fs.val.fport,
								      hash_filter_ntuple(&f->fs, f->dev) &
								      0xFFFFFFFF);
			}

			if (f->fs.val.proto == IPPROTO_UDP) {
				head = &adap->filter_udphash.ehash[f->filter_hash &
					adap->filter_udphash.ehash_mask];
				lock = &adap->filter_udphash.ehash_filter_locks[f->filter_hash &
					adap->filter_udphash.ehash_filter_locks_mask];
			} else {
				head = &adap->filter_tcphash.ehash[f->filter_hash &
					adap->filter_tcphash.ehash_mask];
				lock = &adap->filter_tcphash.ehash_filter_locks[f->filter_hash &
					adap->filter_tcphash.ehash_filter_locks_mask];
			}


			spin_lock_bh(lock);
			list = &head->chain;
			hlist_nulls_add_head_rcu(&f->filter_nulls_node, list);

			/* Store tid value in special filter entry field */
			f->tid = tid;
			f->pending = 0;  /* asynchronous setup completed */
			f->valid = 1;
			spin_unlock_bh(lock);
			cxgb4_insert_tid(t, f, f->tid, 0);
			cxgb4_free_atid(t, ftid);
			if (ctx) {
				ctx->tid = f->tid;
				ctx->result = 0;
			}

			if (f->fs.hitcnts) {
				set_tcb_field(adap, f, tid,
					      W_TCB_TIMESTAMP,
					      V_TCB_TIMESTAMP(M_TCB_TIMESTAMP),
					      V_TCB_TIMESTAMP(0ULL),
					      1);
				set_tcb_field(adap, f, tid,
					      W_TCB_T_RTT_TS_RECENT_AGE,
					      V_TCB_T_RTT_TS_RECENT_AGE(M_TCB_T_RTT_TS_RECENT_AGE),
					      V_TCB_T_RTT_TS_RECENT_AGE(0ULL),
					      1);
			}

			if (f->fs.newdmac)
				set_tcb_tflag(adap, f, tid, S_TF_CCTRL_ECE,
						1, 1);

			if ((f->fs.newvlan == VLAN_INSERT) ||
			    (f->fs.newvlan == VLAN_REWRITE))
				set_tcb_tflag(adap, f, tid, S_TF_CCTRL_RFR,
						1, 1);

			if (f->fs.newsmac) {
				set_tcb_field(adap, f, tid, W_TCB_SMAC_SEL,
					      V_TCB_SMAC_SEL(M_TCB_SMAC_SEL),
					      V_TCB_SMAC_SEL(f->smtidx), 1);
				set_tcb_tflag(adap, f, tid, S_TF_CCTRL_CWR,
					      1, 1);
			}

			if (f->fs.nat_mode) {
				switch(f->fs.nat_mode) {
				case NAT_MODE_DIP:
					set_nat_params(adap, f, tid, true,
						       false, false, false);
					break;

				case NAT_MODE_DIP_DP:
					set_nat_params(adap, f, tid, true,
						       false, true, false);
					break;

				case NAT_MODE_DIP_DP_SIP:
					set_nat_params(adap, f, tid, true,
						       true, true, false);
					break;

				case NAT_MODE_DIP_DP_SP:
					set_nat_params(adap, f, tid, true,
						       false, true, true);
					break;

				case NAT_MODE_SIP_SP:
					set_nat_params(adap, f, tid, false,
						       true, false, true);
					break;

				case NAT_MODE_DIP_SIP_SP:
					set_nat_params(adap, f, tid, true,
						       true, false, true);
					break;

				case NAT_MODE_ALL:
					set_nat_params(adap, f, tid, true,
						       true, true, true);
					break;

				default:
					pr_err("%s: Invalid NAT mode: %d\n",
						__func__, f->fs.nat_mode);
					if (f->l2t)
						cxgb4_l2t_release(f->l2t);
					if(f->smt)
						cxgb4_smt_release(f->smt);
					kfree(f);
					if (ctx) {
						ctx->result = -EINVAL;
						complete(&ctx->completion);
					}
					return;

				}
			}

			if (f->fs.eport >= NUM_UP_TSCH_CHANNEL_INSTANCES)
				set_tcb_tflag(adap, f, tid, S_TF_RECV_TSTMP,
					      1, 1);

			if (f->fs.nat_seq_chk) {
				set_tcb_field(adap, f, tid, W_TCB_RCV_NXT,
					      V_TCB_RCV_NXT(M_TCB_RCV_NXT),
					      V_TCB_RCV_NXT(f->fs.nat_seq_chk),
					      1);
			}

			switch (f->fs.action) {
				case FILTER_PASS:
					if (f->fs.dirsteer)
						set_tcb_tflag(adap, f, tid,
							      S_TF_DIRECT_STEER, 1, 1);
					break;
				case FILTER_DROP:
					set_tcb_tflag(adap, f, tid, S_TF_DROP, 1, 1);
					break;
				case FILTER_SWITCH:
					set_tcb_tflag(adap, f, tid, S_TF_LPBK, 1, 1);
					break;
			}

			if (is_t5(adap->params.chip)) {
				if (f->fs.action == FILTER_DROP) {
					/*
					 * Set Migrating bit to 1, and
					 * set Non-offload bit to 0 - to achieve
					 * Drop action with Hash filters
					 */
					set_tcb_field(adap, f, tid,
						      W_TCB_T_FLAGS,
						      V_TF_NON_OFFLOAD(1) |
						      V_TF_MIGRATING(1),
						      V_TF_MIGRATING(1), 1);
				}
			}

			break;
		}
	default:
		CH_WARN_RATELIMIT(adap,
				  "%s: filter creation PROBLEM; status = %u\n",
				  __func__, status);

		if (ctx) {
			if (status == CPL_ERR_TCAM_FULL)
				ctx->result = -EAGAIN;
			else
				ctx->result = -EINVAL;
		}

		if (f->l2t)
			cxgb4_l2t_release(f->l2t);

		if (f->smt)
			cxgb4_smt_release(f->smt);

		cxgb4_free_atid(t, ftid);
		kfree(f);
	}

	if (ctx)
		complete(&ctx->completion);
}
