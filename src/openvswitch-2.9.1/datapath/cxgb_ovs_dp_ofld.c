/*
 * Copyright (C) 2017-2018 Chelsio Communications.  All rights reserved.
 *
 * Author: Kumar Sanghvi <kumaras@chelsio.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <linux/if_vlan.h>

#include "datapath.h"
#include "conntrack.h"
#include "flow.h"
#include "flow_netlink.h"
#include "vport.h"

/* Mask is at the midpoint of the data. */
#define get_mask(a, type) ((const type)nla_data(a) + 1)

static void cxgb_process_flow_actions(struct sw_flow *flow,
				      struct ch_filter_specification *fs)
{
	const struct nlattr *a;
	int rem;

	nla_for_each_attr(a, flow->sf_acts->actions,
			  flow->sf_acts->actions_len, rem) {
		pr_debug("%s: nla_type = %d\n", __func__, nla_type(a));
		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
		{
			struct nlattr *b = nla_data(a);
			switch (nla_type(b)) {
			case OVS_KEY_ATTR_ETHERNET:
			{
				const struct ovs_key_ethernet *act_eth_key,
				      			      *act_eth_mask;

				pr_debug("%s: OVS_KEY_ATTR_ETHERNET.. \n",
					 __func__);
				act_eth_key = nla_data(b);
				act_eth_mask = get_mask(b,
						struct ovs_key_ethernet *);

				if (act_eth_mask->eth_src[0] == 0xff &&
				    act_eth_mask->eth_src[1] == 0xff &&
				    act_eth_mask->eth_src[2] == 0xff &&
				    act_eth_mask->eth_src[3] == 0xff &&
				    act_eth_mask->eth_src[4] == 0xff &&
				    act_eth_mask->eth_src[5] == 0xff) {
					fs->newsmac = true;
					memcpy(fs->smac, act_eth_key->eth_src,
					       ETH_ALEN);
				}

				if (act_eth_mask->eth_dst[0] == 0xff &&
				    act_eth_mask->eth_dst[1] == 0xff &&
				    act_eth_mask->eth_dst[2] == 0xff &&
				    act_eth_mask->eth_dst[3] == 0xff &&
				    act_eth_mask->eth_dst[4] == 0xff &&
				    act_eth_mask->eth_dst[5] == 0xff) {
					fs->newdmac = true;
					memcpy(fs->dmac, act_eth_key->eth_dst,
					       ETH_ALEN);
				}
				break;
			}
			case OVS_KEY_ATTR_IPV4:
			{
				const struct ovs_key_ipv4 *act_ipv4_key,
				      			  *act_ipv4_mask;

				pr_debug("%s: OVS_KEY_ATTR_IPV4:..\n",
					 __func__);
				act_ipv4_key = nla_data(b);
				act_ipv4_mask = get_mask(b,
						struct ovs_key_ipv4 *);

				if (act_ipv4_mask->ipv4_src == 0xffffffff)
					*(u32 *)&fs->nat_fip =
						act_ipv4_key->ipv4_src;

				if (act_ipv4_mask->ipv4_dst == 0xffffffff)
					*(u32 *)&fs->nat_lip =
						act_ipv4_key->ipv4_dst;

				break;
			}
			case OVS_KEY_ATTR_IPV6:
			{
				const struct ovs_key_ipv6 *act_ipv6_key,
				      			  *act_ipv6_mask;

				pr_debug("%s: OVS_KEY_ATTR_IPV6:..\n",
					 __func__);
				act_ipv6_key = nla_data(b);
				act_ipv6_mask = get_mask(b,
						struct ovs_key_ipv6 *);

				if(act_ipv6_mask->ipv6_src[0] == 0xffffffff &&
				   act_ipv6_mask->ipv6_src[1] == 0xffffffff &&
				   act_ipv6_mask->ipv6_src[2] == 0xffffffff &&
				   act_ipv6_mask->ipv6_src[3] == 0xffffffff)
					*(struct in6_addr *)&fs->nat_fip =
					*(struct in6_addr *)act_ipv6_key->ipv6_src;

				if(act_ipv6_mask->ipv6_dst[0] == 0xffffffff &&
				   act_ipv6_mask->ipv6_dst[1] == 0xffffffff &&
				   act_ipv6_mask->ipv6_dst[2] == 0xffffffff &&
				   act_ipv6_mask->ipv6_dst[3] == 0xffffffff)
					*(struct in6_addr *)&fs->nat_lip =
					*(struct in6_addr *)act_ipv6_key->ipv6_dst;
				break;
			}
			case OVS_KEY_ATTR_UDP:
			{
				const struct ovs_key_udp *act_udp_key,
							 *act_udp_mask;

				pr_debug("%s: OVS_KEY_ATTR_UDP:..\n",
					 __func__);
				act_udp_key = nla_data(b);
				act_udp_mask = get_mask(b,
						struct ovs_key_udp *);

				if (act_udp_mask->udp_src == 0xffff)
					fs->nat_fport =
						cpu_to_be16(act_udp_key->udp_src);

				if (act_udp_mask->udp_dst == 0xffff)
					fs->nat_lport =
						cpu_to_be16(act_udp_key->udp_dst);

				break;
			}
			case OVS_KEY_ATTR_TCP:
			{
				const struct ovs_key_tcp *act_tcp_key,
				      			 *act_tcp_mask;

				pr_debug("%s: OVS_KEY_ATTR_TCP:..\n",
					 __func__);
				act_tcp_key = nla_data(b);
				act_tcp_mask = get_mask(b,
						struct ovs_key_tcp *);

				if (act_tcp_mask->tcp_src == 0xffff)
					fs->nat_fport =
						cpu_to_be16(act_tcp_key->tcp_src);

				if (act_tcp_mask->tcp_dst == 0xffff)
					fs->nat_lport =
						cpu_to_be16(act_tcp_key->tcp_dst);

				break;
			}
			default:
				break;
			};
			break;
		}

		case OVS_ACTION_ATTR_POP_VLAN:
			pr_debug("%s: OVS_ACTION_ATTR_POP_VLAN: case.. \n",
				 __func__);
			fs->newvlan |= VLAN_REMOVE;
			break;

		case OVS_ACTION_ATTR_PUSH_VLAN:
		{
			struct ovs_action_push_vlan *vlan = nla_data(a);

			pr_debug("%s: OVS_ACTION_ATTR_PUSH_VLAN: case.. \n",
				 __func__);
			fs->newvlan |= VLAN_INSERT;
			fs->vlan = ntohs(vlan->vlan_tci) & ~VLAN_TAG_PRESENT;
			break;
		}
		default:
			break;
		}
	}
}

static int cxgb_validate_flow_actions(struct sw_flow *flow, u32 *output_port,
				      u8 *action)
{
	bool action_nosupp = false;
	const struct nlattr *a;
	int rem;

	nla_for_each_attr(a, flow->sf_acts->actions, flow->sf_acts->actions_len,
			 rem) {
		pr_debug("%s: nla_type = %d\n", __func__, nla_type(a));
		switch (nla_type(a)) {
		case OVS_ACTION_ATTR_OUTPUT:
			pr_debug("%s: output-port = %d\n", __func__, nla_get_u32(a));
			*output_port = nla_get_u32(a);
			*action = FILTER_SWITCH;
			break;
		case OVS_ACTION_ATTR_SET_MASKED:
		case OVS_ACTION_ATTR_SET_TO_MASKED:
		{
			struct nlattr *b = nla_data(a);

			pr_debug("%s: nla_type = %d\n", __func__, nla_type(b));
			switch (nla_type(b)) {
			case OVS_KEY_ATTR_ETHERNET:
				pr_debug("%s: OVS_KEY_ATTR_ETHERNET: case.. \n",
					 __func__);
				break;
			case OVS_KEY_ATTR_IPV4:
			{
				const struct ovs_key_ipv4 *act_ipv4_mask;

				pr_debug("%s: OVS_KEY_ATTR_IPV4: case..\n",
					 __func__);
				act_ipv4_mask = get_mask(b,
						struct ovs_key_ipv4 *);
				if (act_ipv4_mask->ipv4_proto ||
				    act_ipv4_mask->ipv4_ttl ||
				    act_ipv4_mask->ipv4_tos ||
				    act_ipv4_mask->ipv4_frag)
					action_nosupp = true;
				break;
			}
			case OVS_KEY_ATTR_IPV6:
			{
				const struct ovs_key_ipv6 *act_ipv6_mask;

				pr_debug("%s: OVS_KEY_ATTR_IPV6: case..\n",
					 __func__);
				act_ipv6_mask = get_mask(b,
						struct ovs_key_ipv6 *);
				if (act_ipv6_mask->ipv6_tclass ||
				    act_ipv6_mask->ipv6_label ||
				    act_ipv6_mask->ipv6_hlimit)
					action_nosupp = true;
				break;
			}
			case OVS_KEY_ATTR_UDP:
				pr_debug("%s: OVS_KEY_ATTR_UDP: case.. \n",
					 __func__);
				break;
			case OVS_KEY_ATTR_TCP:
				pr_debug("%s: OVS_KEY_ATTR_TCP: case.. \n",
					 __func__);
				break;
			default:
				action_nosupp = true;
				break;
			}
			break;
		}
		case OVS_ACTION_ATTR_POP_VLAN:
		case OVS_ACTION_ATTR_PUSH_VLAN:
			break;
		default:
			action_nosupp = true;
			break;
		}
	}

	if (action_nosupp) {
		pr_debug("%s: un-supported action for offload..\n", __func__);
		return 1;
	}

	return 0;
}

static int cxgb_validate_flow_match(struct sw_flow *flow,
				    const struct sw_flow_mask *mask)
{
	pr_debug("%s: flow->key: in_port = %d; src-mac = %x:%x:%x:%x:%x:%x; "
		 "dst-mac = %x:%x:%x:%x:%x:%x; eth-tci = %d; eth-type = %x; "
		 "ip-proto = %d; ip-tos = %d; ip-frag = %d; ip-src = %x; "
		 "ip-dst = %x; tcp-src = %d; tcp-dst = %d; tcp-flags = %x\n",
		 __func__, flow->key.phy.in_port, flow->key.eth.src[0],
		 flow->key.eth.src[1], flow->key.eth.src[2],
		 flow->key.eth.src[3], flow->key.eth.src[4],
		 flow->key.eth.src[5], flow->key.eth.dst[0],
		 flow->key.eth.dst[1], flow->key.eth.dst[2],
		 flow->key.eth.dst[3], flow->key.eth.dst[4],
		 flow->key.eth.dst[5],
		 be16_to_cpu(flow->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT,
		 be16_to_cpu(flow->key.eth.type),
		 flow->key.ip.proto, flow->key.ip.tos, flow->key.ip.frag,
		 be32_to_cpu(flow->key.ipv4.addr.src),
		 be32_to_cpu(flow->key.ipv4.addr.dst), be16_to_cpu(flow->key.tp.src),
		 be16_to_cpu(flow->key.tp.dst), be16_to_cpu(flow->key.tp.flags));

	pr_debug("%s: TUN flow: tun_id = %llx; ip-src = %x; ip-dst = %x; "
		 " tun_flags = %u; tos = %d; ttl = %d; lable = %u; "
		 "l4-src = %u; l4-dst = %u\n",
		 __func__, be64_to_cpu(flow->key.tun_key.tun_id),
		 be32_to_cpu(flow->key.tun_key.u.ipv4.src),
		 be32_to_cpu(flow->key.tun_key.u.ipv4.dst),
		 be16_to_cpu(flow->key.tun_key.tun_flags),
		 flow->key.tun_key.tos, flow->key.tun_key.ttl,
		 be32_to_cpu(flow->key.tun_key.label),
		 be16_to_cpu(flow->key.tun_key.tp_src),
		 be16_to_cpu(flow->key.tun_key.tp_dst));

	if (flow->mask)
		pr_debug("%s: flow->mask: in_port = %d; src-mac = %x:%x:%x:%x:%x:%x; "
			 "dst-mac = %x:%x:%x:%x:%x:%x; eth-type = %d; ip-proto = %d; "
			 "ip-src = %x; ip-dst = %x; tcp-src = %d; tcp-dst = %d; "
			 "tcp-flags = %x\n",
			 __func__, flow->mask->key.phy.in_port,
			 flow->mask->key.eth.src[0], flow->mask->key.eth.src[1],
			 flow->mask->key.eth.src[2], flow->mask->key.eth.src[3],
			 flow->mask->key.eth.src[4], flow->mask->key.eth.src[5],
			 flow->mask->key.eth.dst[0], flow->mask->key.eth.dst[1],
			 flow->mask->key.eth.dst[2], flow->mask->key.eth.dst[3],
			 flow->mask->key.eth.dst[4], flow->mask->key.eth.dst[5],
			 be16_to_cpu(flow->mask->key.eth.type),
			 flow->mask->key.ip.proto,
			 be32_to_cpu(flow->mask->key.ipv4.addr.src),
			 be32_to_cpu(flow->mask->key.ipv4.addr.dst),
			 be16_to_cpu(flow->mask->key.tp.src),
			 be16_to_cpu(flow->mask->key.tp.dst),
			 be16_to_cpu(flow->mask->key.tp.flags));

	pr_debug("%s: mask: in_port = %d; src-mac = %x:%x:%x:%x:%x:%x; "
		 "dst-mac = %x:%x:%x:%x:%x:%x; eth-tci = %x; eth-type = %x; "
		 "ip-proto = %x; ip-tos = %x; ip-frag = %x; ip-src = %x; "
		 "ip-dst = %x; tcp-src = %x; tcp-dst = %x; tcp-flags = %x\n",
		 __func__, mask->key.phy.in_port, mask->key.eth.src[0],
		 mask->key.eth.src[1], mask->key.eth.src[2],
		 mask->key.eth.src[3], mask->key.eth.src[4],
		 mask->key.eth.src[5], mask->key.eth.dst[0],
		 mask->key.eth.dst[1], mask->key.eth.dst[2],
		 mask->key.eth.dst[3], mask->key.eth.dst[4],
		 mask->key.eth.dst[5],
		 be16_to_cpu(mask->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT,
		 be16_to_cpu(mask->key.eth.type),
		 mask->key.ip.proto, mask->key.ip.tos, mask->key.ip.frag,
		 be32_to_cpu(mask->key.ipv4.addr.src),
		 be32_to_cpu(mask->key.ipv4.addr.dst),
		 be16_to_cpu(mask->key.tp.src), be16_to_cpu(mask->key.tp.dst),
		 be16_to_cpu(mask->key.tp.flags));

	pr_debug("%s: TUN mask: tun_id = %llx; ip-src = %x; ip-dst = %x; "
		 "tun_flags = %u; tos = %d; ttl = %d; lable = %u; "
		 "l4-src = %u; l4-dst = %u\n",
		 __func__, be64_to_cpu(mask->key.tun_key.tun_id),
		 be32_to_cpu(mask->key.tun_key.u.ipv4.src),
		 be32_to_cpu(mask->key.tun_key.u.ipv4.dst),
		 be16_to_cpu(mask->key.tun_key.tun_flags),
		 mask->key.tun_key.tos, mask->key.tun_key.ttl,
		 be32_to_cpu(mask->key.tun_key.label),
		 be16_to_cpu(mask->key.tun_key.tp_src),
		 be16_to_cpu(mask->key.tun_key.tp_dst));

	if ((mask->key.eth.src[0] | mask->key.eth.src[1] | mask->key.eth.src[2] |
	     mask->key.eth.src[3] | mask->key.eth.src[4] | mask->key.eth.src[5])) {
		bool smac_match_ignore = false;
		const struct nlattr *a;
		int rem;

		nla_for_each_attr(a, flow->sf_acts->actions,
				  flow->sf_acts->actions_len, rem) {
			switch (nla_type(a)) {
			case OVS_ACTION_ATTR_SET_MASKED:
			case OVS_ACTION_ATTR_SET_TO_MASKED:
			{
				struct nlattr *b = nla_data(a);

				switch (nla_type(b)) {
				case OVS_KEY_ATTR_ETHERNET:
				{
					const struct ovs_key_ethernet *act_eth_mask;

					act_eth_mask = get_mask(b,
							struct ovs_key_ethernet *);

					if (act_eth_mask->eth_src[0] == 0xff &&
					    act_eth_mask->eth_src[1] == 0xff &&
					    act_eth_mask->eth_src[2] == 0xff &&
					    act_eth_mask->eth_src[3] == 0xff &&
					    act_eth_mask->eth_src[4] == 0xff &&
					    act_eth_mask->eth_src[5] == 0xff) {
						smac_match_ignore = true;
					}
					break;
				}
				default:
					break;
				}
				break;
			}
			default:
				break;
			}
		}

		/* OVS datapath puts a source mac-match in the rule when
		 * dl_mod_src is used - even though source mac-match is not
		 * given in original ofctl rule.
		 * So, below is a hack to ignore source mac-match. Else,
		 * dl_mod_src can't be offloaded.
		 * Note that this condition will definitely fail when source
		 * mac-match is actually also provided in the same rule as
		 * dl_mod_src.
		 */
		if (!smac_match_ignore) {
			pr_err("%s: src-mac match not supported for offload..\n",
				__func__);
			return -1;
		}
	}

	if (cpu_to_be16(flow->key.eth.type) == ETH_P_IP) {
		if (mask->key.ip.ttl) {
			pr_err("%s: ttl match not supported for offload.. \n",
				__func__);
			return -1;
		}

		if (mask->key.ip.frag && mask->key.ip.frag != 0xff) {
			pr_err("%s: Unsupported frag mask for offload.. \n",
				__func__);
			return -1;
		}
	}

	if (mask->key.tp.flags) {
		pr_err("%s: transport-flags match not supported for offload..\n",
			__func__);
		return -1;
	}

	if (cpu_to_be16(flow->key.eth.type) == ETH_P_IPV6) {
		if (mask->key.ipv6.label) {
			pr_err("%s: IPv6 label match not supported for offload..\n",
				__func__);
			return -1;
		}

		if ((mask->key.ipv6.nd.sll[0] | mask->key.ipv6.nd.sll[1] |
		     mask->key.ipv6.nd.sll[2] | mask->key.ipv6.nd.sll[3] |
		     mask->key.ipv6.nd.sll[4] | mask->key.ipv6.nd.sll[5]) ||
		    (mask->key.ipv6.nd.tll[0] | mask->key.ipv6.nd.tll[1] |
		     mask->key.ipv6.nd.tll[2] | mask->key.ipv6.nd.tll[3] |
		     mask->key.ipv6.nd.tll[4] | mask->key.ipv6.nd.tll[5])) {
			pr_err("%s: ND LL match not supported for offload..\n",
				__func__);
			return -1;
		}
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
	if (mask->key.tun_key.tun_id) {
		pr_err("%s: Tunnel VNI match not supported for offload.."
		       "on Linux Kernel versions < 4.8. \n",
			__func__);
		return -1;
	}
#endif

	return 0;
}

static bool is_addr_all_mask(u8 *ipmask, int family)
{
	if (family == AF_INET) {
		struct in_addr *addr;

		addr = (struct in_addr *)ipmask;
		if (addr->s_addr == 0xffffffff)
			return true;
	} else if (family == AF_INET6) {
		struct in6_addr *addr6;

		addr6 = (struct in6_addr *)ipmask;
		if (addr6->s6_addr32[0] == 0xffffffff &&
		    addr6->s6_addr32[1] == 0xffffffff &&
		    addr6->s6_addr32[2] == 0xffffffff &&
		    addr6->s6_addr32[3] == 0xffffffff)
			return true;
	}
	return false;
}

static bool is_inaddr_any(u8 *ip, int family)
{
	int addr_type;

	if (family == AF_INET) {
		struct in_addr *addr;

		addr = (struct in_addr *)ip;
		if (addr->s_addr == htonl(INADDR_ANY))
			return true;
	} else if (family == AF_INET6) {
		struct in6_addr *addr6;

		addr6 = (struct in6_addr *)ip;
		addr_type = ipv6_addr_type((const struct in6_addr *)
					   &addr6);
		if (addr_type == IPV6_ADDR_ANY)
			return true;
	}
	return false;
}

static bool is_filter_exact_match(struct ch_filter_specification *fs)
{
	struct ch_filter_tuple full_mask;

	memset(&full_mask, ~0, sizeof(full_mask));

	if (fs->mask.encap_vld)
		return false;

	if (fs->type) {
		if (is_inaddr_any(fs->val.fip, AF_INET6) ||
		    !is_addr_all_mask(fs->mask.fip, AF_INET6))
			return false;

		if (is_inaddr_any(fs->val.lip, AF_INET6) ||
		    !is_addr_all_mask(fs->mask.lip, AF_INET6))
			return false;
	} else {
		if (is_inaddr_any(fs->val.fip, AF_INET) ||
		    !is_addr_all_mask(fs->mask.fip, AF_INET))
			return false;

		if (is_inaddr_any(fs->val.lip, AF_INET) ||
		    !is_addr_all_mask(fs->mask.lip, AF_INET))
			return false;
	}

	if (!fs->val.lport || fs->mask.lport != full_mask.lport)
		return false;

	if (!fs->val.fport || fs->mask.fport != full_mask.fport)
		return false;

	if (fs->mask.fcoe && fs->mask.fcoe != full_mask.fcoe)
		return false;

	if (fs->mask.iport && fs->mask.iport != full_mask.iport)
		return false;

	if (fs->mask.pfvf_vld && fs->mask.pfvf_vld != full_mask.pfvf_vld)
		return false;

	if (fs->mask.ovlan_vld && fs->mask.ovlan_vld != full_mask.ovlan_vld)
		return false;

	if (fs->mask.ivlan && fs->mask.ivlan != full_mask.ivlan)
		return false;

	if (fs->mask.tos && fs->mask.tos != full_mask.tos)
		return false;

	if (fs->mask.proto && fs->mask.proto != full_mask.proto)
		return false;

	if (fs->mask.ethtype && fs->mask.ethtype != full_mask.ethtype)
		return false;

	if (fs->mask.macidx && fs->mask.macidx != full_mask.macidx)
		return false;

	if (fs->mask.matchtype && fs->mask.matchtype != full_mask.matchtype)
		return false;

	if (fs->mask.frag && fs->mask.frag != full_mask.frag)
		return false;

	return true;
}

void cxgb_flow_offload_add(struct flow_table *table, struct sw_flow *flow,
			   const struct sw_flow_mask *mask)
{
	struct datapath *dp = container_of(table, struct datapath, table);
	struct vport *vport_in, *vport_out;
	struct ch_filter_specification *fs;
	const struct device *parent = NULL;
	struct net_device *phydev = NULL;
	struct filter_ctx ctx;
	u32 output_port = 0, input_port = 0;
	int ret, fidx;
	u8 cap = 0, type = 0, action = FILTER_DROP;

	pr_debug("%s: actions_len = %u; flow = %p; flow->mask = %p; mask = %p\n",
		 __func__, flow->sf_acts->actions_len, flow, flow->mask, mask);

	if (cxgb_validate_flow_actions(flow, &output_port, &action))
		return;

	if (cxgb_validate_flow_match(flow, mask))
		return;

	input_port = flow->key.phy.in_port;


	vport_in = ovs_vport_rcu(dp, input_port);
	phydev = vport_in->dev;
	pr_debug("%s: vport_in->dev = %s; vport_in->port_no = %d\n",
		 __func__, vport_in->dev->name, vport_in->port_no);

	parent = phydev->dev.parent;
	if (!parent) {
		/* Try to find physical net_device in case of tunnel traffic */
		phydev = dev_get_by_index(ovs_dp_get_net(dp),
					  vport_in->phydev_ifindex);
		if (phydev) {
			parent = phydev->dev.parent;
			dev_put(phydev);
			if (!parent) {
				pr_err("%s: vport_in not a Chelsio device. Not offloading.\n",
					__func__);
				return;
			}
		} else {
			pr_err("%s: vport_in not a Chelsio device. Not offloading.\n",
				__func__);
			return;
		}
	}

	pr_debug("%s: vport_in parent->driver->name = %s\n",
		 __func__, parent->driver->name);

	if (strcmp("cxgb4", parent->driver->name)) {
		pr_err("%s: vport_in not a Chelsio device. Not offloading.\n",
			__func__);
		return;
	}

	if (action == FILTER_SWITCH) {
		vport_out = ovs_vport_rcu(dp, output_port);
		pr_debug("%s: vport_out->dev = %s;\n",
			 __func__, vport_out->dev->name);

		parent = vport_out->dev->dev.parent;
		if (!parent) {
			pr_err("%s: vport_out not a Chelsio device. Not offloading.\n",
				__func__);
			return;
		}

		pr_debug("%s: vport_out parent->driver->name = %s\n",
			 __func__, parent->driver->name);

		if (strcmp("cxgb4", parent->driver->name)) {
			pr_err("%s: vport_out not a Chelsio device. Not offloading.\n",
				__func__);
			return;
		}
	}

	if (cpu_to_be16(flow->key.eth.type) == ETH_P_IPV6)
		type = 1;

	if (type) {
		if ((flow->key.ipv6.addr.src.s6_addr32[0] &&
		     (mask->key.ipv6.addr.src.s6_addr32[0] == 0xffffffff &&
		      mask->key.ipv6.addr.src.s6_addr32[1] == 0xffffffff &&
		      mask->key.ipv6.addr.src.s6_addr32[2] == 0xffffffff &&
		      mask->key.ipv6.addr.src.s6_addr32[3] == 0xffffffff)) &&
		    (flow->key.ipv6.addr.dst.s6_addr32[0] &&
		     (mask->key.ipv6.addr.dst.s6_addr32[0] == 0xffffffff &&
		      mask->key.ipv6.addr.dst.s6_addr32[1] == 0xffffffff &&
		      mask->key.ipv6.addr.dst.s6_addr32[2] == 0xffffffff &&
		      mask->key.ipv6.addr.dst.s6_addr32[3] == 0xffffffff)) &&
		    (flow->key.tp.src && mask->key.tp.src == 0xffff) &&
		    (flow->key.tp.dst && mask->key.tp.dst == 0xffff))
			cap = 1;
	} else {
		if ((flow->key.ipv4.addr.src && mask->key.ipv4.addr.src == 0xffffffff) &&
		    (flow->key.ipv4.addr.dst && mask->key.ipv4.addr.dst == 0xffffffff) &&
		    (flow->key.tp.src && mask->key.tp.src == 0xffff) &&
		    (flow->key.tp.dst && mask->key.tp.dst == 0xffff))
			cap = 1;
	}

	fs = (struct ch_filter_specification *)kmalloc(sizeof(*fs), GFP_KERNEL);
	if (!fs) {
		pr_err("%s: fs allocation failed for offoading.\n", __func__);
		return;
	}
	memset(fs, 0, sizeof(struct ch_filter_specification));

	cxgb_process_flow_actions(flow, fs);
	fs->cap                 = cap;
	fs->type                = type;
	fs->hitcnts             = 1;
	fs->val.iport           = (input_port - 1) -1;
	fs->val.ethtype         = cpu_to_be16(flow->key.eth.type);
	if (((cpu_to_be16(mask->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT) == 0xefff) &&
	    (be16_to_cpu(flow->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT)) {
		fs->val.ivlan_vld       = 1;
		fs->val.ivlan           = cpu_to_be16(flow->key.eth.vlan.tci) &
						~VLAN_TAG_PRESENT;
	}
	fs->val.proto           = flow->key.ip.proto;
	fs->val.tos             = flow->key.ip.tos;
	fs->val.lport           = cpu_to_be16(flow->key.tp.dst);
	fs->val.fport           = cpu_to_be16(flow->key.tp.src);
	if (type) {
		*(struct in6_addr *)&fs->val.lip = flow->key.ipv6.addr.dst;
		*(struct in6_addr *)&fs->val.fip = flow->key.ipv6.addr.src;
	} else {
		*(u32 *)&fs->val.lip    = flow->key.ipv4.addr.dst;
		*(u32 *)&fs->val.fip    = flow->key.ipv4.addr.src;
		fs->val.frag            = flow->key.ip.frag ? 1: 0;
	}

	if ((cpu_to_be16(flow->key.eth.type) == ETH_P_IP) ||
	    (cpu_to_be16(flow->key.eth.type) == ETH_P_IPV6)) {
		if (mask->key.tun_key.tun_id) {
			fs->val.vni = cpu_to_be64(flow->key.tun_key.tun_id);
			fs->val.encap_vld = 1;
			fs->val.encap_lookup = 1;
		}
	}

	fs->mask.iport          = mask->key.phy.in_port;
	if (fs->mask.iport > 7) {
		pr_debug("iport_mask must be < 8. Using 0\n");
		fs->mask.iport  = 7;
	}
	fs->mask.ethtype        = mask->key.eth.type;
	if (((cpu_to_be16(mask->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT) == 0xefff) &&
	    (be16_to_cpu(flow->key.eth.vlan.tci) & ~VLAN_TAG_PRESENT)) {
		fs->mask.ivlan_vld      = 1;
		fs->mask.ivlan          = cpu_to_be16(mask->key.eth.vlan.tci) &
						~VLAN_TAG_PRESENT;
	}
	fs->mask.proto          = mask->key.ip.proto;
	fs->mask.tos            = mask->key.ip.tos;
	fs->mask.lport          = mask->key.tp.dst;
	fs->mask.fport          = mask->key.tp.src;
	if (type) {
		*(struct in6_addr *)&fs->mask.lip = mask->key.ipv6.addr.dst;
		*(struct in6_addr *)&fs->mask.fip = mask->key.ipv6.addr.src;
	} else {
		*(u32 *)&fs->mask.lip   = mask->key.ipv4.addr.dst;
		*(u32 *)&fs->mask.fip   = mask->key.ipv4.addr.src;
		fs->mask.frag           = mask->key.ip.frag ? 1 : 0;
	}

	if ((cpu_to_be16(flow->key.eth.type) == ETH_P_IP) ||
	    (cpu_to_be16(flow->key.eth.type) == ETH_P_IPV6)) {
		if (mask->key.tun_key.tun_id) {
			fs->mask.vni = cpu_to_be64(mask->key.tun_key.tun_id);
			fs->mask.encap_vld = 1;
			fs->mask.encap_lookup = 1;
		}
	}

	fs->action              = action;
	fs->eport               = output_port ? (output_port - 1) - 1 :
						output_port;

	if ((*(u32 *)fs->nat_lip) || (*(u32 *)fs->nat_fip) || fs->nat_lport ||
	    fs->nat_fport) {
		fs->nat_mode = NAT_MODE_ALL;

		if (!fs->nat_lip) {
			if (fs->type)
				*(struct in6_addr *)&fs->nat_lip =
					*(struct in6_addr *)fs->val.lip;
			else
				*(u32 *)&fs->nat_lip = *(u32 *)fs->val.lip;
		}
		if (!fs->nat_fip) {
			if (fs->type)
				*(struct in6_addr *)&fs->nat_fip =
					*(struct in6_addr *)fs->val.fip;
			else
				*(u32 *)&fs->nat_fip = *(u32 *)fs->val.fip;
		}
		if (!fs->nat_lport)
			fs->nat_lport = fs->val.lport;
		if (!fs->nat_fport)
			fs->nat_fport = fs->val.fport;
	}
	if (fs->cap && !is_filter_exact_match(fs))
		fs->cap = 0;

	if (fs->cap)
		fidx = 0;
	else {
		fidx = cxgb4_get_free_ftid(phydev,
					   type ? PF_INET6 : PF_INET, 0);
		if (fidx < 0) {
			pr_err("%s: No valid fidx for offloading.\n", __func__);
			return;
		}
	}

	pr_debug("%s: type = %d; cap = %d; fidx = %d; in_interrupt = %lu; "
		 "in_atomic = %d; nat_mode = %d\n",
		 __func__, fs->type, fs->cap, fidx, in_interrupt(),
		 in_atomic(), fs->nat_mode);

	init_completion(&ctx.completion);
	ret = cxgb4_set_filter(phydev, fidx, fs, &ctx, GFP_ATOMIC);
	pr_debug("%s: ret from cxgb4_set_filter is %d\n", __func__, ret);
	if (!ret) {
		ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
		if (!ret)
			pr_err("%s: filter creation timed out\n", __func__);
		else {
			ret = ctx.result;
			pr_debug("%s: filter tid is %u\n", __func__, ctx.tid);
			flow->ofld_info.fs = fs;
			flow->ofld_info.flow_id = ctx.tid;
			flow->ofld_info.cap = fs->cap;
			flow->is_offloaded = true;
			flow->ofld_info.netdev = phydev;
		}
	} else
		pr_err("%s: filter creation error %d\n", __func__, ret);
}

void cxgb_flow_offload_stats(struct sw_flow *flow,
			     struct flow_stats *stats)
{
	struct ch_filter_specification *fs = flow->ofld_info.fs;
	struct offload_flow_stats *ofld_stats = &flow->ofld_info.ofld_stats;
	struct offload_flow_stats local_stats;
	int ret;

	if (!fs)
		return;

	pr_debug("%s: flow_id = %u; cap = %d; "
		 "sw-stats: pkt-cnt = %llu; byte-cnt = %llu\n",
		 __func__, flow->ofld_info.flow_id, fs->cap,
		 (unsigned long long)stats->packet_count,
		 (unsigned long long)stats->byte_count);

	if (!flow->ofld_info.init_sw_counters) {
		flow->ofld_info.init_sw_packet_count = stats->packet_count;
		flow->ofld_info.init_sw_byte_count = stats->byte_count;

		pr_debug("%s: sw_init_pkt_cnt = %llu; sw_init_byte_cnt = %llu\n",
			 __func__, (unsigned long long)flow->ofld_info.init_sw_packet_count,
			 (unsigned long long)flow->ofld_info.init_sw_byte_count);
		flow->ofld_info.init_sw_counters = 1;
	}

	local_stats.packet_count = local_stats.byte_count = 0;
	ret = cxgb4_get_filter_counters(flow->ofld_info.netdev, flow->ofld_info.flow_id,
					&local_stats.packet_count,
					&local_stats.byte_count, fs->cap);
	pr_debug("%s: ret from cxgb4-get-filter-count = %d;\n",
		 __func__, ret);
	pr_debug("%s: local: pkt-count = %llu; byte-cnt = %llu; "
		 "ofld-stats: pkt-cnt = %llu; byte-cnt = %llu\n",
		 __func__, (unsigned long long)local_stats.packet_count,
		 (unsigned long long)local_stats.byte_count,
		 (unsigned long long)ofld_stats->packet_count,
		 (unsigned long long)ofld_stats->byte_count);

	if (ret < 0)
		return;

	if (ofld_stats->packet_count != local_stats.packet_count) {
		ofld_stats->packet_count = local_stats.packet_count;
		stats->packet_count = ofld_stats->packet_count +
				      flow->ofld_info.init_sw_packet_count;

		ofld_stats->byte_count = local_stats.byte_count;
		stats->byte_count = ofld_stats->byte_count +
				    flow->ofld_info.init_sw_byte_count;
		stats->used = jiffies;
	}
}

void cxgb_flow_offload_del(struct sw_flow *flow)
{
	struct ch_filter_specification *fs = flow->ofld_info.fs;
	struct filter_ctx ctx;
	int ret;

	if (!fs)
		return;

	pr_debug("%s: flow_id = %u; cap = %d\n",
		 __func__, flow->ofld_info.flow_id, fs->cap);

	init_completion(&ctx.completion);
	ret = cxgb4_del_filter(flow->ofld_info.netdev, flow->ofld_info.flow_id, fs,
			       &ctx, GFP_ATOMIC);
	pr_debug("%s: ret from cxgb4-del_filter = %d\n", __func__, ret);
	if (!ret) {
		ret = wait_for_completion_timeout(&ctx.completion, 10*HZ);
		if (!ret)
			pr_err("%s: filter deletion timed out\n", __func__);
		else
			pr_debug("%s: Deletion context result = %d\n",
				 __func__, ctx.result);
	}
}

