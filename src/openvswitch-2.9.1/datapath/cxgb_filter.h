/*
 * Copyright (C) 2017-2018 Chelsio Communications.  All rights reserved.
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

/*
 * Defined bit width of user definable filter tuples
 */
#define ETHTYPE_BITWIDTH 16
#define FRAG_BITWIDTH 1
#define MACIDX_BITWIDTH 9
#define FCOE_BITWIDTH 1
#define IPORT_BITWIDTH 3
#define MATCHTYPE_BITWIDTH 3
#define PROTO_BITWIDTH 8
#define TOS_BITWIDTH 8
#define PF_BITWIDTH 8
#define VF_BITWIDTH 8
#define IVLAN_BITWIDTH 16
#define OVLAN_BITWIDTH 16
#define ENCAP_VNI_BITWIDTH 24
#define ENCAP_LOOKUP_BITWIDTH 1

/*
 * Filter matching rules.  These consist of a set of ingress packet field
 * (value, mask) tuples.  The associated ingress packet field matches the
 * tuple when ((field & mask) == value).  (Thus a wildcard "don't care" field
 * rule can be constructed by specifying a tuple of (0, 0).)  A filter rule
 * matches an ingress packet when all of the individual individual field
 * matching rules are true.
 *
 * Partial field masks are always valid, however, while it may be easy to
 * understand their meanings for some fields (e.g. IP address to match a
 * subnet), for others making sensible partial masks is less intuitive (e.g.
 * MPS match type) ...
 *
 * Most of the following data structures are modeled on T4 capabilities.
 * Drivers for earlier chips use the subsets which make sense for those chips.
 * We really need to come up with a hardware-independent mechanism to
 * represent hardware filter capabilities ...
 */
struct ch_filter_tuple {
        /*
         * Compressed header matching field rules.  The TP_VLAN_PRI_MAP
         * register selects which of these fields will participate in the
         * filter match rules -- up to a maximum of 36 bits.  Because
         * TP_VLAN_PRI_MAP is a global register, all filters must use the same
         * set of fields.
         */
        uint32_t ethtype:ETHTYPE_BITWIDTH;      /* Ethernet type */
        uint32_t frag:FRAG_BITWIDTH;            /* IP fragmentation header */
        uint32_t ivlan_vld:1;                   /* inner VLAN valid */
        uint32_t ovlan_vld:1;                   /* outer VLAN valid */
        uint32_t pfvf_vld:1;                    /* PF/VF valid */
	uint32_t encap_vld:1;                   /* Encapsulation valid */
	uint32_t encap_lookup:1;                /* Lookup outer or inner hdr */
        uint32_t macidx:MACIDX_BITWIDTH;        /* exact match MAC index */
        uint32_t fcoe:FCOE_BITWIDTH;            /* FCoE packet */
        uint32_t iport:IPORT_BITWIDTH;          /* ingress port */
        uint32_t matchtype:MATCHTYPE_BITWIDTH;  /* MPS match type */
        uint32_t proto:PROTO_BITWIDTH;          /* protocol type */
        uint32_t tos:TOS_BITWIDTH;              /* TOS/Traffic Type */
        uint32_t pf:PF_BITWIDTH;                /* PCI-E PF ID */
        uint32_t vf:VF_BITWIDTH;                /* PCI-E VF ID */
        uint32_t ivlan:IVLAN_BITWIDTH;          /* inner VLAN */
        uint32_t ovlan:OVLAN_BITWIDTH;          /* outer VLAN */
	uint32_t encap_matchtype:MATCHTYPE_BITWIDTH; /* match type for tunnel pkt */
	uint32_t vni:ENCAP_VNI_BITWIDTH;        /* VNI of tunnel */

        /*
         * Uncompressed header matching field rules.  These are always
         * available for field rules.
         */
        uint8_t lip[16];        /* local IP address (IPv4 in [3:0]) */
        uint8_t fip[16];        /* foreign IP address (IPv4 in [3:0]) */
        uint16_t lport;         /* local port */
	uint16_t fport;         /* foreign port */

	uint8_t encap_inner_mac[ETH_ALEN];      /* Inner MAC of encap packet */

	/* reservations for future additions */
	uint8_t rsvd[3];
};


struct ch_filter_specification {
        /*
         * Administrative fields for filter.
         */
        uint32_t hitcnts:1;     /* count filter hits in TCB */
        uint32_t prio:1;        /* filter has priority over active/server */

        /*
         * Fundamental filter typing.  This is the one element of filter
         * matching that doesn't exist as a (value, mask) tuple.
         */
        uint32_t type:1;        /* 0 => IPv4, 1 => IPv6 */
        uint32_t cap:1;         /* 0 => LE-TCAM, 1 => Hash */

        /*
         * Packet dispatch information.  Ingress packets which match the
         * filter rules will be dropped, passed to the host or switched back
         * out as egress packets.
         */
        uint32_t action:2;      /* drop, pass, switch */

        uint32_t rpttid:1;      /* report TID in RSS hash field */

        uint32_t dirsteer:1;    /* 0 => RSS, 1 => steer to iq */
        uint32_t iq:10;         /* ingress queue */

        uint32_t maskhash:1;    /* dirsteer=0: store RSS hash in TCB */
        uint32_t dirsteerhash:1;/* dirsteer=1: 0 => TCB contains RSS hash */
                                /*             1 => TCB contains IQ ID */

        /*
         * Switch proxy/rewrite fields.  An ingress packet which matches a
         * filter with "switch" set will be looped back out as an egress
         * packet -- potentially with some Ethernet header rewriting.
         */
        uint32_t eport:2;       /* egress port to switch packet out */
        uint32_t newdmac:1;     /* rewrite destination MAC address */
        uint32_t newsmac:1;     /* rewrite source MAC address */
        uint32_t swapmac:1;     /* swap SMAC/DMAC for loopback packet */
        uint32_t newvlan:2;     /* rewrite VLAN Tag */
        uint32_t nat_mode:3;    /* specify NAT operation mode */
        uint32_t nat_flag_chk:1;/* check TCP flags before NAT'ing */
        uint32_t nat_seq_chk;   /* sequence value to use for NAT check*/
        uint8_t dmac[ETH_ALEN]; /* new destination MAC address */
        uint8_t smac[ETH_ALEN]; /* new source MAC address */
        uint16_t vlan;          /* VLAN Tag to insert */

        uint8_t nat_lip[16];    /* local IP to use after NAT'ing */
        uint8_t nat_fip[16];    /* foreign IP to use after NAT'ing */
        uint16_t nat_lport;     /* local port to use after NAT'ing */
        uint16_t nat_fport;     /* foreign port to use after NAT'ing */

	uint8_t encap_outer_ip[16]; /* Outer IP for encapsulated packet */
	/* reservation for future additions */
	uint8_t rsvd[6];

        /*
         * Filter rule value/mask pairs.
         */
        struct ch_filter_tuple val;
        struct ch_filter_tuple mask;
};

/*
 * Filter operation context to allow callers of cxgb_set_filter() and
 * cxgb_del_filter() to wait for an asynchronous completion.
 */
struct filter_ctx {
        struct completion completion;   /* completion rendezvous */
        void *closure;                  /* caller's opaque information */
        int result;                     /* result of operation */
        u32 tid;                        /* to store tid of hash filter */
};


#define CH_FILTER_SPECIFICATION_ID 0x2

enum {
        FILTER_PASS = 0,        /* default */
        FILTER_DROP,
        FILTER_SWITCH
};

enum {
        VLAN_NOCHANGE = 0,      /* default */
        VLAN_REMOVE,
        VLAN_INSERT,
        VLAN_REWRITE
};

enum {                         /* Ethernet address match types */
        UCAST_EXACT = 0,       /* exact unicast match */
        UCAST_HASH  = 1,       /* inexact (hashed) unicast match */
        MCAST_EXACT = 2,       /* exact multicast match */
        MCAST_HASH  = 3,       /* inexact (hashed) multicast match */
        PROMISC     = 4,       /* no match but port is promiscuous */
        HYPPROMISC  = 5,       /* port is hypervisor-promisuous + not bcast */
        BCAST       = 6,       /* broadcast packet */
};

enum {                         /* selection of Rx queue for accepted packets */
        DST_MODE_QUEUE,        /* queue is directly specified by filter */
        DST_MODE_RSS_QUEUE,    /* filter specifies RSS entry containing queue */
        DST_MODE_RSS,          /* queue selected by default RSS hash lookup */
        DST_MODE_FILT_RSS      /* queue selected by hashing in filter-specified
                                  RSS subtable */
};

enum {
        NAT_MODE_NONE = 0,      /* No NAT performed */
        NAT_MODE_DIP,           /* NAT on Dst IP */
        NAT_MODE_DIP_DP,        /* NAT on Dst IP, Dst Port */
        NAT_MODE_DIP_DP_SIP,    /* NAT on Dst IP, Dst Port and Src IP */
        NAT_MODE_DIP_DP_SP,     /* NAT on Dst IP, Dst Port and Src Port */
        NAT_MODE_SIP_SP,        /* NAT on Src IP and Src Port */
        NAT_MODE_DIP_SIP_SP,    /* NAT on Dst IP, Src IP and Src Port */
        NAT_MODE_ALL            /* NAT on entire 4-tuple */
};


int cxgb4_get_free_ftid(struct net_device *dev, int family, int prio);
int cxgb4_set_filter(struct net_device *dev, int filter_id,
				struct ch_filter_specification *fs,
				struct filter_ctx *ctx, gfp_t flags);
int cxgb4_del_filter(struct net_device *dev, int filter_id,
				struct ch_filter_specification *fs,
				struct filter_ctx *ctx, gfp_t flags);
int cxgb4_get_filter_counters(struct net_device *dev, int filter_id,
			   u64 *packet_count, u64 *byte_count,
			   int hash);
