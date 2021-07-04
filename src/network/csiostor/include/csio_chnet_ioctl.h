/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures,constants & enum definition for CHNET IOCTLs
 *
 */
#ifndef __CSIO_CHNET_IOCTL_H__
#define __CSIO_CHNET_IOCTL_H__

#include <csio_common_ioctl.h>
#include <csio_stor_ioctl.h>

#define CSIO_CHNET_MAX_PORTS		4

struct csio_chnet_iface_ioctl {
	uint8_t	op;
	uint8_t ifid;
	uint8_t retval;
	uint8_t flags;
};

struct csio_chnet_ifconf_ioctl {
	/* header */
	uint8_t		ifid;
	uint8_t		subop;
	uint16_t	type;
	uint8_t		retval;
	uint8_t		if_state;
	
	/* L2 */
	uint16_t	vlanid;
	uint16_t	mtu;
	uint8_t		mac[8];
	uint16_t	ping_time;
	uint8_t		ping_rsptype;
	uint8_t		ping_param_rspcode;
	uint16_t	ping_pldsize;
	uint8_t		ping_ttl;
	uint16_t	ping_seq;
	union {
		struct _v4 {
			/* L3 IPV4 */
			uint32_t	ipv4_addr;
			uint32_t	ipv4_mask;
			uint32_t	ipv4_gw;
		}v4;
		struct _v6 {
			/* L3 IPV6 */
			uint8_t		ipv6_addr[16];
			uint8_t		ipv6_gw[16];
			uint8_t		prefix_len;
		}v6;
	};
	uint16_t	address_state;
};

#if 0
enum csio_chnet_stat {
	CHNET_STATUS_SUCCESS,
	CHNET_STATUS_FAILURE,
	CHNET_STATUS_IP_CONFLICT,
	CHNET_STATUS_INVALID_IP,
	CHNET_STATUS_HOST_UNREACHABLE,
	CHNET_STATUS_NETWORK_DOWN,
};
#endif

enum csio_chnet_l3cfg_type {
	CSIO_CHNET_L3CFG_TYPE_NONE		= 0x00,
	CSIO_CHNET_L3CFG_TYPE_IPV4		= 0x01,
	CSIO_CHNET_L3CFG_TYPE_IPV6		= 0x02,
	CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4		= 0x03,
	CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6		= 0x04,
	CSIO_CHNET_L3CFG_TYPE_DHCP		= 0x05,
	CSIO_CHNET_L3CFG_TYPE_VLAN_DHCP		= 0x06,
	CSIO_CHNET_L3CFG_TYPE_DHCPV6		= 0x07,
	CSIO_CHNET_L3CFG_TYPE_VLAN_DHCP6	= 0x08,
	CSIO_CHNET_L3CFG_TYPE_RTADV6		= 0x09,
	CSIO_CHNET_L3CFG_TYPE_VLN_RTADV6	= 0x0a,
	CSIO_CHNET_L3CFG_TYPE_LINKLOCAL6	= 0x0b,
};

enum chnet_iface_state {
	CHNET_IFACE_STATE_LINK_DOWN = 0,
	CHNET_IFACE_STATE_LINK_UP = 1,
	CHNET_IFACE_STATE_ENABLED = 3,
};

#endif/*__CSIO_CHNET_IOCTL_H__*/
