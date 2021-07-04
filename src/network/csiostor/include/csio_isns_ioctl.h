/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures and constants for COiSCSI target ISNS IOCTLs
 *
 */
#ifndef __CSIO_ISNS_IOCTL_H__
#define __CSIO_ISNS_IOCTL_H__

#include <csio_common_ioctl.h>

#define CSIO_ISNS_PORT		3205
#define CSIO_ISNS_EID_LEN	256

typedef struct isns_info isns_info;

struct isns_info {
	struct ip_addr  	addr;
	uint16_t                port;
	uint16_t                type;
	uint8_t			ifid;
	uint16_t                vlanid;
	uint32_t                ofid;
	uint8_t			mode;
	uint16_t                op;
	char                    eid[CSIO_ISNS_EID_LEN];
	uint8_t			*buf;
};

struct csio_isns_ioctl {
	struct ip_addr			addr;
	uint16_t			port;
	uint16_t			type;
	uint8_t				ifid;
	uint16_t			vlanid;
	uint8_t				mode;
	uint16_t			op;
	char                    	eid[CSIO_ISNS_EID_LEN];
	int				retval;
};

enum csio_isns_l3cfg_type {
	CSIO_ISNS_L3CFG_TYPE_NONE              = 0x00,
	CSIO_ISNS_L3CFG_TYPE_IPV4              = 0x01,
	CSIO_ISNS_L3CFG_TYPE_IPV6              = 0x02,
};

#endif	/*__CSIO_ISNS_IOCTL_H__*/
