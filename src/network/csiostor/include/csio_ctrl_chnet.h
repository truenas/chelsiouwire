/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures,constants & function prototype declartions for
 * CHNET subsystem.
 *
 */

#ifndef	__CSIO_CTRL_CHNET_H__
#define	__CSIO_CTRL_CHNET_H__

#include <csio_common_ioctl.h>

#define CHNET_IFACE_INVALID_IFID	0
#define CHNET_IFACE_MAX			4

struct csio_chnet_iface;

struct csio_chnet_iface_ipv4 {
    struct csio_chnet_iface       *iface;
    unsigned int                    addr;
    unsigned int                    mask;
    unsigned int                    gw;
    unsigned int                    refcnt;
};

struct csio_chnet_iface_ipv6 {
    struct csio_chnet_iface       *iface;
    unsigned int                    addr[4];
    unsigned int                    prefix_len;
    unsigned int                    gw6[4];
    unsigned int                    refcnt;
};

struct csio_chnet_iface_vlan {
    struct csio_chnet_iface       *iface;
    unsigned short                  vlan_id;
    struct csio_chnet_iface_ipv4  ipv4;
    struct csio_chnet_iface_ipv6  ipv6;
};

struct csio_chnet_iface_linkl {
	struct csio_chnet_iface       *iface;
	unsigned short                  vlan_id;
	struct csio_chnet_iface_ipv6  ipv6;
	struct csio_chnet_iface_ipv6  ipv6_vlan;
};

struct csio_chnet_iface {
	unsigned int                    if_id;
	unsigned int                    if_state;
	unsigned int			tclient;
	unsigned short                  mtu;
	unsigned short			old_mtu;
	unsigned int                    address_state;
	struct csio_hw                  *hw;
	struct csio_t4port              *tport;
	struct csio_lnode               *ln;
	struct csio_chnet_iface       *vif;
	struct csio_chnet_iface_ipv4  ipv4;
	struct csio_chnet_iface_ipv6  ipv6;
	struct csio_chnet_iface_vlan  vlan_info;
	struct csio_chnet_iface_linkl	link_local;
	/* iface lock TODO replace it with wrapper */
	csio_mutex_t			mlock;	/* lock for iface operation */
	csio_spinlock_t			hlock; /* lock for transport_handle */
	unsigned int op_pending;
	void *transport_handle;
};

struct csio_ctrl_chnet {
	struct csio_chnet_iface ifaces[CHNET_IFACE_MAX];
};

enum csio_oss_error csio_chnet_init_ifaces(struct csio_hw *);

struct csio_chnet_iface *csio_chnet_iface_addr_get(struct csio_hw *, int, struct ip_addr *);
int csio_chnet_iface_addr_put(struct csio_hw *, struct csio_chnet_iface *, int, struct ip_addr *);

#endif	/* __CSIO_CTRL_CHNET_H__ */
