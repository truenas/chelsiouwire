/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: functions to init, start, get and put chnet ifaces
 *
 */

#include <csio_defs.h>
#include <csio_ctrl_devs.h>
#include <csio_ctrl_chnet.h>

csio_retval_t
csio_chnet_iface_start(struct csio_chnet_iface *iface)
{
	csio_retval_t rc = CSIO_SUCCESS;

	/* let's not bring up the link by default for now */

	/* portid value is the handle */
	/*rc = csio_foiscsi_do_link_cmd(iface->hw, iface->tport->portid,
		FW_CHNET_IFACE_CMD_SUBOP_LINK_UP, iface->tport->portid);*/

	return rc;
}

enum csio_oss_error
csio_chnet_init_ifaces(struct csio_hw *hw)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_ctrl_chnet *chnet_cdev;
	struct csio_chnet_iface *iface;
	int i;

	chnet_cdev = csio_hw_to_chnet_cdev(hw);

	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &chnet_cdev->ifaces[hw->t4port[i].portid];
		iface->if_id = CHNET_IFACE_INVALID_IFID;
		csio_spin_lock_init(&iface->hlock);
		iface->hw = hw;
		iface->mtu = 1500;
		iface->vlan_info.vlan_id = 0xfff;
		iface->tport = &hw->t4port[i];
		csio_mutex_init(&iface->mlock);
	}
	return rc;
}

struct csio_chnet_iface *
csio_chnet_iface_addr_get(struct csio_hw *hw,
		int ip_type, struct ip_addr *addr)
{
	struct csio_ctrl_chnet *chnet_cdev;
	struct csio_chnet_iface *iface = NULL;
	int i = 0, got = 0;
	unsigned long flags;
	
	chnet_cdev = csio_hw_to_chnet_cdev(hw);

	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &chnet_cdev->ifaces[i];
		csio_spin_lock_irqsave(hw, &iface->hlock, flags);
		if (!iface->op_pending) {
			if (ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
				if (iface->ipv4.addr == addr->ip4) {
					iface->ipv4.refcnt++;
					csio_dbg(hw,
					 "got interface %d ip %u.%u.%u.%u\n", i,
					 (iface->ipv4.addr >> 24) & 0xff,
					 (iface->ipv4.addr >> 16) & 0xff,
					 (iface->ipv4.addr >> 8) & 0xff,
					 iface->ipv4.addr & 0xff);
					csio_dbg(hw,
					  "%s: iface->ipv4.refcnt [%d]\n",
					  __FUNCTION__, iface->ipv4.refcnt);
					got = 1;
				} else if (iface->vlan_info.ipv4.addr ==
							   addr->ip4) {
					iface->vlan_info.ipv4.refcnt++;
#if 0
					csio_dbg(hw,
					  "got interface %d, vlanid %d, ip "
					  "%u.%u.%u.%u\n", i,
					  iface->vlan_info.vlan_id,
					  (iface->vlan_info.ipv4.addr >> 24) &
									  0xff,
					  (iface->vlan_info.ipv4.addr >> 16) &
									  0xff,
					  (iface->vlan_info.ipv4.addr >> 8) &
									  0xff,
					  iface->vlan_info.ipv4.addr & 0xff);
					csio_dbg(hw,
					  "%s: iface->vlan_info.ipv4.refcnt "
					  "[%d]\n", __FUNCTION__,
					  iface->vlan_info.ipv4.refcnt);
#endif
					got = 1;
				}
			} else { /* IPv6 */
				if (!csio_memcmp((void*) iface->ipv6.addr,
					(void *) addr->ip6, 16)) {
					iface->ipv6.refcnt++;
					got = 1;
					csio_dbg(hw,
					 "got interface %d ip %pI6\n", i,
					 iface->ipv6.addr);
					csio_dbg(hw,
					  "%s: iface->ipv6.refcnt [%d]\n",
					  __FUNCTION__, iface->ipv6.refcnt);

				} else if (!csio_memcmp((void *)iface->\
						vlan_info.ipv6.addr,
						addr->ip6, 16)) {
					iface->vlan_info.ipv6.refcnt++;
					got = 1;

					csio_dbg(hw,
					 "got interface %d vlanid %d ip %pI6\n",
					 i, iface->vlan_info.vlan_id,
					 iface->vlan_info.ipv6.addr);
					csio_dbg(hw, "%s: "
					  "iface->vlan_info.ipv6.refcnt [%d]\n",
					  __FUNCTION__,
					  iface->vlan_info.ipv6.refcnt);
				}
			}
		}
		csio_spin_unlock_irqrestore(hw, &iface->hlock, flags);
		if (got)
			break;
	}
	if (got)
		return iface;
	else
		return NULL;
}

/* iface locked by the caller */
int csio_chnet_iface_addr_put(struct csio_hw *hw,
			struct csio_chnet_iface *iface, int ip_type,
			struct ip_addr *addr)
{
	int done = 0;

	if (ip_type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
		CSIO_DB_ASSERT(addr->ip4);
		if (iface->ipv4.addr == addr->ip4) {
			CSIO_DB_ASSERT(iface->ipv4.refcnt > 0);
			iface->ipv4.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->ipv4.refcnt [%d]\n",
				__FUNCTION__, iface->ipv4.refcnt);
		} else if (iface->vlan_info.ipv4.addr == addr->ip4) {
			CSIO_DB_ASSERT(iface->vlan_info.ipv4.refcnt > 0);
			iface->vlan_info.ipv4.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->vlan_info.ipv4.refcnt [%d]\n",
				__FUNCTION__, iface->vlan_info.ipv4.refcnt);
		}
	} else { /* IPV6 */
		CSIO_DB_ASSERT(addr->ip6);
		if (!memcmp(iface->ipv6.addr, addr->ip6, 16)) {
			CSIO_DB_ASSERT(iface->ipv6.refcnt > 0);
			iface->ipv6.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->ipv6.refcnt [%d]\n",
				__FUNCTION__, iface->ipv6.refcnt);
			
		} else if (!memcmp(iface->vlan_info.ipv6.addr, addr->ip6, 16)) {
			CSIO_DB_ASSERT(iface->vlan_info.ipv6.refcnt > 0);
			iface->vlan_info.ipv6.refcnt--;
			done = 1;
			csio_dbg(hw, "%s: iface->vlan_info.ipv6.refcnt [%d]\n",
				__FUNCTION__, iface->vlan_info.ipv6.refcnt);
		}
	}
	return done;
}


