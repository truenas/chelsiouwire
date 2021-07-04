/*
 *  Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: iscsi specific mailbox module.
 *
 */

#include <csio_lnode.h>
#include <csio_mb.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_os_hw.h>
#include <csio_trans_foiscsi.h>
#include <csio_ctrl_devs.h>
#ifdef __CSIO_COISCSI_ENABLED__
#include <csio_coiscsi_fwevts.h>
#endif

extern struct csio_lnode_os_ops *lni_ops;

static csio_retval_t
csio_foiscsi_node_wr_handler(struct csio_hw *hw,
			struct fw_foiscsi_node_wr *node_wr)
{
	struct fw_foiscsi_node_wr *wr = node_wr;
	struct csio_lnode_iscsi *lni =
		(struct csio_lnode_iscsi *)(uintptr_t)wr->cookie;
	short inode_db_idx = -1;
	uint32_t op = CLEAR_INSTANCE;

	if (wr->subop ==  FW_FOISCSI_WR_SUBOP_ADD)
		op = ASSIGN_INSTANCE;
	else if (wr->subop == FW_FOISCSI_WR_SUBOP_DEL)
		op = CLEAR_INSTANCE;

	lni->inode_flowid = G_FW_WR_FLOWID(csio_be32_to_cpu(wr->no_sess_recv_to_len16));

	lni->no_recov = (csio_be16_to_cpu(wr->retry_timeout) == 0xFFFF);

	csio_info(hw, "inode flowid = %x recov to %d lni->no_recov %d\n",
		lni->inode_flowid, csio_be16_to_cpu(wr->retry_timeout), lni->no_recov);

	if (wr->status)
		goto out;

	if (wr->subop ==  FW_FOISCSI_WR_SUBOP_ADD ||
	    wr->subop ==  FW_FOISCSI_WR_SUBOP_MOD) {
		lni->valid = 1;
		inode_db_idx = lni->inode_id;

	} else if (wr->subop == FW_FOISCSI_WR_SUBOP_DEL) {
		csio_dbg(hw, "Clear: idx = %d",
				(csio_be16_to_cpu(wr->nodeid) + 1));

		memset(lni->inst.name, 0, FW_FOISCSI_NAME_MAX_LEN);
		memset(lni->inst.alias, 0, FW_FOISCSI_ALIAS_MAX_LEN);
		memset(lni->inst.chap_id, 0, FW_FOISCSI_NAME_MAX_LEN);
		memset(lni->inst.chap_sec, 0, FW_FOISCSI_CHAP_SEC_MAX_LEN);

		lni->valid = 0;
		lni->num_sessions = 0;
	}

out:
	csio_transport_event_handler(hw, op, wr->status,
			lni->inode_id, NULL, 0);

	return CSIO_SUCCESS;
}

static csio_retval_t
csio_foiscsi_ctrl_wr_handler(struct csio_hw *hw,
		struct fw_foiscsi_ctrl_wr *wr){

	struct csio_rnode *rn = (struct csio_rnode *)(uintptr_t)wr->cookie;

	u8 status = wr->status;

	if (wr->subop == FW_FOISCSI_WR_SUBOP_DEL)
		csio_foiscsi_ctrl_del(rn, status);
	else
		csio_foiscsi_ctrl_add(hw, rn, wr, status);

	return CSIO_SUCCESS;
}

static void
csio_fwevt_ifconf_dhcp_set(struct csio_hw *hw,
				struct fw_chnet_ifconf_wr *wr, int32_t rc,
				struct csio_chnet_ifconf_ioctl *ifconf_info)
{
	struct fw_ifconf_dhcp_info  *dinfo;

	dinfo = (struct fw_ifconf_dhcp_info*)
		((uint8_t*) wr + (sizeof(__be64)*4));

#ifdef __CSIO_DEBUG__
	csio_dump_buffer((uint8_t*)wr, sizeof(__be64)*6);
#endif
	csio_dbg(hw, "%s:\ndinfo->addr [0x%x]\ndinfo->mask [0x%x]\n"
		"dinfo->gw [0x%x]\n", __FUNCTION__,
		csio_be32_to_cpu(dinfo->addr),
		csio_be32_to_cpu(dinfo->mask),
		csio_be32_to_cpu(dinfo->gw));

	ifconf_info->v4.ipv4_addr = csio_be32_to_cpu(dinfo->addr);
	ifconf_info->v4.ipv4_mask = csio_be32_to_cpu(dinfo->mask);
	ifconf_info->v4.ipv4_gw = csio_be32_to_cpu(dinfo->gw);

	ifconf_info->vlanid = csio_be16_to_cpu(dinfo->vlanid);
	ifconf_info->mtu = csio_be16_to_cpu(dinfo->mtu);

	return;
}

static void
csio_fwevt_ifconf_addr6_set(struct csio_hw *hw,
				struct fw_chnet_ifconf_wr *wr, int32_t rc,
				struct csio_chnet_ifconf_ioctl *ifconf_info)
{
	struct fw_ifconf_addr6_info  *ainfo;

	ainfo = (struct fw_ifconf_addr6_info*)
		((uint8_t*) wr + (sizeof(__be64)*4));

#ifdef __CSIO_DEBUG__
	csio_dump_buffer((uint8_t*)wr, sizeof(__be64)*6);
#endif
	if (rc == CSIO_SUCCESS) {
		ifconf_info->v6.prefix_len = ainfo->prefix_len;
		memcpy(ifconf_info->v6.ipv6_addr, (void *)&ainfo->addr_hi, 16);
		memcpy(ifconf_info->v6.ipv6_gw, (void *)&ainfo->router_hi, 16);
		csio_dbg(hw, "%s:\n\tainfo->addr [%pI6]\n\tainfo->prefix_len [%u]\n"
				"\tainfo->gw6 [%pI6]\n", __FUNCTION__,
			ifconf_info->v6.ipv6_addr,
			ifconf_info->v6.prefix_len,
			ifconf_info->v6.ipv6_gw);
	}
	ifconf_info->vlanid = csio_be16_to_cpu(ainfo->vlanid);

	return;
}

static void
csio_fwevt_ifconf_ping_pld(struct csio_hw *hw,
			   struct fw_chnet_ifconf_wr *wr, int32_t rc,
			   struct csio_chnet_ifconf_ioctl *ifconf_info)
{
	struct fw_ifconf_ping_info *pinfo;

	pinfo = (struct fw_ifconf_ping_info *)
		((uint8_t *)wr + (sizeof(__be64) * 4));

#ifdef __CSIO_DEBUG__
	csio_dump_buffer((uint8_t *)wr, sizeof(__be64) * 6);
#endif
	if (rc == CSIO_SUCCESS) {
		ifconf_info->ping_pldsize =
			csio_be16_to_cpu(pinfo->ping_pldsize);
		csio_dbg(hw, "%s:\n\tpinfo->ping_pldsize %u\n",
			 __FUNCTION__, ifconf_info->ping_pldsize);
	}
}

static csio_retval_t
csio_foiscsi_ifconf_async_wr_handler(struct csio_hw *hw,
			struct fw_chnet_ifconf_wr *wr)
{
	struct csio_chnet_ifconf_ioctl ifconf_info;
	struct csio_ctrl_chnet *chnet_cdev = NULL;
	struct csio_chnet_iface *iface = NULL;
	void *data = NULL;
	int32_t rc = CSIO_SUCCESS;
	uint32_t if_flid;
	unsigned long handle = wr->cookie;
	unsigned long cookie_val = 0;
	unsigned int op = 0;
	int i;

	csio_dbg(hw, "%s: wr->retval %d\n", __FUNCTION__, wr->retval);
	rc = wr->retval;

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

#ifdef __CSIO_DEBUG__
	csio_dump_buffer((uint8_t *)wr, sizeof(__be64)*6);
#endif
	switch(wr->subop) {
		case FW_CHNET_IFCONF_WR_SUBOP_IPV4_SET:
			op = IFCONF_IPV4_SET;
			cookie_val = csio_be64_to_cpu(wr->cookie);
			handle = (cookie_val & 0xff);
			ifconf_info.vlanid = ((cookie_val >> 8) & 0xffff);
			data = &ifconf_info;
			csio_dbg(hw, "cookie_val 0x%x handle %d vlanid 0x%x\n", 
				(unsigned int)cookie_val, (int)handle, ifconf_info.vlanid);
			break;
		case FW_CHNET_IFCONF_WR_SUBOP_VLAN_SET:
			op = IFCONF_IPV4_VLAN_SET;
			break;
		case FW_CHNET_IFCONF_WR_SUBOP_MTU_SET:
			op = IFCONF_MTU_SET;
			break;

		case FW_CHNET_IFCONF_WR_SUBOP_DHCP_SET:
			op = IPV4_DHCP_SET;
			csio_fwevt_ifconf_dhcp_set(hw, wr, rc, &ifconf_info);
			data = &ifconf_info;
			break;

		case FW_CHNET_IFCONF_WR_SUBOP_IPV6_SET:
			op = IFCONF_IPV6_SET;
			cookie_val = csio_be64_to_cpu(wr->cookie);
			handle = (cookie_val & 0xff);
			ifconf_info.vlanid = ((cookie_val >> 8) & 0xffff);
			data = &ifconf_info;
			csio_dbg(hw, "cookie_val 0x%x handle %d vlanid 0x%x\n", 
				(unsigned int)cookie_val, (int)handle, ifconf_info.vlanid);
			break;

		case FW_CHNET_IFCONF_WR_SUBOP_DHCPV6_SET:
			op = IPV6_DHCP_SET;
			csio_dbg(hw, "%s: dhcp6 response rcvd from fw\n", __FUNCTION__);
			csio_fwevt_ifconf_addr6_set(hw, wr, rc, &ifconf_info);

			if (rc == CSIO_SUCCESS)
				ifconf_info.type = CSIO_CHNET_L3CFG_TYPE_DHCPV6;

			data = &ifconf_info;
			break;

		case FW_CHNET_IFCONF_WR_SUBOP_LINKLOCAL_ADDR_SET:
			op = IFCONF_LINKLOCAL_ADDR_SET;
			csio_dbg(hw, "%s: link-local ipv6 response rcvd from fw\n", __FUNCTION__);
			csio_fwevt_ifconf_addr6_set(hw, wr, rc, &ifconf_info);

			if (rc == CSIO_SUCCESS)
				ifconf_info.type = CSIO_CHNET_L3CFG_TYPE_LINKLOCAL6;

			/* Unsolicited response, match ifid to get handle */
			if_flid = G_FW_CHNET_IFACE_CMD_IFID(csio_be32_to_cpu(wr->if_flowid));
			for (i = 0; i < hw->num_t4ports; i++) {
				iface = &chnet_cdev->ifaces[hw->t4port[i].portid];
				if (iface && iface->if_id == if_flid) {
					handle = iface->tport->portid;
					break;
				}
			}

			data = &ifconf_info;
			break;
		case FW_CHNET_IFCONF_WR_SUBOP_RA_BASED_ADDR_SET:
			op = IFCONF_RA_BASED_ADDR_SET;
			csio_dbg(hw, "%s: router advertised ipv6 response rcvd from fw\n", __FUNCTION__);
			csio_fwevt_ifconf_addr6_set(hw, wr, rc, &ifconf_info);

			if (rc == CSIO_SUCCESS)
				ifconf_info.type = CSIO_CHNET_L3CFG_TYPE_RTADV6;

			/* Unsolicited response, match ifid to get handle */
			if_flid = G_FW_CHNET_IFACE_CMD_IFID(csio_be32_to_cpu(wr->if_flowid));
			for (i = 0; i < hw->num_t4ports; i++) {
				iface = &chnet_cdev->ifaces[hw->t4port[i].portid];
				if (iface && iface->if_id == if_flid) {
					handle = iface->tport->portid;
					break;
				}
			}
			data = &ifconf_info;
			break;
		case FW_CHNET_IFCONF_WR_SUBOP_ICMP_PLD_PING4:
		case FW_CHNET_IFCONF_WR_SUBOP_ICMP_PLD_PING6:
			if (wr->subop == FW_CHNET_IFCONF_WR_SUBOP_ICMP_PLD_PING4)
				op = IFCONF_IPV4_PING;
			else
				op = IFCONF_IPV6_PING;
	
			cookie_val = csio_be64_to_cpu(wr->cookie);
			handle = (cookie_val & 0xff);
			ifconf_info.vlanid = ((cookie_val >> 8) & 0xffff);
			ifconf_info.retval = wr->retval;
			ifconf_info.ping_time = csio_be16_to_cpu(wr->u.ping.ping_time);
			ifconf_info.ping_rsptype = wr->u.ping.ping_rsptype;
			ifconf_info.ping_param_rspcode = wr->u.ping.ping_param_rspcode_to_fin_bit;
			ifconf_info.ping_ttl 	 = wr->u.ping.ping_ttl;
			csio_fwevt_ifconf_ping_pld(hw, wr, rc, &ifconf_info);
			data = &ifconf_info;
			csio_dbg(hw, "cookie_val 0x%x handle %d vlanid 0x%x\n", 
				(unsigned int)cookie_val, (int)handle, ifconf_info.vlanid);
			break;
		case FW_CHNET_IFCONF_WR_SUBOP_PMTU6_CLEAR:
			op = IFCONF_PMTU6_CLEAR;
			cookie_val = csio_be64_to_cpu(wr->cookie);
			handle = (cookie_val & 0xff);
			csio_dbg(hw, "cookie_val 0x%x handle %d\n",
				(unsigned int)cookie_val, (int)handle);
			break;
		default:
			csio_dbg(hw, "%s: Unhandled subop %d\n", __FUNCTION__, wr->subop);
			break;
	}

	csio_transport_event_handler(hw, op, rc,
					handle, data, 0);

	return rc;
}

static csio_retval_t
csio_chnet_iface_cmd_handler(struct csio_hw *hw,
			struct fw_chnet_iface_cmd* cmd)
{
	struct csio_chnet_iface_info iface_info;
	int portid = G_FW_CHNET_IFACE_CMD_PORTID(
			csio_be32_to_cpu(cmd->op_to_portid));

	iface_info.portid = portid;
	iface_info.if_state = G_FW_CHNET_IFACE_CMD_IFSTATE(
					csio_be32_to_cpu(cmd->ifid_ifstate));
	if (iface_info.if_state == CHNET_IFACE_STATE_ENABLED) {
		iface_info.if_id =  G_FW_CHNET_IFACE_CMD_IFID(
			csio_be32_to_cpu(cmd->ifid_ifstate));
		csio_memcpy(iface_info.mac, cmd->mac, 6);
		csio_dbg(hw, "csio_chnet_iface_cmd_handler: portid [%u], "
				"iface_info.if_id [0x%x]\n", portid, iface_info.if_id);
	}
	csio_transport_event_handler(hw,
			((cmd->subop == FW_CHNET_IFACE_CMD_SUBOP_LINK_UP)?\
				IFACE_CMD_SUBOP_LINK_UP:IFACE_CMD_SUBOP_LINK_DOWN),
				CSIO_SUCCESS, portid, &iface_info, 0);
	return 0;
}



static csio_retval_t
csio_foiscsi_debug_cmd_handler(struct csio_hw *hw, struct fw_debug_cmd *cmd)
{
	csio_mb_dump_fw_dbg(hw, (__be64 *)cmd);

	return CSIO_SUCCESS;
}

/**
 *  csio_iscsi_fwevt_handler - handles iscsi fw events.
 */
void
csio_foiscsi_fwevt_handler(struct csio_hw *hw, uint8_t cpl_op, __be64 *cmd)
{

}

csio_retval_t csio_foiscsi_mb_fwevt_handler(struct csio_hw *hw, __be64 *cmd)
{
	uint8_t opcode = *(uint8_t *)cmd;
	int rc = CSIO_SUCCESS;

	switch (opcode) {
	case FW_PORT_CMD:
		/*rc = csio_foiscsi_port_cmd_handler(hw,
					(struct fw_port_cmd*)cmd);*/
		rc = t4_handle_fw_rpl(&hw->adap, cmd);
		break;
	case FW_FOISCSI_NODE_WR:
		rc = csio_foiscsi_node_wr_handler(hw,
					(struct fw_foiscsi_node_wr*)cmd);
		break;
	
	case FW_FOISCSI_CTRL_WR:
		
		rc = csio_foiscsi_ctrl_wr_handler(hw,
					(struct fw_foiscsi_ctrl_wr*)cmd);
		break;

	case FW_CHNET_IFCONF_WR:
		rc = csio_foiscsi_ifconf_async_wr_handler(hw,
					(struct fw_chnet_ifconf_wr*)cmd);
		break;
	
	case FW_CHNET_IFACE_CMD:
		rc = csio_chnet_iface_cmd_handler(hw,
					(struct fw_chnet_iface_cmd*)cmd);
		break;
#ifdef __CSIO_COISCSI_ENABLED__
	case FW_COISCSI_TGT_WR:
		rc = csio_coiscsi_tgt_fwevt_handler(hw,
				(struct fw_coiscsi_tgt_wr*)cmd);
		break;

	case FW_COISCSI_TGT_CONN_WR:
		rc = csio_conn_fwevt_handler(hw, 
				(struct fw_coiscsi_tgt_conn_wr*)cmd);
		break;

	case FW_ISNS_WR:
		rc = csio_isns_client_fwevt_handler(hw, (struct fw_isns_wr*)cmd);
		break;

	case FW_COISCSI_STATS_WR:
		rc = csio_coiscsi_stats_fwevt_handler(hw,
				(struct fw_coiscsi_stats_wr*)cmd);
		break;
#endif
	case FW_DEBUG_CMD:
		rc = csio_foiscsi_debug_cmd_handler(hw,
					(struct fw_debug_cmd*)cmd);
		break;
	
	default:
		csio_dbg(hw,
		 "%s: Unknown op [0x%0x] on foiscsi fwevt_q.\n",
		 				__FUNCTION__, opcode);
		rc = CSIO_INVAL;
		/*CSIO_ASSERT(opcode)*/;
		break;
	}
	return rc;
}

