/*
 *  Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: foiscsi transport functions. The possible transport could be
 * chelsio properietary interface (ioctl based),  open-iscsi or any other.
 *
 */
#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_trans_foiscsi.h>
#include <csio_ctrl_foiscsi.h>
#include <csio_ctrl_chnet.h>
#include <csio_ctrl_devs.h>
#include <csio_foiscsi.h>
#include <csio_os_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_ibft.h>
#include <csio_foiscsi_persistent.h>
#include <csio_lnode.h>

//static struct csio_ctrl_foiscsi foiscsi_cdev;
/* Maintains the per adapter instance of foiscsi common transport */

static struct csio_list foiscsi_transport_list;

/*static struct foiscsi_transport *transport_list[MAX_TRANSPORT_SUPPORTED];*/
/*static unsigned int num_transport;*/

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
static int bootlogin_threadfunc(void *data)
{
	struct csio_hw *hw = (struct csio_hw*)data;

	if (csio_foiscsi_persistent_init() == CSIO_SUCCESS) {
		csio_foiscsi_ibft_login(hw);
		csio_foiscsi_persistent_login(hw);
	}
	return 0;
}

static void csio_bootlogin_start(struct csio_oss_timer *t)
{
	struct csio_bootlogin *bootlogin = csio_container_of(
						t,struct csio_bootlogin,
						bootlogin_timer);
	struct csio_hw *hw = csio_bootlogin_to_hw(bootlogin);

	if (csio_is_hw_ready(hw))
		csio_wake_up(bootlogin->bootlogin_ts);
	else if (bootlogin->attempt++ < 3)
		csio_timer_start(&bootlogin->bootlogin_timer,
			3000);
}
#endif

static int
csio_foiscsi_sess_table_alloc(struct csio_foiscsi_sess_table *sess_table,
			      unsigned int start, unsigned num)
{
	sess_table->start = start;
	sess_table->last = 0;
	sess_table->max = num;

	csio_head_init(&sess_table->rni_list);
	csio_spin_lock_init(&sess_table->tlock);

	sess_table->bitmap = foiscsi_alloc(BITS_TO_LONGS(num) * sizeof(long));
	if (!sess_table->bitmap)
		return -ENOMEM;

	bitmap_zero(sess_table->bitmap, num);

	return 0;
}

void csio_foiscsi_sess_table_free(struct csio_foiscsi_sess_table *sess_table)
{
	foiscsi_free(sess_table);
}

/* Do not sleep in this function. Caller is protecting it with hw spin lock */
int csio_iscsi_transport_init(struct csio_hw *hw)
{
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct csio_transport *transport = NULL;
	unsigned int i;
	int rv = 0;
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	char thread_name[20];
	struct csio_bootlogin *bootlogin = csio_hw_to_bootlogin(hw);
#endif

	/* if this is the first call into transport layer,
	 * get done with transport initilization */
	if (!hw->transport_init_done) {
		csio_head_init(&foiscsi_transport_list);
		
		for (i = 0; i < csio_os_iscsi_transport_count(); i++) {
			
			transport = csio_os_iscsi_transport_get(i);

			if (transport && transport->init_handler) {
				csio_elem_init((struct csio_list *)transport);
				rv = transport->init_handler(hw);
				if (rv == -1) {
					csio_err(hw,
				"transport %s failed to initialize\n",
				csio_os_iscsi_transport_get_name(transport));
					rv = -ENODEV;
					goto out;
				}
				csio_enq_at_tail(&foiscsi_transport_list,
						transport);
			}
			
		}
		hw->transport_init_done = 1;
	}

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);

	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi cdev missing\n");
		rv = -ENODEV;
		goto out;
	}

	/* initialize other fields of foiscsi_cdev */
	foiscsi_cdev->max_init_instances = FW_FOISCSI_INIT_NODE_MAX;
	for (i = 0; i < FW_FOISCSI_INIT_NODE_MAX; i++) {
		csio_mutex_init(&foiscsi_cdev->instance[i].inode_lock);
	}

	/* Enable ipv6 */
	if (!is_t4(hw->adap.params.chip))
		csio_enable_foiscsi_ipv6(hw);
	
	if (csio_chnet_init_ifaces(hw) != CSIO_SUCCESS) {
		rv = -ENODEV;
		goto free_foiscsi_inst;
	}

	rv = csio_foiscsi_sess_table_alloc(&foiscsi_cdev->sess_table,
				1, CSIO_FOISCSI_NUM_RNODES);
	if (rv) {
		csio_err(hw, "FOiSCSI hw allocations failed. rv [%d].\n", rv);
		goto free_foiscsi_inst;
	}
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	sprintf(thread_name, "boot_thread%d", hw->dev_num );
	bootlogin->bootlogin_ts = csio_kthread_create(
				bootlogin_threadfunc, (void *)hw,
				thread_name);

	/* wake up thread only when hw initialization is done */
	csio_timer_init(&bootlogin->bootlogin_timer,
					csio_bootlogin_start, 0);
	csio_timer_start(&bootlogin->bootlogin_timer, 3000);
#endif
	return rv;

free_foiscsi_inst:
	/*csio_deq_elem((struct csio_list *)foiscsi_inst);
	foiscsi_free(foiscsi_inst);*/
out:
	return rv;
}

int csio_iscsi_transport_uninit(struct csio_hw *hw)
{
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	/*
	 * bail out if we are not even initialized.
	 * */
	if (!hw->transport_init_done)
		goto out;

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	csio_timer_stop(&csio_hw_to_bootlogin(hw)->bootlogin_timer);
#endif
	CSIO_DB_ASSERT(
		csio_list_empty(&foiscsi_cdev->sess_table.rni_list));
	foiscsi_free(foiscsi_cdev->sess_table.bitmap);
out:
	return 0;
}

/* No protection for trasport_list because register fn is called in serial
 * order as of now. */
int csio_foiscsi_register_transport(struct csio_hw *hw,
		struct csio_transport *transport)
{
	/*unsigned int i;*/

	if (!transport)
		return -1;

	csio_dbg(hw, "%s: transport type %d\n", __FUNCTION__, transport->type);

	/* Only chelsio transport(in all platform) can have the registered ioctl
	 * handler. */
	if (!is_chelsio_transport(transport->type) && transport->ioctl_handler)
		return -1;
#if 0
	for (i = 0; i < MAX_TRANSPORT_SUPPORTED; i++) {
		if (!transport_list[i]) {
			transport_list[i] = transport;
			num_transport++;
			break;
		}
	}
	if (i == MAX_TRANSPORT_SUPPORTED)
		return -1;
#endif
	return 0;
}

/* NOT USED AS OF NOW */
int csio_foiscsi_unregister_transport(struct csio_hw *hw,
		struct csio_transport *transport)
{
#if 0
	unsigned int i;

	for (i = 0; i < MAX_TRANSPORT_SUPPORTED; i++) {
		if (transport_list[i] == transport) {
			transport_list[i] = NULL;
			num_transport--;
			break;
		}
	}
#endif
	return 0;
}

csio_retval_t
csio_chnet_link_up_cmd_handler(struct csio_hw *hw,
		struct csio_chnet_iface_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVALID_REQUEST;
		return EINVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINST_NOT_FOUND;
		return EINVAL;
	}

	iface = &chnet_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	/* iface->op_pending = 1; */

	rc = csio_foiscsi_do_link_cmd(hw, iface->tport->portid, req->flags,
			FW_CHNET_IFACE_CMD_SUBOP_LINK_UP, iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS)
		iface->op_pending = 0;

ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_chnet_link_down_cmd_handler(struct csio_hw *hw,
		struct csio_chnet_iface_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EIFACE_INVALID_PORT;
		return EINVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINST_NOT_FOUND;
		return EINVAL;
	}

	iface = &chnet_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	/* iface->op_pending = 1; */

	rc = csio_foiscsi_do_link_cmd(hw, iface->tport->portid, req->flags,
			FW_CHNET_IFACE_CMD_SUBOP_LINK_DOWN,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS)
		iface->op_pending = 0;

ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_chnet_vlan_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	iface = &chnet_cdev->ifaces[req->ifid];
	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if ((iface->vlan_info.ipv4.addr) ||
	    (iface->vlan_info.ipv6.addr[0] ||
	     iface->vlan_info.ipv6.addr[1] ||
	     iface->vlan_info.ipv6.addr[2] ||
	     iface->vlan_info.ipv6.addr[3])) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		csio_dbg(hw, "%s: addr in use. Cannot change vlan\n",
				__FUNCTION__);
		goto ulock_out;
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = EBUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;
	iface->vlan_info.vlan_id = req->vlanid;

	csio_dbg(hw, "iface->if_id [%0x], iface->if_state [%0x]\n",
			iface->if_id, iface->if_state);

	rc = csio_foiscsi_do_vlan_req(hw, op, iface->if_id, req->vlanid,
			iface->tport->portid);
	
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_chnet_pmtu6_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv4.refcnt);

	if(csio_vlan_valid(vlanid) &&
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		/* Link is not up */
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (iface->ipv4.refcnt > 0 || iface->ipv6.refcnt > 0) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	csio_dbg(hw, "iface->if_id [%0x], iface->if_state [%0x]\n",
			iface->if_id, iface->if_state);

	rc = csio_foiscsi_do_pmtu6_clean_req(hw, op, iface->if_id, req,
						iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}

ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_chnet_mtu_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], iface->if_state [%0x] "
			"iface->ipv4.refcnt [%u], iface->ipv6.refcnt [%u] \n", __FUNCTION__,
			iface->if_id, iface->if_state, iface->ipv4.refcnt, iface->ipv6.refcnt);

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		/* Link is not up */
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (iface->ipv4.refcnt > 0 || iface->ipv6.refcnt > 0) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	if (op == CSIO_CHNET_IFCONF_MTU_GET_IOCTL) {
		req->mtu = iface->mtu;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;
	iface->old_mtu = iface->mtu;
	iface->mtu = req->mtu;

	csio_dbg(hw, "iface->if_id [%0x], iface->if_state [%0x]\n",
			iface->if_id, iface->if_state);

	rc = csio_foiscsi_do_mtu_req(hw, op, iface->if_id, req->mtu,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_chnet_iface_get(struct csio_hw *hw,
		struct csio_chnet_ifconf_ioctl *req)
{
	int rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;

	csio_dbg(hw, "%s: req->ifid [%u]\n", __FUNCTION__, req->ifid);

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		return EINVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		return EINVAL;
	}

	iface = &chnet_cdev->ifaces[req->ifid];

	csio_mutex_lock(&iface->mlock);
	csio_dbg(hw, "%s: iface->if_id [%0x], vlanid [%u], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u] "
			"iface->ipv6.refcnt [%u] "
			"iface->mtu [%u]\n",
			__FUNCTION__, iface->if_id, iface->vlan_info.vlan_id,
			iface->if_state, iface->ipv4.refcnt,
			iface->ipv6.refcnt, iface->mtu);

	req->vlanid = iface->vlan_info.vlan_id;
	req->mtu = iface->mtu;
	req->address_state = iface->address_state;
	req->if_state = iface->if_state;

	csio_mutex_unlock(&iface->mlock);

	return rc;
}

csio_retval_t
csio_chnet_ifconf_ipv4_set_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv4.refcnt);

	if(csio_vlan_valid(vlanid) && 
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (vlanid == CSIO_MAX_VLAN_NUM) {
		if (iface->ipv4.refcnt > 0) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	} else if (csio_vlan_valid(vlanid)) {
		if (iface->vlan_info.ipv4.refcnt > 0 ) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	if (csio_vlan_valid(vlanid)) {
		iface->vlan_info.ipv4.addr = req->v4.ipv4_addr;
		iface->vlan_info.ipv4.mask = req->v4.ipv4_mask;
		iface->vlan_info.ipv4.gw = req->v4.ipv4_gw;
	} else {
		iface->ipv4.addr = req->v4.ipv4_addr;
		iface->ipv4.mask = req->v4.ipv4_mask;
		iface->ipv4.gw = req->v4.ipv4_gw;
	}

	rc = csio_foiscsi_ifconf_ip_set(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_chnet_ifconf_ipv4_ping_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv4.refcnt);

	if(csio_vlan_valid(vlanid) && 
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_err(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (iface->op_pending) {
		csio_err(hw, "%s: iface op pending %d\n",
				__FUNCTION__, iface->op_pending);
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	rc = csio_foiscsi_ifconf_ip_ping(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_chnet_ifconf_ipv6_ping_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv4.refcnt);

	if(csio_vlan_valid(vlanid) && 
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_err(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (iface->op_pending) {
		csio_err(hw, "%s: iface op pending %d\n",
				__FUNCTION__, iface->op_pending);
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	rc = csio_foiscsi_ifconf_ip_ping(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_chnet_ifconf_ipv6_set_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];
	csio_dbg(hw, "%s: iface->if_id [%0x], vlan-id [%d], vlan-prio [%d], "
			"iface->if_state [%0x], iface->ipv6.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, vlanid,
			(req->vlanid >> 13) & 0xf, iface->if_state,
			iface->ipv6.refcnt);

	if(csio_vlan_valid(vlanid) && 
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exist\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != 1) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto ulock_out;
	}

	if (vlanid == CSIO_MAX_VLAN_NUM) {
		if (iface->ipv6.refcnt > 0) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	} else if (csio_vlan_valid(vlanid)) {
		if (iface->vlan_info.ipv6.refcnt > 0 ) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto ulock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	if (csio_vlan_valid(vlanid)) {
		csio_memcpy(iface->vlan_info.ipv6.addr, req->v6.ipv6_addr, 16);
		csio_memcpy(iface->vlan_info.ipv6.gw6, req->v6.ipv6_gw, 16);
		iface->vlan_info.ipv6.prefix_len = req->v6.prefix_len;
	} else {
		csio_memcpy(iface->ipv6.addr, req->v6.ipv6_addr, 16);
		csio_memcpy(iface->ipv6.gw6, req->v6.ipv6_gw, 16);
		iface->ipv6.prefix_len = req->v6.prefix_len;
	}

	rc = csio_foiscsi_ifconf_ip_set(hw, op, iface->if_id, req,
			iface->tport->portid);
	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;

}

csio_retval_t
csio_chnet_ifconf_ip_get(struct csio_hw *hw,
		struct csio_chnet_ifconf_ioctl *req)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface = NULL;
	struct csio_chnet_iface_ipv4 *ifipv4 = NULL;
	struct csio_chnet_iface_ipv6 *ifipv6 = NULL;
	struct csio_ctrl_chnet *chnet_cdev;
	unsigned int vlan = 0;
	uint16_t vlanid = 0;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		rc = EINVAL;
		goto out;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		return EINVAL;
	}

	vlanid = req->vlanid & CSIO_VLAN_MASK;
	iface = &chnet_cdev->ifaces[req->ifid];

	if(csio_vlan_valid(vlanid)) {
		if((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid) {
			csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
			return EINVAL;
		}
		vlan = 1;
	}

	csio_dbg(hw, "%s: waiting on mutex\n", __FUNCTION__);

	csio_mutex_lock(&iface->mlock);
	csio_dbg(hw, "%s: iface->if_id [%0x], vlanid [%d], "
			"iface->if_state [%0x], iface->ipv4.refcnt [%u]\n",
			__FUNCTION__, iface->if_id, req->vlanid,
			iface->if_state, iface->ipv4.refcnt);

	if (req->type == CSIO_CHNET_L3CFG_TYPE_IPV4) {
		if (vlan)
			ifipv4 = &iface->vlan_info.ipv4;
		else
			ifipv4 = &iface->ipv4;

		req->v4.ipv4_addr = ifipv4->addr;
		req->v4.ipv4_mask = ifipv4->mask;
		req->v4.ipv4_gw = ifipv4->gw;
	} else { /* IPv6 */
		if(req->subop == CSIO_APP_OP_LLOCAL) {
			if (vlan)
				ifipv6 = &iface->link_local.ipv6_vlan;
			else
				ifipv6 = &iface->link_local.ipv6;
		} else {
			if (vlan)
				ifipv6 = &iface->vlan_info.ipv6;
			else
				ifipv6 = &iface->ipv6;
		}
		csio_memcpy(req->v6.ipv6_addr, ifipv6->addr, 16);
		csio_memcpy(req->v6.ipv6_gw, ifipv6->gw6, 16);
		req->v6.prefix_len = ifipv6->prefix_len;
	}
	req->type = iface->address_state;

	csio_mutex_unlock(&iface->mlock);
out:
	return rc;
}

csio_retval_t
csio_chnet_ifconf_dhcp_set_cmd_handler(struct csio_hw *hw,
		struct csio_chnet_ifconf_ioctl *req, uint8_t op, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface = NULL;
	struct csio_ctrl_chnet *chnet_cdev;
	uint16_t vlanid;

	if (req->ifid >= hw->num_t4ports) {
		csio_err(hw, "invalid ifid %d\n", req->ifid);
		req->retval = CSIO_EINVAL;
		return EINVAL;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		req->retval = CSIO_EINVAL;
		return EINVAL;
	}

	vlanid = (req->vlanid & CSIO_VLAN_MASK);
	iface = &chnet_cdev->ifaces[req->ifid];

	if(csio_vlan_valid(vlanid) && 
		((iface->vlan_info.vlan_id & CSIO_VLAN_MASK) != vlanid)) {
		csio_err(hw, "VLAN(%d) interface not exists\n", vlanid);
		req->retval = CSIO_EINVAL;
		return CSIO_INVAL;
	}

	csio_mutex_lock(&iface->mlock);

	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link [%0x] is not up\n",
				__FUNCTION__, req->ifid);
		req->retval = CSIO_EIFACE_ENOLINK;
		rc = CSIO_INVAL;
		goto unlock_out;
	}

	csio_dbg(hw, "%s: iface [%p], vlanid [%d], iface->if_id [%0x], "
			"iface->if_state [%0x]\n",
			__FUNCTION__, iface, req->vlanid,
			iface->if_id, iface->if_state);

	if (vlanid == CSIO_MAX_VLAN_NUM) {
		if (op == CSIO_CHNET_IFCONF_IPV4_DHCP_SET_IOCTL &&
				iface->ipv4.refcnt > 0) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		} else if (op == CSIO_CHNET_IFCONF_IPV6_DHCP_SET_IOCTL &&
				iface->ipv6.refcnt > 0) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		}
	} else if (csio_vlan_valid(vlanid)) {
		if (op == CSIO_CHNET_IFCONF_IPV4_DHCP_SET_IOCTL && 
				iface->vlan_info.ipv4.refcnt > 0 ) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		} else if (op == CSIO_CHNET_IFCONF_IPV6_DHCP_SET_IOCTL && 
				iface->vlan_info.ipv6.refcnt > 0 ) {
			req->retval = CSIO_EIFACE_BUSY;
			rc = CSIO_BUSY;
			goto unlock_out;
		}
	}
	if (iface->op_pending) {
		req->retval = CSIO_EIFACE_BUSY;
		rc = CSIO_BUSY;
		goto unlock_out;
	}
	iface->op_pending = 1;
	iface->transport_handle = handle;

	rc = csio_foiscsi_ifconf_dhcp_set(hw, iface->if_id, req,
			iface->tport->portid);

	req->retval = rc;
	if (rc != CSIO_SUCCESS) {
		iface->op_pending = 0;
		iface->transport_handle = NULL;
	}
unlock_out:
	csio_mutex_unlock(&iface->mlock);
	return rc;
}

csio_retval_t
csio_foiscsi_ioctl_assign_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx, i, flowid = 0;
	struct csio_chnet_iface *iface = NULL;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct csio_ctrl_chnet *chnet_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		csio_err(hw, "invalid initiator instance %d\n", ini_inst->id);
		ini_inst->retval = CSIO_EINVALID_INIT_INST;
		rc = -1;
		goto out;
	}

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = CSIO_EINST_NOT_FOUND;
		rc = -1;
		goto out;
	}

	inst_idx = ini_inst->id - 1;

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	for (i = 0; i < hw->num_t4ports; i++) {
		iface = &chnet_cdev->ifaces[i];
		flowid = iface->if_id;
		if (flowid) {
			csio_dbg(hw, "Got flowid [0x%x] at iface idx %d\n",
					flowid, i);
			break;
		}
	}
	if (!flowid) {
		csio_dbg(hw, "iface not provisioned\n");
		ini_inst->retval = CSIO_EIFACE_NOT_PROVISIONED;
		rc = -1;
		goto out;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		ini_inst->retval = CSIO_EINST_BUSY;
		rc = -1;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_foiscsi_assign_instance_handler(hw, iface->if_id,
			ini_inst, inst_idx+1);
	ini_inst->retval = rc;
	if (rc != CSIO_SUCCESS) {
		inst->op_pending = 0;
		inst->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
out:
	return rc;
}

csio_retval_t
csio_foiscsi_ioctl_clear_instance_handler(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst, void *handle)
{
	unsigned int inst_idx;
	enum csio_oss_error rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		ini_inst->retval = CSIO_EINVALID_INIT_INST;
		return CSIO_INVAL;
	}

	inst_idx = ini_inst->id - 1;

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = CSIO_EINST_NOT_FOUND;
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		ini_inst->retval = CSIO_EINST_BUSY;
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_foiscsi_clear_instance_handler(hw, ini_inst, inst_idx+1);
	ini_inst->retval = rc;
	if (rc != CSIO_SUCCESS) {
		inst->op_pending = 0;
		inst->transport_handle = NULL;
	}
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

csio_retval_t
csio_foiscsi_set_chap_secret(struct csio_hw *hw,
		struct foiscsi_instance *ini_inst)
{
	unsigned int inst_idx;
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;

	if ((ini_inst->id <= 0) || (ini_inst->id > FW_FOISCSI_INIT_NODE_MAX)) {
		ini_inst->retval = CSIO_EINVALID_INIT_INST;
		return CSIO_INVAL;
	}

	inst_idx = ini_inst->id - 1;

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		ini_inst->retval = CSIO_EINST_NOT_FOUND;
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);
	rc = csio_foiscsi_set_chap_secret_handler(hw, ini_inst);
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}


csio_retval_t
csio_foiscsi_ioctl_show_instance_handler(struct csio_hw *hw,
	struct foiscsi_instance *ini_inst)
{
	return csio_foiscsi_show_instance_handler(hw, ini_inst);
}

csio_retval_t
csio_foiscsi_ioctl_get_count_handler(struct csio_hw *hw,
		struct foiscsi_count *cnt)
{
	return csio_foiscsi_get_count_handler(hw, cnt);
}

csio_retval_t
csio_foiscsi_ioctl_get_sess_info_handler (struct csio_hw *hw,
		struct foiscsi_sess_info *sess_info)
{
	return csio_foiscsi_get_sess_info_handler(hw, sess_info);
}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
csio_retval_t
csio_foiscsi_ioctl_persistent_show_handler(struct csio_hw *hw,
				struct iscsi_persistent_target_db *target_db)
{
	return csio_foiscsi_persistent_show_handler(hw, target_db);
}

csio_retval_t
csio_foiscsi_ioctl_persistent_clear_handler(struct csio_hw *hw, uint8_t idx)
{
	return csio_foiscsi_persistent_clear_handler(hw, idx);
}
#endif

csio_retval_t
csio_ln_login_handler(struct csio_hw *hw, void *arg1,
			struct foiscsi_login_info *linfo,
			bool do_disc, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx = linfo->inode_id - 1;
	struct csio_ctrl_instance *inst;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	struct csio_lnode_iscsi *lni = NULL;
	struct csio_lnode *ln = NULL;
#endif

	if (inst_idx >= FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %d\n", inst_idx);
		return CSIO_INVAL;
	}

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];

	if (inst->op_pending) {
		return CSIO_BUSY;
	}
	
	csio_mutex_lock(&inst->inode_lock);

	iface = csio_chnet_iface_addr_get(hw, linfo->ip_type, &linfo->src_ip);
	if (!iface) {
		csio_err(hw, "Interface not provisioned\n");
		rc = CSIO_EIFACE_NOT_PROVISIONED;
		goto ulock_out;
	}
	if (iface->if_state != CHNET_IFACE_STATE_LINK_UP) {
		csio_dbg(hw, "%s: link is not up\n", __FUNCTION__);
		rc = CSIO_EIFACE_ENOLINK;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;
	inst->iface = iface;

	rc = csio_ln_login(hw, arg1, linfo, do_disc, inst_idx+1);
	if (rc != CSIO_SUCCESS) {
		csio_spin_lock_irq(hw, &iface->hlock);
		csio_chnet_iface_addr_put(hw, iface, linfo->ip_type, &linfo->src_ip);
		csio_spin_unlock_irq(hw, &iface->hlock);
		inst->op_pending = 0;
		inst->transport_handle = NULL;
		goto ulock_out;
	}

#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE	
	if (linfo->persistent) {
		ln = csio_foiscsi_get_lnode(hw, linfo->inode_id);
		if (!ln) {
			csio_dbg(hw, "inode not found\n");
			rc = CSIO_EINST_NOT_FOUND;
			goto ulock_out;
		}
		
		lni = csio_lnode_to_iscsi(ln);
		
		rc = csio_add_persistent_target(hw, linfo, lni, iface);
		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "failed to add to persistent db\n");
			goto ulock_out;
		}
	}
#endif
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

csio_retval_t
csio_ln_logout_handler(struct csio_hw *hw, void *arg1,
    struct foiscsi_logout_info *linfo, void *handle)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int inst_idx = linfo->inode_id - 1;
	struct csio_ctrl_instance *inst;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	
	if (inst_idx >= FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %d\n", inst_idx);
		return CSIO_INVAL;
	}

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	csio_mutex_lock(&inst->inode_lock);

	if (inst->op_pending) {
		rc = CSIO_BUSY;
		goto ulock_out;
	}
	inst->op_pending = 1;
	inst->transport_handle = handle;

	rc = csio_ln_logout(hw, arg1, linfo, inst_idx+1);
	/*
	 * rc can be != CSIO_SUCCESS in two cases,
	 * 1. logout_all, the last session logout returns CSIO_EOBJ_NOT_FOUND
	 * 2. logout failure.
	 * In both cases, We will expect a completion in ioctl_handler,
	 * So not cleaning op_pending here.
	 */
ulock_out:
	csio_mutex_unlock(&inst->inode_lock);
	return rc;
}

/* Response handlers */
static csio_retval_t
handle_link_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data)
{
	struct csio_chnet_iface *iface = NULL;
	struct csio_chnet_iface_info *iface_info = data;
	/* struct iscsi_transport_handle *h = NULL; */
	struct csio_ctrl_chnet *chnet_cdev;
	csio_retval_t rc = CSIO_SUCCESS;

	if (handle >= hw->num_t4ports) {
		csio_err(hw, "invalid handle %lu\n", handle);
		rc = CSIO_INVAL;
		goto out;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	iface = &chnet_cdev->ifaces[hw->t4port[handle].portid];

	csio_dbg(hw, "%s: if_state [%0x]\n",
			__FUNCTION__, iface_info->if_state);
	iface->if_state = iface_info->if_state;
	if (iface->if_state == CHNET_IFACE_STATE_ENABLED) {
		iface->if_id = iface_info->if_id;
		csio_memcpy(iface->tport->mac, iface_info->mac, 6);
		csio_dbg(hw, "handle_link_op_resp: "
		"MAC[%u]:[%x:%x:%x:%x:%x:%x]\n", hw->t4port[handle].portid,
	    iface->tport->mac[0], iface->tport->mac[1],
	    iface->tport->mac[2], iface->tport->mac[3],
	    iface->tport->mac[4], iface->tport->mac[5]);
	}
out:
	return rc;
}

static csio_retval_t
handle_ifconf_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
		unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_chnet_iface *iface = NULL;
	struct csio_chnet_ifconf_ioctl *req;
	struct csio_chnet_iface_ipv4 *ipv4_addr;
	struct csio_chnet_iface_ipv6 *ipv6_addr;
	struct iscsi_transport_handle *h = NULL;
	struct csio_ctrl_chnet *chnet_cdev;
	uint8_t	vlan_shift = 0;

	if (handle >= hw->num_t4ports) {
		csio_err(hw, "invalid handle %lu\n", handle);
		rc = CSIO_INVAL;
		goto out;
	}

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if (!chnet_cdev) {
		csio_err(hw, "chnet inst not found\n");
		return CSIO_INVAL;
	}

	iface = &chnet_cdev->ifaces[hw->t4port[handle].portid];
	if (!iface->transport_handle || !iface->op_pending) {
		if (!iface->transport_handle && opcode != IFCONF_LINKLOCAL_ADDR_SET &&
			opcode != IFCONF_RA_BASED_ADDR_SET)
			goto out;
	}
	if (status != CSIO_SUCCESS)
		csio_dbg(hw, "%s: status %d, operation failed\n",
				__FUNCTION__, status);

	switch (opcode) {
	case IFCONF_IPV4_VLAN_SET:
		if (status != CSIO_SUCCESS)
			iface->vlan_info.vlan_id = 0;
		else
			csio_dbg(hw, "ifid[%u] : vlan %u provisioned\n",
					iface->tport->portid,
					iface->vlan_info.vlan_id);
		break;

	case IFCONF_MTU_SET:
		if (status != CSIO_SUCCESS) {
			iface->mtu = iface->old_mtu;
			iface->old_mtu = 0;
		} else {
			csio_dbg(hw, "ifid[%d] : mtu changed to %u\n",
					iface->tport->portid, iface->mtu);
		}
		break;

	case IFCONF_IPV4_SET:
		req = data;
		if (csio_vlan_valid(req->vlanid)) {
			ipv4_addr =  &iface->vlan_info.ipv4;
			vlan_shift = VLAN_SHIFT;
		} else {
			ipv4_addr = &iface->ipv4;
		}

		if (status != CSIO_SUCCESS) {
			ipv4_addr->addr = 0;
			ipv4_addr->mask = 0;
			ipv4_addr->gw = 0;
		} else {
			iface->address_state &= ~(CSIO_IPV4_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV4_STATIC << vlan_shift);
		}

		csio_dbg(hw, "ifid[%d] : ip %u.%u.%u.%u provisioned\n",
				iface->tport->portid,
				(ipv4_addr->addr >> 24) & 0xff,
				(ipv4_addr->addr >> 16) & 0xff,
				(ipv4_addr->addr >> 8) & 0xff,
				ipv4_addr->addr & 0xff);
		break;

	case IPV4_DHCP_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_chnet_ifconf_ioctl *ifconf_info = data;
			if (csio_vlan_valid(ifconf_info->vlanid)) {
				ipv4_addr = &iface->vlan_info.ipv4;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv4_addr = &iface->ipv4;
			}

			/* get MTU of the interface */
			iface->mtu = ifconf_info->mtu;
			ipv4_addr->addr = ifconf_info->v4.ipv4_addr;
			ipv4_addr->mask = ifconf_info->v4.ipv4_mask ;
			ipv4_addr->gw = ifconf_info->v4.ipv4_gw;
			csio_dbg(hw, "ifid[%d] : ip %u.%u.%u.%u "
					"provisioned by dhcp\n",
					iface->tport->portid,
					(ipv4_addr->addr >> 24) & 0xff,
					(ipv4_addr->addr >> 16) & 0xff,
					(ipv4_addr->addr >> 8) & 0xff,
					ipv4_addr->addr & 0xff);
			if (iface->transport_handle) {
				req = &((struct chnet_transport_handle *)
						(iface->transport_handle))->\
					iparam.u.ifconf_req;
				req->v4.ipv4_addr = ipv4_addr->addr;
				req->v4.ipv4_mask = ipv4_addr->mask;
				csio_dbg(hw, "%s: req->ipv4_addr [0x%x],"
						" req->ipv4_mask [0x%x]\n",
						__FUNCTION__, req->v4.ipv4_addr,
						req->v4.ipv4_mask);
			}
			iface->address_state &= ~(CSIO_IPV4_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV4_DHCP << vlan_shift);
		}
		break;

	case IFCONF_IPV6_SET:
		req = data;
		if (csio_vlan_valid(req->vlanid)) {
			ipv6_addr =  &iface->vlan_info.ipv6;
			vlan_shift = VLAN_SHIFT;
		} else {
			ipv6_addr = &iface->ipv6;
		}

		if (status != CSIO_SUCCESS) {
			memset(ipv6_addr->addr, 0, 16);
			memset(ipv6_addr->gw6, 0, 16);
			ipv6_addr->prefix_len = 0;
		} else {
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_STATIC << vlan_shift);
		}

		csio_dbg(hw, "ifid[%d] : ip %pI6 provisioned\n",
			iface->tport->portid, ipv6_addr->addr);
		break;

	case IPV6_DHCP_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_chnet_ifconf_ioctl *ifconf_info = data;
			if (csio_vlan_valid(ifconf_info->vlanid)) {
				ipv6_addr = &iface->vlan_info.ipv6;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->ipv6;
			}

			csio_memcpy(ipv6_addr->addr, ifconf_info->v6.ipv6_addr, 16);
			csio_memcpy(ipv6_addr->gw6, ifconf_info->v6.ipv6_gw, 16);
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len ;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned by dhcp\n",
					iface->tport->portid,
					ipv6_addr->addr);
			if (iface->transport_handle) {
				req = &((struct chnet_transport_handle *)
						(iface->transport_handle))->\
					iparam.u.ifconf_req;
				csio_memcpy(req->v6.ipv6_addr,
					ipv6_addr->addr, 16);
				req->v6.prefix_len = ipv6_addr->prefix_len;
				csio_dbg(hw, "%s: req->ipv6_addr [%pI6],"
						" req->prefix_len [%u]\n",
						__FUNCTION__, req->v6.ipv6_addr,
						req->v6.prefix_len);
			}
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_DHCP << vlan_shift);
		}
		break;

	case IFCONF_LINKLOCAL_ADDR_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_chnet_ifconf_ioctl *ifconf_info = data;
			if (csio_vlan_valid(ifconf_info->vlanid)) {
				ipv6_addr = &iface->link_local.ipv6_vlan;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->link_local.ipv6;
			}

			csio_memcpy(ipv6_addr->addr, ifconf_info->v6.ipv6_addr, 16);
			csio_memcpy(ipv6_addr->gw6, ifconf_info->v6.ipv6_gw, 16);
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned as link-local address\n",
					iface->tport->portid,
					ipv6_addr->addr);
			iface->address_state |= CSIO_IPV6_LLOCAL;
		}
		break;

	case IFCONF_RA_BASED_ADDR_SET:
		if (status == CSIO_SUCCESS && data) {
			struct csio_chnet_ifconf_ioctl *ifconf_info = data;
			if (csio_vlan_valid(ifconf_info->vlanid)) {
				ipv6_addr = &iface->vlan_info.ipv6;
				vlan_shift = VLAN_SHIFT;
			} else {
				ipv6_addr = &iface->ipv6;
			}

			csio_memcpy(ipv6_addr->addr, ifconf_info->v6.ipv6_addr, 16);
			csio_memcpy(ipv6_addr->gw6, ifconf_info->v6.ipv6_gw, 16);
			ipv6_addr->prefix_len = ifconf_info->v6.prefix_len ;
			iface->mtu = ifconf_info->mtu;
			csio_dbg(hw, "ifid[%d] : ip %pI6 "
					"provisioned by router advertisement\n",
					iface->tport->portid,
					ipv6_addr->addr);
			iface->address_state &= ~(CSIO_IPV6_MASK << vlan_shift);
			iface->address_state |= (CSIO_IPV6_RTADV << vlan_shift);
		}
		break;
	case IFCONF_IPV4_PING:
	case IFCONF_IPV6_PING:
		if (data) {
			struct csio_chnet_ifconf_ioctl *ifconf_info = data;
			if (iface->transport_handle) {
				req = &((struct chnet_transport_handle *)
					(iface->transport_handle))->\
					iparam.u.ifconf_req;
				req->retval = ifconf_info->retval;
				req->ping_rsptype = ifconf_info->ping_rsptype;
				req->ping_param_rspcode = ifconf_info->ping_param_rspcode;
				req->ping_pldsize = ifconf_info->ping_pldsize;
				req->ping_time = ifconf_info->ping_time;
				req->ping_ttl = ifconf_info->ping_ttl;
				csio_dbg(hw, "IPV4 PING: status [%d] type [%d] code[%d] size [%d] time [%d] ttl[%d]\n",
					req->retval, req->ping_rsptype,
					req->ping_param_rspcode,
					req->ping_pldsize, req->ping_time,
					req->ping_ttl);
			}
		}
		break;
	case IFCONF_PMTU6_CLEAR:
		if (status != CSIO_SUCCESS)
			csio_dbg(hw, "ifid[%d] : pmtu clear failed\n",
						iface->tport->portid);
		else
			csio_dbg(hw, "ifid[%d] : pmtu cleared\n",
						iface->tport->portid);
		break;
	case IFCONF_ADDR_EXPIRED:
		/* Not supported */
		break;
	}

	if (opcode != IFCONF_LINKLOCAL_ADDR_SET &&
				opcode != IFCONF_RA_BASED_ADDR_SET) {
		h = iface->transport_handle;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_instance_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	struct csio_ctrl_instance *instance;
	struct iscsi_transport_handle *h = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	unsigned int inst_idx = handle - 1;

	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		rc = CSIO_INVAL;
		csio_err(hw, "invalid initiator instance id %u\n", inst_idx);
		goto out;
	}
	
	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	instance = &foiscsi_cdev->instance[inst_idx];

	if (instance->op_pending) {
		h = instance->transport_handle;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_login_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
		unsigned long handle, void *data)
{
	csio_retval_t rc = CSIO_SUCCESS;
	unsigned int inst_idx = handle - 1;
	struct csio_ctrl_instance *inst;
	struct csio_chnet_iface *iface;
	struct iscsi_transport_handle *h = NULL;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct foiscsi_login_info *ipinfo = data;

	csio_dbg(hw, "%s: inst_idx %d\n", __FUNCTION__, inst_idx);
	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance id %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	if (!data) {
		csio_err(hw, "missing ip info in instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	
	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	if (!inst->op_pending)
		goto out;

	iface = inst->iface;
	if ((status != CSIO_SUCCESS) ||
	    (opcode == ISCSI_DISC_TARGS)) {
		csio_spin_lock_irq(hw, &iface->hlock);
		csio_chnet_iface_addr_put(hw, iface, ipinfo->ip_type,
				&ipinfo->src_ip);
		csio_spin_unlock_irq(hw, &iface->hlock);
	}

	if (inst->op_pending) {
		h = inst->transport_handle;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

static csio_retval_t
handle_logout_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
			unsigned long handle, void *data, int hid)
{
	unsigned int i;
	csio_retval_t rc = CSIO_SUCCESS;
	unsigned int inst_idx = handle - 1;
	struct csio_chnet_iface *iface = NULL;
	struct csio_ctrl_instance *inst = NULL;
	struct iscsi_transport_handle *h;
	struct foiscsi_transport_handle *fh;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct csio_ctrl_chnet *chnet_cdev;
	struct foiscsi_login_info *ipinfo;

	csio_dbg(hw, "%s: inst_idx %d\n", __FUNCTION__, inst_idx);

	if (inst_idx > FW_FOISCSI_INIT_NODE_MAX) {
		csio_err(hw, "invalid initiator instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	if (!data) {
		csio_err(hw, "missing ip info in instance %u\n", inst_idx);
		rc = CSIO_INVAL;
		goto out;
	}
	ipinfo = data;

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		rc = CSIO_INVAL;
		goto out;
	}

	inst = &foiscsi_cdev->instance[inst_idx];
	if (!inst->op_pending)
		goto out;

	if(hid) {
		chnet_cdev = csio_hw_to_chnet_cdev(hw);
		for (i = 0; i < hw->num_t4ports; i++) {
			iface = &chnet_cdev->ifaces[i];
			csio_spin_lock_irq(he, &iface->hlock);
			if (csio_chnet_iface_addr_put(hw, iface, ipinfo->ip_type,
					&ipinfo->src_ip)) {
				csio_spin_unlock_irq(hw, &iface->hlock);
				break;
			}
			csio_spin_unlock_irq(hw, &iface->hlock);
		}
	}

	if (inst->op_pending) {
		h = inst->transport_handle;
		fh = (struct foiscsi_transport_handle*)h;
		fh += hid;
		h = (struct iscsi_transport_handle*)fh;
		//inst->transport_handle = NULL;
		//inst->op_pending = 0;
		if (h && h->transport && h->transport->event_handler)
			h->transport->event_handler(hw, opcode, status, h);
	}
out:
	return rc;
}

#ifdef __CSIO_COISCSI_ENABLED__
static csio_retval_t
handle_target_op_resp(struct csio_hw *hw, uint32_t opcode, uint32_t status,
		      unsigned long handle, void *data)
{
	struct csio_lnode_coiscsi *lncoi = data;
	struct iscsi_transport_handle *h;

        if (lncoi->op_pending) {
		h = lncoi->transport_handle;
		if (h && h->transport && h->transport->event_handler)
                	h->transport->event_handler(hw, opcode, status, h);
	}

	return 0;
}
#endif

csio_retval_t csio_transport_ioctl_handler(struct csio_hw *hw,
		enum csio_ioctl_type type,
		uint32_t opcode, unsigned long arg,
		void *buffer, uint32_t buffer_len)
{
	csio_retval_t rc = CSIO_INVAL;
	/*unsigned int i;*/
	struct csio_list *tmp = NULL;
	struct csio_transport *transport = NULL;
#ifdef __CSIO_COISCSI_ENABLED__
	struct csio_coiscsi_tgtm *tgtm = csio_hw_to_coiscsi_tgtm(hw);
#endif
	/* Check for all registered transport, if ioctl handler is registered
 	 * then call it and break; */

	csio_list_for_each(tmp, &foiscsi_transport_list) {
		transport = (struct csio_transport *) tmp;
		if (transport && transport->ioctl_handler[type]) {
			/* Only platform's chelsio transport can
			 * have the registered
		 	 * ioctl. So we are safe. */
#ifdef __CSIO_COISCSI_ENABLED__
			csio_mutex_lock(&tgtm->ioctl_lock);
			if (tgtm->ioctl_pending) {
				rc = EBUSY;
				csio_mutex_unlock(&tgtm->ioctl_lock);
				break;
			}
			tgtm->ioctl_pending = 1;
			csio_mutex_unlock(&tgtm->ioctl_lock);
#endif
			rc = transport->ioctl_handler[type](hw, opcode, arg,
							buffer, buffer_len);
#ifdef __CSIO_COISCSI_ENABLED__
			csio_mutex_lock(&tgtm->ioctl_lock);
			tgtm->ioctl_pending = 0;
			csio_mutex_unlock(&tgtm->ioctl_lock);
#endif
			break;
		}
	}

	csio_dbg(hw, "%s: opcode [%d], rc [%d].\n", __FUNCTION__, opcode, rc);

	return rc;
}

/* This function should be called by LLD from the WR response handlers. This
 * function will call the appropriate transport */
csio_retval_t csio_transport_event_handler(struct csio_hw *hw,
		uint32_t opcode, uint32_t status,
		unsigned long handle, void *data, int hid)
{
	csio_retval_t rc =  CSIO_SUCCESS;
	/* struct iscsi_transport_handle *h = NULL; */

	csio_dbg(hw, "%s: opcode %d, handle %lu\n",
			__FUNCTION__, opcode, handle);


	/* if opcode is iface specific then the handle is the portid value
	 * or if opcode is instance/login/discovery/logout related then
	 * handle is the instance id */

	/* if the internal transport handle is null that means no transport is
	 * waiting for this event. This may be for us only. This will happen
	 * mostly in iface start case. TODO */

	switch(opcode) {
	case IFACE_CMD_SUBOP_LINK_UP:
	case IFACE_CMD_SUBOP_LINK_DOWN:
		rc = handle_link_op_resp(hw, opcode, status, handle, data);
		break;
	case IFCONF_IPV4_VLAN_SET:
	case IFCONF_MTU_SET:
	case IFCONF_MTU_GET:
	case IFCONF_IPV4_SET:
	case IPV4_DHCP_SET:
	case IPV6_DHCP_SET:
	case IFCONF_IPV6_SET:
	case IFCONF_LINKLOCAL_ADDR_SET:
	case IFCONF_RA_BASED_ADDR_SET:
	case IFCONF_IPV4_PING:
	case IFCONF_IPV6_PING:
	case IFCONF_PMTU6_CLEAR:
		rc = handle_ifconf_op_resp(hw, opcode, status, handle, data);
		break;
	case ASSIGN_INSTANCE:
	case CLEAR_INSTANCE:
		rc = handle_instance_op_resp(hw, opcode, status, handle, data);
		break;
	case ISCSI_LOGIN_TO_TARGET:
	case ISCSI_DISC_TARGS:
		rc = handle_login_op_resp(hw, opcode, status, handle, data);
		break;
	case LOGOUT_FROM_TARGET:
		rc = handle_logout_op_resp(hw, opcode, status, handle, data, hid);
		break;
#ifdef __CSIO_COISCSI_ENABLED__
	case START_TARGET:
	case STOP_TARGET:
		rc = handle_target_op_resp(hw, opcode, status, handle, data);
		break;
#endif
	default:
		csio_dbg(hw, "unknown event %d in transport from LLD\n",opcode);
	}
	return CSIO_SUCCESS;
}

static inline unsigned int foiscsi_instance_op(unsigned int op)
{
	unsigned int rc = 0;
	if (op == ASSIGN_INSTANCE ||  op == CLEAR_INSTANCE ||
		op == ISCSI_LOGIN_TO_TARGET || op == ISCSI_DISC_TARGS ||
		op == LOGOUT_FROM_TARGET)
		rc = 1;

	return rc;
}

static inline unsigned int chnet_iface_op(unsigned int op)
{
	unsigned int rc = 0;

	if (op == IFACE_CMD_SUBOP_LINK_UP || op == IFACE_CMD_SUBOP_LINK_DOWN ||
		op == IFCONF_IPV4_VLAN_SET || op == IFCONF_MTU_SET ||
		op == IFCONF_MTU_GET || op == IFCONF_IPV4_SET ||
		op == IPV4_DHCP_SET ||
		op == IPV6_DHCP_SET || op == IFCONF_IPV6_SET ||
		op == IFCONF_IPV4_PING || op == IFCONF_IPV6_PING ||
		op == IFCONF_PMTU6_CLEAR)
		rc = 1;
	return rc;
}

#ifdef __CSIO_COISCSI_ENABLED__
static inline unsigned int coiscsi_target_op(unsigned int op)
{
	unsigned int rc = 0;

	if (op == START_TARGET || op == STOP_TARGET)
		rc = 1;
	return rc;
}
#endif

csio_retval_t
csio_clean_op_handle(struct csio_hw *hw, uint32_t op, uint32_t id,
			void *thandle)
{
	struct csio_ctrl_instance *inst;
	struct csio_chnet_iface *iface;
	struct csio_ctrl_foiscsi *foiscsi_cdev;
	struct csio_ctrl_chnet *chnet_cdev;

	foiscsi_cdev = csio_hw_to_foiscsi_cdev(hw);
	if (!foiscsi_cdev) {
		csio_err(hw, "foiscsi inst not found\n");
		return CSIO_INVAL;
	}

	if(foiscsi_instance_op(op)) {
		/* the thandle is present in the foiscsi_cdev->instance array */
		if (id > 0  && id <= FW_FOISCSI_INIT_NODE_MAX) {
			inst = &foiscsi_cdev->instance[id - 1];
			csio_mutex_lock(&inst->inode_lock);
			if ((inst->transport_handle == thandle) &&
			 	 inst->op_pending) {
				inst->transport_handle = NULL;
				inst->op_pending = 0;
			}
			csio_mutex_unlock(&inst->inode_lock);
		}
	} else if (chnet_iface_op(op)) {
		/* the thandle is present in the foiscsi_cdev->ifaces array */

		if (id >= hw->num_t4ports)
			goto out;
		
		chnet_cdev = csio_hw_to_chnet_cdev(hw);
		iface = &chnet_cdev->ifaces[id];
		csio_mutex_lock(&iface->mlock);
		if ((iface->transport_handle == thandle) &&
				(iface->op_pending)) {
			iface->transport_handle = NULL;
			iface->op_pending = 0;
		}
		csio_mutex_unlock(&iface->mlock);
	}
out:
	return CSIO_SUCCESS;
}

