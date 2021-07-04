/*
 *  Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Chelsio cxgbtool based transport.
 */
/*
linux_chelsio
linux_oiscsi
windows_chelsio
others
*/

#include <csio_defs.h>
#include <csio_trans_foiscsi.h>
#include <csio_stor_ioctl.h>
#include <csio_foiscsi.h>
#include <csio_ctrl_devs.h>
#ifdef __CSIO_COISCSI_ENABLED__
#include <csio_lnode_coiscsi.h>
#include <csio_ctrl_coiscsi.h>
#endif

struct op_handle {
	uint32_t status;
	//struct completion completion;  reaplce this with cmplobj.cmpl
	csio_cmpl_t	cmplobj;
};

static csio_retval_t csio_foiscsi_linux_event_handler(struct csio_hw *,
		uint32_t, uint32_t, struct iscsi_transport_handle *);

static csio_retval_t csio_foiscsi_linux_ioctl_handler(struct csio_hw *,
		uint32_t, unsigned long, void *, uint32_t);

#ifdef __CSIO_COISCSI_ENABLED__
static csio_retval_t csio_coiscsi_linux_ioctl_handler(struct csio_hw *,
                uint32_t, unsigned long, void *, uint32_t);
#endif
static csio_retval_t csio_chnet_linux_ioctl_handler(struct csio_hw *,
		uint32_t, unsigned long, void *, uint32_t);

#ifdef __CSIO_COISCSI_ENABLED__
static csio_retval_t csio_isns_linux_ioctl_handler(struct csio_hw *,
		uint32_t, unsigned long, void *, uint32_t);
#endif
static int csio_iscsi_transport_linux_ch_init(struct csio_hw *);

static struct csio_transport transport = {
	.name		= "linux_ch",
	.type		= LINUX_CHELSIO,
	.event_handler	= csio_foiscsi_linux_event_handler,
	.ioctl_handler[CSIO_IOCTL_TYPE_FOISCSI]	= csio_foiscsi_linux_ioctl_handler,
#ifdef __CSIO_COISCSI_ENABLED__
	.ioctl_handler[CSIO_IOCTL_TYPE_COISCSI]	= csio_coiscsi_linux_ioctl_handler,
#endif
	.ioctl_handler[CSIO_IOCTL_TYPE_CHNET]	= csio_chnet_linux_ioctl_handler,
#ifdef __CSIO_COISCSI_ENABLED__
	.ioctl_handler[CSIO_IOCTL_TYPE_ISNS]	= csio_isns_linux_ioctl_handler,
#endif
	.init_handler	= csio_iscsi_transport_linux_ch_init
};

static int csio_iscsi_transport_count = 1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,13,0)
static inline void reinit_completion(struct completion *x)
{
	INIT_COMPLETION(*x);
}
#endif

char *csio_os_iscsi_transport_get_name(struct csio_transport *transp)
{
	return transp->name;
}

int csio_os_iscsi_transport_count(void)
{
	return csio_iscsi_transport_count;
}

struct csio_transport *csio_os_iscsi_transport_get(unsigned int idx)
{
	return &transport;
}

static int csio_iscsi_transport_linux_ch_init(struct csio_hw *hw)
{
	/* register the transport type and event callback with the LLD */
	return csio_foiscsi_register_transport(hw, &transport);
}

/* called from interrupt context. DO NOT SLEEP IN IT */
static csio_retval_t csio_foiscsi_linux_event_handler(struct csio_hw *hw,
		uint32_t op, uint32_t status,
		struct iscsi_transport_handle *h)
{
	
	csio_dbg(hw, "%s: op %d, status %d\n", __FUNCTION__, op, status);
	/* if waiting for any event then unblock it */
	
	if (h) {
		((struct op_handle *)(h->handle))->status = status;
		complete(&((struct op_handle *)(h->handle))->cmplobj.cmpl);
	}
	return CSIO_SUCCESS;
}
static csio_retval_t logout_from_all_target(struct csio_hw *hw,
		struct foiscsi_logout_info *linfo,
		struct iscsi_transport_handle *h)
{
	int rc, id, sess_cnt=0;
	struct foiscsi_transport_handle *fh = (struct foiscsi_transport_handle *)h;
	struct op_handle handle;
	struct iscsi_transport_handle *lh = h;
#if 0
	int ret;
#endif

	id = linfo->inode_id;
	init_completion(&handle.cmplobj.cmpl);
	fh++;
	lh = (struct iscsi_transport_handle *)fh;
	lh->transport = &transport;
	lh->handle = &handle;
	memcpy(&fh->iparam, linfo, sizeof(*linfo));
	for(;;) {
		/* logout from all session. Call logout till fn returns
		 * error or no more session. */

		rc = csio_ln_logout_handler(hw, NULL, linfo, h);
		/* Either error or no more session to logout */
		if (rc != CSIO_SUCCESS) {
			if (!sess_cnt && h && h->transport &&
						h->transport->event_handler)
				h->transport->event_handler(hw,
						LOGOUT_FROM_TARGET, 0, h);
			break;
		}
		sess_cnt++;
		/* wait for event callback */
		csio_dbg(hw, "%s: waiting for command completion..\n",
				__FUNCTION__);
#if 1
		wait_for_completion(&((struct op_handle *)
					lh->handle)->cmplobj.cmpl);
#else
		/*ret = wait_for_completion_timeout(&((struct op_handle *)h->handle)->\
				cmplobj.cmpl, FOISCSI_LOGIN_TIMEOUT); */
		ret = wait_for_completion_interruptible(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);

		/* if ((ret == 0) || (ret < 0)) { */
		if (ret < 0) {
			csio_err(hw, "Timeout/Error waiting for the "
					"LLD logout resp ret = %d\n", ret);
			rc  = -EFAULT;
			csio_clean_op_handle(hw, LOGOUT_FROM_TARGET, id, h);
			goto out;
		}
#endif
		csio_dbg(hw, "%s: Unblocking command status %d\n", __FUNCTION__,
				((struct op_handle *)lh->handle)->status);
		reinit_completion((&((struct op_handle *)lh->handle)->cmplobj.cmpl));
		/* Clean the handle inside LLD */
		csio_clean_op_handle(hw, LOGOUT_FROM_TARGET, id, h);
	}
#if 0
out:
#endif
	if (rc == CSIO_EZERO_OBJ_FOUND)
		rc = CSIO_SUCCESS;

	return rc;
}

static void
csio_clear_address_state(struct csio_hw *hw, struct csio_chnet_ifconf_ioctl *req, unsigned int iface_op)
{
	struct csio_ctrl_chnet *chnet_cdev;
	struct csio_chnet_iface *iface;
	int vlan = 0;

	chnet_cdev = csio_hw_to_chnet_cdev(hw);
	if(!chnet_cdev)
		return;



	iface = &chnet_cdev->ifaces[hw->t4port[req->ifid].portid];

	if (csio_vlan_valid(iface->vlan_info.vlan_id))
		vlan = VLAN_SHIFT;
	
	/* Shift bit for vlan operations */
	if (iface_op == IFCONF_IPV4_SET)
		iface->address_state &= ~(CSIO_IPV4_MASK << vlan);
	else if (iface_op == IFCONF_IPV6_SET)
		iface->address_state &= ~(CSIO_IPV6_MASK << vlan);
}


#ifdef __CSIO_COISCSI_ENABLED__
static csio_retval_t csio_isns_linux_ioctl_handler(struct csio_hw *hw, 
		uint32_t op, unsigned long arg, void *buffer, 
		uint32_t buffer_len)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	void __user *payload = NULL;
	uint8_t __user *rsp = NULL;
	isns_info isns;
	struct csio_isns_ioctl *isns_ioctl = NULL;
	struct csio_isnsm *isnsm = csio_hw_to_isnsm(hw);
	unsigned long flags;

	csio_dbg(hw, "recv op [0x%x]\n", op);

	csio_spin_lock_irqsave(hw, &hw->lock, flags);

	isns_ioctl = (struct csio_isns_ioctl *)buffer;
	payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));

	if(op == CSIO_STOP_ISNS_IOCTL) {
		if((isns_ioctl->mode == CSIO_APP_MOD_ISNS_SERVER && !isnsm->list_server_cnt) ||
		   (isns_ioctl->mode == CSIO_APP_MOD_ISNS_CLIENT && !isnsm->client_cnt)) {
			rc = CSIO_EINVALID_OPER;
		}

		if(rc != CSIO_SUCCESS) {
			csio_err(hw, "ERR!! Trying to stop iSNS %s before starting\n",
					(isns_ioctl->mode == CSIO_APP_MOD_ISNS_SERVER? "LISTENING SERVER":"CLIENT"));
			isns_ioctl->retval = rc;
			csio_spin_unlock_irqrestore(hw, &hw->lock, flags);
			goto out;
		}
	}

	if(!isnsm->init_done) {
		csio_mutex_init(&isnsm->isns_mtx);
		csio_spin_lock_init(&isnsm->isns_spinlock);
		csio_head_init(&isnsm->snhead);
		csio_head_init(&isnsm->rnhead);
		isnsm->hw = hw;
		isnsm->init_done = 1;
		isnsm->list_server_cnt = 0;
		isnsm->client_cnt = 0;
	}
	csio_spin_unlock_irqrestore(hw, &hw->lock, flags);

	csio_mutex_lock(&isnsm->isns_mtx);

	if(op == CSIO_START_ISNS_IOCTL || op == CSIO_STOP_ISNS_IOCTL) {

		memset(&isns.addr, 0, sizeof(struct ip_addr));
		memcpy((uint8_t *)&isns.addr, (uint8_t *)&isns_ioctl->addr, 
				sizeof(struct ip_addr));
		isns.port = isns_ioctl->port;
		isns.type = isns_ioctl->type;
		isns.ifid = isns_ioctl->ifid;
		isns.vlanid = isns_ioctl->vlanid;
		isns.mode = isns_ioctl->mode;
		memset(isns.eid, 0, CSIO_ISNS_EID_LEN);
		strcpy(isns.eid, isns_ioctl->eid);

		csio_dbg(hw, "type %d ifid %d vlanid %d mode %d op 0x%x eid %s\n",
			isns.type, isns.ifid, isns.vlanid, isns.mode, op, isns.eid);
	}

	switch (op) {

		case CSIO_START_ISNS_IOCTL:
			rc = csio_start_isns(hw, &isns);
			isns_ioctl->retval = rc;
			break;

		case CSIO_STOP_ISNS_IOCTL:
			rc = csio_stop_isns(hw, &isns);
			isns_ioctl->retval = rc;
			break;

		case CSIO_SHOW_ISNS_IOCTL:
			rsp = (uint8_t *)buffer + (sizeof(struct csio_isns_ioctl));
			isns.mode = isns_ioctl->mode;
			isns.buf = rsp + sizeof(int);
			rc = csio_show_isns(hw, &isns);
			memcpy(rsp, &rc, sizeof(int));		
			break;

		default:
			rc = CSIO_INVAL;
	}
	csio_mutex_unlock(&isnsm->isns_mtx);


out:
	/* 
	 * ISNS TODO - check whether this is needed
	 * ibft calls don't have a userspace buffer
	 */
	if(arg) {
		/* copy_to_user */
		if ((payload) && (copy_to_user(payload, buffer, buffer_len)))
			rc = -EFAULT;
	}

	return rc;
}

static csio_retval_t csio_coiscsi_linux_ioctl_handler(struct csio_hw *hw,
		uint32_t op, unsigned long arg,
		void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	unsigned int int_op = 0;
	void __user *payload = NULL;
	struct op_handle handle;
	struct coiscsi_transport_handle *ch;
	struct iscsi_transport_handle *h;
	char *tgt_name = NULL;

	csio_dbg(hw, "recv op [0x%x]\n", op);

	init_completion(&handle.cmplobj.cmpl);
	ch = foiscsi_alloc(sizeof(struct coiscsi_transport_handle));
	if (!ch)
		return -ENOMEM;		
	h = &ch->i_handle;
	h->transport = &transport;
	h->handle = &handle;

	switch (op) {
	case CSIO_COISCSI_START_TARGET_IOCTL: {
		struct coiscsi_target_ioctl *tinfo =
			(struct coiscsi_target_ioctl *)buffer;
		int_op = START_TARGET;
		memcpy(&ch->iparam, tinfo, sizeof(*tinfo));
		tgt_name = tinfo->tinst.tgt_name;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_assign_target_instance(hw,
				tinfo, (void *)h, COISCSI_LNODE_INIT);
		break;
	}
	case CSIO_COISCSI_STOP_TARGET_IOCTL: {
		struct coiscsi_target_ioctl *tinfo =
			(struct coiscsi_target_ioctl *)buffer;
		int_op = STOP_TARGET;
		memcpy(&ch->iparam, tinfo, sizeof(*tinfo));
		tgt_name = tinfo->tinst.tgt_name;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_remove_target_instance(hw, tinfo, (void *)h);
		break;
	}
	case CSIO_COISCSI_UPDATE_TARGET_IOCTL: {
		struct coiscsi_target_ioctl *tinfo =
			(struct coiscsi_target_ioctl *)buffer;
		int_op = MOD_TARGET;
		memcpy(&ch->iparam, tinfo, sizeof(*tinfo));
		tgt_name = tinfo->tinst.tgt_name;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_update_target_instance(hw, tinfo, (void *)h);
		break;
	}
	case CSIO_COISCSI_SHOW_TARGET_IOCTL: {
		struct coiscsi_target_ioctl *tinfo =
			(struct coiscsi_target_ioctl *)buffer;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_show_target_instance(hw, tinfo, (void *)h);
		break;
	}
	case CSIO_COISCSI_TARGET_INFO_IOCTL: {
		struct coiscsi_target_info_ioctl *tinfo =
			(struct coiscsi_target_info_ioctl *)buffer;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_get_target_info(hw, tinfo, (void *)h);
		break;
	}
	case CSIO_COISCSI_TARGET_STATS_IOCTL: 
	case CSIO_COISCSI_TARGET_STATS_CLR_IOCTL: {
		struct coiscsi_target_stats_ioctl *stats =
			(struct coiscsi_target_stats_ioctl *)buffer;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_coiscsi_get_target_stats(hw, stats, op, (void *)h);
		break;
	}
	default:
		rc = CSIO_INVAL;

	}

	/* ibft calls don't have a userspace buffer */
	if(arg) {
		/* copy_to_user */
		if ((payload) && (copy_to_user(payload, buffer, buffer_len)))
			rc = -EFAULT;
	}

	if (ch)
		foiscsi_free(ch);
	return rc;
}
#endif

static csio_retval_t csio_foiscsi_linux_ioctl_handler(struct csio_hw *hw,
		uint32_t op, unsigned long arg,
		void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	int timeout = 0, hcount=0;
	unsigned int int_op = 0, id = 0xffff; /* invalid value */
	void __user *payload = NULL;
	struct op_handle handle;
	struct foiscsi_transport_handle *fh;
	struct iscsi_transport_handle *h;
	
	csio_dbg(hw, "%s: recv op [0x%x]\n", __FUNCTION__, op);

	hcount = (op == CSIO_FOISCSI_LOGOUT_FROM_TARGET) ? 2 : 1;
	init_completion(&handle.cmplobj.cmpl);
	fh = foiscsi_alloc(hcount * sizeof(struct foiscsi_transport_handle));
	if (!fh)
		return -ENOMEM;		
	h = &fh->i_handle;
	h->transport = &transport;
	h->handle = &handle;

	/* LLD already takes care of keeping only
	 * one active operation at a time. */
	switch (op) {
	case CSIO_FOISCSI_ASSIGN_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		int_op = ASSIGN_INSTANCE;
		id = ini_inst->id;
		memcpy(&fh->iparam, ini_inst, sizeof(*ini_inst));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ioctl_assign_instance_handler(hw, ini_inst, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_CLEAR_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		int_op = CLEAR_INSTANCE;
		id = ini_inst->id;
		memcpy(&fh->iparam, ini_inst, sizeof(*ini_inst));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_foiscsi_ioctl_clear_instance_handler(hw, ini_inst, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_SHOW_INSTANCE_IOCTL: {
		struct foiscsi_instance *ini_inst =
			(struct foiscsi_instance *)buffer;
		rc = csio_foiscsi_ioctl_show_instance_handler(hw, ini_inst);
		break;
	}
	case CSIO_FOISCSI_GET_COUNT_IOCTL: {
		struct foiscsi_count *cnt = (struct foiscsi_count *)buffer;
		rc  = csio_foiscsi_ioctl_get_count_handler(hw, cnt);
		break;
	}
	case CSIO_FOISCSI_SESSION_INFO_IOCTL: {
		struct foiscsi_sess_info *sess_info =
			(struct foiscsi_sess_info *)buffer;
		rc = csio_foiscsi_ioctl_get_sess_info_handler(hw, sess_info);
		break;
	}
	case CSIO_FOISCSI_LOGIN_TO_TARGET: {
		struct foiscsi_login_info *linfo =
			(struct foiscsi_login_info *)buffer;
		int_op = ISCSI_LOGIN_TO_TARGET;
		id = linfo->inode_id;
		memcpy(&fh->iparam, linfo, sizeof(*linfo));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_ln_login_handler(hw, NULL, linfo, 0, h);
		timeout = FOISCSI_LOGIN_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_LOGOUT_FROM_TARGET: {
		struct foiscsi_logout_info *linfo =
			(struct foiscsi_logout_info *) buffer;
		int_op = LOGOUT_FROM_TARGET;
		id = linfo->inode_id;
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		if (linfo->sess_id < 0)
			rc = logout_from_all_target(hw, linfo, h);
		else  {
			memcpy(&fh->iparam, linfo, sizeof(*linfo));
			rc = csio_ln_logout_handler(hw, NULL, linfo, h);
		}
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_FOISCSI_DISC_TARGS: {
		struct foiscsi_login_info *linfo =
			(struct foiscsi_login_info *)buffer;
		int_op = ISCSI_DISC_TARGS;
		id = linfo->inode_id;
		memcpy(&fh->iparam, linfo, sizeof(*linfo));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_ln_login_handler(hw, NULL, linfo, 1, h);
		timeout = FOISCSI_LOGIN_TIMEOUT;
		break;
	}
#ifdef CSIO_FOISCSI_PERSISTENT_ENABLE
	case CSIO_FOISCSI_PERSISTENT_GET_IOCTL: {
		struct iscsi_persistent_target_db *target_db =
			( struct iscsi_persistent_target_db * )buffer;
		rc = csio_foiscsi_ioctl_persistent_show_handler(hw, target_db);
		break;
	}
	case CSIO_FOISCSI_PERSISTENT_CLEAR_IOCTL: {
		struct iscsi_persistent_target_db *target_db =
			( struct iscsi_persistent_target_db * )buffer;
		rc = csio_foiscsi_ioctl_persistent_clear_handler(hw,
				target_db->num_persistent_targets);
		break;
	}
#endif
	default:
		rc = CSIO_INVAL;
	}

	if ((rc == CSIO_SUCCESS) && timeout) {
		/* int ret; */
		/* Wait for response for a timeout value */
		csio_dbg(hw, "%s: waiting for command completion..\n",
				__FUNCTION__);
#if 1
		wait_for_completion(&((struct op_handle *)h->handle)->cmplobj.cmpl);
#else
		ret = wait_for_completion_interruptible(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);
		/*ret = wait_for_completion_timeout(&((struct op_handle *)h->handle)->\
							cmplobj.cmpl, timeout);
		if ((ret == 0) || (ret < 0)) { */
		if (ret < 0) {
			csio_err(hw, "Error in waiting for the "
					"LLD resp, ret %d\n", ret);
			rc  = -EFAULT;
			goto out;
		}
#endif
		csio_dbg(hw, "%s: Unblocking command status %d\n",
		 __FUNCTION__, ((struct op_handle *)h->handle)->status);
		
		if (!((struct op_handle *)h->handle)->status) {
			if (int_op == ASSIGN_INSTANCE) {
				/* pass chap secret */
				struct foiscsi_instance *ini_inst =
					(struct foiscsi_instance *)buffer;
				csio_foiscsi_set_chap_secret(hw, ini_inst);
			}
		} else {
			
			if ((int_op == ISCSI_LOGIN_TO_TARGET ||
			     int_op == ISCSI_DISC_TARGS) &&
			     buffer) {
				struct foiscsi_login_info *linfo = (struct foiscsi_login_info *)buffer;

				linfo->status = ((struct op_handle *)h->handle)->status;
				csio_dbg(hw, "%s: linfo->status [0x%x]\n", __FUNCTION__, linfo->status);
				rc = -EAGAIN;
			} 
		}
	}

	/* ibft calls don't have a userspace buffer */
	if(arg) {
		/* copy_to_user */
		if ((payload) && (copy_to_user(payload, buffer, buffer_len)))
			rc = -EFAULT;
	}

	if (op == CSIO_FOISCSI_LOGOUT_FROM_TARGET) {
		struct foiscsi_login_info *linfo =
					(struct foiscsi_login_info *)buffer;
		csio_foiscsi_clear_logout_all(hw, linfo->inode_id);
	}
	if (timeout)
		csio_clean_op_handle(hw, int_op, id, h);
	if (fh)
		foiscsi_free(fh);
	return rc;
}

static csio_retval_t csio_chnet_linux_ioctl_handler(struct csio_hw *hw,
		uint32_t op, unsigned long arg,
		void *buffer,
		uint32_t buffer_len)
{
	enum csio_oss_error rc = CSIO_SUCCESS;
	int timeout = 0;
	unsigned int int_op = 0, id = 0xffff; /* invalid value */
	void __user *payload = NULL;
	struct op_handle handle;
	struct chnet_transport_handle *nh;
	struct iscsi_transport_handle *h;
	
	csio_dbg(hw, "%s: recv op [0x%x]\n", __FUNCTION__, op);

	init_completion(&handle.cmplobj.cmpl);
	nh = foiscsi_alloc(sizeof(struct chnet_transport_handle));
	if (!nh)
		return -ENOMEM;
	h = &nh->i_handle;
	h->transport = &transport;
	h->handle = &handle;

	/* LLD already takes care of keeping only
	 * one active operation at a time. */
	switch (op) {
	case CSIO_CHNET_IFACE_LINK_UP_IOCTL: {
		struct csio_chnet_iface_ioctl *req = buffer;
		int_op = IFACE_CMD_SUBOP_LINK_UP;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_link_up_cmd_handler(hw, req);
		break;
	}
	case CSIO_CHNET_IFACE_LINK_DOWN_IOCTL: {
		struct csio_chnet_iface_ioctl *req = buffer;
		int_op = IFACE_CMD_SUBOP_LINK_DOWN;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_chnet_link_down_cmd_handler(hw, req);
		break;
	}

	case CSIO_CHNET_IFCONF_VLAN_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV4_VLAN_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_vlan_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}

	case CSIO_CHNET_IFCONF_MTU_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_MTU_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_mtu_cmd_handler(hw, op, req, h);
		//rc = csio_foiscsi_do_mtu_req(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_CHNET_IFCONF_MTU_GET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_MTU_GET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_mtu_cmd_handler(hw, op, req, NULL);
		break;
	}
	case CSIO_CHNET_IFACE_GET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		rc = csio_chnet_iface_get(hw, req);
		break;
	}
	case CSIO_CHNET_IFCONF_IPV4_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV4_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_ifconf_ipv4_set_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV4_GET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		rc = csio_chnet_ifconf_ip_get(hw, req);
		break;
	}
	case CSIO_CHNET_IFCONF_IPV6_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV6_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_ifconf_ipv6_set_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV6_GET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		rc = csio_chnet_ifconf_ip_get(hw, req);
		break;
	}
	case CSIO_CHNET_IFCONF_IPV4_DHCP_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IPV4_DHCP_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_chnet_ifconf_dhcp_set_cmd_handler(hw, req, op, h);
		timeout = 200*HZ;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV6_DHCP_SET_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IPV6_DHCP_SET;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc  = csio_chnet_ifconf_dhcp_set_cmd_handler(hw, req, op, h);
		timeout = 200*HZ;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV4_PING_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV4_PING;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_ifconf_ipv4_ping_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV6_PING_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_IPV6_PING;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_ifconf_ipv6_ping_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	case CSIO_CHNET_IFCONF_IPV6_PMTU_CLEAR_IOCTL: {
		struct csio_chnet_ifconf_ioctl *req = buffer;
		int_op = IFCONF_PMTU6_CLEAR;
		id = req->ifid;
		memcpy(&nh->iparam, req, sizeof(*req));
		payload = (void __user *)(arg  + sizeof(ioctl_hdr_t));
		rc = csio_chnet_pmtu6_cmd_handler(hw, op, req, h);
		timeout = FOISCSI_CMD_TIMEOUT;
		break;
	}
	default:
		rc = CSIO_INVAL;
	}

	if ((rc == CSIO_SUCCESS) && timeout) {
		/* int ret; */
		/* Wait for response for a timeout value */
		csio_dbg(hw, "%s: waiting for command completion..\n",
				__FUNCTION__);
#if 1
		wait_for_completion(&((struct op_handle *)h->handle)->cmplobj.cmpl);
#else
		ret = wait_for_completion_interruptible(&((struct op_handle *)
					h->handle)->cmplobj.cmpl);
		/*ret = wait_for_completion_timeout(&((struct op_handle *)h->handle)->\
							cmplobj.cmpl, timeout);
		if ((ret == 0) || (ret < 0)) { */
		if (ret < 0) {
			csio_err(hw, "Error in waiting for the "
					"LLD resp, ret %d\n", ret);
			rc  = -EFAULT;
			goto out;
		}
#endif
		csio_dbg(hw, "%s: Unblocking command status %d\n",
		 __FUNCTION__, ((struct op_handle *)h->handle)->status);
		
		if (!((struct op_handle *)h->handle)->status) {
				/* Set address state as well */
				switch (int_op) {
				case IPV4_DHCP_SET:
				case IPV6_DHCP_SET:
				case IFCONF_IPV4_PING:
				case IFCONF_IPV6_PING:
					memcpy(buffer, &nh->iparam, sizeof(
					       struct csio_chnet_ifconf_ioctl));
					break;
				case IFCONF_IPV4_SET:
				case IFCONF_IPV6_SET: {
					struct csio_chnet_ifconf_ioctl *req = buffer;
					if (req->subop == CSIO_APP_OP_CLEAR)
						csio_clear_address_state(hw, req, int_op);
				}
				default:
					break;
				}
		} else {
			struct csio_chnet_ifconf_ioctl *req = buffer;
			req->retval = ((struct op_handle *)h->handle)->status;
			if (int_op == IFCONF_IPV4_SET ||
				   int_op == IFCONF_IPV6_SET) {
				if ((((struct op_handle *)h->handle)->status ==
						FW_EADDRINUSE) ||
				    (((struct op_handle *)h->handle)->status ==
						FW_EADDRNOTAVAIL)) {
					rc = -EINVAL;
				}
			} else if(int_op == IFCONF_IPV4_PING ||
					int_op == IFCONF_IPV6_PING) {
				memcpy(buffer, &nh->iparam, sizeof(
				       struct csio_chnet_ifconf_ioctl));
			}
		}
	}

	/* ibft calls don't have a userspace buffer */
	if(arg) {
		/* copy_to_user */
		if ((payload) && (copy_to_user(payload, buffer, buffer_len)))
			rc = -EFAULT;
	}
	
	if (timeout)
		csio_clean_op_handle(hw, int_op, id, h);
	if (nh)
		foiscsi_free(nh);
	return rc;
}

