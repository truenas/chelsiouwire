/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CSIO_TRANS_FOISCSI_H__
#define __CSIO_TRANS_FOISCSI_H__

#include <csio_defs.h>
#include <csio_hw.h>
#include <csio_lnode_foiscsi.h>
#include <csio_foiscsi.h>
#include <csio_ctrl_foiscsi.h>
#ifdef __CSIO_COISCSI_ENABLED__
#include <csio_isns.h>
#endif

enum IP_COMBINATION {
	F_IPV4 = 1,
	F_IPV6,
	F_IPV4_IPV6
};

enum OP_TYPE {
	IFACE_CMD_SUBOP_LINK_UP = 1,
	IFACE_CMD_SUBOP_LINK_DOWN,
	IFCONF_IPV4_VLAN_SET,
	IFCONF_MTU_SET,
	IFCONF_MTU_GET,
	IFCONF_IPV4_SET,
	IPV4_DHCP_SET,
	IFCONF_IPV6_SET,
	IPV6_DHCP_SET,
	IFCONF_LINKLOCAL_ADDR_SET,
	IFCONF_RA_BASED_ADDR_SET,
	IFCONF_ADDR_EXPIRED,
	ASSIGN_INSTANCE,
	CLEAR_INSTANCE,
	ISCSI_LOGIN_TO_TARGET,
	ISCSI_DISC_TARGS,
	LOGOUT_FROM_TARGET,
	IFCONF_IPV4_PING,
	IFCONF_IPV6_PING,
	IFCONF_PMTU6_CLEAR
};

enum TRANSPORT_TYPE {
	LINUX_CHELSIO = 0,
	LINUX_OISCSI,
	WINDOWS_CHELSIO,
	INVALID_TRANSPORT_TYPE
};

#define VLAN_SHIFT 0x1
#define DHCP_SHIFT 0x2
#define VLAN_DHCP_SHIFT (VLAN_SHIFT + DHCP_SHIFT)
enum address_type {
	CSIO_ADDRESS_NONE,
	CSIO_IPV4_STATIC,
	CSIO_IPV4_VLAN = CSIO_IPV4_STATIC << VLAN_SHIFT,
	CSIO_IPV4_DHCP = CSIO_IPV4_STATIC << DHCP_SHIFT,
	CSIO_IPV4_DHCP_VLAN = CSIO_IPV4_STATIC << VLAN_DHCP_SHIFT,
	CSIO_IPV6_STATIC = CSIO_IPV4_DHCP_VLAN << 0x1,
	CSIO_IPV6_VLAN = CSIO_IPV6_STATIC << VLAN_SHIFT,
	CSIO_IPV6_DHCP = CSIO_IPV6_STATIC << DHCP_SHIFT,
	CSIO_IPV6_DHCP_VLAN = CSIO_IPV6_STATIC << VLAN_DHCP_SHIFT,
	CSIO_IPV6_RTADV = CSIO_IPV6_DHCP_VLAN << 0x1,
	CSIO_IPV6_RTADV_VLAN = CSIO_IPV6_RTADV << VLAN_SHIFT,
	CSIO_IPV6_LLOCAL = CSIO_IPV6_RTADV_VLAN << 0x1,
};

#define CSIO_IPV4_MASK (CSIO_IPV4_STATIC | CSIO_IPV4_DHCP)
#define CSIO_IPV6_MASK (CSIO_IPV6_STATIC | CSIO_IPV6_DHCP | CSIO_IPV6_RTADV)

struct csio_chnet_iface_info {
	unsigned int portid;
	unsigned int if_state;
	unsigned int if_id;
	unsigned char mac[6];
};

struct foiscsi_transport_in_param {
	union {
		struct csio_chnet_iface_info	iface_info;
		struct csio_chnet_iface_ioctl iface_req;
		struct csio_chnet_ifconf_ioctl ifconf_req;
		struct foiscsi_instance ini_inst;
		struct foiscsi_count cnt;
		struct foiscsi_sess_info sess_info;
		struct foiscsi_login_info linfo;

	}u;
};

struct chnet_transport_in_param {
	union {
		struct csio_chnet_iface_info	iface_info;
		struct csio_chnet_iface_ioctl	iface_req;
		struct csio_chnet_ifconf_ioctl	ifconf_req;
	}u;
};

#ifdef __CSIO_COISCSI_ENABLED__
struct coiscsi_transport_in_param {
	union {
		struct coiscsi_target_ioctl	target_info;
	}u;
};
#endif

struct iscsi_transport_handle {
	struct csio_transport *transport;
	void *handle;  /* Transport specific data */
};

struct foiscsi_transport_handle {
	struct iscsi_transport_handle 	i_handle;
	struct foiscsi_transport_in_param iparam;  /* needed only for async calls */
	//unsigned char scratch[64];
};

#ifdef __CSIO_COISCSI_ENABLED__
struct coiscsi_transport_handle {
	struct iscsi_transport_handle	i_handle;
	struct coiscsi_transport_in_param iparam;
};
#endif

struct chnet_transport_handle {
	struct iscsi_transport_handle	i_handle;
	struct chnet_transport_in_param iparam;
};

#define MAX_TRANSPORT_SUPPORTED 2  /* Enough per platform. say chelsio and 
									* open-iscsi together in worst case.
									* Increase this value when adding more
									* transport but sure it won't be needed. */

typedef csio_retval_t (*event_handler_cb_t)(struct csio_hw *, uint32_t,
			uint32_t, struct iscsi_transport_handle *);

typedef csio_retval_t (*ioctl_handler_cb_t)(struct csio_hw *, uint32_t,
			unsigned long, void *, uint32_t);

typedef int (*init_handler_cb_t)(struct csio_hw *);

#define	CSIO_MAX_IOCTL_CLIENTS	4

enum csio_ioctl_type {
	CSIO_IOCTL_TYPE_CHNET = 0,
	CSIO_IOCTL_TYPE_FOISCSI,
	CSIO_IOCTL_TYPE_COISCSI,
	CSIO_IOCTL_TYPE_ISNS
};

struct csio_transport {
	struct csio_list	list_node;
	unsigned char		name[32];
	unsigned int		type;	/* Transport type */
	
	/* event handler called from interrupt context. DO NOT SLEEP IN IT */
	event_handler_cb_t	event_handler;
	
	/* ioctl handler is added here because device ioctl handler
	 * is common for fcoe and iscsi both, and for iscsi we want
	 * to handle ioctl in transport glue.  Chelsio transport on
	 * all platform will have this handler. */

	ioctl_handler_cb_t	ioctl_handler[CSIO_MAX_IOCTL_CLIENTS];

	/* Note: Every platform specific transport must have the
	 * initilization function
	 * DO NOT SLEEP IN INIT FUNCTIONS */
	init_handler_cb_t	init_handler;
};

static inline unsigned int is_chelsio_transport(unsigned int transport_type)
{
	if ((transport_type == LINUX_CHELSIO) || transport_type == WINDOWS_CHELSIO)
		return 1;
	return 0;
}

/* Called by LLD to start transport glue initialization */
int csio_iscsi_transport_init(struct csio_hw *hw);
int csio_iscsi_transport_uninit(struct csio_hw *hw);

/* Called by the specific transports to register themselves with the glue */
int csio_foiscsi_register_transport(struct csio_hw *hw, 
					struct csio_transport *transport);

/* Called by the LLD to handle ioctl in the transport. */
csio_retval_t csio_transport_ioctl_handler(struct csio_hw *, enum csio_ioctl_type,
		uint32_t, unsigned long, void *, uint32_t);

/* Called by LLD to give the response back to transport */
csio_retval_t csio_transport_event_handler(struct csio_hw *, 
		uint32_t, uint32_t, unsigned long, void *, int hid);

/* Control plane operations interface, called by particular transport */
csio_retval_t
csio_chnet_link_up_cmd_handler(struct csio_hw *hw,
                        struct csio_chnet_iface_ioctl *req);
csio_retval_t
csio_chnet_link_down_cmd_handler(struct csio_hw *hw,
                        struct csio_chnet_iface_ioctl *req);
csio_retval_t
csio_chnet_vlan_cmd_handler(struct csio_hw *hw, uint32_t op, 
			struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_mtu_cmd_handler(struct csio_hw *hw, uint32_t op, 
			struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_iface_get(struct csio_hw *hw,
        struct csio_chnet_ifconf_ioctl *req);
csio_retval_t
csio_chnet_ifconf_ipv4_set_cmd_handler(struct csio_hw *hw, uint32_t op, 
			struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_ifconf_ipv4_ping_cmd_handler(struct csio_hw *hw, uint32_t op, 
			struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_ifconf_ipv6_set_cmd_handler(struct csio_hw *hw, uint32_t op, 
		struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_ifconf_ipv6_ping_cmd_handler(struct csio_hw *hw, uint32_t op, 
			struct csio_chnet_ifconf_ioctl *req, void *handle);
csio_retval_t
csio_chnet_ifconf_ip_get(struct csio_hw *hw,
                struct csio_chnet_ifconf_ioctl *req);
csio_retval_t
csio_chnet_ifconf_dhcp_set_cmd_handler(struct csio_hw *hw,
		struct csio_chnet_ifconf_ioctl *req, uint8_t op, void *handle);
csio_retval_t 
csio_foiscsi_ioctl_assign_instance_handler(struct csio_hw *hw,
                struct foiscsi_instance *ini_inst, void *handle);
csio_retval_t 
csio_foiscsi_ioctl_clear_instance_handler(struct csio_hw *hw,
                struct foiscsi_instance *ini_inst, void *handle);
csio_retval_t
csio_foiscsi_set_chap_secret(struct csio_hw *hw,
                struct foiscsi_instance *ini_inst);

csio_retval_t
csio_foiscsi_ioctl_show_instance_handler(struct csio_hw *hw,
        struct foiscsi_instance *ini_inst);
csio_retval_t
csio_foiscsi_ioctl_get_count_handler(struct csio_hw *hw, 
								struct foiscsi_count *cnt);
csio_retval_t
csio_foiscsi_ioctl_get_sess_info_handler (struct csio_hw *hw, 
		struct foiscsi_sess_info *sess_info);
csio_retval_t
csio_ln_login_handler(struct csio_hw *hw, void *arg1, 
			struct foiscsi_login_info *linfo, bool do_disc, void *handle);
csio_retval_t
csio_ln_logout_handler(struct csio_hw *hw, void *arg1,
    struct foiscsi_logout_info *linfo, void *handle);

csio_retval_t
csio_clean_op_handle(struct csio_hw *hw, uint32_t op, uint32_t id, 
			void *thandle);
csio_retval_t
csio_foiscsi_ioctl_persistent_show_handler(struct csio_hw *hw, 
 				struct iscsi_persistent_target_db *target_db);
csio_retval_t
csio_foiscsi_ioctl_persistent_clear_handler(struct csio_hw *hw, uint8_t idx);
csio_retval_t
csio_chnet_pmtu6_cmd_handler(struct csio_hw *hw, uint32_t op,
		struct csio_chnet_ifconf_ioctl *req, void *handle);
#endif /* __CSIO_TRANS_FOISCSI_H__ */

