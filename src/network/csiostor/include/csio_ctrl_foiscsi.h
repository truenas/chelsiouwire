/*
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CSIO_CTRL_FOISCSI_H__
#define __CSIO_CTRL_FOISCSI_H__

#include <csio_trans_foiscsi.h>
#include <csio_os_transutil_foiscsi.h>
#include <csio_foiscsi.h>

#define CSIO_FOISCSI_NUM_LNODES		CSIO_MAX_T4PORTS
#define CSIO_FOISCSI_NUM_RNODES		2048
#define CSIO_MAX_TARGETS_PER_BUS	ISCSI_MAX_TARGETS_PER_BUS

struct csio_chnet_iface;

enum csio_foiscsi_tclient {
	CSIO_FOISCSI_TCLIENT_CLI = 1,
	CSIO_FOISCSI_TCLIENT_BOOT = 2,
	CSIO_FOISCSI_TCLIENT_PERSISTENT = 3,
	CSIO_FOISCSI_TCLIENT_IMA = 4,
};

struct csio_foiscsi_sess_table {
	struct csio_list	rni_list;
	unsigned int		start;
	unsigned int		last;
	unsigned int		max;
	csio_spinlock_t		tlock;
	unsigned long		*bitmap;
};

struct csio_ctrl_instance {
	/* instance lock TODO replace it with wrapper. */
	csio_mutex_t	inode_lock; /* lock for instance related operation */
	struct csio_chnet_iface *iface;
	unsigned int portid;
	unsigned int op_pending;
	void *transport_handle;
};

struct csio_ctrl_foiscsi {
	/* session_map TODO */
	unsigned int			max_init_instances;
	/* following 3 fields are not getting used as of now. */
	unsigned int			max_sessions;
	unsigned int			max_conn_per_sess;
	unsigned int			max_ifaces;
	/* TODO Instance structure array [max_instances supported] */
	struct csio_ctrl_instance	instance[FW_FOISCSI_INIT_NODE_MAX];
	struct csio_foiscsi_sess_table	sess_table;
};

struct csio_bootlogin {
	csio_task_struct_t *bootlogin_ts;
	csio_timer_t bootlogin_timer;
	int attempt;
        union {
               struct csio_chnet_iface_ioctl iface_req;
               struct csio_chnet_ifconf_ioctl ifconf_req;
        } request;
	struct foiscsi_instance ini_inst;
	struct foiscsi_login_info linfo;
};

int csio_foiscsi_persistent_login(struct csio_hw *hw);
int csio_foiscsi_persistent_init(void);

int csio_persistent_check(struct csio_hw *hw, struct iscsi_persistent_target_db *target_db);
/* CRM - add_persistent_iface change - CS 1477 in foiscis repo */
int csio_add_persistent_iface(struct csio_hw *hw, struct csio_chnet_iface *iface, int login_ip_type, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_instance(struct csio_hw *hw, struct csio_lnode_iscsi *lni, int inode_id, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_target_info(struct csio_hw *hw, struct foiscsi_login_info *login, struct iscsi_persistent_target_db *targetdb);
int csio_add_persistent_target(struct csio_hw *hw,
                               struct foiscsi_login_info *login,
                               struct csio_lnode_iscsi *lni,
                               struct csio_chnet_iface *iface);

int csio_foiscsi_persistent_show_handler(struct csio_hw *hw,
                                struct iscsi_persistent_target_db *target_db);

int csio_foiscsi_persistent_clear_handler(struct csio_hw *hw, uint8_t idx);

#endif /* END __CSIO_CTRL_FOISCSI_H__ */
