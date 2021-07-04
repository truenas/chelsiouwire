/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 * 
 * Description: Data structures and function prototype declaration for COiSCSI
 * target iSNS functions
 * 
 */

#ifndef	__CSIO_ISNS_H__
#define __CSIO_ISNS_H__

#include <csio_defs.h>
#include <csio_wr.h>
#include <csio_ctrl_coiscsi.h>
#include <csio_coiscsi_external.h>

struct csio_isnsm {
	struct csio_hw		*hw;		/* Pointer to HW moduel */
	struct csio_list	rnhead;		/* rnode list */
	struct csio_list	snhead;		/* snode list */
	uint8_t			init_done;
	uint8_t			list_server_cnt;
	uint8_t			client_cnt;
	csio_mutex_t		isns_mtx;
	csio_spinlock_t		isns_spinlock;
};

int csio_isns_conn_handle(void *);
int csio_isns_pdu_handle(void *);
struct coiscsi_snode *isns_snode_alloc(struct csio_isnsm *);
void isns_snode_free(struct coiscsi_snode *);
int coiscsi_issue_close_conn_wr(struct csio_rnode *, void *);
int csio_coiscsi_issue_isns_wr(isns_data *);
int csio_coiscsi_issue_isns_xmit_wr(isns_data *);
int csio_start_isns(struct csio_hw *, isns_info *);
int csio_stop_isns(struct csio_hw *, isns_info *);
int csio_show_isns(struct csio_hw *, isns_info *);

#endif	/* __CSIO_ISNS_H__ */

