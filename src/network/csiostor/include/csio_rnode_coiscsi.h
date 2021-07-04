/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures, constants and function prototype declaration
 * for COiSCSI target rnodes
 *
 */

#ifndef __CSIO_RNODE_COISCSI_H__
#define __CSIO_RNODE_COISCSI_H__

#include <csio_defs.h>
#include <csio_mb_foiscsi.h>
#include <csio_lnode_coiscsi.h>

#define COISCSI_VALUE_NUM_COUNT_MAX	5 /* 16 bytes for ip, 4 for port */

struct csio_rnode_coiscsi {
	struct csio_sm          sm;
	struct csio_rnode       *rn;            /* Owning rnode */

	struct csio_coiscsi_tgtreq	*tgtreq;
	struct csio_coiscsi_rcvreq	*rcvreq;

	uint32_t		v_num[COISCSI_VALUE_NUM_COUNT_MAX];	/* initiator ip/port */
	void			*ch_conn;
	struct fw_coiscsi_tgt_conn_wr c_wr;
	csio_cmpl_t		mod_cmplobj; /* will complete when SUBOP_MOD comes from FW */
	csio_cmpl_t		del_cmplobj; /* will complete when SUBOP_DEL comes from FW */

	uint32_t                statsn;
	uint32_t		credit;

}__attribute__((aligned(sizeof(unsigned long))));


struct csio_rnode * csio_coiscsi_alloc_rnode(struct coiscsi_snode *sn);
struct csio_rnode_coiscsi *csio_get_rnc(struct coiscsi_snode *sn, uint32_t flowid);
void csio_coiscsi_free_rnode(struct csio_rnode *);

void csio_put_rnc(struct csio_rnode_coiscsi *rnc);
#endif /* ifndef __CSIO_RNODE_COISCSI_H__ */
