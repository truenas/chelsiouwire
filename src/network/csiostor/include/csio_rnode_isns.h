/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures, constants and function prototype declaration
 * for COiSCSI target iSNS functions
 *
 */

#ifndef __CSIO_RNODE_ISNS_H__
#define __CSIO_RNODE_ISNS_H__

#include <csio_defs.h>
#include <csio_mb_foiscsi.h>
#include <csio_isns.h>

#define ISNS_VALUE_NUM_COUNT_MAX	5 				/* 16 bytes for ip, 4 for port */

struct csio_rnode_isns {
	struct csio_hw		*hwp;
	struct csio_sm          sm;
	struct csio_rnode       *rn; 					/* Owning rnode */
	uint32_t		v_num[ISNS_VALUE_NUM_COUNT_MAX];	/* initiator ip/port */
	void			*ch_conn;
	csio_cmpl_t		mod_cmplobj; 				/* will complete when SUBOP_MOD comes from FW */
	csio_cmpl_t		del_cmplobj; 				/*   will complete when SUBOP_DEL comes from FW */
}__attribute__((aligned(sizeof(unsigned long))));


struct csio_rnode * csio_alloc_isns_rnode(struct csio_hw *, struct csio_list *);
void csio_free_isns_rnode(struct csio_hw *, struct csio_rnode *);
struct csio_rnode *csio_isns_rn_lookup(struct csio_hw *, struct csio_list *, uint32_t );
struct csio_rnode_isns *csio_get_rns(struct csio_hw *, struct csio_list *, uint32_t );
void csio_put_rns(struct csio_rnode_isns *rns);

#endif /* ifndef __CSIO_RNODE_ISNS_H__ */
