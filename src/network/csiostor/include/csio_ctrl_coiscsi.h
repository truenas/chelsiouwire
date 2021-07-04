/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Constants for COiSCSI target driver
 *
 */
#ifndef	__CSIO_CTRL_COISCSI_H__
#define	__CSIO_CTRL_COISCSI_H__

#include <csio_coiscsi_ioctl.h>

#define	CSIO_COISCSI_NUM_LNODES		4096
#define CSIO_COISCSI_NUM_TGT_PORTALS	4096
#define	CSIO_COISCSI_NUM_SNODES		16
#define CSIO_COISCSI_NUM_RNODES		4096
#ifdef __COISCSI_MAX_CONFIG__
#define	CSIO_COISCSI_NUM_TGTRQS		8192*2
#else
#define	CSIO_COISCSI_NUM_TGTRQS		8192
#endif
#define	CSIO_COISCSI_NUM_RCVRQS		(128 * 4096)
#define COISCSI_NUM_DBUFS		(( 8 * CSIO_COISCSI_NUM_RCVRQS) - 1)
#define	CSIO_ISNS_NUM_SNODES		128
#define CSIO_ISNS_NUM_RNODES		4096
/* slab limits should add up to max conns supported */
#ifdef __COISCSI_MAX_CONFIG__
#define COISCSI_TREQ_NUM_HI_REQS	0
#define COISCSI_TREQ_NUM_MI_REQS	0
#define COISCSI_TREQ_NUM_LO_REQS	4096
#else 
#define COISCSI_TREQ_NUM_HI_REQS	4
#define COISCSI_TREQ_NUM_MI_REQS	12
#define COISCSI_TREQ_NUM_LO_REQS	3460
#endif

#define COISCSI_TREQ_SLAB_HI_REQS	COISCSI_TREQ_NUM_HI_REQS
#define COISCSI_TREQ_SLAB_MI_REQS	(COISCSI_TREQ_NUM_HI_REQS + \
					COISCSI_TREQ_NUM_MI_REQS)
#define COISCSI_TREQ_NUM_REQS_MAX	(COISCSI_TREQ_NUM_HI_REQS + \
					COISCSI_TREQ_NUM_MI_REQS  + \
					COISCSI_TREQ_NUM_LO_REQS)
/* 
 * credits decide the max cmd q len,
 * min qdepth should be atleast 2.
 */
#define COISCSI_TREQ_HI_CREDIT	256 /* qdepth for hi_reqs */
#define COISCSI_TREQ_MI_CREDIT	14  /* qdepth for mi_reqs */
#define COISCSI_TREQ_LO_CREDIT	2  /* qdepth for lo_reqs */
/* credits per slab */
#define COISCSI_TREQ_HI_LIMIT	(COISCSI_TREQ_NUM_HI_REQS * COISCSI_TREQ_HI_CREDIT)
#define COISCSI_TREQ_MI_LIMIT	(COISCSI_TREQ_NUM_MI_REQS * COISCSI_TREQ_MI_CREDIT)
#define COISCSI_TREQ_LO_LIMIT	(COISCSI_TREQ_NUM_LO_REQS * COISCSI_TREQ_LO_CREDIT)
#define COISCSI_TREQ_CREDIT_LIMIT	(COISCSI_TREQ_HI_LIMIT + \
					COISCSI_TREQ_MI_LIMIT +  \
					COISCSI_TREQ_LO_LIMIT)
struct csio_ctrl_coiscsi {
	struct csio_list	tgtlnhead;
	unsigned int		max_tgt_inst;
};

#endif	/* __CSIO_CTRL_COISCSI_H__ */
