/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Function prototype declaration for COiSCSI fwevt handlers
 *
 */
#ifndef	__CSIO_COISCSI_FWEVTS_H__
#define	__CSIO_COISCSI_FWEVTS_H__

int csio_coiscsi_tgt_fwevt_handler(struct csio_hw *, struct fw_coiscsi_tgt_wr *);
int csio_coiscsi_stats_fwevt_handler(struct csio_hw *, struct fw_coiscsi_stats_wr *);
int csio_conn_fwevt_handler(struct csio_hw *, struct fw_coiscsi_tgt_conn_wr *);
int csio_coiscsi_tgt_conn_fwevt_handler(struct csio_hw *, struct fw_coiscsi_tgt_conn_wr *);
int csio_isns_conn_fwevt_handler(struct csio_hw *, struct fw_coiscsi_tgt_conn_wr *);
int csio_isns_client_fwevt_handler(struct csio_hw *, struct fw_isns_wr *);


#endif	/* __CSIO_COISCSI_FWEVTS_H__ */
