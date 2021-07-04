/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures, constants and enum definitions for COiSCSI
 * IOCTLs
 *
 */
#ifndef __CSIO_COISCSI_IOCTL_H__
#define __CSIO_COISCSI_IOCTL_H__

#include <csio_common_ioctl.h>

#define ISCSI_TGT_PARAM_FILE	"/etc/csio_iscsi_tgt_param.conf"

#ifndef FW_FOISCSI_NAME_MAX_LEN
#define FW_FOISCSI_NAME_MAX_LEN 224
#endif

#ifndef FW_FOISCSI_CHAP_SEC_MAX_LEN
#define FW_FOISCSI_CHAP_SEC_MAX_LEN     128
#endif

enum CSIO_OP_TYPE {
	START_TARGET = 21,
	STOP_TARGET,
	MOD_TARGET,
	CONN_REQUEST,
	PROGRAM_RESPONSE,
	XMIT_RESPONSE,
};

/* Note : careful changing the layout of this structure, alignment
 * can affect how --op show works
 */
struct coiscsi_target_inst {

	uint32_t			tnode_id;
	
	/* Common attributes */
	uint16_t			auth_method;
	uint16_t			auth_policy;

	uint16_t			max_con;
	uint16_t			max_r2t;

	uint16_t			time2wait;
	uint16_t			time2retain;

	uint16_t			ping_timeout;
	uint8_t				hd_dd_dgst;
	uint8_t				rsvd[1];

	uint32_t			max_rcv_dsl;

	uint32_t			first_burst;
	uint32_t			max_burst;

	uint16_t			ping_interval;
	uint8_t				tgt_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				tgt_alias[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	uint8_t				ini_chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				ini_chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	uint8_t				tcp_wscale;
	uint8_t				tcp_wsen;
	uint8_t				lun_count;
	uint8_t				acl_enable;
	uint8_t				shadow_mode;
	uint8_t				num_portal;
	uint8_t 			tgt_disk[0];
};

struct coiscsi_trgt_conn_attr {
	struct ip_addr	listen_addr;
	uint16_t	listen_port;
	uint16_t	tpgt;
	uint16_t	redir;
	uint8_t		ip_type;
};

struct coiscsi_target_disc {
	uint16_t			disc_auth_method;
	uint16_t			disc_auth_policy;
	uint8_t				disc_chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				disc_chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	uint8_t				disc_ini_chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				disc_ini_chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
};

struct coiscsi_target_ioctl {
	int				op;
	int				retval;
	struct coiscsi_trgt_conn_attr	conn_attr;
	struct coiscsi_target_disc	disc_auth;
	struct coiscsi_target_inst	tinst;
};

#define ISCSI_CONTROL_DATA_MAX_BUFLEN	131072
struct coiscsi_target_info_ioctl {
	uint8_t                         tgt_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t                         lun_count;
	uint8_t                         portal_count;
	uint16_t			lun_buf_size;
	char				databuf[ISCSI_CONTROL_DATA_MAX_BUFLEN];
};

#define MAX_PPOD_ZONES	11
#define TGT_FW_RSRC_TOT 0
#define TGT_FW_RSRC_MAX 1
#define TGT_FW_RSRC_CUR 2
#define TGT_FW_RSRC_ALL 3

struct coiscsi_target_stats_ioctl {
	uint8_t		wr_status;
	union coiscsi_stats {
		struct coiscsi_resource {
			uint8_t    num_ipv4_tgt[TGT_FW_RSRC_ALL];
			uint8_t    num_ipv6_tgt[TGT_FW_RSRC_ALL];
			uint16_t   num_l2t_entries[TGT_FW_RSRC_ALL];
			uint16_t   num_csocks[TGT_FW_RSRC_ALL];
			uint16_t   num_tasks[TGT_FW_RSRC_ALL];
			uint16_t   num_ppods_zone[MAX_PPOD_ZONES][TGT_FW_RSRC_ALL];
			uint32_t   num_bufll64[TGT_FW_RSRC_ALL];
		} rsrc;
	}u;
};

enum vla_type {
        type_lun,
        type_port,
        type_acl,
};

struct coiscsi_vla_block {
	uint16_t	total_len;
	enum vla_type	block_type;
	uint16_t	block_len;
};

struct coiscsi_portal_info {
	uint8_t		ip_type;
	uint8_t		tpgt;
	uint16_t	port;
	struct ip_addr	ip;
	uint16_t	redir;
};

#endif	/*__CSIO_COISCSI_IOCTL_H__*/
