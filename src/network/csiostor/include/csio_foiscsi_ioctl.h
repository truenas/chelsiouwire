/*
 *  Copyright (C) 2008-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description:
 *
 */
#ifndef __CSIO_FOISCSI_IOCTL_H__
#define __CSIO_FOISCSI_IOCTL_H__

#include <csio_common_ioctl.h>

#define ISCSI_SEND_TARGETS_BUF_LEN 	(512 * 2048)
#define	MAX_IDX				8

enum iscsi_stat {
	ISCSI_STATUS_SUCCESS,
	ISCSI_STATUS_MORE_BUF,
	ISCSI_STATUS_FAILURE,
	ISCSI_STATUS_IP_CONFLICT,
	ISCSI_STATUS_INVALID_IP,
	ISCSI_STATUS_HOST_UNREACHABLE,
	ISCSI_STATUS_NETWORK_DOWN,
	ISCSI_STATUS_TIMEOUT,
	ISCSI_STATUS_INVALID_HANDLE
};

struct foiscsi_instance {
	int		op;
	int		id;
	uint8_t		retval;
	uint8_t		res[3];
	uint16_t	login_retry_cnt;
	uint16_t	recovery_timeout;
	char		name[FW_FOISCSI_NAME_MAX_LEN];
	char		alias[FW_FOISCSI_ALIAS_MAX_LEN];
	char		chap_id[FW_FOISCSI_NAME_MAX_LEN];
	char		chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	char		vend_key[FW_FOISCSI_KEY_MAX_LEN];
	char		vend_val[FW_FOISCSI_VAL_MAX_LEN];
	char		res1[3];
};

enum foiscsi_count_type {
	FOISCSI_INSTANCE_COUNT = 0,
	FOISCSI_SESSION_COUNT,
	FOISCSI_IFACE_COUNT,
};

struct foiscsi_count {
	int type;
	int count;
	int inode_idx;
};

struct num_target {
	uint32_t	port;
	uint32_t	num_reg_target; 
};

struct targ_del {
	uint8_t		name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t		ip_type;  /* ipv4 or ipv6 */
	struct ip_addr	ip;
	uint16_t	port;
	uint32_t	status;
	uint8_t		pad;
};

struct foiscsi_sess_info {
	int		inode_idx;
	int		sess_idx;
	int 		ip_type;
	struct ip_addr	init_ip;
	struct ip_addr	targ_ip;
	uint16_t	targ_port;
	uint8_t		tpgt;
	uint8_t		port;
	uint8_t		state;
	uint8_t		rsvd[3];
	uint8_t		targ_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t		targ_alias[FW_FOISCSI_NAME_MAX_LEN];
};

struct foiscsi_login_info {
	int				op;
	uint16_t			login_retry_cnt;
	uint16_t			abort_timeout;
	uint16_t			lur_timeout;
	uint16_t			recovery_tmo; /* currently used by ESXi only */
	int				inode_id;
	int				sess_id; /* out param. driver returns */
	int				ip_type;
	struct ip_addr			tgt_ip; /* discovery target ip */
	struct ip_addr			src_ip; /* initiator ip */
	uint32_t			buf_len; /* length of the buf having sendtargets resp */
	uint32_t			status;
	uint32_t			vlanid;
	int				sess_idx;
	void				*disc_buf;
	struct fw_foiscsi_sess_attr	sess_attr;
	struct fw_foiscsi_conn_attr	conn_attr;
	uint16_t			tgt_port; /* disc target tcp port */
	uint8_t				persistent;
	uint8_t				tgt_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t				tgt_alias[FW_FOISCSI_ALIAS_MAX_LEN];
	char				tgt_id[FW_FOISCSI_NAME_MAX_LEN];
	char				tgt_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
};

struct foiscsi_logout_info {
	int		op;
	int		inode_id;
	int		sess_id;
	int		status;
};

int foiscsi_manage_instance(int, int, int, char *, char *,
		char *ini_user, char *ini_sec, char *vend_key, char *vend_val);
int foiscsi_manage_session(int hw, int op, int dbindex,
		char *sip, char *targetname, char *dip, int tcp_port,
		int sid,  char *auth_method, char *policy, char *tgt_user,
		char *tgt_sec, int persistent, unsigned int vlanid,
		uint8_t tcp_wscale, uint8_t tcp_wsen);
int foiscsi_do_discovery(int hw, int op, int dbindex,
		char *sip, char *dip, int tcp_port, unsigned int vlanid,
		struct foiscsi_login_info *);

#endif/*__CSIO_FOISCSI_IOCTL_H__*/
