/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures to hold COiSCSI target config
 *
 */

#ifndef FW_FOISCSI_NAME_MAX_LEN
#define FW_FOISCSI_NAME_MAX_LEN 224
#endif

#ifndef FW_FOISCSI_CHAP_SEC_MAX_LEN
#define FW_FOISCSI_CHAP_SEC_MAX_LEN     128
#endif

struct coiscsi_ioctl_list {
	struct coiscsi_ioctl_list *next;
	int	len;
	void 	*i_buf;
};

struct coiscsi_lun_portal {
        struct coiscsi_lun_portal   *next;
	union {
		struct portal {
		        uint16_t        t_port;
			uint16_t	tpgt;
			struct ip_addr  listen_addr;
			uint8_t		ip_type;
			uint16_t	redir;
		}p;
		struct lun_info {
			char 		*disk;
			uint16_t	lun_len;
		}l;
	};
};

struct coiscsi_parse_inst {

	struct coiscsi_lun_portal	*p_list;
	struct coiscsi_lun_portal	*l_list;
	struct coiscsi_lun_portal	*a_list;

	/* Common attributes */
	uint16_t                        auth_method;
	uint16_t                        auth_policy;
	uint16_t                        max_con;
	uint16_t                        max_r2t;
	uint16_t                        time2wait;
	uint16_t                        time2retain;
	uint32_t                        max_burst;
	uint8_t				hd_dd_dgst;
	uint8_t				rsvd[1];
	uint32_t                        max_rcv_dsl;
	uint32_t                        first_burst;
	uint16_t                        ping_timeout;
	uint16_t                        ping_interval;
	uint8_t                         tgt_name[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t                         tgt_alias[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t                         chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t                         chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	uint8_t                         ini_chap_id[FW_FOISCSI_NAME_MAX_LEN];
	uint8_t                         ini_chap_sec[FW_FOISCSI_CHAP_SEC_MAX_LEN + 1];
	uint8_t				port_count;
	uint8_t                         lun_count;
	uint8_t				acl_en;
	uint8_t				shadow;
	uint8_t				tcp_wscale;
	uint8_t				tcp_wsen;
};
