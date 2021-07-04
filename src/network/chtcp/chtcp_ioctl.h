/*
 * Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2 or the OpenIB.org BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer.
 *      - Redistributions in binary form must reproduce the above
 *	  copyright notice, this list of conditions and the following
 *	  disclaimer in the documentation and/or other materials
 *	  provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
#ifndef __CHTCP_IOCTL_H__
#define __CHTCP_IOCTL_H__

#define CHTCP_MODULE_VERSION		"3.14.0.3"

#define CHTCP_MAX_ADAPTER_NUM	(4)
#define CHTCP_MAX_PORT		(4)
#define CHTCP_PCI_DEVNAME_LEN	(32)

enum {
	CHTCP_IOCTL_GET_DEV_INFO 	= 0,
	CHTCP_IOCTL_ALLOC_TXQ,
	CHTCP_IOCTL_ALLOC_RXQ,
	CHTCP_IOCTL_CPL_PASS_OPEN,
	CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ,
	CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ,
	CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL,
	CHTCP_IOCTL_GET_TID_INFO,
	CHTCP_IOCTL_FREE_SOCK,
	CHTCP_IOCTL_FREE_TXQ,
	CHTCP_IOCTL_FREE_RXQ,
	CHTCP_IOCTL_CHECK_ARP_FAILURE,
	CHTCP_IOCTL_RELEASE_TID,
	CHTCP_IOCTL_SETUP_CONM_CTX,
	CHTCP_IOCTL_MAXNR,			
};

#define	CHTCP_IOCTL_MAGIC	(0x5D)

/* IOCTLs for CHTCP  */
#define CHTCP_IOCTL_GET_DEV_INFO_CMD	\
_IOR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_GET_DEV_INFO, struct chtcp_adapter_info)

struct chtcp_adapter_info {
	__u64 bar2_length;
	__u8 pci_devname[CHTCP_PCI_DEVNAME_LEN];
	__u8 nports;
	__u8 pf;
	__u8 wr_cred;
	__u8 fl_buf_idx;
	__u32 fl_buf_size;
	__u32 fl_starve_thres;
	__u32 fl_align;
	__u32 sge_fl_db;
	__u32 stat_len;
	__u32 pktshift;
	__u16 mtus[NMTUS];
	enum chip_type adapter_type;
};

#define CHTCP_IOCTL_ALLOC_TXQ_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_ALLOC_TXQ, struct chtcp_txq_info)

struct chtcp_txq_info {
	union {
		struct {
			__u64 phys_addr;
			__u32 nentries;
			__u8 port_id;
		} in;
		struct {
			__u32 cntxt_id;
			__u32 bar2_qid;
			__u64 bar2_offset;
		} out;
	} u;
};


#define CHTCP_IOCTL_ALLOC_RXQ_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_ALLOC_RXQ, struct chtcp_rxq_info)

struct chtcp_rxq_info {
	union {
		struct {
			__u64 q_phys_addr;
			__u32 q_size;
			__u32 iqe_len;
			__u64 fl_addr;
			__u32 fl_size;
			__u8 port_id;
			__u8 pack_en;
		} in;
		struct {
			__u16 q_cntxt_id;
			__u16 q_abs_id;
			__u32 q_bar2_qid;
			__u64 q_bar2_offset;
			__u8 pack_en;
			__u16 fl_cntxt_id;
			__u32 fl_bar2_qid;
			__u64 fl_bar2_offset;
		} out;
	} u;
};

#define	CHTCP_IOCTL_CPL_PASS_OPEN_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_CPL_PASS_OPEN, struct chtcp_create_server_info)

struct chtcp_sock_addr {
	__u32 tcp_port;
	__u8 ip_addr[16];
};

struct chtcp_create_server_info {
	union {
		struct {
			struct chtcp_sock_addr addr;
			__u16 rss_iq[CHTCP_MAX_PORT];
			__u8 is_ipv4;
		} in;
		struct {
			__u32 stid;
			__u32 port_id;
			__u16 ss_family;
		} out;
	} u;
};

#define CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ_CMD	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_CPL_CLOSE_LISTSRV_REQ, struct chtcp_free_server_info)

#define CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL_CMD	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_CPL_CLOSE_LISTSRV_RPL, struct chtcp_free_server_info)

struct chtcp_free_server_info {
	__u32 stid;
	__u16 rss_qid;
};

#define CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_CPL_PASS_ACCEPT_REQ, struct chtcp_conn_info)

#ifndef __user
#define __user
#endif
struct chtcp_conn_info {
	void __user *res;
	union {
		struct {
			__u32 pkt_len;
			__u32 tid;
			__u16 port_id;
			__u16 rss_qid;
		} in;
		struct {
			__u32 tx_chan;
			__u32 snd_win;
			__u32 rcv_win;
			__u8 is_ipv4;
			struct chtcp_sock_addr local_addr;
			struct chtcp_sock_addr remote_addr;
		} out;
	} u;
};

#define CHTCP_IOCTL_GET_TID_INFO_CMD	\
_IOR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_GET_TID_INFO, struct chtcp_tid_info)

struct chtcp_tid_info {
	__u32 ntids;
	__u32 nstids;
	__u32 natids;
	__u32 tid_base;
	__u32 stid_base;
};

#define CHTCP_IOCTL_FREE_TXQ_CMD	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_FREE_TXQ, struct chtcp_free_txq_info)

struct chtcp_free_txq_info {
	__u8 port_id;
	__u32 eq_id;
};

#define CHTCP_IOCTL_FREE_RXQ_CMD	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_FREE_RXQ, struct chtcp_free_rxq_info)

struct chtcp_free_rxq_info {
	__u8 port_id;
	__u32 iq_id;
	__u32 fl_id;
};

#define CHTCP_IOCTL_CHECK_ARP_FAILURE_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_CHECK_ARP_FAILURE, struct chtcp_arp_info)

struct chtcp_arp_info {
	union {
		__u32 tid;
		__u8 arp_failed;
	} u;
};

#define CHTCP_IOCTL_FREE_SOCK_CMD 	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_FREE_SOCK, __u32)

#define CHTCP_IOCTL_RELEASE_TID_CMD	\
_IOW(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_RELEASE_TID, __u32)

#define CHTCP_IOCTL_SETUP_CONM_CTX_CMD	\
_IOWR(CHTCP_IOCTL_MAGIC, CHTCP_IOCTL_SETUP_CONM_CTX, struct chtcp_conm_ctx_info)

/* congestion manager context info */
struct chtcp_conm_ctx_info {
	__u8 port_id;
	__u32 iq_id;
};
 
#endif /* __CHTCP_IOCTL_H__ */
