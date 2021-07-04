/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures, enums and function handlers for csiostor
 * and coiscsi interface(glue) code
 *
 */
#ifndef __CSIO_COISCSI_EXTERNAL_H__
#define __CSIO_COISCSI_EXTERNAL_H__

#include <csio_defs.h>
#include <csio_coiscsi_tgt.h>
#include <csio_isns_ioctl.h>

#define COISCSI_DDP_ERR_MASK	0xFF68000

/* tgtreq ops */
#define COISCSI_TREQ_XMIT_PDU		0
#define COISCSI_TREQ_XMIT_DATA_IN	1
#define COISCSI_TREQ_XMIT_R2T		2
#define COISCSI_TREQ_TAG_RESERVE	3
#define COISCSI_TREQ_ABORT		4

/* for xmit completion */ 
#define COISCSI_PDU_XMIT_WAIT_CMPL	0x20000
#define COISCSI_PDU_XMIT_DONE		0x40000
#define COISCSI_PDU_XMIT_ERROR		0x80000



enum CSIO_HANDLERS {
        TARGET_HANDLER = 1,
        CONN_REQUEST_HANDLER,
	PROGRAM_RESPONSE_HANDLER,
	XMIT_RESPONSE_HANDLER,
};

typedef struct isns_data isns_data;

struct isns_data {
       uint8_t                 op;
       uint32_t                totallen;
       uint32_t                sg_cnt;
       void                    *sglist;
       struct  data_sgl        sgl[32];
       uint8_t                 conn_wait_cmpl;
       uint8_t                 data_wait_cmpl;
       void                    *pdata1;        /* Holds csio_hw */
       void                    *pdata2;        /* Holds pdev */
       uint32_t                flow_id;
       isns_info               isns_info;      /* Holds isns server & connection details */
       uint8_t                 status;
       uint16_t                 iq_idx;
       struct completion       *conn_op_cmpl;
       struct completion       *data_op_cmpl;
};

enum {
       ISNS_OP_TARG_REG,
       ISNS_OP_TARG_UNREG,
       ISNS_OP_SCN_REG,
       ISNS_OP_SCN_UNREG,
       ISNS_OP_ESI_RSP,
       ISNS_OP_SCN_RSP,
       ISNS_OP_QUERY_PEER,
       ISNS_OP_SET_ACL,
};

struct uld_tgt_handler {
	int32_t (*start_target_node)(void *object, char *lun_list);		/* Allocate requiste node/lun structures */
	int32_t (*update_target_node)(void *object, char *lun_list);		/* Update requiste node/lun structures */
	int32_t (*stop_target_node)(void *object);				/* De-allocate node */
	int32_t (*start_server)(void *object, void *, void **return_object);	/* Start faux listening server */
	int32_t (*accept_connection)(void *, void *, void *, void *);		/* Fake a connection accept */
	int32_t (*adjust_connection)(void *rnc_object, void *adjust_props);	/* Adjust connection digest */
	int32_t (*close_connection)(void *object, void *rnc_object, void *pdev, int destroy);	/* Fake a connection close */
	int32_t (*stop_server)(void *object);					/* Tear down connection */
	int32_t (*recv_data)(struct csio_coiscsi_rcvreq *);			/* data recved, process it */
	int32_t (*xmit_data)(struct csio_coiscsi_tgtreq *);			/* Send tx data */
	int32_t (*display_target_info)(void *, char *); 			/* display target details */
	int32_t (*update_portal)(void *object);					/* Update portal list */
	int32_t	(*cmpl_handler)(void *, void *); 				/* xmit completion handler */
	int32_t (*start_isns)(void *, void *, void *);				/* start isns capability */
	int32_t (*stop_isns)(void *, void *, void *); 				/* stop isns capability */
        int32_t (*show_isns)(void *, void *, void *); 				/* show isns capability */
        int32_t (*send_isns_pdu)(void *); 					/* Send iSNS PDU */
        int32_t (*recv_isns_pdu)(uint16_t, void *, uint8_t, void *); 		/* Receive iSNS PDU */
        int32_t (*send_isns_conn_req)(void *); 					/* Send iSNS PDU */
        int32_t (*accept_isns_conn)(void *, void *, uint32_t, void *);          /* Accept iSNS connection */
        int32_t (*close_isns_conn)(void *, uint8_t );                           /* Close iSNS connection */
};

struct csio_target_props {
	void 	*tinst_ptr;
	void 	*disc_auth;
	uint32_t	ip_addr[4];
	uint32_t	port;
	uint32_t	max_burst;
	uint32_t	cur_statsn;
	uint16_t	tpgt;
	uint16_t	redir;
	uint16_t	max_r2t;
	uint32_t	max_tdsl;
	uint32_t	max_rdsl;
	uint8_t		ip_type;
	uint8_t		hdigest;
	uint8_t		ddigest;
};

//typedef int (*csio_target_handler_func)(void * object, unsigned int opcode);
void csio_register_target_handlers(struct uld_tgt_handler *);
void csio_tag_rnc_conn(void *, void*, uint32_t *);
int csio_get_rnc_flowid(void *);
void csio_issue_close_conn_wr_sync(void *);
void coiscsi_connection_cleanup(void *, uint32_t);
void coiscsi_connection_close(void *);
void *coiscsi_socket_accept(void *);
void coiscsi_socket_close(void *);
void coiscsi_reject_conn(void *);
void isns_connection_close(void *, uint8_t);
void csio_tag_rns_conn(void *, void*, uint32_t *);
int coiscsi_issue_del_n_wait_for_mod(struct csio_rnode *, void *, uint32_t, struct completion *);
int coiscsi_ack_mod_n_wait_for_del(struct csio_rnode *, void *, struct completion *);
#ifdef __CSIO_ISNS_CONN_MOD__
int isns_ack_mod_n_wait_for_del(struct csio_rnode *, void *, struct completion *);
#endif


#endif	/*__CSIO_COISCSI_EXTERNAL_H__*/
