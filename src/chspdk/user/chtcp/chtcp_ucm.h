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
#ifndef __CHTCP_UCM_H__
#define __CHTCP_UCM_H__

int chtcp_handle_close_listsrv_rpl(struct chtcp_uadapter *adap, const void *rsp);
void chtcp_free_lcsk(struct chtcp_listen_sock *lcsk);
void check_for_arp_failure(struct chtcp_sock_list *sock_list);
int chtcp_handle_cpl_fw4_ack(struct chtcp_uadapter *adap, const void *rsp);

int chtcp_handle_abort_rpl_rss(struct chtcp_uadapter *adap, const void *cpl);
int chtcp_handle_abort_req_rss(struct chtcp_uadapter *adap, const void *cpl);
int chtcp_send_abort_rpl(struct chtcp_sock *csk);
int chtcp_send_abort_req(struct chtcp_sock *csk, bool reset);
int chtcp_handle_pass_open_rpl(struct chtcp_uadapter *adap, const void *rsp);
int chtcp_handle_close_con_rpl(struct chtcp_uadapter *adap, const void *cpl);
int chtcp_send_close_con_req(struct chtcp_sock *csk);
int chtcp_handle_peer_close(struct chtcp_uadapter *adap, const void *cpl);
int chtcp_handle_pass_establish(struct chtcp_uadapter *adap, const void *cpl);
int chtcp_handle_pass_accept_req(struct chtcp_sge_ofld_rxq *rxq,
				  struct chtcp_mbuf_q  *mbufq);
int chtcp_listen_sock_close(struct chtcp_listen_sock *lcsk);
int chtcp_client_sock_close(struct chtcp_sock *csk);
struct rte_mbuf *chtcp_get_flowc_mbuf(struct chtcp_sock *csk);

#endif // __CHTCP_UCM_H__
