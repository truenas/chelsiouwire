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
#ifndef	__CHTCP_KCM_H__
#define	__CHTCP_KCM_H__

int chtcp_handle_pass_open_req(struct chtcp_kadapter *dev, void __user *useraddr);
int chtcp_handle_close_listsrv_req(struct chtcp_kadapter *dev, void __user *useraddr);
int chtcp_handle_pass_accept_req(struct chtcp_kadapter *dev, void __user *useraddr);
int chtcp_handle_close_listsrv_rpl(struct chtcp_kadapter *dev, u32 stid);
int chtcp_handle_free_sock(struct chtcp_kadapter *dev, void __user *useraddr);
int chtcp_handle_release_tid(struct chtcp_kadapter *dev, void __user *useraddr);
int chtcp_handle_arp_failure(struct chtcp_kadapter *dev, void __user *useraddr);
void chtcp_free_kcsk(struct chtcp_kadapter *dev, u32 tid);
int chtcp_remove_server(struct chtcp_kadapter *dev,
			struct chtcp_klisten_sock *lcsk, u16 rss_qid);
#endif
