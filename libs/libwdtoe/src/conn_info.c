#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include "ntuples.h"
#include "libwdtoe.h"
#include "common.h"
#include "debug.h"
#include "device.h"
#include "conn_info.h"

extern struct passive_tuple *k_passive_tuples;

void debug_print_k_passive_tuples(void)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		DBG(DBG_LOOKUP, "k_passive_tuples[%d], stid [%u], "
			"pip [0x%x], pport [%u], "
			"in_use [%u], tid [%d]\n",
			i, k_passive_tuples[i].stid,
			k_passive_tuples[i].pip, k_passive_tuples[i].pport,
			k_passive_tuples[i].in_use,
			k_passive_tuples[i].tid);
	}
}

void debug_print_conn_info(struct wdtoe_conn_info *conn_info)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		DBG(DBG_LOOKUP, "conn_info[%d], atid [%u], stid [%u], "
			"lport [%u], pip [0x%x], pport [%u], "
			"tid [%d], sockfd [%d], state [%d], "
			"tcp_state [%d], port_num [%d], copied [%u], "
			"buf_len [%u]\n",
			i, conn_info[i].atid, conn_info[i].stid,
			conn_info[i].lport, conn_info[i].pip,
			conn_info[i].pport, conn_info[i].tid,
			conn_info[i].sockfd, conn_info[i].state,
			conn_info[i].tcp_state,
			conn_info[i].port_num,
			conn_info[i].copied,
			conn_info[i].buf_len);
	}
}

struct wdtoe_conn_info *alloc_conn_info(size_t entries)
{
	struct wdtoe_conn_info *wci = NULL;

	wci = calloc(entries, sizeof(*wci));
	if (!wci) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for conn_info\n");
		return NULL;
	}

	return wci;
}

int init_conn_info(struct wdtoe_conn_info *wci, size_t entries)
{
	unsigned int i;

	if (!wci || !entries) {
		DBG(DBG_RES_ALLOC, "invalid parameter(s)\n");
		return -1;
	}

	for (i = 0; i < entries; i++) {
		wci[i].atid = 0;
		wci[i].stid = 0;
		wci[i].lport = 0;
		wci[i].pip = 0;
		wci[i].pport = 0;
		wci[i].tid = -2;
		wci[i].sockfd = -1;
		wci[i].state = AVAILABLE;
		wci[i].tcp_state = TCP_IDLE;
		wci[i].port_num = -1;
		wci[i].copied = 0;
		wci[i].buf_len = 0;
		wci[i].buf_idx = -1;
		/* set the flags so the first packet is sent through WD path */
		wci[i].wd_flags |= F_TX_PREV_PATH;
		wci[i].wd_sock_flags = 0;
		wci[i].max_credits = 0;
		atomic_set(&wci[i].cur_credits, 0);
		wci[i].pend_credits = 0;
	}

	return 0;
}

struct wdtoe_listsvr *alloc_listsvr(size_t entries)
{
	struct wdtoe_listsvr *lsvr;

	lsvr = calloc(NWDTOECONN, sizeof(*lsvr));
	if (!lsvr) {
		DBG(DBG_RES_ALLOC, "could not allocate memory for "
		    "listen server info\n");
		return NULL;
	}

	return lsvr;
}

int init_listsvr(struct wdtoe_listsvr *lsvr, size_t entries)
{
	unsigned int i;

	if (!lsvr || !entries) {
		DBG(DBG_RES_ALLOC, "invalid parameter(s)\n");
		return -1;
	}

	for (i = 0; i < entries; i++) {
		lsvr[i].sockfd = 0;
		lsvr[i].idx = -1;
		lsvr[i].listen_port = 0;
		atomic_set(&lsvr[i].ref_cnt, 0);
	}

	return 0;
}

void wdtoe_add_rem_tid(unsigned int tid, enum wdtoe_tid_action action)
{
	struct wdtoe_pass_tid_resp resp;
	struct wdtoe_pass_tid cmd;
	int ret;

	cmd.tid = tid;
	cmd.action = action;

	ret = wdtoe_cmd_pass_tid(wd_dev->devfd, &cmd, sizeof(cmd), &resp,
				 sizeof(resp));
	if (ret < 0)
		DBG(DBG_CONN, "failed to pass tid \n");

	return;
}
