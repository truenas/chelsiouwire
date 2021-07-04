#ifndef __LIBWDTOE_CONN_INFO_H__
#define __LIBWDTOE_CONN_INFO_H__

#include <sys/types.h>
#include <pthread.h>
#include "common.h"
#include "ntuples.h"
#include "device.h"


extern struct wdtoe_device *wd_dev;

/* here also reset buffer's cidx and pidx */
static inline void return_buf(struct wdtoe_device *dev, int buf_idx)
{
	pthread_spin_lock(&dev->stack_info->buf.lock);
	dev->stack_info->buf.flags[buf_idx] = 0;
	dev->stack_info->buf.sw_txq[buf_idx].cidx = 0;
	dev->stack_info->buf.sw_txq[buf_idx].pidx = 0;
	atomic_set(&dev->stack_info->buf.sw_txq[buf_idx].in_use, 0);
	dev->stack_info->buf.sw_fl[buf_idx].cidx = 0;
	dev->stack_info->buf.sw_fl[buf_idx].pidx = 0;
	atomic_set(&dev->stack_info->buf.sw_fl[buf_idx].in_use, 0);
	pthread_spin_unlock(&dev->stack_info->buf.lock);
}

/*
 * returns 0 on success
 * returns -1 if the stid is not found in table
 */
static inline int passive_tuple_get_peer_info(struct passive_tuple *ct,
				       unsigned int stid, unsigned int tid,
				       __u32 *pip, __u16 *pport)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (ct[i].stid == stid && ct[i].tid == tid && ct[i].in_use) {
			*pip = ct[i].pip;
			*pport = ct[i].pport;
			return 0;
		}
	}

	return -1;
}

static inline int conn_tuple_get_lport(struct conn_tuple *ct, unsigned int atid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (ct[i].atid == atid)
			return ct[i].lport;
	}

	return -1;
}

static inline int conn_info_get_free_ntuple(struct wdtoe_conn_info *wci)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].state == AVAILABLE)
			return i;
	}

	return -1;
}

/* return -1 if not find in table */
static inline int conn_info_remove_sockfd_entry(struct wdtoe_conn_info *wci,
					 int sockfd)
{
	int i;

	/* Forked process closing standard output etc. */
	if (sockfd < 3)
		return 0;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].sockfd == sockfd) {
			/* we find the entry, now we clear it */
			wci[i].atid = 0;
			wci[i].stid = 0;
			wci[i].lport = 0;
			wci[i].pip = 0;
			wci[i].pport = 0;
			wci[i].tid = -2;
			wci[i].sockfd = -1;
			wci[i].state = 0;
			wci[i].tcp_state = 0;
			wci[i].port_num = -1;
			wci[i].copied = 0;
			wci[i].buf_len = 0;
			return 0;
		}
	}

	return -1;
}

/* If the entry is not found returns 0 */
static inline int conn_info_get_tid_from_sfd(struct wdtoe_conn_info *wci, int sockfd)
{
	int i;

	/* Forked process closing standard output etc */
	if (sockfd < 3)
		return 0;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].sockfd == sockfd) {
			return wci[i].tid;
		}
	}
	return 0;
}

static inline void conn_info_free_entry(struct wdtoe_conn_info *wci, int tid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].tid == tid)
			wci[i].state = AVAILABLE;
	}
}

static inline int conn_info_insert_cpl_tuple(struct wdtoe_conn_info *wci,
				      unsigned int atid, unsigned int stid,
				      unsigned int tid, unsigned int lport,
				      __u32 pip, __u16 pport, int buf_idx)
{
	int idx = conn_info_get_free_ntuple(wci);

	if (idx == -1)
		return -1;
	wci[idx].atid = atid;
	wci[idx].stid = stid;
	wci[idx].tid = tid;
	wci[idx].lport = lport;
	wci[idx].pip = pip;
	wci[idx].pport = pport;
	wci[idx].state = INCOMPLETE;
	wci[idx].buf_idx = buf_idx;

	return 0;
}

static inline int conn_info_insert_sockfd_passive(struct wdtoe_conn_info *wci,
					   __u32 pip, __u16 pport,
					   unsigned int sockfd, int *tid,
					   int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].state == INCOMPLETE
			&& wci[i].pport == pport
			&& wci[i].pip == pip) {
			wci[i].sockfd = sockfd;
			wci[i].tcp_state = TCP_ESTABLISHED;
			wci[i].state = IN_USE;
			*tid = wci[i].tid;
			*idx = i;
			return 0;
		}
	}

	return -1;
}

/* XXX need to have return value to indicate error */
/* XXX now just assume it's successful */
static inline int get_free_entry_from_priv_conn_info(struct wdtoe_conn_info *c,
					      int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].state == AVAILABLE) {
			*idx = i;
			return 0;
		}
	}

	return -1;
}

static inline int conn_info_insert_sockfd_active(struct wdtoe_conn_info *wci,
					  unsigned int lport,
					  unsigned int sockfd,
					  int *tid, int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].state == INCOMPLETE
			&& wci[i].lport == lport) {
			wci[i].sockfd = sockfd;
			wci[i].tcp_state = TCP_ESTABLISHED;
			wci[i].state = IN_USE;
			*tid = wci[i].tid;
			*idx = i;
			return 0;
		}
	}

	return -1;
}

/* XXX we may need to add return value */
static inline int conn_info_copy_entry(struct wdtoe_conn_info *c_from,
				struct wdtoe_conn_info *c_to,
				int idx_from)
{
	int ret;
	int idx_to;
	int credits;
	/* get index in the "to" structure */
	ret = get_free_entry_from_priv_conn_info(c_to, &idx_to);

	if (ret < 0) {
		DBG(DBG_LOOKUP, "could not get a free entry from"
		    " private conn_info table\n");
		return ret;
	}

	c_to[idx_to].atid = c_from[idx_from].atid;
	c_to[idx_to].stid = c_from[idx_from].stid;
	c_to[idx_to].lport = c_from[idx_from].lport;
	c_to[idx_to].pip = c_from[idx_from].pip;
	c_to[idx_to].pport = c_from[idx_from].pport;
	c_to[idx_to].tid = c_from[idx_from].tid;
	c_to[idx_to].sockfd = c_from[idx_from].sockfd;
	c_to[idx_to].state = c_from[idx_from].state;
	c_to[idx_to].tcp_state = c_from[idx_from].tcp_state;
	c_to[idx_to].port_num = c_from[idx_from].port_num;
	c_to[idx_to].copied = c_from[idx_from].copied;
	c_to[idx_to].buf_len = c_from[idx_from].buf_len;
	c_to[idx_to].buf_idx = c_from[idx_from].buf_idx;
	c_to[idx_to].wd_flags = c_from[idx_from].wd_flags;
	c_to[idx_to].wd_sock_flags = c_from[idx_from].wd_sock_flags;
	c_to[idx_to].max_credits = c_from[idx_from].max_credits;
	/* atomic operations to "cur_credits" */
	credits = atomic_read(&c_from[idx_from].cur_credits);
	atomic_set(&c_to[idx_to].cur_credits, credits);
	c_to[idx_to].pend_credits = c_from[idx_from].pend_credits;

	return 0;
}

static inline int conn_info_insert_info(struct wdtoe_conn_info *wci,
				 unsigned int sockfd, int tid,
				 int port_num,  unsigned int max_cred)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].state == IN_USE &&
		    wci[i].sockfd == sockfd &&
		    wci[i].tid == tid) {
			wci[i].port_num = port_num;
			wci[i].max_credits = max_cred;
			atomic_set(&wci[i].cur_credits, max_cred);
			wci[i].pend_credits = 0;
			return 0;
		}
	}

	return -1;
}

static inline int set_tid_state(struct wdtoe_conn_info *c, unsigned int tid,
			 enum wdtoe_tcp_states new_state)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].tid == tid) {
			DBG(DBG_CONN | DBG_LOOKUP, "connection with "
			    "tid [%d] is now in TCP state [%d]\n",
			    tid, new_state);

			c[i].tcp_state = new_state;

			return 0;
		}
	}

	DBG(DBG_CONN | DBG_LOOKUP, "could not set TCP state "
	    "for connection with tid [%d]\n", tid);

	return -1;
}

static inline int get_tid_tcp_state(struct wdtoe_conn_info *c, int tid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].tid == tid) {
			return c[i].tcp_state;
		}
	}

	DBG(DBG_CONN | DBG_LOOKUP, "could not get TCP state "
	    "for connection with tid [%d]\n", tid);

	return -1;
}

static inline void conn_info_remove_tid_entry(struct wdtoe_conn_info *c,
				       int tid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].tid == tid) {
			c[i].atid = 0;
			c[i].stid = 0;
			c[i].lport = 0;
			c[i].pip = 0;
			c[i].pport = 0;
			c[i].tid = -2;
			c[i].sockfd = -1;
			c[i].state = 0;
			c[i].tcp_state = 0;
			c[i].port_num = -1;
			c[i].copied = 0;
			c[i].buf_len = 0;
			return_buf(wd_dev, c[i].buf_idx);
			c[i].buf_idx = -1;
			c[i].wd_flags = 0;
			c[i].wd_sock_flags = 0;
			c[i].max_credits = 0;
			atomic_set(&c[i].cur_credits, 0);
			c[i].pend_credits = 0;
			return;
		}
	}

	DBG(DBG_CONN | DBG_LOOKUP, "could not remove entry from "
	    "conn_info table for tid [%d]\n", tid);
}

static inline int get_idx_from_tid(struct wdtoe_conn_info *wci, int tid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].tid == tid)
			return i;
	}
	return -1;
}

static inline int get_idx_from_sockfd(struct wdtoe_conn_info *wci, int sockfd)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].sockfd == sockfd)
			return i;
	}
	return -1;
}

static inline int conn_info_get_tid(struct wdtoe_conn_info *wci, int sockfd,
			     int *port_num, int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (wci[i].sockfd == sockfd) {
			if (port_num)
				*port_num = wci[i].port_num;

			if (idx)
				*idx = i;

			return wci[i].tid;
		}
	}

	return -1;
}

static inline int conn_info_get_idx(struct wdtoe_conn_info *c, int sockfd, int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].sockfd == sockfd) {
			*idx = i;
			return 0;
		}
	}

	return -1;
}

static inline int conn_info_get_idx_from_tid(struct wdtoe_conn_info *c,
				      unsigned int tid, int *idx)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].tid == tid) {
			*idx = i;
			return 0;
		}
	}

	return -1;
}

static inline int check_sockfd_peer_closed(struct wdtoe_conn_info *c, int sockfd)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].sockfd == sockfd) {
			if (c[i].tcp_state == TCP_ESTABLISHED) {
				return 0;
			} else if (c[i].tcp_state == TCP_CLOSE_WAIT) {
				DBG(DBG_CONN | DBG_LOOKUP, "found sockfd [%d] "
				    "peer_closed\n", sockfd);

				return 1;
			} else {
				DBG(DBG_CONN | DBG_LOOKUP, "found sockfd [%d] "
				    "unexpected state\n", sockfd);

				return 0;
			}
		}
	}

	DBG(DBG_CONN | DBG_LOOKUP, "sockfd [%d] is not "
	    "in conn_info table\n", sockfd);

	return 0;
}

static inline int check_tid_peer_closed(struct wdtoe_conn_info *c, int tid)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if (c[i].tid == tid) {
			if (c[i].tcp_state == TCP_ESTABLISHED) {
				return 0;
			} else if (c[i].tcp_state == TCP_CLOSE_WAIT) {
				DBG(DBG_CONN | DBG_LOOKUP, "found tid [%d] "
				    "peer_closed\n", tid);
				return 1;
			} else {
				DBG(DBG_CONN | DBG_LOOKUP, "found tid [%d] "
				    "unexpected state\n", tid);
				return 0;
			}
		}
	}

	DBG(DBG_CONN | DBG_LOOKUP, "tid [%d] is not in conn_info table\n", tid);

	return 0;
}

/* pass the port number in here */
/*XXX need a return value in case the table is full */
/*XXX need to pass the idx, which is returned by cmd_reg_listen */
static inline void insert_listen_svr(struct wdtoe_listsvr *svr, int fd, __u16 port)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if(svr[i].listen_port == 0) {
			svr[i].sockfd = fd;
			svr[i].listen_port = port;
			atomic_set(&svr[i].ref_cnt, 1);
			return;
		}
	}
}

static inline int remove_listen_svr(struct wdtoe_listsvr *svr, int fd, __u16 *port)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if(svr[i].sockfd == fd) {
			/* get the listen_port */
			*port = svr[i].listen_port;
			svr[i].listen_port = 0;
			svr[i].sockfd = 0;
			atomic_set(&svr[i].ref_cnt, 0);
			return 0;
		}
	}
	return -1;
}

static inline int decre_listen_svr(struct wdtoe_listsvr *svr, int fd, __u16 port)
{
	int i;

	for (i = 0; i < NWDTOECONN; i++) {
		if(svr[i].listen_port == port) {
			atomic_decr(&svr[i].ref_cnt);
			if (atomic_read(&svr[i].ref_cnt) == 0) {
				DBG(DBG_CONN, "close time for socket [%d], "
					" and port [%u] come!\n",
					fd, port);
				/* clear the other fields */
				svr[i].sockfd = 0;
				svr[i].listen_port = 0;
				return 0;
			}
			return -1;
		}
	}
	return -1;
}

void insert_listen_svr(struct wdtoe_listsvr *, int, __u16);
int remove_listen_svr(struct wdtoe_listsvr *, int , __u16 *);
int decre_listen_svr(struct wdtoe_listsvr *, int fd, __u16);
struct wdtoe_conn_info *alloc_conn_info(size_t entries);
int init_conn_info(struct wdtoe_conn_info *wci, size_t entries);
struct wdtoe_listsvr *alloc_listsvr(size_t entries);
int init_listsvr(struct wdtoe_listsvr *lsvr, size_t entries);
void wdtoe_add_rem_tid(unsigned int tid, enum wdtoe_tid_action action);
#endif
