/*
 * This file handles offloading of listening sockets.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * Written by Dimitris Michailidis (dm@chelsio.com)
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#include <linux/module.h>
#include <linux/toedev.h>
#include <net/tcp.h>
#include <net/offload.h>
#include <net/addrconf.h>
#include "l2t.h"
#include "clip_tbl.h"
#include "defs.h"
#include "tom.h"
#include "cpl_io_state.h"
#include "t4_msg.h"
#include "t4fw_interface.h"
#include "offload.h"

static inline int listen_hashfn(const struct sock *sk)
{
	return ((unsigned long)sk >> 10) & (LISTEN_INFO_HASH_SIZE - 1);
}

/*
 * Create and add a listen_info entry to the listen hash table.  This and the
 * listen hash table functions below cannot be called from softirqs.
 */
static struct listen_info *listen_hash_add(struct tom_data *d, struct sock *sk,
					   unsigned int stid)
{
	struct listen_info *p = kmalloc(sizeof(*p), GFP_KERNEL);

	if (p) {
		int bucket = listen_hashfn(sk);

		p->sk = sk;	/* just a key, no need to take a reference */
		p->stid = stid;
		spin_lock(&d->listen_lock);
		p->next = d->listen_hash_tab[bucket];
		d->listen_hash_tab[bucket] = p;
		spin_unlock(&d->listen_lock);
	}
	return p;
}

/*
 * Given a pointer to a listening socket return its server TID by consulting
 * the socket->stid map.  Returns -1 if the socket is not in the map.
 */
static int listen_hash_find(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p;

	spin_lock(&d->listen_lock);
	for (p = d->listen_hash_tab[bucket]; p; p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Delete the listen_info structure for a listening socket.  Returns the server
 * TID for the socket if it is present in the socket->stid map, or -1.
 */
static int listen_hash_del(struct tom_data *d, struct sock *sk)
{
	int stid = -1, bucket = listen_hashfn(sk);
	struct listen_info *p, **prev = &d->listen_hash_tab[bucket];

	spin_lock(&d->listen_lock);
	for (p = *prev; p; prev = &p->next, p = p->next)
		if (p->sk == sk) {
			stid = p->stid;
			*prev = p->next;
			kfree(p);
			break;
		}
	spin_unlock(&d->listen_lock);
	return stid;
}

/*
 * Compare the netdev address with lld array
 */
static bool comp_netdev_lld_refs(struct toedev *tdev, struct net_device *ndev)
{
	int i;

	for (i = 0; i < tdev->nlldev; i++) {
		if (ndev != tdev->lldev[i]) {
			if (i == tdev->nlldev - 1)
				return false; /* reached the end */
			continue;
		} else
			break;
	}
	return true;
}

/*
 * Check if the ip addr match ours, This function gets address of
 * net_device using the ip addr and compares it with the net_device
 * addresses in tdev->lldev[] array, returns net_device if matched else
 * NULL.
 */
static struct net_device *match_any_lld_netdev(struct toedev *tdev, struct sock *sk)
{
	struct net_device *ndev = tdev->lldev[0];
	struct net_device *tmp_ndev = NULL;
	struct net_device *slave = NULL;
	bool put = false;
	bool ret = true;

	rcu_read_lock();
	if (sk->sk_family == PF_INET) {
		if (likely(!inet_sk(sk)->inet_rcv_saddr)) {
			if (TOM_DATA(tdev)->rss_qid[1] !=
				TOM_DATA(tdev)->rss_qid[0])
				ret = false;
			goto clean_up;	/* Allow wildcard,note ret is true */
		}
		ndev = ip_dev_find(&init_net, inet_sk(sk)->inet_rcv_saddr);
		put = true;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	} else if (sk->sk_family == PF_INET6) {
		int addr_type;

		addr_type = ipv6_addr_type((const struct in6_addr *)
					   &sk->sk_v6_rcv_saddr);
		if (likely(addr_type == IPV6_ADDR_ANY)) {
			if (TOM_DATA(tdev)->rss_qid[1] !=
				TOM_DATA(tdev)->rss_qid[0])
				ret = false;
			goto clean_up;	/* Allow wildcard,note ret is true */
		}
		for_each_netdev_rcu(&init_net, ndev) {
			if (ipv6_chk_addr(&init_net,
				(struct in6_addr *)&sk->sk_v6_rcv_saddr,
								ndev, 1)) {
				tmp_ndev = ndev;
				break;
			}
		}
		ndev = tmp_ndev;
#endif
	} else {
		rcu_read_unlock();
		return NULL;
	}

	if (unlikely(ndev == NULL)) {
		rcu_read_unlock();
		return NULL;
	}

	/* get real net_device if it is vlan */
	if (ndev->priv_flags & IFF_802_1Q_VLAN) {
		if (put) {
			struct net_device *vlan_ndev = ndev;

			ndev = vlan_dev_real_dev(vlan_ndev);
			dev_put(vlan_ndev);
			put = false;
		} else
			ndev = vlan_dev_real_dev(ndev);
	}

	/* If it is bonded interface check any slave matches our lld
	 * if so we will return true.
	 */
	if (netif_is_bond_master(ndev)) {
		for_each_netdev_in_bond_rcu(ndev, slave) {
			/* get real net_device if slave is vlan */
			if (slave->priv_flags & IFF_802_1Q_VLAN)
				slave = vlan_dev_real_dev(slave);
			if (comp_netdev_lld_refs(tdev, slave)) {
				ret = true;
				goto clean_up;
			}
		}
		ret = false; /* none of the slaves matched */
	} else {
		ret = comp_netdev_lld_refs(tdev, ndev);
	}

clean_up:
	rcu_read_unlock();
	if (put)
		dev_put(ndev);

	if (!ret)
		return NULL;

	if (netif_is_bond_master(ndev))
		return slave;
	else
		return ndev;
}

/*
 * Start a listening server by sending a passive open request to HW.
 */
void t4_listen_start(struct toedev *dev, struct sock *sk,
		     const struct offload_req *orq)
{
	int stid;
	struct tom_data *d = TOM_DATA(dev);
	struct listen_ctx *ctx;
	const struct offload_settings *settings;
	int err = 0;
	int offload;
	unsigned char iport = 0, mask = 0, rxchan = 0;
	struct net_device *portdev;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	int addr_type = 0;
	bool clip_valid = false;
#endif

	if (!d)
		return;

	rcu_read_lock();
	if (toedev_in_shutdown_rcu(dev)) {
		rcu_read_unlock();
		return;
	}
	settings = lookup_ofld_policy(dev, orq, d->conf.cop_managed_offloading);
	offload = settings->offload;
	rcu_read_unlock();

	if (!offload)
		return;

        if (!TOM_TUNABLE(dev, activated))
                return;

	/* Allow if rcv_addr is wildcard address or if it matches the ip addr
	 * of any of our low level driver interface addr
	 */
	portdev = match_any_lld_netdev(dev, sk);
	if (!portdev)
		return;		/* Ip addr not matching */

	if (listen_hash_find(d, sk) >= 0)   /* already have it */
		return;

	ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return;

	__module_get(THIS_MODULE);
	ctx->tom_data = d;
	ctx->lsk = sk;
	ctx->state = T4_LISTEN_START_PENDING;
	skb_queue_head_init(&ctx->synq);

	if (sk->sk_family == PF_INET && d->lldi->enable_fw_ofld_conn)
		stid = cxgb4_alloc_sftid(d->tids, sk->sk_family,
					ctx);
	else
		stid = cxgb4_alloc_stid(d->tids, sk->sk_family,
					ctx);

	if (stid < 0)
		goto free_ctx;
	
	sock_hold(sk);

	if (!listen_hash_add(d, sk, stid))
		goto free_stid;

	if (sk->sk_family == PF_INET) {
		if (inet_sk(sk)->inet_rcv_saddr) {
			iport = cxgb4_port_idx(portdev);
			mask = ~0;
			rxchan = cxgb4_port_e2cchan(portdev);
		}

		if (d->lldi->enable_fw_ofld_conn)
			err = cxgb4_create_server_filter(portdev, stid,
							 inet_sk(sk)->inet_rcv_saddr,
							 inet_sk(sk)->inet_sport,
							 cpu_to_be16(TOM_TUNABLE(dev, offload_vlan)),
							 d->rss_qid[rxchan], iport, mask);
		else {
			err = cxgb4_create_server(portdev, stid,
						  inet_sk(sk)->inet_rcv_saddr,
						  inet_sk(sk)->inet_sport,
						  cpu_to_be16(TOM_TUNABLE(dev, offload_vlan)),
						  d->rss_qid[rxchan]);
			}
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	} else {
		addr_type = ipv6_addr_type((const struct in6_addr *)
					   &sk->sk_v6_rcv_saddr);
		if (addr_type != IPV6_ADDR_ANY) {
			err = cxgb4_clip_get(dev->lldev[0],
				(const u32 *)&sk->sk_v6_rcv_saddr, 1);
			if (err)
				goto del_hash;
			clip_valid = true;
			rxchan = cxgb4_port_e2cchan(portdev);
		}
		err = cxgb4_create_server6(portdev, stid,
					   &sk->sk_v6_rcv_saddr,
					   inet_sk(sk)->inet_sport,
					   d->rss_qid[rxchan]);
#endif
	}
	if (err > 0)
		err = net_xmit_errno(err);
	if (err)
		goto del_hash;

	if (!err)
		return;
del_hash:
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (clip_valid)
		cxgb4_clip_release(dev->lldev[0],
				   (const u32 *)&sk->sk_v6_rcv_saddr, 1);
#endif
	listen_hash_del(d, sk);
free_stid:
	cxgb4_free_stid(d->tids, stid, sk->sk_family);
	sock_put(sk);
free_ctx:
	kfree(ctx);
	module_put(THIS_MODULE);
}

/*
 * Stop a listening server by sending a close_listsvr request to HW.
 * The server TID is freed when we get the reply.
 */
void t4_listen_stop(struct toedev *tdev, struct sock *sk)
{
	struct tom_data *d = TOM_DATA(tdev);
	struct listen_ctx *listen_ctx;
	int stid;
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	int addr_type = 0;
#endif

	/* If the device is in shutdown then LLD resources
	 * would have been destroyed by now, so simply bail-out
	 */
	if (toedev_in_shutdown(tdev))
		return;

        stid = listen_hash_del(d, sk);
        if (stid < 0)
                return;

	listen_ctx = (struct listen_ctx *)lookup_stid(d->tids, stid);
	if (!listen_ctx)
		return;

	t4_reset_synq(listen_ctx);

	cxgb4_remove_server(tdev->lldev[0], stid, d->rss_qid[0], sk->sk_family == PF_INET6);
	if (d->lldi->enable_fw_ofld_conn && sk->sk_family == PF_INET)
		cxgb4_remove_server_filter(tdev->lldev[0], stid, d->rss_qid[0], sk->sk_family == PF_INET6);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (sk->sk_family == PF_INET6) {
		addr_type = ipv6_addr_type((const struct in6_addr *)
					&sk->sk_v6_rcv_saddr);
		if (addr_type != IPV6_ADDR_ANY)
			cxgb4_clip_release(tdev->lldev[0],
			 (const u32 *)&sk->sk_v6_rcv_saddr, 1);
	}
#endif
	t4_disconnect_acceptq(sk);
}

/*
 * Process a CPL_CLOSE_LISTSRV_RPL message.  If the status is good we release
 * the STID.
 */
static int do_close_server_rpl(struct tom_data *td, struct sk_buff *skb)
{
        struct cpl_close_listsvr_rpl *rpl = (struct cpl_close_listsvr_rpl *)cplhdr(skb);
        unsigned int stid = GET_TID(rpl);
	void *data = lookup_stid(td->tids, stid);

        if (rpl->status != CPL_ERR_NONE)
                printk(KERN_ERR "Unexpected CLOSE_LISTSRV_RPL status %u for "
                       "STID %u\n", rpl->status, stid);
        else {
                struct listen_ctx *listen_ctx = (struct listen_ctx *)data;

                cxgb4_free_stid(td->tids, stid, listen_ctx->lsk->sk_family);
                sock_put(listen_ctx->lsk);
                kfree(listen_ctx);
		module_put(THIS_MODULE);
        }

        return CPL_RET_BUF_DONE;
}

/*
 * Process a CPL_PASS_OPEN_RPL message.
 */
int do_pass_open_rpl(struct tom_data *td, struct sk_buff *skb)
{
	struct cpl_pass_open_rpl *rpl = (struct cpl_pass_open_rpl *)cplhdr(skb);
	unsigned int stid = GET_TID(rpl);
	struct listen_ctx *listen_ctx;

	listen_ctx = (struct listen_ctx *)lookup_stid(td->tids, stid);

	if (!listen_ctx) {
		printk(KERN_ERR "no listening context for STID %u\n", stid);
		return CPL_RET_BUF_DONE;
	}

	if (listen_ctx->state == T4_LISTEN_START_PENDING) {
		listen_ctx->state = T4_LISTEN_STARTED;
		return CPL_RET_BUF_DONE;
	}

	if (rpl->status != CPL_ERR_NONE)
		printk(KERN_ERR "Unexpected PASS_OPEN_RPL status %u for "
		       "STID %u\n", rpl->status, stid);
	else {
		cxgb4_free_stid(td->tids, stid, listen_ctx->lsk->sk_family);
		sock_put(listen_ctx->lsk);
		kfree(listen_ctx);
		module_put(THIS_MODULE);
	}

	return CPL_RET_BUF_DONE;
}

void __init t4_init_listen_cpl_handlers(void)
{
	t4tom_register_cpl_handler(CPL_PASS_OPEN_RPL, do_pass_open_rpl);
	t4tom_register_cpl_handler(CPL_CLOSE_LISTSRV_RPL, do_close_server_rpl);
}

#ifdef CONFIG_PROC_FS
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include "t4_linux_fs.h"

#define PROFILE_LISTEN_HASH 1

#if PROFILE_LISTEN_HASH
# define BUCKET_FIELD_NAME "Bucket"
# define BUCKET_FMT "%-9d"
# define BUCKET(sk) , listen_hashfn(sk)
#else
# define BUCKET_FIELD_NAME
# define BUCKET_FMT
# define BUCKET(sk)
#endif

/*
 * Return the first entry in the listen hash table that's in
 * a bucket >= start_bucket.
 */
static struct listen_info *listen_get_first(struct seq_file *seq,
					    int start_bucket)
{
	struct tom_data *d = seq->private;

	for (; start_bucket < LISTEN_INFO_HASH_SIZE; ++start_bucket)
		if (d->listen_hash_tab[start_bucket])
			return d->listen_hash_tab[start_bucket];
	return NULL;
}

static struct listen_info *listen_get_next(struct seq_file *seq,
					   const struct listen_info *p)
{
	return p->next ? p->next : listen_get_first(seq,
						    listen_hashfn(p->sk) + 1);
}

/*
 * Must be called with the listen_lock held.
 */
static struct listen_info *listen_get_idx(struct seq_file *seq, loff_t pos)
{
	struct listen_info *p = listen_get_first(seq, 0);

	if (p)
		while (pos && (p = listen_get_next(seq, p)))
			pos--;

	return pos ? NULL : p;
}

static struct listen_info *listen_get_idx_lock(struct seq_file *seq, loff_t pos)
{
	struct tom_data *d = seq->private;

	spin_lock(&d->listen_lock);
	return listen_get_idx(seq, pos);
}

static void *listen_seq_start(struct seq_file *seq, loff_t *pos)
{
	return *pos ? listen_get_idx_lock(seq, *pos - 1) : SEQ_START_TOKEN;
}

static void *listen_seq_next(struct seq_file *seq, void *v, loff_t *pos)
{
	if (v == SEQ_START_TOKEN)
		v = listen_get_idx_lock(seq, 0);
	else
		v = listen_get_next(seq, v);
	++*pos;
	return v;
}

static void listen_seq_stop(struct seq_file *seq, void *v)
{
	if (v != SEQ_START_TOKEN)
		spin_unlock(&((struct tom_data *)seq->private)->listen_lock);
}

static int listen_seq_show(struct seq_file *seq, void *v)
{
	if (v == SEQ_START_TOKEN)
		seq_puts(seq,
			 "TID     Port    " BUCKET_FIELD_NAME \
			 "   IP address\n");
	else {
		char ipaddr[40]; /* enough for full IPv6 address + NULL */
		struct listen_info *p = v;
		struct sock *sk = p->sk;
		if (sk->sk_family == AF_INET)
			sprintf(ipaddr, "%pI4", &inet_sk(sk)->inet_rcv_saddr);
#if defined(CONFIG_TCPV6_OFFLOAD)
		else
			sprintf(ipaddr, "%pI6c", &sk->sk_v6_rcv_saddr);
#endif
			seq_printf(seq, "%-7d %-8u" BUCKET_FMT "%s\n", p->stid,
				   ntohs(inet_sk(sk)->inet_sport) BUCKET(sk),
				   ipaddr);
	}
	return 0;
}

static struct seq_operations listen_seq_ops = {
	.start = listen_seq_start,
	.next = listen_seq_next,
	.stop = listen_seq_stop,
	.show = listen_seq_show
};

static int proc_listeners_open(struct inode *inode, struct file *file)
{
	int rc = seq_open(file, &listen_seq_ops);

	if (!rc) {
		struct seq_file *seq = file->private_data;

		seq->private = PDE_DATA(inode);
	}
	return rc;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static struct proc_ops proc_listeners_fops = {
	.proc_open = proc_listeners_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = seq_release
};
#else
static struct file_operations proc_listeners_fops = {
	.owner = THIS_MODULE,
	.open = proc_listeners_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release
};
#endif

/*
 * Create the proc entry for the listening servers under dir.
 */
int t4_listen_proc_setup(struct proc_dir_entry *dir, struct tom_data *d)
{
	struct proc_dir_entry *p;

	if (!dir)
		return -EINVAL;

	p = proc_create_data("listeners", S_IRUGO, dir,
			     &proc_listeners_fops, d);
	if (!p)
		return -ENOMEM;

        SET_PROC_NODE_OWNER(p, THIS_MODULE);
	return 0;
}

void t4_listen_proc_free(struct proc_dir_entry *dir)
{
	if (dir)
		remove_proc_entry("listeners", dir);
}
#endif
