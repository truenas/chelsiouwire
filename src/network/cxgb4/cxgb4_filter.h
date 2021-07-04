/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver for Linux.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifdef CONFIG_NUMA
#include <linux/vmalloc.h>
#endif
#include "t4_msg.h"

#define WORD_MASK       0xffffffff

static inline void ehash_filter_locks_free(struct filter_hashinfo *hashinfo)
{
	if (hashinfo->ehash_filter_locks) {
#ifdef CONFIG_NUMA
		unsigned int size = (hashinfo->ehash_filter_locks_mask + 1) *
			sizeof(spinlock_t);
		if (size > PAGE_SIZE)
			vfree(hashinfo->ehash_filter_locks);
		else
#endif
		kfree(hashinfo->ehash_filter_locks);
		hashinfo->ehash_filter_locks = NULL;
	}
}

unsigned int inet_ehashfn(struct net *net, const __be32 laddr,
			  const __u16 lport, const __be32 faddr,
			  const __be16 fport);
unsigned int t4_inet6_ehashfn(struct net *net, const struct in6_addr *laddr,
			      const u16 lport, const struct in6_addr *faddr,
			      const __be16 fport);

int init_hash_filter(struct adapter *adap);
void filter_rpl(struct adapter *adap, const struct cpl_set_tcb_rpl *rpl);
void hash_filter_rpl(struct adapter *adap,
			    const struct cpl_act_open_rpl *rpl);
void hash_del_filter_rpl(struct adapter *adap,
				const struct cpl_abort_rpl_rss *rpl);
int cxgb4_get_filter_count(struct adapter *adapter, unsigned int fidx,
					u64 *c, int hash, bool get_byte);
extern const struct file_operations filters_debugfs_fops;
extern const struct file_operations hash_filters_debugfs_fops;
void clear_filter(struct adapter *adap, struct filter_entry *f);

int set_filter_wr(struct adapter *adapter, int fidx, gfp_t gfp_mask);
int delete_filter(struct adapter *adapter, unsigned int fidx,
				gfp_t gfp_mask);
void clear_all_filters(struct adapter *adapter);
int writable_filter(struct filter_entry *f);
int cxgb4_set_filter(struct net_device *dev, int filter_id,
				struct ch_filter_specification *fs,
				struct filter_ctx *ctx, gfp_t flags);
int cxgb4_del_filter(struct net_device *dev, int filter_id,
				struct ch_filter_specification *fs,
				struct filter_ctx *ctx, gfp_t flags);
int cxgb4_get_filter_counters(struct net_device *dev, unsigned int fidx,
			      u64 *hitcnt, u64 *bytecnt, int hash);
void cxgb4_flush_all_filters(struct adapter *adapter, gfp_t flags);
