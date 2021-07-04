/*
 * Copyright (c) 2016 Chelsio Communications, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __CXGBIT_COMPAT_H__
#define __CXGBIT_COMPAT_H__

#ifdef __CXGB4TOE__

#include "common.h"
#include "cxgb4_ofld.h"
#include "t4fw_interface.h"

#define FW_OFLD_TX_DATA_WR_ULPMODE	V_TX_ULP_MODE
#define FW_OFLD_TX_DATA_WR_ULPSUBMODE	V_TX_ULP_SUBMODE
#define FW_OFLD_TX_DATA_WR_SHOVE	V_TX_SHOVE

#endif /* #ifdef __CXGB4TOE__ */

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,18,0)
static inline
struct sk_buff *cxgbit_alloc_skb_with_frags(unsigned long header_len,
					    unsigned long data_len)
{
        struct sk_buff *skb;
        struct page *page;
        unsigned long page_size;
        int npages = (data_len + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
        int i;

	if (npages > MAX_SKB_FRAGS)
		return NULL;

        skb = alloc_skb(header_len, GFP_KERNEL);
        if (!skb)
                return NULL;

        skb->truesize += npages << PAGE_SHIFT;

        for (i = 0; npages > 0; i++) {
                page = alloc_page(GFP_KERNEL);
                if (!page)
                        goto free_skb;

                page_size = min_t(unsigned long, data_len,
				  PAGE_SIZE);
                skb_fill_page_desc(skb, i, page, 0, page_size);
                data_len -= page_size;
                npages -= 1;
        }
        return skb;

free_skb:
        kfree_skb(skb);
        return NULL;
}
#endif

#endif /* __CXGBIT_COMPAT_H__ */
