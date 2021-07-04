/*
 * Copyright (C) 2017-2018 Chelsio Communications.  All rights reserved.
 *
 * Author: Kumar Sanghvi <kumaras@chelsio.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include "cxgb_filter.h"

struct flow_table;
struct sw_flow;
struct sw_flow_mask;
struct flow_stats;

struct offload_flow_stats {
	u64 packet_count;
	u64 byte_count;
};

struct offload_info {
	struct net_device *netdev;
	struct ch_filter_specification *fs;
	struct offload_flow_stats ofld_stats;
	u64 init_sw_packet_count;
	u64 init_sw_byte_count;
	u32 flow_id;
	u8 cap;
	bool init_sw_counters;
};

void cxgb_flow_offload_add(struct flow_table *table, struct sw_flow *flow,
                           const struct sw_flow_mask *mask);
void cxgb_flow_offload_stats(struct sw_flow *flow, struct flow_stats *stats);
void cxgb_flow_offload_del(struct sw_flow *flow);
