/*
 * This file is part of the Chelsio T4/T5/T6 Ethernet driver.
 *
 * Copyright (C) 2003-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */

#ifndef __CXGB4VF_OSDEP_H__
#define __CXGB4VF_OSDEP_H__

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/ethtool.h>

#include "cxgb4vf_compat.h"

#ifndef SPEED_40000
#define SPEED_40000 40000
#endif

/*
 * The Linux drivers have been converted to deal with the new 32-bit Firmware
 * Port Capabilities.
 */
#define T4VF_OS_NEW_FW_CAPS32 1

#endif /* __CXGB4VF_OSDEP_H__ */
