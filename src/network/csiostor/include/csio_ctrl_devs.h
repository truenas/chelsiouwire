/*
 * Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structure and inline functions to get char device reference
 * for all storage drivers
 */

#ifndef	__CSIO_CTRL_DEVS_H__
#define	__CSIO_CTRL_DEVS_H__

#include <csio_ctrl_chnet.h>
#include <csio_ctrl_foiscsi.h>
#ifdef __CSIO_COISCSI_ENABLED__
#include <csio_ctrl_coiscsi.h>
#endif
#include <csio_os_hw.h>


struct csio_control_dev {
	struct csio_ctrl_chnet		chnet_cdev;
	struct csio_ctrl_foiscsi	foiscsi_cdev;
#ifdef __CSIO_COISCSI_ENABLED__
	struct csio_ctrl_coiscsi	coiscsi_cdev;
#endif
	struct csio_bootlogin		bootlogin;
};

static inline struct csio_control_dev *csio_hw_to_cdev(struct csio_hw *hw)
{
	return (struct csio_control_dev *)csio_oshw_to_prv_data(csio_hw_to_os(hw));
}

static inline struct csio_ctrl_chnet *csio_hw_to_chnet_cdev(struct csio_hw *hw)
{
	return &csio_hw_to_cdev(hw)->chnet_cdev;
}

#ifdef __CSIO_FOISCSI_ENABLED__
static inline struct csio_ctrl_foiscsi *csio_hw_to_foiscsi_cdev(struct csio_hw *hw)
{
	return &csio_hw_to_cdev(hw)->foiscsi_cdev;
}
#endif

#ifdef __CSIO_COISCSI_ENABLED__
static inline struct csio_ctrl_coiscsi *csio_hw_to_coiscsi_cdev(struct csio_hw *hw)
{
	return &csio_hw_to_cdev(hw)->coiscsi_cdev;
}
#endif

static inline struct csio_bootlogin *csio_hw_to_bootlogin(struct csio_hw *hw)
{
	return &csio_hw_to_cdev(hw)->bootlogin;
}

static inline struct csio_hw *csio_bootlogin_to_hw(struct csio_bootlogin *bl)
{
	struct csio_control_dev *cdev = csio_container_of(
						bl, struct csio_control_dev,
						bootlogin);
	void *oshw_private_data = (void *)cdev;
	struct csio_os_hw *os_hw = csio_container_of(oshw_private_data,
						     struct csio_os_hw,
						     prv_data);

	return &os_hw->hw;
}

#endif	/* __CSIO_CTRL_DEVS_H__ */

