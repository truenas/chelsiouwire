#
# Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.
#
# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2 or the OpenIB.org BSD license
# below:
#
#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:
#
#      - Redistributions of source code must retain the above
#	  copyright notice, this list of conditions and the following
#	  disclaimer.
#      - Redistributions in binary form must reproduce the above
#	  copyright notice, this list of conditions and the following
#	  disclaimer in the documentation and/or other materials
#	  provided with the distribution.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
SPDK_ROOT_DIR := $(abspath $(CURDIR)/../spdk)
include $(SPDK_ROOT_DIR)/mk/spdk.common.mk

SO_VER := 2
SO_MINOR := 0

#Include
CFLAGS += -I.
CFLAGS += -I$(SPDK_ROOT_DIR)/dpdk/lib/librte_eal/common/include
CFLAGS += -I$(SPDK_ROOT_DIR)/dpdk/build/include
CFLAGS += -I$(SPDK_ROOT_DIR)/lib/nvmf
#CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/../dev/T4/common/)
#CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/../dev/T4/firmware/)
#CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/../dev/T4/linux/chtcp/)
CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/../chtcp_common)
CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/firmware/)
CFLAGS += -I$(abspath $(CONFIG_CXGB4_SRC)/chtcp/)
CFLAGS += -I$(SPDK_ROOT_DIR)/module/event/subsystems/nvmf/

LIBNAME = sock_chtcp
C_SRCS = chtcp_umain.c chtcp_usge.c chtcp_ucm.c

SPDK_MAP_FILE = $(SPDK_ROOT_DIR)/mk/spdk_blank.map
include $(SPDK_ROOT_DIR)/mk/spdk.lib.mk
