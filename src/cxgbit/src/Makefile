SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

FLAGS += -D__CXGB4TOE__
FLAGS += -DCONFIG_CHELSIO_T4_CORE
FLAGS += -DCONFIG_CHELSIO_T4_OFFLOAD_MODULE
FLAGS += -DCONFIG_TCP_OFFLOAD_MODULE

# sw repo (4.X) uses napi_alloc_skb() but not the backport repos
# which also implies that lro_rx_handler() with parameter *napi
ifneq ($(shell $(grep) 'cxgb4_pktgl_to_skb' \
			$(CXGB4TOE_SRC)/cxgb4/cxgb4_ofld.h | \
                $(grep) -c 'napi'),0)
  FLAGS += -DCXGB4_NAPI_ALLOC_SKB
endif

ifneq ($(MAKECMDGOALS),clean)
  include $(drvdir)/t4_flags.mk
endif

EXTRA_CFLAGS += -DLINUX -D__KERNEL__ -DMODULE -O2 -pipe -Wall
EXTRA_CFLAGS += $(OFLAGS)
EXTRA_CFLAGS += $(FLAGS) $(CPPFLAGS)

EXTRA_CFLAGS += -I$(CXGB4TOE_SRC)/include -I$(CXGB4TOE_SRC)/cxgb4
EXTRA_CFLAGS += -I$(CXGB4TOE_SRC)/../dev/T4/common
EXTRA_CFLAGS += -I$(KSRC)/include -I$(KSRC)/drivers/target/iscsi
EXTRA_CFLAGS += -I.

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
					-o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

EXTRA_SYMFILE = "$(CXGB4TOE_SRC)/$(modulesymfile)"

obj-m := cxgbit.o
cxgbit-y := cxgbit_cm.o cxgbit_ddp.o cxgbit_main.o cxgbit_target.o

.PHONY: default
default: prep build

.PHONY: prep
prep: symvers
symvers:
	@rm -f $(modulesymfile)

.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) KBUILD_EXTMOD=$(shell pwd) \
		KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMFILE)" modules

.PHONY: clean
clean:
	-/bin/rm -rf *.ko* ?odule* .tmp_versions *.mod.* *.o .*.o.* .*.cmd
