# Makefile for Chelsio T4 chcr driver.
# Copyright (c) 2006-2021 Chelsio Communications, Inc.
SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

# Includes.
EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(srcdir)/cxgb4
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I.

CFILES  = chcr_core.c chcr_algo.c chcr_ipsec.c

TARGET  = chcr.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/net/chcr
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/updates/kernel/drivers/net/chcr

driver := $(TARGET:.o=.ko)

ifneq ($(modulesymfile),)
  override symverfile = symverfile="$(topdir)/$(modulesymfile) \
                                    -o $(drvdir)/$(modulesymfile)"
else
  override symverfile =
endif

EXTRA_SYMFILE = "$(srcdir)/cxgb4/$(modulesymfile)"

obj-m := $(TARGET)
$(TARGET:.o=)-objs := $(CFILES:.c=.o)

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: default
default: prep build

.PHONY: prep
prep:

.PHONY: build
build:
	@$(MAKE) $(symverfile) -C $(KOBJ) KBUILD_EXTMOD=$(shell pwd) \
		KBUILD_EXTRA_SYMBOLS="$(EXTRA_SYMFILE)" modules

.PHONY: install
install:
	@-if [ -e "$(old_install_path)/$(driver)" ]; then \
		echo "* Removing old driver at $(old_install_path)/$(driver)"; \
		/bin/rm -f "$(old_install_path)/$(driver)"; \
	fi;
	@install -D $(verbose) -m 644 $(driver) $(install_path)/$(driver)

.PHONY: uninstall
uninstall:
	@-if [ -n "$(verbose)" ]; then \
	    echo "Removing $(install_path)/$(driver)";\
		if [ -e "$(old_install_path)/$(driver)" ]; then \
		    echo "Removing $(old_install_path)/$(driver)";\
		fi; \
	  fi;\
	  /bin/rm -f "$(install_path)/$(driver)"; \
	  /bin/rm -f "$(old_install_path)/$(driver)";

.PHONY: clean
clean:
	-/bin/rm -rf $(driver) $(TARGET) $(TARGET:.o=.mod.c) \
	             $(TARGET:.o=.mod.o) $(CLEAN_FILES) \
		     .*cmd .tmp_versions *.symvers
