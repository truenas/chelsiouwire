# Makefile for Chelsio chtcp driver.
#
# Copyright (c) 2020-2021 Chelsio Communications. All rights reserved.

# This software is available to you under a choice of one of two
# licenses.  You may choose to be licensed under the terms of the GNU
# General Public License (GPL) Version 2 or the OpenIB.org BSD license
# below:

#     Redistribution and use in source and binary forms, with or
#     without modification, are permitted provided that the following
#     conditions are met:

#      - Redistributions of source code must retain the above
#	  copyright notice, this list of conditions and the following
#	  disclaimer.
#      - Redistributions in binary form must reproduce the above
#	  copyright notice, this list of conditions and the following
#	  disclaimer in the documentation and/or other materials
#	  provided with the distribution.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

SHELL = /bin/sh

# The top-level makefile defines required variables and flags.
ifneq ($(shell [ $(MAKELEVEL) -ge 1 ] && echo 1),1)
  $(error Please use the top-level Makefile to build this driver)
endif

EXTRA_CFLAGS += $(FLAGS)
EXTRA_CFLAGS += -I$(srcdir)/include
EXTRA_CFLAGS += -I$(srcdir)/cxgb4
EXTRA_CFLAGS += -I$(KSRC)/include
EXTRA_CFLAGS += -I. -g -O1

CFILES  = chtcp_kmain.c chtcp_kcm.c chtcp_ksge.c
TARGET  = chtcp.o
CLEAN_FILES := $(wildcard *.c)
CLEAN_FILES := $(CLEAN_FILES:.c=.o)

lib_path     := $(PREFIX)/lib/modules/$(utsrelease)
module_path   = updates/drivers/chtcp
install_path := $(lib_path)/$(module_path)
old_install_path := $(lib_path)/$(module_path)

ifeq ($(kseries),2.4)
  $(error offload driver is not supported on 2.4 series kernel)
  driver := $(TARGET)
  $(TARGET): $(filter-out $(TARGET),$(CFILES:.c=.o))
	$(LD) -r $^ -o $@
else
  driver := $(TARGET:.o=.ko)
endif

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
