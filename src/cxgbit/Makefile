# Makefile for Chelsio open-iscsi Target T4,T5 Offload driver.
# Copyright (c) 2008-2012 Chelsio Communications, Inc.
SHELL = /bin/bash
 
#
# kernel parameters:
# - KDIR/KSRC/KOBJ=, optional
#
# offload parameters:
# - CXGB4TOE_SRC=	path to linux_t4_build/
#

# Define grep error output to NULL, since -s is not portable.
grep = grep 2>/dev/null

# ALL subdirectories
ALLSUBDIRS := src

# subdirectories to be build
SUBDIRS := $(ALLSUBDIRS)

# Honor the -s (silent) make option.
verbose := $(if $(filter s,$(MAKEFLAGS)),,-v)

# Define paths.
srcdir := $(shell pwd)
topdir := $(shell cd $(srcdir)/.. && pwd)

$(warning srcdir=$(srcdir), topdir=$(topdir).)

ifneq ($(MAKECMDGOALS),clean)
  include kernel_check.mk

  ifneq ($(MAKECMDGOALS),uninstall)
    include distro_check.mk

    include cxgb_check.mk
    ifeq ($(CXGB4TOE_SRC),)
      SUBDIRS := $(filter-out src,$(SUBDIRS))
    endif
  endif #ifneq uninstall
endif 

ifneq ($(wildcard $(KINC)/linux/kconfig.h),)
  FLAGS += -DKERNEL_HAS_KCONFIG_H
endif
ifneq ($(wildcard $(KINC)/linux/export.h),)
  FLAGS += -DKERNEL_HAS_EXPORT_H
endif

# Don't allow ARCH to overwrite the modified variable when passed to
# the sub-makes.
MAKEOVERRIDES := $(filter-out ARCH=%,$(MAKEOVERRIDES))
# Don't allow CFLAGS/EXTRA_CFLAGS to clobber definitions in sub-make.
MAKEOVERRIDES := $(filter-out CFLAGS=%,$(MAKEOVERRIDES))
MAKEOVERRIDES := $(filter-out EXTRA_CFLAGS=%,$(MAKEOVERRIDES))

# Exports.
export grep
export srcdir
export topdir
export KERNELRELEASE
export KSRC
export KOBJ
export KINC
# arm64 specific fix to include <ksrc>/arch/<karch> folder properly.
# This hack is motivated by the RHEL7.X/CentOS7.X release where the 
# uname Architecture is indicated as "aarch64" but the 
# real Architecture source directory is "arm64"
ifeq ($(ARCH),aarch64)
  ifeq ($(wildcard $(KOBJ)/arch/$(ARCH)/Makefile),)
    override MAKECMDGOALS = $(MAKECMDGOALS) "ARCH=arm64"
  else
    export ARCH
  endif
else
  export ARCH
endif
export FLAGS
export verbose
export utsrelease
export kversions
export kseries
export kversion
export modulesymfile

install_path := $(PREFIX)/lib/modules/$(utsrelease)/updates/kernel/drivers/target/iscsi/cxgbit/

.PHONY: eval.mak

.PHONY: default
default: subdirs post

.PHONY: install
install: install-mods

.PHONY: uninstall
uninstall: uninstall-mods

.PHONY: subdirs $(SUBDIRS)
subdirs: $(SUBDIRS)
$(SUBDIRS):
	@if [ -n "$(verbose)" ]; then \
	   echo "#######################";\
	   printf "####  %-8s%5s####\n" $(@);\
	   echo "#######################";\
	 fi;
	@drvdir=$(shell pwd)/$(@) $(MAKE) -C $(@);

#	/bin/cp -f $(modulesymfile) $(@)/;
#	   /bin/cp -f $(@)/$(modulesymfile) .;\

.PHONY: post
post:
	@if [ -n "$(post_msg)" ]; then \
	   echo -e "\nWARNING:\n $(post_msg)";\
	 fi;

.PHONY: clean
clean:
	@for dir in $(ALLSUBDIRS); do \
	   echo "#######################";\
	   printf "####  %-8s%5s####\n" $$dir;\
	   echo "#######################";\
	  drvdir=$(shell pwd)/$$dir $(MAKE) -C $$dir clean;\
	done;
	@-/bin/rm -f *.symvers eval.mak 2>/dev/null;

.PHONY: install-mods
install-mods:
	@echo "installing kernel modules to $(install_path) ..."
	@mkdir -p -m 755 $(install_path)
	@-for m in $(ALLSUBDIRS); do \
		if [ -f "$$m/cxgbit.ko" ]; then \
			install -v -m 644 $$m/cxgbit.ko $(install_path); \
		fi; \
	done;
	@depmod -a || true

.PHONY: uninstall-mods
uninstall-mods:
	@echo "Un-installing $(install_path) ..."
	@/bin/rm -rf $(install_path)*
	@depmod -a
	
.PHONY: help
help:
	@echo "Build Targets:";\
	 echo " install             - Installs all compiled drivers.";\
	 echo " uninstall           - Uninstalls drivers.";\
	 echo " clean               - Removes all generated files.";\
	 echo;\
	 echo "Build Options:";\
	 echo " KOBJ=<path>         - Kernel build (object) path.";\
	 echo " KSRC=<path>         - Kernel source path.";\
	 echo "                     - Note: When using KSRC or KOBJ, both";\
	 echo "                             variables must be specified.";\
	 echo " KDIR=<path>         - Kernel build and source path. Shortcut";\
	 echo "                       for KOBJ=KSRC=<path>.";\
	 echo;
