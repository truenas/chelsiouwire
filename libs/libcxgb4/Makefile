#
# Copyright (c) 2009-2021 Chelsio Communications, Inc.
#

#
# These must be setup prior to calling Makefile
#
#
# ./rdma-core must contain a rdma-core tree ready to use
#
# IBV_VERS - set to the ibverbs/provider ABI.  For all
# pre-rdma-core libibverbs packages, and rdma-core releases < 14,
# the ABI is 2, otherwise it is the same as the rdma-core release.
# EG rdma-core release 15 is IBV_VERS 15.
#
# IBV_INST - set to the subdir for installing the provider lib.
# For non rdma-core installs, this is "", for rdma-core installs
# this is "libibverbs". IE /usr/lib64 vs /usr/lib64/libibverbs
#
# PKG_VERS - set to the rdma-core version for all rdma-core
# releases >= 14, for pre-rdma-core packages set it to IBV_VERS.
#

SHELL = /bin/bash

default_target: all
.PHONY : default_target

ifeq ("x$(IBV_VERS)", "x")
    $(error ERROR: IBV_VERS must be defined.  Use build.sh to invoke make)
endif

ifeq ("x$(PKG_VERS)", "x")
    $(error ERROR: PKG_VERS must be defined.  Use build.sh to invoke make)
endif

ifeq ($(shell [ -a rdma-core ] || echo 1), 1)
    $(error ERROR: ./rdma-core not found.  Use build.sh to invoke make)
endif

#
# We need cmake or cmake 3
#
ifeq ($(shell hash cmake3 2>/dev/null && echo 1), 1)
    CMAKE = cmake3
else
    ifeq ($(shell hash cmake 2>/dev/null && echo 1), 1)
        CMAKE = cmake
    else
        $(error ERROR: cmake is required but not found)
    endif
endif

#
# Use ninja if it is installed
#
ifeq ($(shell hash ninja-build 2>/dev/null && echo 1), 1)
    NINJA = ninja-build
else
    ifeq ($(shell hash ninja 2>/dev/null && echo 1), 1)
        NINJA = ninja
    endif
endif

PATCH=`which patch`
ver_lt_15=$(shell echo "$(PKG_VERS) < 15" | bc)
ver_ge_16=$(shell echo "$(PKG_VERS) >= 16" | bc)
ver_ge_17=$(shell echo "$(PKG_VERS) >= 17" | bc)
ver_ge_18=$(shell echo "$(PKG_VERS) >= 18" | bc)
ver_ge_20=$(shell echo "$(PKG_VERS) >= 20" | bc)
ver_ge_21=$(shell echo "$(PKG_VERS) >= 21" | bc)
ver_ge_24=$(shell echo "$(PKG_VERS) >= 24" | bc)
ver_ge_25=$(shell echo "$(PKG_VERS) >= 25" | bc)
ver_ge_28=$(shell echo "$(PKG_VERS) >= 28" | bc)

CMAKE_FLAGS += -DENABLE_STATIC=1

#
# Sets up the rdma-core build tree
#
build/CMakeCache.txt:
	@rm -fr build
	@mkdir build
	@if [ "x$(NINJA)" == "x" ]; then  \
		(cd build; $(CMAKE) $(CMAKE_FLAGS) ../rdma-core) \
	else \
		(cd build; $(CMAKE) $(CMAKE_FLAGS) -GNinja ../rdma-core) \
	fi

#
# Copies the uwire src into the rdma-core build tree and builds libcxgb4
#
build/lib/libcxgb4-rdmav$(IBV_VERS).so: build/CMakeCache.txt src/*.[ch] patches/*
	@cp -f src/*.[ch] rdma-core/providers/cxgb4;
	@if [[ "1" == "$(ver_ge_16)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/1-libcxgb4__libcxgb4_build_with_rdmacore_version_16_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_17)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/2-libcxgb4__libcxgb4_build_with_rdmacore_version_17_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_18)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/3-libcxgb4__libcxgb4_build_with_rdmacore_version_18_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_20)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/4-libcxgb4__libcxgb4_build_with_rdmacore_version_20_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_21)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/5-libcxgb4__libcxgb4_build_with_rdmacore_version_21_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_24)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/6-libcxgb4__libcxgb4_build_with_rdmacore_version_24_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_25)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/7-libcxgb4__libcxgb4_build_with_rdmacore_version_25_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_ge_28)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/8-libcxgb4__libcxgb4_build_with_rdmacore_version_28_and_higher.patch) \
	fi;
	@if [[ "1" == "$(ver_lt_15)" ]]; then \
		($(PATCH) -sN -p1 < ./patches/1-libcxgb4__revert_send_with_invalidate.patch) \
	fi;
	@if [ "x$(NINJA)" == "x" ]; then  \
		make -C build cxgb4-rdmav$(IBV_VERS) cxgb4; \
	else \
		$(NINJA) -C build cxgb4-rdmav$(IBV_VERS) cxgb4; \
	fi

all: build/lib/libcxgb4-rdmav$(IBV_VERS).so
.PHONY : all

install: build/lib/libcxgb4-rdmav$(IBV_VERS).so
	install `find build/ -name libcxgb4-rdmav$(IBV_VERS).so` /usr/lib64/$(IBV_INST)
	install `find build/providers/ -name cxgb4.driver` /etc/libibverbs.d
	install `find build/ -name libcxgb4*.a` /usr/lib64/
.PHONY : install

clean:
	@if [ "x$(NINJA)" == "x" ]; then  \
		make --silent -C build clean; \
	else \
		$(NINJA) -C build clean; \
	fi
.PHONY : clean

distclean:
	@rm -fr build
	@rm -fr rdma-core
.PHONY : distclean
