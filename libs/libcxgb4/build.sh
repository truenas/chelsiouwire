#!/bin/bash

set -e

#
# Deal with distclean rule here so we don't have
# to checkout rdma-core just to then erase it via
# the Makefile distclean rule.
#
if [[ "x${1}" == "xdistclean" ]] ; then
	rm -fr rdma-core
	rm -fr build
	exit 0
fi


	#
	# determine if we're building against an rdma-core installed system
	# or not, and what rdma-core git commit id to use.  Also set
	# IBV_INST accordlingly
	#
	if hash dpkg-query 2>/dev/null; then
		rdma_core_version=$(dpkg-query -l rdma-core|grep ii|awk '{print $3}')
		dist_ubuntu="1"
	elif hash rpm 2>/dev/null; then
		rdma_core_version=$(rpm -qi rdma-core|grep Version | awk '{print $3}' 2>/dev/null)
	else
		echo "ERROR: no rpm or dpkg-query command found"
		exit 1
	fi

	if [[ "x$rdma_core_version" != "x" ]] ; then
		# echo "System installed with rdma-core version $rdma_core_version..."
		rev=${rdma_core_version%.0}
		if [[ $rev =~ ^[+-]?[0-9]+$ ]] ; then
			if [[ $rev -ge 24 ]] ; then
				rev=${rdma_core_version}
			else
				rev=${rdma_core_version%.0}
			fi
		fi
		commit=v${rev}
		pre_rdma_core=0
		IBV_INST="libibverbs"
	else
		# echo "System installed with pre-rdma-core packages..."
		commit=0c0914e1e9b7a68bcebfe785b6df30500ca7d2e0
		pre_rdma_core=1
		IBV_INST=""
	fi

#
# Skip this if ./rdma-core is already setup
#
if [[ ! -a ./rdma-core ]] ; then
	#
	# if RDMA_CORE is set, then use that git repo.
	# else clone rdma-core from github.com
	#
	if [[ "x${RDMA_CORE}" != "x" ]] ; then
		echo "Cloning rdma-core from ${RDMA_CORE}..."
		git clone ${RDMA_CORE} rdma-core >/dev/null 2>&1 || echo "git clone failed"
	else
		echo "Cloning rdma-core from github..."
		git clone https://github.com/linux-rdma/rdma-core >/dev/null 2>&1 || echo "git clone failed"
	fi
else
	(
	cd rdma-core
	echo "Checking out rdma-core commit $commit..."
	if [[ $pre_rdma_core -eq 0 && "x$dist_ubuntu" != "x" ]] ; then
		git checkout -f debian/${rdma_core_version%ubuntu*} >/dev/null 2>&1 || echo "git checkout failed"
	else
		git checkout -f $commit >/dev/null 2>&1 || echo "git checkout failed"
	fi

	if [[ $pre_rdma_core -eq 1 ]] ; then
		echo "Applying pre_rdma_core patches..."
		for p in ../patches/*support.patch ; do
			patch -sN -p1 < $p
		done
	else
		if [[ $commit = "v14" ]]||[[ $commit = "v13" ]] ; then
			patch -sN -p1 < ../patches/fix_static_build.patch || echo
		fi
	fi
		
	patch -sN -p1 < ../patches/fix_maybe_uninitialized_warning_cmake.patch || echo

	)

	if [[ "x${IBV_VERS}" == "x" ]] ; then
		IBV_VERS=$(grep "set(IBVERBS_PABI_VERSION " ./rdma-core/CMakeLists.txt 2>/dev/null |awk '{print $2}'|tr -d '")')
		if [[ "x${IBV_VERS}" == "x" ]] ; then
			IBV_VERS=2
		fi
		PKG_VERS=$(grep "set(PACKAGE_VERSION " ./rdma-core/CMakeLists.txt 2>/dev/null |awk '{print $2}'|tr -d '")')
		if [[ "x${PKG_VERS}" == "x" ]] ; then
		        PKG_VERS=2
		fi
	fi

	echo ${IBV_VERS} > rdma-core/IBV_VERS
	echo ${IBV_INST} > rdma-core/IBV_INST
	echo ${PKG_VERS} > rdma-core/PKG_VERS

	IBV_VERS=$(cat rdma-core/IBV_VERS)
	IBV_INST=$(cat rdma-core/IBV_INST)
	PKG_VERS=$(cat rdma-core/PKG_VERS)
fi

export IBV_VERS
export PKG_VERS
export IBV_INST
make $*
