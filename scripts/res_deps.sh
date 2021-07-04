#! /bin/bash

PWD=$(pwd)
spdkSrc=${PWD}/src/chspdk/user/spdk
rpmdir=${PWD}/support
sslconf="/etc/pki/tls/openssl.cnf"
BUILDBINARIES="make patch"
BB_RPM="make patch"
BB_DEB="make patch"
if [[ $lib_support -eq 1 ]] || [[ $ISCSI_INIT -eq 1 ]] || [[ $CRYPTO_SSL -eq 1 ]] || [[ $DPDK_DEP -eq 1 ]]; then
	BUILDBINARIES=$(echo "$BUILDBINARIES automake autoconf flex bison g++ killall")
	BB_RPM=$(echo "$BB_RPM automake autoconf flex bison gcc-c++ psmisc")
	BB_DEB=$(echo "$BB_DEB automake autoconf flex bison g++ psmisc")
fi
if [[ $lib_support -eq 1 ]] ; then
        BUILDBINARIES=$(echo "$BUILDBINARIES libtool cmake git")
	if [[ ${KDIST} == "SLES12sp3" ]] || [[ ${KDIST} == "SLES12sp4" ]] || [[ ${KDIST} == "SLES15" ]] || [[ ${KDIST} == "SLES15sp1" ]]; then
		BB_RPM=$(echo "$BB_RPM libtool cmake git-core")
	else
		BB_RPM=$(echo "$BB_RPM libtool cmake git")
	fi
	if [[ ${KDIST} == "ubuntu-14.04.4" ]] ; then
		BB_DEB=$(echo "$BB_DEB libtool cmake git")
	else
		BB_DEB=$(echo "$BB_DEB libtool-bin cmake git")
	fi
fi
BB_RPM_INST=""
BB_DEB_INST=""
BB_DEPS=""
SSL_H="/usr/include/openssl/evp.h"
SSL_F=0
SSL_P=""
logfile="depsinstall.log"
chspdk_logfile="chspdk_depsinstall.log"
echo > $logfile
touch $logfile
#GREEN='\033[0;32m'
#WARNING='\033[93m'
#FAIL='\033[91m'
#RESET='\033[0m'
#
ARCH=`uname -m`

GREEN=''
WARNING=''
FAIL=''
RESET=''

if [[ $DEB -eq 1 ]] ; then
	apt-get update > /dev/null 2>&1
	UPDTR="apt-get"
	RINST="install --reinstall"
	PBIN="dpkg -s"

	sslconf="/usr/lib/ssl/openssl.cnf"
	cp -f ${sslconf} ${rpmdir}/openssl.cnf.ch

	if [[  $ISCSI_INIT -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES iscsiadm")
		BB_DEB=$(echo "$BB_DEB open-iscsi")
	fi
	if [[ $lib_support -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES yacc pkg-config")
		BB_DEB=$(echo "$BB_DEB byacc pkg-config")

		distver=$(cat /etc/os-release  | grep VERSION_ID | head -1 | awk -F "=" '{print $2}' | awk -F "\"" '{print $2}' | awk -F "." '{print $1}' | tr '[:upper:]' '[:lower:]')		

		if [[ $rdma_support -eq 1 ]]; then
			#if [[ ${KDIST} == "ubuntu-18.04.1" ]] || [[ ${KDIST} == "ubuntu-18.04.2" ]]; then
			if [[ -f /usr/bin/dpkg ]] && [[ $distver -gt 17 ]] ; then
				if [[ ! -f /usr/lib64/libibverbs.so ]] ; then
					BB_DEPS+=" rdma-core  libibverbs1 librdmacm1 librdmacm-dev libibverbs-dev ibverbs-utils rdmacm-utils"
				fi
			fi
			#if [[ ${KDIST} == "ubuntu-16.04" ]] || [[ ${KDIST} == "ubuntu-16.04.4" ]] || [[ ${KDIST} == "ubuntu-16.04.5" ]]; then
			if [[ -f /usr/bin/dpkg ]] && [[ $distver -eq  16 ]]  ; then
				if [[ ! -f /usr/lib/libibverbs.so ]] ; then
					BB_DEPS+=" libibverbs1 librdmacm1 libibverbs-dev librdmacm-dev ibverbs-utils rdmacm-utils"
				fi
			fi
		fi
	fi
	BB_DEPS+=" python"
	if [[ $tgt_cli -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES targetcli")
		BB_DEB=$(echo "$BB_DEB targetcli-fb")
	fi
	if [[ $SRPM -ne 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES dpkg-deb")
		BB_DEB=$(echo "$BB_DEB dpkg")
	fi
	if [[ ! -f /usr/bin/unmkinitramfs ]] ; then
		cp ${rpmdir}/unmkinitramfs /usr/bin
	fi
        if [[ $CHSPDK_DEP -eq 1 ]]; then
		sudo ${spdkSrc}/scripts/pkgdep.sh >> $chspdk_logfile 2>&1 
	fi
	SSL_P="libssl-dev"
	GLC=" libc-dev"
	FF="-y"
	BB_PAC=("${BB_DEB[@]}")
	[[ $lib_support -eq 1 ]] && [[ ! -f /lib/${ARCH}-linux-gnu/libnl-3.so ]] && BB_DEPS+=" libnl-3-dev"
	[[ $lib_support -eq 1 ]] && [[ ! -f /usr/lib/${ARCH}-linux-gnu/libnl-route-3.so ]] && BB_DEPS+=" libnl-route-3-dev"
elif [[ $SLES -eq 1 ]] ; then
	UPDTR="zypper"
	RINST="install -f"
	PBIN="rpm -q"
	BB_DEPS+=" kernel-default-devel"
	if [[  $ISCSI_INIT -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES iscsiadm")
		BB_RPM=$(echo "$BB_RPM open-iscsi")
	fi
	if [[ $lib_support -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES yacc")
		BB_RPM=$(echo "$BB_RPM bison")
		if [[ $rdma_support -eq 1 ]] ; then
			if [[ ${KDIST} == "SLES12sp3" ]] || [[ ${KDIST} == "SLES12sp4" ]] || [[ ${KDIST} == "SLES15" ]] || [[ ${KDIST} == "SLES15sp1" ]]; then
				if [[ ! -f /usr/lib64/libibverbs.so ]] ; then
					BB_DEPS+=" rdma-core-devel libibverbs-utils librdmacm-utils "
				fi
			fi
		fi
	fi
	if [[ $tgt_cli -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES targetcli")
		BB_RPM=$(echo "$BB_RPM targetcli-fb")
	fi
	if [[ $SRPM -ne 1 ]] ; then
		if [[ $DRACUT -eq 1 ]] ; then
			BUILDBINARIES=$(echo "$BUILDBINARIES rpm rpmbuild dracut")
			BB_RPM=$(echo "$BB_RPM rpm rpm-build dracut")
		else
			BUILDBINARIES=$(echo "$BUILDBINARIES rpm rpmbuild")
			BB_RPM=$(echo "$BB_RPM rpm rpm-build")
		fi
	fi
	SSL_P="openssl-devel"
	GLC=" glibc-devel glibc-devel-static"
	FF="-n"
	BB_PAC=("${BB_RPM[@]}")
	[[ $IWARP_WPM -eq 1 ]] && [[ ! -f /usr/lib64/libnl-3.so ]] && [[ ! -f /usr/lib/libnl-3.so ]] && BB_DEPS+=" libnl3-devel"
	[[ ! -f $KOBJP/include/generated/utsrelease.h ]] && [[ ! -f $KOBJP/include/linux/utsrelease.h ]] && BB_DEPS+=" kernel-devel"
elif [[ $RHEL -eq 1 ]] ; then
	UPDTR="yum"
	RINST="reinstall"
	PBIN="rpm -q"
		
	cp -f ${sslconf} ${rpmdir}/openssl.cnf.ch

	if [[  $ISCSI_INIT -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES iscsiadm")
		BB_RPM=$(echo "$BB_RPM iscsi-initiator-utils")
	fi
	if [[ $lib_support -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES yacc")
		BB_RPM=$(echo "$BB_RPM byacc")

		if [[ $rdma_support -eq 1 ]] ; then
			if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]] || [[ ${KDIST} == "RHEL7.4" ]] || [[ ${KDIST} == "RHEL7.5" ]] || [[ ${KDIST} == "RHEL7.6" ]] || [[ ${KDIST} == "RHEL7.7" ]] || [[ ${KDIST} == "RHEL7.8" ]] || [[ ${KDIST} == "RHEL7.9" ]]; then
				if [[ ! -f /usr/lib64/libibverbs.so ]] ; then
					BB_DEPS+=" rdma-core-devel libibverbs-utils librdmacm-utils libibumad libibumad-devel"
				fi
			fi
		fi

		if  [[ ${KDIST} == "RHEL7.7" ]] || [[ ${KDIST} == "RHEL7.8" ]] || [[ ${KDIST} == "RHEL7.9" ]]; then
			#BB_DEPS+=" libnl3-devel"
			rpm -q libnl3-devel > /dev/null 2>&1
			if [[ $? -ne 0 ]] ; then
				rpm -ivh ${rpmdir}/libnl3-devel-3.2.28-4.el7.x86_64.rpm  --force --nodeps >> $logfile 2>&1
			fi
		fi
		if  [[ ${KDIST} == "RHEL7.6" ]]; then
			if [[ $(cat /etc/os-release  | grep -ic cent) -gt 0 ]] ; then
				BB_DEPS+=" libnl3-devel"
			fi
		fi
	fi
	if [[ $tgt_cli -eq 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES targetcli")
		BB_RPM=$(echo "$BB_RPM targetcli")
	fi
	if [[ $SRPM -ne 1 ]] ; then
		BUILDBINARIES=$(echo "$BUILDBINARIES rpm rpmbuild dracut")
		BB_RPM=$(echo "$BB_RPM rpm rpm-build dracut")
	fi

        if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]]; then
		BB_DEPS+=" perl"
		BB_DEPS+=" elfutils-libelf-devel"
		
                if [[ $(which python  &> /dev/null ; echo $?) -ne 0 ]] ; then
                        printf "The python package is required to continue installation. Please install it manually or run install-python.sh script and try again."
                        exit 1
                fi

        fi

        if [[ $CHSPDK_DEP -eq 1 ]]; then
		if [[ ${KDIST} == "RHEL7.6" ]] ||  [[ ${KDIST} == "RHEL7.7" ]] || [[ ${KDIST} == "RHEL7.8" ]] || [[ ${KDIST} == "RHEL7.9" ]]; then
			BB_DEPS+=" libaio"
			BB_DEPS+=" libaio-devel"
			BB_DEPS+=" numactl-devel"
			BB_DEPS+=" libuuid-devel"
			BB_DEPS+=" rdma-core-devel"
			BB_DEPS+=" openssl-devel"
			BB_DEPS+=" nasm"
			sh ${spdkSrc}/scripts/pkgdep.sh >> $chspdk_logfile 2>&1
			BB_DEPS+=" CUnit-devel"
		fi
		if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]]; then
			BB_DEPS+=" libaio"
			BB_DEPS+=" libaio-devel"
			BB_DEPS+=" numactl-devel"
			BB_DEPS+=" libuuid-devel"
			BB_DEPS+=" rdma-core-devel"
			BB_DEPS+=" openssl-devel"
			rpm -q CUnit-devel > /dev/null 2>&1
			if [[ $? -ne 0 ]] ; then
				rpm -ivh ${rpmdir}/CUnit-devel-2.1.3-17.el8.x86_64.rpm  --force --nodeps >> $logfile 2>&1
			fi
			sh ${spdkSrc}/scripts/pkgdep.sh >> $chspdk_logfile 2>&1
		fi
	fi

	SSL_P="openssl-devel"
	GLC=" glibc-devel"
	FF="-y"
	BB_PAC=("${BB_RPM[@]}")

	if [[ $IWARP_WPM -eq 1 ]] ;then 
		if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]]; then
			[[ ! -f /usr/lib64/libnl-3.so ]] && [[ ! -f /usr/lib/libnl-3.so ]] && BB_DEPS+=" libnl3-devel"
		else
			[[ ! -f /usr/lib64/libnl.so ]] && [[ ! -f /usr/lib/libnl.so ]] && BB_DEPS+=" libnl-devel"
		fi
	fi	

  if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]]; then
			if [[ ${DIST} == "kernel5u10" ]] || [[ ${DIST} == "kernel5u4" ]] ; then
				BB_DEPS+=" krb5-devel"
			fi
  fi

	[[ ! -f $KOBJP/include/generated/utsrelease.h ]] && [[ ! -f $KOBJP/include/linux/utsrelease.h ]] && BB_DEPS+=" kernel-devel-$(uname -r)"
else
	UPDTR="unsupported"
	UPDTR_F=$UPDTR
fi
#echo $ISCSI_INIT
if [[ $ISCSI_INIT -eq 1 ]] ; then
	if [[ ! -f /usr/include/openssl/evp.h ]] ; then
		BB_DEPS+=" ${SSL_P}"
	fi
	if [[ ! -f /usr/lib/libc.so ]] && [[ ! -f /usr/lib64/libc.so ]] && [[ ! -f /usr/lib/${ARCH}-linux-gnu/libc.so ]] ; then
		BB_DEPS+=" ${GLC}"
	fi
fi

if [[ $CRYPTO_SSL -eq 1 ]] ; then
	[[ ! -f /usr/lib64/httpd/modules/mod_ssl.so ]] && BB_DEPS+=" mod_ssl"
fi

if [[ $KERN_DEPS -eq 1 ]] || [[ $lib_support -eq 1 ]]; then
	addps=""
	if [[ $(which bc &> /dev/null ; echo $?) -ne 0 ]] ; then
		addps=" bc "
	fi
	if [[ ! -f "/usr/include/ncurses.h" ]] && [[ $KERN_DEPS -eq 1 ]]; then
		if [[ $UPDTR == "apt-get" ]] ; then
			addps+=" libncurses-dev "
		else
			addps+=" ncurses-devel "
		fi
	fi
	BB_DEPS+=${addps}
fi

function list_deps
{
	bb_c=0
	for bb in $BUILDBINARIES ; do
		if [[ $(which $bb &> /dev/null ; echo $?) -ne 0 ]] ; then
			#BB_DEPS+=" ${BB_PAC[$bb_c]}"
			count=$((bb_c+1))
			deps_bin=$(echo $BB_PAC|cut -d" " -f$count)
			BB_DEPS+=" $deps_bin"
		fi
		#echo $bb, $BB_DEPS
		((bb_c+=1))
	done
}

function chk_instPacks 
{
	# -y - yum/apt, -n - zypper
	if [[ $BB_DEPS != "" ]] ; then
		echo -n "|Installing : "
	fi
	for bb in $BB_DEPS ; do
		#echo $UPDTR $FF install ${bb} 
		echo -en "${GREEN}${bb}${RESET} "
		$PBIN ${bb} > /dev/null 2>&1 && $UPDTR $FF $RINST ${bb} >> $logfile 2>&1 || $UPDTR $FF install ${bb} >> $logfile 2>&1
		if [[ $? -ne 0 ]] ; then
			FAILDEPS+=" ${bb}"
			FD_F=1
		fi
	done
	[[ $CRYPTO_SSL -eq 1 ]] && $UPDTR $FF install perl-WWW-Curl &> /dev/null || echo -n ""
	echo
  if [[ ${KDIST} == "RHEL8.3" ]] || [[ ${KDIST} == "RHEL8.2" ]] ||  [[ ${KDIST} == "RHEL8.1" ]] || [[ ${KDIST} == "RHEL8.0" ]]; then
			if [[ ${DIST} == "kernel5u10" ]] || [[ ${DIST} == "kernel5u4" ]] ; then
				[[ ! -f /usr/include/rpc/rpc.h ]] &&  ln -s /usr/include/gssrpc/rpc.h /usr/include/rpc/
			fi
  fi
	if [[ $FD_F -eq 1 ]] ; then
		echo "|Failed to install following package(s) using ${UPDTR}:|"
		echo -en $WARNING
		echo ${FAILDEPS} | sed -e 's/^ //g' | sed -e 's/ /, /g'
		echo -en $RESET
		echo -e "\n|The above packages are required to continue installation,|"
		echo "|Please install these packages maually or configure \"${UPDTR}\" properly.|"
		exit 1
	elif [[ `echo $BB_DEPS | sed -e 's/^[[:space:]]*//'` != "" ]] ; then
		#echo /lib/modules/$(uname -r)/build/include/generated/utsrelease.h
		[[ $(echo $BB_DEPS | grep -c kernel-devel) -gt 0 ]] && \
		[[ ! -f /lib/modules/$(uname -r)/build/include/generated/utsrelease.h ]] && \
	        echo -e "|Unable to locate kernel-devel package |\n" && \
		echo "Please check and re-install kernel-devel package for your current kernel - $(uname -r)" && exit 1
		echo "|Installed all dependent packages.|"
		exit 0
	fi
}

function checkUPDTR
{
	if [[ `echo $BB_DEPS | sed -e 's/^[[:space:]]*//'` != "" ]] ; then
		if [[ $UPDTR != "unsupported" ]] ; then
			if [[ $(which $UPDTR &> /dev/null ; echo $?) -ne 0 ]] ; then
				echo "|Please install and configure \"$UPDTR\" to install dependencies or "
				echo "|install the below dependencies manually and restart the installation."
				echo -en $WARNING
				echo $BB_DEPS | sed -e 's/^ //g' | sed -e 's/ /, /g'
				echo -en $RESET
				exit 1
			fi
		else
			echo "|Unable to configure yum/zypper/apt-get."
			echo "|Please install the below dependencies and restart the installation.|"
			echo -en $WARNING
			echo $BB_DEPS | sed -e 's/^ //g' | sed -e 's/ /, /g'
			echo -en $RESET
			exit 1
		fi
	else
		exit 0
	fi
}

list_deps
if [[ $BB_DEPS != "" ]] ; then
	checkUPDTR
	chk_instPacks
fi
