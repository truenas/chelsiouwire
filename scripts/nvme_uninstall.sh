#! /bin/bash

BB_RPM_INST=""
BB_DEB_INST=""
BB_DEPS=""
SSL_F=0
SSL_P=""
logfile="nvme_install.log"
echo > $logfile
touch $logfile
#GREEN='\033[0;32m'
#WARNING='\033[93m'
#FAIL='\033[91m'
#RESET='\033[0m'
#
ARCH=`uname -m`
#RHEL=1

GREEN=''
WARNING=''
FAIL=''
RESET=''
BUILDBINARIES="nvme nvmetcli "
BUILDBINARIES_RPM="nvme-cli nvmetcli "


if [[ $SLES -eq 1 ]] ; then
	echo "SLES" >> $logfile 2>&1
        UPDTR="zypper"
        RINST="remove"
        PBIN="rpm -q"
        FF="-y"
elif [[ $RHEL -eq 1 ]] ; then
        UPDTR="yum"
        RINST="remove"
        PBIN="rpm -q"
        FF="-y"
else
        UPDTR="unsupported"
        UPDTR_F=$UPDTR
fi


function list_deps
{
	bb_c=0
	for bb in $BUILDBINARIES ; do
		if [[ $(which $bb &> /dev/null ; echo $?) -eq 0 ]] ; then
			count=$((bb_c+1))
			deps_bin=$(echo $BUILDBINARIES_RPM|cut -d" " -f$count)
			BB_DEPS+=" $deps_bin"
		fi
		echo "bb=" $bb "$BB_DEPS=" $BB_DEPS >> $logfile 2>&1
		#sleep 10
		((bb_c+=1))
	done
}

function uninstPacks 
{
	# -y - yum/apt, -n - zypper
        echo "################################################## "
        echo "#          Uninstalling NVMe-Utils                 # "
        echo "################################################## "
	echo ""
	if [[ $BB_DEPS != "" ]] ; then
		echo -n "|Uninstalling : " >> $logfile 2>&1
		echo -n "Uninstalling : $BB_DEPS"
		echo ""
		echo ""
        else
                echo -n "$BUILDBINARIES_RPM Already uninstalled. "
                echo ""
                echo ""

	fi
	for bb in $BB_DEPS ; do
		echo $UPDTR $FF uninstall ${bb} >> $logfile 2>&1
		echo -en "${GREEN}${bb}${RESET} " >> $logfile 2>&1
		$PBIN ${bb} > /dev/null 2>&1 && $UPDTR $FF $RINST ${bb} >> $logfile 2>&1 || $UPDTR $FF install ${bb} >> $logfile 2>&1
		if [[ $? -ne 0 ]] ; then
			FAILDEPS+=" ${bb}"
			FD_F=1
		fi
	done
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
		echo "|Installed all dependent packages.|" >> $logfile 2>&1
		exit 0
	fi
}

function checkUPDTR
{
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
			echo "|Unable to configure yum/zypper."
			echo "|Please install the below dependencies and restart the installation.|"
			echo -en $WARNING
			echo $BB_DEPS | sed -e 's/^ //g' | sed -e 's/ /, /g'
			echo -en $RESET
			exit 1
		fi
}

#list_deps
#checkUPDTR
#uninstPacks
