#!/bin/bash

PWD=$(pwd)
PKGNAME=chelsio
CHVERSION=$(pwd | awk -F "ChelsioUwire-" '{print $2}' | awk -F "-" '{print $1}' )
DKMS_PREP=${PWD}/dkms
DKMS_DIR=${DKMS_PREP}/${PKGNAME}-${CHVERSION}
CHSRCDIR=${PWD}/build/src/network/
cplist="bonding cudbg_inc cxgb4 include Makefile t4_tom toecore"
usrc="/usr/src"
OLDVER=$(dkms status | grep -i chelsio | awk -F ", " '{print $2}' | tail -1 )
instch=0
insttls=0
uninstch=0
args=("$@")
argslen=${#args[@]}

function uninstall
{
	echo
	echo "Uninstalling Chelsio drivers present in the machine"
	make uninstall &> /dev/null
	# Check for old dkms package
	if [ -e "/var/lib/dkms/$PKGNAME/$OLDVER" ]; then
		echo "Removing old $PKGNAME-$OLDVER DKMS files"
		dkms remove -m $PKGNAME -v $OLDVER --all
		[ -d "$usrc/${PKGNAME}-${OLDVER}" ] && rm -rf $usrc/${PKGNAME}-${OLDVER}
	fi

}

function install
{
	# Prepare Uwire package and create src bundle
	make distclean # Comment if any local changes
	make prep

	if [ -d "$DKMS_DIR" ] ; then
		rm -rf $DKMS_DIR
	fi

	mkdir -p $DKMS_DIR

	# Copy specified products to dkms bundle - TODO : Add specific product support
	for p in $cplist ; do 
		cp -rf  $CHSRCDIR/$p $DKMS_DIR/
	done
	sed -i s"|PACKAGE_VERSION=.*|PACKAGE_VERSION=\"$CHVERSION\"|"g ${PWD}/chelsio-dkms.conf
	cp -f ${PWD}/chelsio-dkms.conf $DKMS_DIR/dkms.conf

	# check firmware
	#dpkg -s chelsio-series4-firmware &> /dev/null;
	#if [ $? -ne 0 ]; then
		echo 
		echo "Installing Chelsio Firmware"
		make -C ${PWD}/debrules firmware CONF=UNIFIED_WIRE VERSION=${CHVERSION}
		echo
		dpkg --force overwrite -i ${PWD}/debrules/debinaries/chelsio-series4-firmware-${CHVERSION}* ; echo
	#fi

	# Install chelsio tools
	make tools_install

	# copy dkms bundle to /usr/src
	cp -rf $DKMS_DIR $usrc/

	dkms add -m $PKGNAME -v $CHVERSION

	dkms install -m $PKGNAME -v $CHVERSION

	# Install tls crypto
	[[ $insttls -eq 1 ]] && make crypto_install
}

function checkDKMS
{
	which dkms &> /dev/null || \
		apt-get install dkms || \
		( echo "Unable to locate/install dkms, Please install dkms using \"apt-get install dkms\" and restart the installation" ; \
		exit 1 )
}


function chelp
{
	echo 
	echo "Chelsio DKMS script for Uwire package"
	echo 
	echo "Options:"
	echo "          -i   - Installs Chelsio NIC,TOE,BONDING drivers to DKMS tree"
	echo "          -tls - Installs Chelsio openssl modules"
	echo "          -u   - Removes Chelsio drivers from DKMS tree"
	echo "          -h   - Print help"
	echo 
}

for ar in ${args[*]} ; do
case $ar in
-i) instch=1 
    ;;
-tls) insttls=1
    ;;
-u) uninstch=1
    ;;
-h) chelp
    exit 0
    ;;
*) [ $argslen -gt 0 ] && echo "Invalid Argument." ;
   chelp
   exit 1
   ;;
esac
done

if [ $instch -eq 1 ] && [ $uninstch -eq 1 ] ; then
	echo "Please select only one option"
	exit 1
fi

checkDKMS

[ $uninstch -eq 1 ] && uninstall

if [ $instch -eq 1 ] ; then
	echo
	echo "*************************************************"
	echo "Preparing to install Chelsio drivers to DKMS tree"
	echo "*************************************************"
	echo
	echo "Cleaning up before starting the installation"
	uninstall
	install
fi
