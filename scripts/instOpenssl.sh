#! /bin/bash

PWD=$(pwd)
UNAME_R=$(uname -r)
ARCH=$(uname -m)
supportedDist="RHEL7.3 RHEL7.4 RHEL7.5 RHEL7.6 RHEL7.7 RHEL7.8 RHEL7.9 RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 SLES12sp3 SLES12sp4 SLES15 SLES15sp1"
kdist=$1
sslrpmdir=${PWD}/src/ssl-rpms
dfsslrpmdir=${PWD}/src/ssl-rpms/distro
ssl_ver=""
#[[ ${ARCH} == "aarch64" ]] && ssl_ver="a"
RHEL80_OSSL="openssl-libs-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm  openssl-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm  openssl-devel-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm"
RHEL81_OSSL="openssl-libs-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm"
RHEL82_OSSL="openssl-libs-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm"
RHEL83_OSSL="openssl-libs-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm"
RHEL79_OSSL="openssl-libs-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-devel-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm"
RHEL78_OSSL="openssl-libs-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-devel-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm"
RHEL77_OSSL="openssl-libs-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm openssl-devel-1.0.2k-19.el7${ssl_ver}.${ARCH}.rpm"
RHEL76_OSSL="openssl-libs-1.0.2k-16.el7${ssl_ver}.${ARCH}.rpm openssl-1.0.2k-16.el7${ssl_ver}.${ARCH}.rpm openssl-devel-1.0.2k-16.el7${ssl_ver}.${ARCH}.rpm"
RHEL75_OSSL="openssl-libs-1.0.2k-12.el7${ssl_ver}.${ARCH}.rpm openssl-1.0.2k-12.el7${ssl_ver}.${ARCH}.rpm openssl-devel-1.0.2k-12.el7${ssl_ver}.${ARCH}.rpm"
RHEL74_OSSL="openssl-libs-1.0.2k-8.el7.${ARCH}.rpm openssl-1.0.2k-8.el7.${ARCH}.rpm openssl-devel-1.0.2k-8.el7.${ARCH}.rpm"
RHEL73_OSSL="openssl-libs-1.0.1e-60.el7.${ARCH}.rpm openssl-1.0.1e-60.el7.${ARCH}.rpm openssl-devel-1.0.1e-60.el7.${ARCH}.rpm"
SLES123_OSSL="libopenssl1_0_0-1.0.2j-59.1.${ARCH}.rpm openssl-1.0.2j-59.1.${ARCH}.rpm libopenssl-devel-1.0.2j-59.1.${ARCH}.rpm libopenssl1_0_0-hmac-1.0.2j-59.1.${ARCH}.rpm"
SLES124_OSSL="libopenssl1_0_0-1.0.2p-2.11.${ARCH}.rpm openssl-1_0_0-1.0.2p-2.11.${ARCH}.rpm libopenssl-1_0_0-devel-1.0.2p-2.11.${ARCH}.rpm libopenssl1_0_0-hmac-1.0.2p-2.11.${ARCH}.rpm"
SLES15_OSSL="libopenssl1_1-1.1.0h-2.3.${ARCH}.rpm openssl-1_1-1.1.0h-2.3.${ARCH}.rpm libopenssl-1_1-devel-1.1.0h-2.3.${ARCH}.rpm libopenssl1_1-hmac-1.1.0h-2.3.${ARCH}.rpm"
SLES151_OSSL="libopenssl1_1-1.1.0i-12.9.${ARCH}.rpm openssl-1_1-1.1.0i-12.9.${ARCH}.rpm libopenssl-1_1-devel-1.1.0i-12.9.${ARCH}.rpm"



if [[ ${kdist} == "SLES15" ]] ; then
        dfsslrpmdir+="/SLES15/${ARCH}/"
        dfsslinstrpms=${SLES15_OSSL}
elif [[ ${kdist} == "SLES15sp1" ]] ; then
        dfsslrpmdir+="/SLES15sp1/${ARCH}/"
        dfsslinstrpms=${SLES151_OSSL}
elif [[ ${kdist} == "SLES12sp4" ]] ; then
	dfsslrpmdir+="/SLES12sp4/${ARCH}/"
	dfsslinstrpms=${SLES124_OSSL}
elif [[ ${kdist} == "SLES12sp3" ]] ; then
	dfsslrpmdir+="/SLES12sp3/${ARCH}/"
	dfsslinstrpms=${SLES123_OSSL}
elif [[ ${kdist} == "RHEL8.0" ]] ; then
        dfsslrpmdir+="/RHEL8.0/${ARCH}/"
        dfsslinstrpms=${RHEL80_OSSL}
elif [[ ${kdist} == "RHEL8.1" ]] ; then
        dfsslrpmdir+="/RHEL8.1/${ARCH}/"
        dfsslinstrpms=${RHEL81_OSSL}
elif [[ ${kdist} == "RHEL8.2" ]] ; then
        dfsslrpmdir+="/RHEL8.2/${ARCH}/"
        dfsslinstrpms=${RHEL82_OSSL}
elif [[ ${kdist} == "RHEL8.3" ]] ; then
        dfsslrpmdir+="/RHEL8.3/${ARCH}/"
        dfsslinstrpms=${RHEL83_OSSL}
elif [[ ${kdist} == "RHEL7.8" ]] ; then
	dfsslrpmdir+="/RHEL7.8/${ARCH}/"
	dfsslinstrpms=${RHEL78_OSSL}
elif [[ ${kdist} == "RHEL7.9" ]] ; then
	dfsslrpmdir+="/RHEL7.9/${ARCH}/"
	dfsslinstrpms=${RHEL79_OSSL}
elif [[ ${kdist} == "RHEL7.7" ]] ; then
	dfsslrpmdir+="/RHEL7.7/${ARCH}/"
	dfsslinstrpms=${RHEL77_OSSL}
elif [[ ${kdist} == "RHEL7.6" ]] ; then
	dfsslrpmdir+="/RHEL7.6/${ARCH}/"
	dfsslinstrpms=${RHEL76_OSSL}
elif [[ ${kdist} == "RHEL7.5" ]] ; then
	dfsslrpmdir+="/RHEL7.5/${ARCH}/"
	dfsslinstrpms=${RHEL75_OSSL}
elif [[ ${kdist} == "RHEL7.4" ]] ; then
	dfsslrpmdir+="/RHEL7.4/${ARCH}/"
	dfsslinstrpms=${RHEL74_OSSL}
else
	dfsslrpmdir+="/RHEL7.3/${ARCH}/"
	dfsslinstrpms=${RHEL73_OSSL}
fi



function inst_ssllibs
{
	#echo -en "Restoring inbox openssl :  "
        ( cd ${dfsslrpmdir} ; 
		for dfsslrpm in $dfsslinstrpms ; do
			if [[ $dfsslrpm == "libopenssl-1_1-devel-1.1.0h-2.3.x86_64.rpm" ]] || [[ $dfsslrpm == "libopenssl-1_0_0-devel-1.0.2p-2.11.x86_64.rpm" ]] || [[ $dfsslrpm == "libopenssl-1_1-devel-1.1.0i-12.9.x86_64.rpm" ]]; then
				dfsslp=`echo $dfsslrpm | cut -d- -f-3`
			else
				dfsslp=`echo $dfsslrpm | cut -d- -f-2`
			fi
			if [[ ${kdist} == "RHEL8.0" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1 ${dfsslrpmdir}
			fi
			if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1c ${dfsslrpmdir}
			fi
			if [[ ${kdist} == "RHEL8.3" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1g ${dfsslrpmdir}
			fi
			rpm -q $dfsslp > /dev/null 2>&1
			if [[ $? -eq 0 ]] ; then
				rpm -e $dfsslp --nodeps --allmatches
			fi
			if [[ ${kdist} == "RHEL8.0" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1 ]] ; then
					cp ${dfsslrpmdir}/libcrypto.so.1.1.1 /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1  /usr/lib64/libcrypto.so.1.1 > /dev/null 2>&1
				fi	
			fi
			if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1c ]] ; then
					cp ${dfsslrpmdir}/libcrypto.so.1.1.1c /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1c  /usr/lib64/libcrypto.so.1.1 > /dev/null 2>&1
				fi	
			fi
			if [[ ${kdist} == "RHEL8.3" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1g ]] ; then
					cp ${dfsslrpmdir}/libcrypto.so.1.1.1g /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1g  /usr/lib64/libcrypto.so.1.1
				fi
			fi
			rpm -ivh $dfsslrpm --force > /dev/null 2>&1;
		done ) 
	#echo -en "Done"
}

inst_ssllibs
