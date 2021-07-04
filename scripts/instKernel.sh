#! /bin/bash

PWD=$(pwd)
srcDir=${PWD}/kernels
pkver="5.4.105"
UNAME_R=$(uname -r)
ARCH=$(uname -m)
kernelDir=${srcDir}/kernel-${pkver}/
tgtkdir=/usr/src/linux-${pkver}-chelsio
supportedDist="RHEL7.3 RHEL7.4 RHEL7.5 RHEL7.6 RHEL7.7 RHEL7.8 RHEL7.9 RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 SLES12sp3 SLES12sp4 SLES15 SLES15sp1"
kdist=$1
wconf=$2
ssl=0
kernel_reboot=0
sslconf="/etc/pki/tls/openssl.cnf"
modsslconf="/etc/httpd/conf.d/ssl.conf"
supportdir=${PWD}/support
sslrpmdir=${PWD}/src/ssl-rpms
chsslrpmdir=${PWD}/src/ssl-rpms/chelsio
dfsslrpmdir=${PWD}/src/ssl-rpms/distro
depsdir=${PWD}/src/ssl-rpms/deps-rpms
centos=0
centstr=""
base73=`uname -r | grep -c ^3"\."10"\."0-514`
base74=`uname -r | grep -c ^3"\."10"\."0-693`
base75=`uname -r | grep -c ^3"\."10"\."0-862`
base76=`uname -r | grep -c ^3"\."10"\."0-957`
base76_arm=`uname -r | grep -c ^4"\."14"\."0-115`
base77=`uname -r | grep -c ^3"\."10"\."0-1062`
base78=`uname -r | grep -c ^3"\."10"\."0-1127`
base79=`uname -r | grep -c ^3"\."10"\."0-1160`
base80=`uname -r | grep -c ^4"\."18"\."0-80`
base81=`uname -r | grep -c ^4"\."18"\."0-147`
base82=`uname -r | grep -c ^4"\."18"\."0-193`
base83=`uname -r | grep -c ^4"\."18"\."0-240`
af_algver="3.14.0.3"
af_algrel="0"
ssl_ver=""
[[ ${ARCH} == "aarch64" ]] && ssl_ver="a"
RHEL80_OSSL="openssl-libs-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm  openssl-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm  openssl-devel-1.1.1-8.el8${ssl_ver}.${ARCH}.rpm"
RHEL81_OSSL="openssl-libs-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1c-2.el8${ssl_ver}.${ARCH}.rpm"
RHEL83_OSSL="openssl-libs-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1g-11.el8${ssl_ver}.${ARCH}.rpm"
RHEL82_OSSL="openssl-libs-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm openssl-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm openssl-devel-1.1.1c-15.el8${ssl_ver}.${ARCH}.rpm"
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

chafalgrpms=af_alg-${af_algver}-${af_algrel}.${ARCH}

if  echo ${kdist} | grep -i "ubuntu"  ; then
	echo ""
else
	opensslver=$(rpm -qa | grep ^openssl-1 | cut -d- -f2,3)
fi

GREEN='\033[0;32m'
WARNING='\033[93m'
FAIL='\033[91m'
RESET='\033[0m'

cpu_count=$(getconf _NPROCESSORS_ONLN)

#CRYPTOKPARAMS=("CONFIG_XFRM_USER=y CONFIG_NET_KEY=y CONFIG_INET=y CONFIG_IP_ADVANCED_ROUTER=y CONFIG_IP_MULTIPLE_TABLES=y CONFIG_INET_AH=y CONFIG_INET_ESP=y CONFIG_INET_IPCOMP=y CONFIG_INET_XFRM_MODE_TRANSPORT=y CONFIG_INET_XFRM_MODE_TUNNEL=y CONFIG_INET_XFRM_MODE_BEET=y CONFIG_IPV6=y CONFIG_INET6_AH=y CONFIG_INET6_ESP=y CONFIG_INET6_IPCOMP=y CONFIG_INET6_XFRM_MODE_TRANSPORT=y CONFIG_INET6_XFRM_MODE_TUNNEL=y CONFIG_INET6_XFRM_MODE_BEET=y CONFIG_IPV6_MULTIPLE_TABLES=y CONFIG_NETFILTER=y CONFIG_NETFILTER_XTABLES=y CONFIG_NETFILTER_XT_MATCH_POLICY=y")
#CRYPTOKPARAMS=("CONFIG_CRYPTO_USER_API_AEAD=y CONFIG_XFRM_USER=y CONFIG_NET_KEY=y CONFIG_INET=y CONFIG_IP_ADVANCED_ROUTER=y CONFIG_IP_MULTIPLE_TABLES=y CONFIG_INET_AH=y CONFIG_INET_ESP=y CONFIG_INET_IPCOMP=y CONFIG_INET_XFRM_MODE_TRANSPORT=y CONFIG_INET_XFRM_MODE_TUNNEL=y CONFIG_INET_XFRM_MODE_BEET=y CONFIG_IPV6=y CONFIG_INET6_AH=y CONFIG_INET6_ESP=y CONFIG_INET6_IPCOMP=y CONFIG_INET6_XFRM_MODE_TRANSPORT=y CONFIG_INET6_XFRM_MODE_TUNNEL=y CONFIG_INET6_XFRM_MODE_BEET=y CONFIG_IPV6_MULTIPLE_TABLES=y CONFIG_NETFILTER=y CONFIG_NETFILTER_XTABLES=y CONFIG_NETFILTER_XT_MATCH_POLICY=y CONFIG_CRYPTO_USER_API_HASH=y CONFIG_CRYPTO_USER_API_SKCIPHER=y CONFIG_CRYPTO_USER_API_RNG=y")

CRYPTOKPARAMS=("CONFIG_KEYS=y CONFIG_KEYS_DEBUG_PROC_KEYS=y CONFIG_SECURITY=y CONFIG_SECURITY_NETWORK=y CONFIG_SECURITY_NETWORK_XFRM=y CONFIG_LSM_MMAP_MIN_ADDR=65536 CONFIG_SECURITY_SELINUX=y CONFIG_SECURITY_SELINUX_BOOTPARAM=y CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1 CONFIG_SECURITY_SELINUX_DISABLE=y CONFIG_SECURITY_SELINUX_DEVELOP=y CONFIG_SECURITY_SELINUX_AVC_STATS=y CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=1 CONFIG_DEFAULT_SECURITY_SELINUX=y CONFIG_DEFAULT_SECURITY="selinux" CONFIG_CRYPTO=y CONFIG_CRYPTO_FIPS=y CONFIG_CRYPTO_ALGAPI=y CONFIG_CRYPTO_ALGAPI2=y CONFIG_CRYPTO_AEAD=y CONFIG_CRYPTO_AEAD2=y CONFIG_CRYPTO_BLKCIPHER=y CONFIG_CRYPTO_BLKCIPHER2=y CONFIG_CRYPTO_HASH=y CONFIG_CRYPTO_HASH2=y CONFIG_CRYPTO_RNG=y CONFIG_CRYPTO_RNG2=y CONFIG_CRYPTO_PCOMP=y CONFIG_CRYPTO_PCOMP2=y CONFIG_CRYPTO_MANAGER=y CONFIG_CRYPTO_MANAGER2=y CONFIG_CRYPTO_NULL=y CONFIG_CRYPTO_WORKQUEUE=y CONFIG_CRYPTO_TEST=m CONFIG_CRYPTO_GCM=y CONFIG_CRYPTO_SEQIV=y CONFIG_CRYPTO_CBC=y CONFIG_CRYPTO_CTR=y CONFIG_CRYPTO_ECB=y CONFIG_CRYPTO_HMAC=y CONFIG_CRYPTO_GHASH=y CONFIG_CRYPTO_MD4=m CONFIG_CRYPTO_MD5=y CONFIG_CRYPTO_SHA1=y CONFIG_CRYPTO_SHA256=y CONFIG_CRYPTO_AES=y CONFIG_CRYPTO_AES_X86_64=y CONFIG_CRYPTO_ZLIB=y CONFIG_CRYPTO_LZO=y CONFIG_CRYPTO_USER_API=y CONFIG_CRYPTO_USER_API_HASH=y CONFIG_CRYPTO_USER_API_SKCIPHER=y CONFIG_CRYPTO_HW=y CONFIG_CRYPTO_USER_API_AEAD=m CONFIG_CRYPTO_CRYPTD=y CONFIG_CRYPTO_MCRYPTD=y CONFIG_CRYPTO_AUTHENC=y CONFIG_CRYPTO_CCM=y CONFIG_CRYPTO_CTS=y CONFIG_CRYPTO_XTS=y CONFIG_CRYPTO_SHA512=y CONFIG_CRYPTO_DEFLATE=y CONFIG_CRYPTO_ANSI_CPRNG=y CONFIG_CRYPTO_USER_API_RNG=y")
ISERKPARAMS=("CONFIG_INFINIBAND_ISER=m CONFIG_INFINIBAND_ISERT=m")
NVMKPARAMS=("CONFIG_NVME_CORE=m CONFIG_NVME_FABRICS=m CONFIG_NVME_TCP=m CONFIG_NVME_TARGET_TCP=m CONFIG_BLK_DEV_NVME=m CONFIG_NVME_RDMA=m CONFIG_NVME_TARGET=m CONFIG_NVME_TARGET_RDMA=m CONFIG_NVME_RDMA=m CONFIG_BLK_DEV_NULL_BLK=m CONFIG_CONFIGFS_FS=y")
LIOKPARAMS=("CONFIG_TARGET_CORE=m CONFIG_ISCSI_TARGET=m CONFIG_CONFIGFS_FS=m CONFIG_CRYPTO_CRC32C_INTEL=m CONFIG_CRYPTO_CRCT10DIF=m CONFIG_CRC_T10DIF=m")
ARMPARAMS=("CONFIG_CHELSIO_T1=m CONFIG_CHELSIO_T1_1G=y CONFIG_CHELSIO_T3=m CONFIG_CHELSIO_T4=m CONFIG_CHELSIO_T4VF=m CONFIG_INFINIBAND_USER_MAD=m CONFIG_INFINIBAND_USER_ACCESS=m CONFIG_INFINIBAND_USER_MEM=y CONFIG_INFINIBAND_CXGB3=m CONFIG_INFINIBAND_CXGB3_DEBUG=y CONFIG_INFINIBAND_CXGB4=m CONFIG_SCSI_CXGB3_ISCSI=m CONFIG_SCSI_CXGB4_ISCSI=m")
OVSPARAMS=("CONFIG_CMA=y CONFIG_NF_TABLES=m CONFIG_NF_TABLES_INET=m CONFIG_NET_UDP_TUNNEL=m CONFIG_NF_NAT=m CONFIG_NF_NAT_IPV4=m CONFIG_NF_NAT_IPV6=m CONFIG_NF_NAT_PROTO_GRE=m CONFIG_NF_CONNTRACK=m CONFIG_NF_DEFRAG_IPV6=m CONFIG_LIBCRC32C=m CONFIG_NF_DEFRAG_IPV4=m CONFIG_OPENVSWITCH=m CONFIG_OPENVSWITCH_GRE=m CONFIG_OPENVSWITCH_VXLAN=m CONFIG_OPENVSWITCH_GENEVE=m CONFIG_IPV6_GRE=m CONFIG_NET_IPGRE=m CONFIG_NF_CT_PROTO_GRE=m")

distro=${kdist}
for distn in $supportedDist ; do
        if [[ "$distn" =~ "$distro" ]] ; then
                ssl=1
                break
        else
                ssl=0
        fi
done

if [ $(cat /etc/os-release  | grep -ic cent) -gt 0 ] ; then
	centos=1
	centstr=".centos"
else
	centos=0
fi

if [[ ${kdist} == "SLES15" ]] ; then
        chsslrpmdir+="/SLES15/${ARCH}/"
        dfsslrpmdir+="/SLES15/${ARCH}/"
        sslconf="/etc/ssl/openssl.cnf"
        modsslconf="/etc/apache2/vhosts.d/vhost-ssl.conf"
        chsslinstrpms=${SLES15_OSSL}
        dfsslinstrpms=${SLES15_OSSL}
        depsdir=${depsdir}/SLES15
        #modsslrpm=apache2-mod_nss-1.0.17-1.28.${ARCH}.rpm
        pkgmgr="zypper"
        packs="zlib-devel libelf-devel xz-devel keyutils-devel libcom_err-devel libsepol-devel libverto-devel libpcrecpp0 libpcreposix0 pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "SLES15sp1" ]] ; then
        chsslrpmdir+="/SLES15sp1/${ARCH}/"
        dfsslrpmdir+="/SLES15sp1/${ARCH}/"
        sslconf="/etc/ssl/openssl.cnf"
        modsslconf="/etc/apache2/vhosts.d/vhost-ssl.conf"
        chsslinstrpms=${SLES151_OSSL}
        dfsslinstrpms=${SLES151_OSSL}
        depsdir=${depsdir}/SLES15sp1
        #modsslrpm=apache2-mod_nss-1.0.14-19.3.1.${ARCH}.rpm
        pkgmgr="zypper"
        packs="zlib-devel libelf-devel xz-devel keyutils-devel libcom_err-devel libsepol-devel libverto-devel libpcrecpp0 libpcreposix0 pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "SLES12sp4" ]] ; then
	chsslrpmdir+="/SLES12sp4/${ARCH}/"
	dfsslrpmdir+="/SLES12sp4/${ARCH}/"
	sslconf="/etc/ssl/openssl.cnf"
	modsslconf="/etc/apache2/vhosts.d/vhost-ssl.conf"
	chsslinstrpms="${SLES124_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${SLES124_OSSL}
	depsdir=${depsdir}/SLES12sp4
	#modsslrpm=apache2-mod_nss-1.0.14-19.3.1.${ARCH}.rpm
	pkgmgr="zypper"
        packs="zlib-devel libelf-devel xz-devel keyutils-devel libcom_err-devel libsepol-devel libverto-devel libpcrecpp0 libpcreposix0 pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "SLES12sp3" ]] ; then
	chsslrpmdir+="/SLES12sp3/${ARCH}/"
	dfsslrpmdir+="/SLES12sp3/${ARCH}/"
	sslconf="/etc/ssl/openssl.cnf"
	modsslconf="/etc/apache2/vhosts.d/vhost-ssl.conf"
	chsslinstrpms="${SLES123_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${SLES123_OSSL}
	depsdir=${depsdir}/SLES12sp3
	#modsslrpm=apache2-mod_nss-1.0.14-18.3.${ARCH}.rpm
	pkgmgr="zypper"
        packs="zlib-devel libelf-devel xz-devel keyutils-devel libcom_err-devel libsepol-devel libverto-devel libpcrecpp0 libpcreposix0 pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL8.0" ]] ; then
        chsslrpmdir+="/RHEL8.0/${ARCH}/"
        dfsslrpmdir+="/RHEL8.0/${ARCH}/"
        chsslinstrpms=${RHEL80_OSSL}
        dfsslinstrpms=${RHEL80_OSSL}
        depsdir=${depsdir}/RHEL8.0
        #modsslrpm="mod_ssl-2.4.37-10.el8${centstr}.${ARCH}.rpm"
        modsslrpm="mod_ssl-2.4.37-10.module+el8+2764+7127e69e${centstr}.${ARCH}.rpm"
        pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL8.1" ]] ; then
        chsslrpmdir+="/RHEL8.1/${ARCH}/"
        dfsslrpmdir+="/RHEL8.1/${ARCH}/"
        chsslinstrpms=${RHEL81_OSSL}
        dfsslinstrpms=${RHEL81_OSSL}
        depsdir=${depsdir}/RHEL8.1
        #modsslrpm="mod_ssl-2.4.37-16.el8${centstr}.${ARCH}.rpm"
        modsslrpm="mod_ssl-2.4.37-16.module+el8.1.0+4134+e6bad0ed${centstr}.${ARCH}.rpm"
        pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL8.2" ]] ; then
        chsslrpmdir+="/RHEL8.2/${ARCH}/"
        dfsslrpmdir+="/RHEL8.2/${ARCH}/"
        chsslinstrpms=${RHEL82_OSSL}
        dfsslinstrpms=${RHEL82_OSSL}
        depsdir=${depsdir}/RHEL8.2
        #modsslrpm="mod_ssl-2.4.37-16.el8${centstr}.${ARCH}.rpm"
        modsslrpm="mod_ssl-2.4.37-21.module+el8.2.0+5008+cca404a3${centstr}.${ARCH}.rpm"
        pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL8.3" ]] ; then
        chsslrpmdir+="/RHEL8.3/${ARCH}/"
        dfsslrpmdir+="/RHEL8.3/${ARCH}/"
        chsslinstrpms=${RHEL83_OSSL}
        dfsslinstrpms=${RHEL83_OSSL}
        depsdir=${depsdir}/RHEL8.3
        #modsslrpm="mod_ssl-2.4.37-16.el8${centstr}.${ARCH}.rpm"
        modsslrpm="mod_ssl-2.4.37-30.module+el8.3.0+7001+0766b9e7${centstr}.${ARCH}.rpm"
        pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.9" ]] ; then
        chsslrpmdir+="/RHEL7.9/${ARCH}/"
        dfsslrpmdir+="/RHEL7.9/${ARCH}/"
        chsslinstrpms="${RHEL79_OSSL} ${chafalgrpms}.rpm"
        dfsslinstrpms=${RHEL79_OSSL}
        depsdir=${depsdir}/RHEL7.9
        modsslrpm="mod_ssl-2.4.6-95.el7${centstr}.${ARCH}.rpm"
        pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.8" ]] ; then
	chsslrpmdir+="/RHEL7.8/${ARCH}/"
	dfsslrpmdir+="/RHEL7.8/${ARCH}/"
	chsslinstrpms="${RHEL78_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL78_OSSL}
	depsdir=${depsdir}/RHEL7.8
	modsslrpm="mod_ssl-2.4.6-93.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.7" ]] ; then
	chsslrpmdir+="/RHEL7.7/${ARCH}/"
	dfsslrpmdir+="/RHEL7.7/${ARCH}/"
	chsslinstrpms="${RHEL77_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL77_OSSL}
	depsdir=${depsdir}/RHEL7.7
	modsslrpm="mod_ssl-2.4.6-90.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.6" ]] ; then
	chsslrpmdir+="/RHEL7.6/${ARCH}/"
	dfsslrpmdir+="/RHEL7.6/${ARCH}/"
	chsslinstrpms="${RHEL76_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL76_OSSL}
	depsdir=${depsdir}/RHEL7.6
	modsslrpm="mod_ssl-2.4.6-88.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.5" ]] ; then
	chsslrpmdir+="/RHEL7.5/${ARCH}/"
	dfsslrpmdir+="/RHEL7.5/${ARCH}/"
	chsslinstrpms="${RHEL75_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL75_OSSL}
	depsdir=${depsdir}/RHEL7.5
	modsslrpm="mod_ssl-2.4.6-80.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
elif [[ ${kdist} == "RHEL7.4" ]] ; then
	chsslrpmdir+="/RHEL7.4/${ARCH}/"
	dfsslrpmdir+="/RHEL7.4/${ARCH}/"
	chsslinstrpms="${RHEL74_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL74_OSSL}
	depsdir=${depsdir}/RHEL7.4
	modsslrpm="mod_ssl-2.4.6-67.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
else
	chsslrpmdir+="/RHEL7.3/${ARCH}/"
	dfsslrpmdir+="/RHEL7.3/${ARCH}/"
	chsslinstrpms="${RHEL73_OSSL} ${chafalgrpms}.rpm"
	dfsslinstrpms=${RHEL73_OSSL}
	depsdir=${depsdir}/RHEL7.3
	modsslrpm="mod_ssl-2.4.6-45.el7${centstr}.${ARCH}.rpm"
	pkgmgr="yum"
        packs="zlib-devel elfutils-libelf-devel xz-devel elfutils-devel keyutils-libs-devel libcom_err-devel libsepol-devel libverto-devel pcre-devel libselinux-devel krb5-devel"
fi
chmodsslconf=${modsslconf}.ch
	
if [[ ${kdist} == "RHEL7.6" ]] ||  [[ ${kdist} == "RHEL7.7" ]] || [[ ${kdist} == "RHEL7.8" ]] || [[ ${kdist} == "RHEL7.9" ]]; then
	rhel7=1
fi

if [[ ${kdist} == "RHEL8.3" ]] || [[ ${kdist} == "RHEL8.2" ]] ||  [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.0" ]]; then
	rhel8=1
fi

function print_title
{
	echo
	echo "*******************************************************"
	echo "     Installing $1"
	echo "*******************************************************"
	echo
}

function checkdependencies
{
	echo "Checking & Installing dependencies"
        for pr in $packs ; do
                rpm -q $pr;
                if [[ $? -ne 0 ]] ; then
                        ${pkgmgr} install -y $pr 2>/dev/null || rpm -ivh ${depsdir}/${pr}*
                        if [[ $? -ne 0 ]] ; then
                                echo -e "${WARNING}Failed to install dependencies, please install $pr rpm package and restart the installation.${RESET}"; \
                                exit 1
                        fi;
                fi
        done
}

function inst_ssllibs
{
        installssllibs=1
	xtfl=0
        cp -f ${supportdir}/openssl.cnf.ch  ${sslconf}.rpmsave
        cp -f ${sslconf}.rpmsave ${sslconf}.chbak
        ( cd ${chsslrpmdir} ; 
		for chsslrpm in $chsslinstrpms ; do
			if [[ $chsslrpm == "libopenssl-1_1-devel-1.1.0h-2.3.x86_64.rpm" ]] || [[ $chsslrpm == "libopenssl-1_0_0-devel-1.0.2p-2.11.x86_64.rpm" ]] || [[ $chsslrpm == "libopenssl-1_1-devel-1.1.0i-12.9.x86_64.rpm" ]]; then
				chsslp=`echo $chsslrpm | cut -d- -f-3`
			else
				chsslp=`echo $chsslrpm | cut -d- -f-2`
			fi
			if [[ ${kdist} == "RHEL8.0" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1 ${chsslrpmdir}
			fi
			if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1c ${chsslrpmdir}
			fi
			if [[ ${kdist} == "RHEL8.3" ]] ; then
				cp /usr/lib64/libcrypto.so.1.1.1g ${chsslrpmdir}
			fi
			rpm -q $chsslp
			if [[ $? -eq 0 ]] ; then
				rpm -e $chsslp --nodeps --allmatches
			fi
			if [[ ${kdist} == "RHEL8.0" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1 ]] ; then
					cp ${chsslrpmdir}/libcrypto.so.1.1.1 /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1  /usr/lib64/libcrypto.so.1.1
				fi	
			fi
			if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1c ]] ; then
					cp ${chsslrpmdir}/libcrypto.so.1.1.1c /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1c  /usr/lib64/libcrypto.so.1.1
				fi	
			fi
			if [[ ${kdist} == "RHEL8.3" ]] ; then
				if [[ ! -f /usr/lib64/libcrypto.so.1.1.1g ]] ; then
					cp ${chsslrpmdir}/libcrypto.so.1.1.1g /usr/lib64/
					ln -s  /usr/lib64/libcrypto.so.1.1.1g  /usr/lib64/libcrypto.so.1.1
				fi
			fi
			rpm -ivh $chsslrpm --force;
		done ) ; chsslstat=1
	if [[ ${kdist} != "SLES12sp3" ]] && [[ ${kdist} != "SLES12sp4" ]] && [[ ${kdist} != "SLES15" ]] && [[ ${kdist} != "SLES15sp1" ]]; then
		ct_mssltpm=$(echo ${modsslrpm} | awk -F ".rpm" '{print $1}')
		mod_ssl_rpm="mod_ssl"
		rpm -q $mod_ssl_rpm;
		if [[ $? -ne 0 ]] ; then
			# If mod_ssl rpm is not present first try installing from local copy.
			rpm -ivh ${chsslrpmdir}/${ct_mssltpm}.rpm --force --nodeps
		
			# If fails try installing from iso.
			if [[ $? -ne 0 ]] ; then
				${pkgmgr} install -y  $mod_ssl_rpm
				if [[ $? -ne 0 ]] ; then
					echo "mod_ssl installation Failed"
					echo "Please configure ${pkgmgr} and restart the installation"
					xtfl=1
				fi
			fi
			
			# Uncomment if in case needed as below part related to Apache which should be conf. by user.		 
	                #if [[ $? -eq 0 ]] ; then
			#	if [[ ${kdist} != "SLES12sp3" ]] && [[ ${kdist} != "SLES12sp4" ]] && [[ ${kdist} != "SLES15" ]] && [[ ${kdist} != "SLES15sp1" ]]; then
			#		if [ ! -f /etc/pki/tls/private/localhost.key ] ; then
			#		        echo "Key is not present in the machine";
			#		        xtfl=1
			#		fi
			#		if [ ! -f /etc/pki/tls/certs/localhost.crt ] ; then
			#			echo "Cert is not present in the machine";
			#			xtfl=1
			#		fi
			#	fi
			#fi

			if [[ $xtfl -eq 1 ]] ; then
				exit 1
			fi
		fi
	fi
	if [[ ${base73} -eq 1 ]] ; then
		install -v ${chsslrpmdir}/../openssl_73.cnf ${sslconf}
	elif [[ ${base74} -eq 1 ]] ; then
		install -v ${chsslrpmdir}/../openssl_74.cnf ${sslconf}
        elif [[ ${base80} -eq 1 ]] || [[ ${base81} -eq 1 ]] || [[ ${base82} -eq 1 ]] || [[ ${base83} -eq 1 ]] || [[ ${rhel8} -eq 1 ]] ; then
        	[[ -f ${sslconf}.rpmsave ]] && cp -f ${sslconf}.rpmsave ${sslconf}
                sed -i '/ssl_conf = ssl_module/a engines = openssl_engines\n\n[openssl_engines]\nafalg = afalg_engine\n\n[afalg_engine]\n#default_algorithms = ALL\ninit =1'  ${sslconf}
        else
        	[[ -f ${sslconf}.rpmsave ]] && cp -f ${sslconf}.rpmsave ${sslconf}
                sed -i '/oid_section/a openssl_conf = openssl_def\n\n[openssl_def]\nengines = openssl_engines\n\n[openssl_engines]\naf_alg = af_alg_engine\n\n[af_alg_engine]\nCIPHERS=aes-128-cbc aes-192-cbc aes-256-cbc\nDIGESTS=sha1 sha224 sha256 sha384 sha512' ${sslconf}		
	fi
        if [[ ${base80} -eq 1 ]] || [[ ${base81} -eq 1 ]] || [[ ${base82} -eq 1 ]] || [[ ${base83} -eq 1 ]] || [[ ${rhel8} -eq 1 ]] ; then
		rm -rf /usr/chssl/share /usr/chssl/lib/pkgconfig/libcrypto.pc /usr/chssl/lib/pkgconfig/libssl.pc /usr/chssl/openssl/ct_log_list.cnf /usr/chssl/openssl/ct_log_list.cnf.dist /usr/chssl/openssl/openssl.cnf.dist
		# Copy afalg.so from /usr/chssl/lib/engines-1.1 to /usr/lib64/engines-1.1/
                [[ ! -f  /usr/lib64/engines-1.1/afalg.so.orig ]] &&  cp /usr/lib64/engines-1.1/afalg.so /usr/lib64/engines-1.1/afalg.so.orig &&  cp /usr/chssl/lib/engines-1.1/afalg.so /usr/lib64/engines-1.1/
	fi
}

function inst_defssl
{
	#packs="openssl-libs openssl openssl-devel"
	packs=${dfsslinstrpms}
	#packs="openssl-libs-1.0.1e-60.el7 openssl-1.0.1e-60.el7  openssl-devel-1.0.1e-60.el7"	
	for pr in $packs ; do
		if [[ ${kdist} == "RHEL8.0" ]] ; then
			cp /usr/lib64/libcrypto.so.1.1.1 ${chsslrpmdir}
		fi
		if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
			cp /usr/lib64/libcrypto.so.1.1.1c ${chsslrpmdir}
		fi
		if [[ ${kdist} == "RHEL8.3" ]] ; then
			cp /usr/lib64/libcrypto.so.1.1.1g ${chsslrpmdir}
		fi
		fpkg=`echo $pr | cut -d- -f-2`
		rpm -q $fpkg
		if [[ $? -eq 0 ]] ; then
			#rpm -ivh ${dfsslrpmdir}/$pr*
		#else
			rpm -e $fpkg --nodeps --allmatches
			#rpm -ivh $fpkg
		fi
		if [[ ${kdist} == "RHEL8.0" ]] ; then
			if [[ ! -f /usr/lib64/libcrypto.so.1.1.1 ]] ; then
				cp ${chsslrpmdir}/libcrypto.so.1.1.1 /usr/lib64/
				ln -s  /usr/lib64/libcrypto.so.1.1.1  /usr/lib64/libcrypto.so.1.1
			fi	
		fi
		if [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] ; then
			if [[ ! -f /usr/lib64/libcrypto.so.1.1.1c ]] ; then
				cp ${chsslrpmdir}/libcrypto.so.1.1.1c /usr/lib64/
				ln -s  /usr/lib64/libcrypto.so.1.1.1c  /usr/lib64/libcrypto.so.1.1
			fi	
		fi
		if [[ ${kdist} == "RHEL8.3" ]] ; then
			if [[ ! -f /usr/lib64/libcrypto.so.1.1.1g ]] ; then
				cp ${chsslrpmdir}/libcrypto.so.1.1.1g /usr/lib64/
				ln -s  /usr/lib64/libcrypto.so.1.1.1g  /usr/lib64/libcrypto.so.1.1
			fi
		fi
		${pkgmgr} install -y $fpkg 2>/dev/null || rpm -ivh ${dfsslrpmdir}/${fpkg}*.${ARCH}*
	done
}

function dis_selinux
{
        if [[ $(cat /etc/selinux/config | grep ^SELINUX= | cut -d= -f2 | tr -d ' ') != "disabled" ]] ; then
                sed -i "s/^SELINUX=.*/SELINUX=disabled/g" /etc/selinux/config
                echo "Disabled SELINUX in /etc/selinux/config file."
                reboot=1
        fi;
}

function ch_sshconf
{
	[[ ! -f /etc/ssh/sshd_config.chbak ]] && cp -f /etc/ssh/sshd_config /etc/ssh/sshd_config.chbak
        if [[ $(cat /etc/ssh/sshd_config | grep ^UsePrivilegeSeparation -c) -gt 0 ]] ; then
                sed -i 's/UsePrivilegeSeparation .*/UsePrivilegeSeparation yes/g' /etc/ssh/sshd_config
                echo "Set \"UsePrivilegeSeparation yes\" in /etc/ssh/sshd_config"
                reboot=1
        else
                sed -i 's/#UsePrivilegeSeparation .*/UsePrivilegeSeparation yes/g' /etc/ssh/sshd_config
                echo "Set \"UsePrivilegeSeparation yes\" in /etc/ssh/sshd_config"
                reboot=1
        fi
}

function ch_sslConf
{
        if [[ ! -f ${modsslconf}.orig ]] ; then
                cp -f $modsslconf ${modsslconf}.orig
                echo "The original ssl config file is backed up to ${modsslconf}.orig"
        fi
        while read -r line ; do
                if [[ `echo $line | grep "^SSLCipherSuite" -c` -gt 0 ]]; then
			if [[ ${base73} -eq 1 ]] || [[ ${base74} -eq 1 ]] || [[ ${base75} -eq 1 ]] || [[ ${base76} -eq 1 ]] || [[ ${base77} -eq 1 ]] || [[ ${base78} -eq 1 ]] || [[ ${base79} -eq 1 ]] || [[ ${rhel7} -eq 1 ]] ; then
				echo "SSLCipherSuite AES128-SHA256:HIGH:MEDIUM" >> $chmodsslconf
			#else
				#echo "SSLCipherSuite AES128-GCM-SHA256:HIGH:MEDIUM" >> $chmodsslconf
			fi
                elif [[ `echo $line | grep "^SSLCryptoDevice" -c` -gt 0 ]] ; then
			if [[ ${base73} -eq 1 ]] || [[ ${base74} -eq 1 ]] || [[ ${base75} -eq 1 ]] || [[ ${base76} -eq 1 ]] || [[ ${base77} -eq 1 ]] || [[ ${base78} -eq 1 ]] || [[ ${base79} -eq 1 ]] || [[ ${rhel7} -eq 1 ]] ; then
				echo "SSLCryptoDevice af_alg" >> $chmodsslconf
			fi
                else
                        echo $line >> $chmodsslconf
                fi
        done < $modsslconf
        mv $chmodsslconf $modsslconf
}

function checkkernel
{
        #check if kernel has crypto params enabled or kernel installed by chelsio
        echo "Checking for Kernel Version"
        ktag=$(echo ${UNAME_R} | cut -d . -f3 | cut -d - -f2)
        if [[ $ktag == "chelsio" ]] ; then
                installkernel=0
		echo "The Current kernel has all settings configured"
		exit 0
        fi
}

function progress
{
	p=0
	pid=$1
	spin='-\|/'
	while kill -0 $pid 2>/dev/null ; do
		p=$(( (p+1) %4 ))
		echo -en "\b${spin:$p:1}"
		sleep .1
	done
	echo -ne "\b${GREEN}Done${RESET}\n"
}

function prepKconfig
{
	echo "Preparing kernel config file"
	cd $tgtkdir;
	bootconfig=`ls /boot/config-$UNAME_R | head -1 `
	[[ ! -f $bootconfig ]] && bootconfig=`ls -t /boot/config* | head -1 `
	cp $bootconfig .config
	kfconfig=".config"
	sed -i 's/# CONFIG_RDMA_SIW is not set/CONFIG_RDMA_SIW=m/g' $kfconfig
	if [[ $ssl -eq 1 ]] ; then
		for cpr in ${CRYPTOKPARAMS[*]} ; do
			cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
			[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
		done
	
		sed -i 's/CONFIG_CRYPTO_CRYPTD=m/CONFIG_CRYPTO_CRYPTD=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_MCRYPTD=m/CONFIG_CRYPTO_MCRYPTD=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_AUTHENC=m/CONFIG_CRYPTO_AUTHENC=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_CCM=m/CONFIG_CRYPTO_CCM=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_CTS=m/CONFIG_CRYPTO_CTS=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_XTS=m/CONFIG_CRYPTO_XTS=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_SHA512=m/CONFIG_CRYPTO_SHA512=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_DEFLATE=m/CONFIG_CRYPTO_DEFLATE=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_ANSI_CPRNG=m/CONFIG_CRYPTO_ANSI_CPRNG=y/g' $kfconfig
		sed -i 's/CONFIG_CRYPTO_USER_API_RNG=m/CONFIG_CRYPTO_USER_API_RNG=y/g' $kfconfig
		sed -i 's/CONFIG_SYSTEM_TRUSTED_KEYS="certs\/rhel.pem"/CONFIG_SYSTEM_TRUSTED_KEYS=""/' $kfconfig

	fi
	for cpr in ${ISERKPARAMS[*]} ; do
		cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
		[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
	done
	for cpr in ${NVMKPARAMS[*]} ; do
		cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
		[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
	done
	for cpr in ${LIOKPARAMS[*]} ; do
		cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
		[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
	done
	for cpr in ${OVSPARAMS[*]} ; do
		cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
		[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
	done
	if [[ $(echo ${ARCH} | grep -c aarch64 ) -gt 0 ]] ; then
		for cpr in ${ARMPARAMS[*]} ; do
			cpLT=$(echo $cpr | awk -F '=' '{print $1}' )
			[[ $(zgrep "${cpLT}=[y|m]" $kfconfig) ]] || echo $cpr >> $kfconfig
		done
	fi
	
}

function install_kernel
{
	print_title "Kernel-$pkver with Crypto support"
	echo -n "Copying Kernel source to $tgtkdir :   " ; 
	( mkdir -p $tgtkdir ; cp -rf $kernelDir/* $tgtkdir/ ; cp -rf $kernelDir/.* $tgtkdir/ 2>/dev/null ) &
	pid=$! # Process Id of the previous running command
	progress $pid
	( cd ${tgtkdir} && make clean > /dev/null 2>&1 ) ;
	cd ${tgtkdir} ;
	prepKconfig
	make olddefconfig
	sed -i 's/# CONFIG_RDMA_SIW is not set/CONFIG_RDMA_SIW=m/g' $kfconfig
	make -j ${cpu_count} && make -j ${cpu_count} modules_install && make -j ${cpu_count} install && \
        kernel_stat=1 && echo "Kernel Installation Successful" && kernel_reboot=1 && ( echo -e "\nThe kernel is installed at $tgtkdir" )|| \
        ( echo "Kernel Installation Failed " )
	#grubby --set-default-index=0 ; \

}

if [[ $wconf -eq 1 ]] ; then
	if [[ $ssl -eq 1 ]] ; then
		if [[ $base74 -lt 1 ]] ; then
			checkdependencies
			inst_ssllibs
			[[ ${kdist} != "SLES12sp3" ]] && [[ ${kdist} != "SLES12sp4" ]] && [[ ${kdist} != "SLES15" ]]  && [[ ${kdist} != "SLES15sp1" ]] && dis_selinux
			if [[ ${base73} -eq 1 ]] || [[ ${base74} -eq 1 ]] || [[ ${base75} -eq 1 ]] || [[ ${base76} -eq 1 ]] || [[ ${base77} -eq 1 ]] || [[ ${base78} -eq 1 ]] || [[ ${base79} -eq 1 ]] || [[ ${rhel7} -eq 1 ]] ; then
				ch_sshconf
			fi
			#ch_sslConf
		fi
	fi
else
	checkkernel
	if [[ $ssl -eq 1 ]] ; then
		checkdependencies
		inst_defssl
		dis_selinux
	fi ;
	install_kernel
fi

if [[ $kernel_reboot -eq 1 ]] ; then
	#echo -e "${WARNING}Please edit the grub config file to boot in to the installed kernel and reboot the machine $RESET | tee -a ${PWD}/deps.log"
	echo -e "${WARNING}Please edit the grub config file to boot in to the installed kernel and reboot the machine $RESET"
elif [[ $reboot -eq 1 ]] ; then
	#echo -e "$WARNING Please reboot the machine for the configuration changes to take effect $RESET | tee -a ${PWD}/deps.log"
	echo -e "$WARNING Please reboot the machine for the configuration changes to take effect $RESET"
fi
