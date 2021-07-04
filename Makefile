SHELL := /bin/bash
NwSrc := build/src
FwSrc := build/src/network/firmware
FwTar := /lib/firmware/cxgb4/
ToolSrc := build/tools
LibSrc := build/libs
SnifferSrc  := build/tools/sniffer
specs := specs
debrules := debrules
DEBIAN := 0
PDEB := 0
logpath := $(shell pwd)
pwd := $(shell pwd)
arch := $(shell uname -m)
rpmLoc := $(shell pwd)/rpmbuild/RPMS/$(arch)
removelogs := $(shell rm -rf deps.log temp.log )
touchlogs := $(shell touch temp.log )
openssl = 0
libverbs = 0
libcm = 0
iwarp_comp := 0
dist := 
DISTRO := 
ppc_dist :=
aarch_7u3_dist :=
aarch_7u5_dist :=
aarch_7u6_dist :=
DEBUG := 0
vers := 3.14.0.3
pathssl := /usr/include/openssl/evp.h
pathverbs64 := /usr/lib64/libibverbs.so
pathverbs := /usr/lib/libibverbs.so
pathcm64 := /usr/lib64/librdmacm.so
pathcm := /usr/lib/librdmacm.so
pathcmu := /usr/lib/x86_64-linux-gnu/librdmacm.so
pathnl := /usr/include/netlink/socket.h
pathnl3 := /usr/include/libnl3/netlink/socket.h
debDistros := ubuntu12u04 ubuntu12u042 ubuntu14u041 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u04 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041  ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 Debian
rpmgen := 0
UM_UNINST := 0
error_exit := 1
libs_ofed := 0
ipv6_enable := 0
ipv6_chk := $(shell ls /proc/sys/net/)
moddir = $(shell echo "/lib/modules/`uname -r`/." ;)
udp_libs := libcxgb4_udp:libcxgb4_sock:libcxgb4_udp_debug:libcxgb4_sock_debug
iser_libs :=
installprecheck := 0
firm_config := UNIFIED_WIRE
debug_patch := 1
kerFlag := 0
tgtsum = 0
IWARP_WPM := 1
UM_VERSION:=2.4-78
OVS_VERSION:=2.9.1
NULL_OUT := /dev/null
AUTO_INST := 0
AUTO_BIN := $(shell which autoconf 2>/dev/null  )
TOOLS_UNINST := 0
SETPTP := 0
cop_dpdk := 1
chsslbin := chopenssl
chcr := chcr:
INSTCHCR := 1
chcr_sum := chcr/TLS
ARCH64 := x86_64 ppc64 ppc64le aarch64
modconf = /etc/modprobe.d/chelsio.conf
dracut := 1
cp_tls := 0
rdma_core_version := 0
initimg=/boot/initramfs-$(shell uname -r).img
ISERKPARAMS=CONFIG_INFINIBAND_ISER=m CONFIG_INFINIBAND_ISERT=m
NVMKPARAMS=CONFIG_BLK_DEV_NVME=m CONFIG_NVME_RDMA=m CONFIG_NVME_TARGET=m CONFIG_NVME_TARGET_RDMA=m CONFIG_NVME_RDMA=m CONFIG_BLK_DEV_NULL_BLK=m CONFIG_CONFIGFS_FS=y
LIOKPARAMS=CONFIG_TARGET_CORE=m CONFIG_ISCSI_TARGET=m CONFIG_CONFIGFS_FS=m CONFIG_CRYPTO_CRC32C_INTEL=m CONFIG_CRYPTO_CRCT10DIF=m CONFIG_CRC_T10DIF=m
CRYPTOKPARAMS=CONFIG_KEYS=y CONFIG_KEYS_DEBUG_PROC_KEYS=y CONFIG_SECURITY=y CONFIG_SECURITY_NETWORK=y CONFIG_SECURITY_NETWORK_XFRM=y CONFIG_LSM_MMAP_MIN_ADDR=65536 CONFIG_SECURITY_SELINUX=y CONFIG_SECURITY_SELINUX_BOOTPARAM=y CONFIG_SECURITY_SELINUX_BOOTPARAM_VALUE=1 CONFIG_SECURITY_SELINUX_DISABLE=y CONFIG_SECURITY_SELINUX_DEVELOP=y CONFIG_SECURITY_SELINUX_AVC_STATS=y CONFIG_SECURITY_SELINUX_CHECKREQPROT_VALUE=1 CONFIG_DEFAULT_SECURITY_SELINUX=y CONFIG_DEFAULT_SECURITY="selinux" CONFIG_CRYPTO=y CONFIG_CRYPTO_FIPS=y CONFIG_CRYPTO_ALGAPI=y CONFIG_CRYPTO_ALGAPI2=y CONFIG_CRYPTO_AEAD=y CONFIG_CRYPTO_AEAD2=y CONFIG_CRYPTO_BLKCIPHER=y CONFIG_CRYPTO_BLKCIPHER2=y CONFIG_CRYPTO_HASH=y CONFIG_CRYPTO_HASH2=y CONFIG_CRYPTO_RNG=y CONFIG_CRYPTO_RNG2=y CONFIG_CRYPTO_PCOMP=y CONFIG_CRYPTO_PCOMP2=y CONFIG_CRYPTO_MANAGER=y CONFIG_CRYPTO_MANAGER2=y CONFIG_CRYPTO_NULL=y CONFIG_CRYPTO_WORKQUEUE=y CONFIG_CRYPTO_CRYPTD=y CONFIG_CRYPTO_AUTHENC=y CONFIG_CRYPTO_TEST=m CONFIG_CRYPTO_CCM=y CONFIG_CRYPTO_GCM=y CONFIG_CRYPTO_SEQIV=y CONFIG_CRYPTO_CBC=y CONFIG_CRYPTO_CTR=y CONFIG_CRYPTO_CTS=y CONFIG_CRYPTO_ECB=y CONFIG_CRYPTO_XTS=y CONFIG_CRYPTO_HMAC=y CONFIG_CRYPTO_GHASH=y CONFIG_CRYPTO_MD4=m CONFIG_CRYPTO_MD5=y CONFIG_CRYPTO_SHA1=y CONFIG_CRYPTO_SHA256=y CONFIG_CRYPTO_SHA512=y CONFIG_CRYPTO_AES=y CONFIG_CRYPTO_AES_X86_64=y CONFIG_CRYPTO_DEFLATE=y CONFIG_CRYPTO_ZLIB=y CONFIG_CRYPTO_LZO=y CONFIG_CRYPTO_ANSI_CPRNG=y CONFIG_CRYPTO_USER_API=y CONFIG_CRYPTO_USER_API_HASH=y CONFIG_CRYPTO_USER_API_SKCIPHER=y CONFIG_CRYPTO_HW=y
ARMPARAMS=CONFIG_CHELSIO_T1=m CONFIG_CHELSIO_T1_1G=y CONFIG_CHELSIO_T3=m CONFIG_CHELSIO_T4=m CONFIG_CHELSIO_T4VF=m CONFIG_INFINIBAND_USER_MAD=m CONFIG_INFINIBAND_USER_ACCESS=m CONFIG_INFINIBAND_USER_MEM=y CONFIG_INFINIBAND_CXGB3=m CONFIG_INFINIBAND_CXGB3_DEBUG=y CONFIG_INFINIBAND_CXGB4=m CONFIG_SCSI_CXGB3_ISCSI=m CONFIG_SCSI_CXGB4_ISCSI=m
$(shell [ $$(echo $$PATH| grep ^/sbin: -c) -eq 0 ] && [ $$(echo $$PATH| grep :/sbin: -c) -eq 0  ] && echo -e "PATH=/sbin:$$PATH" >> ~/.bashrc 2>/dev/null ; . ~/.bashrc 2>/dev/null ;)
ifneq ($(AUTO_BIN), ) 
  AUTOCONF_VER := $(strip $(shell $(AUTO_BIN) --version | head -1 | awk '{print $$4}' 2>/dev/null ))
  AU_MAJVER := $(word 1, $(subst ., ,$(AUTOCONF_VER)))
  AU_MINVER := $(word 2, $(subst ., ,$(AUTOCONF_VER)))
  AUTO_INST := $(shell [ \( $(AU_MINVER) -lt 2  -a  $(AU_MAJVER) -lt 63 \) ] && echo 1 || echo 0 ; )
else
  AUTO_INST := 1
endif
ifdef BENCHMARKS
    BENCHMARK_FLAG := $(BENCHMARKS)
else
    BENCHMARK_FLAG := 0
endif

ifdef SKIP_RPM
    NORPMKERNELFLAG := $(SKIP_RPM)
endif
ifndef SKIP_DEPS
    SKIP_DEPS := 0
endif
ifndef SKIP_INIT
    SKIP_INIT := 0
endif
ifdef SKIP_ALL
    ifeq (${SKIP_ALL},1)
      SKIP_RPM := 1
      SKIP_DEPS := 1
    endif
endif
ifeq (${SKIP_INIT},1)
    dracut := 0
endif

ifndef NORPMKERNELFLAG
    NORPMKERNELFLAG := 0
endif
ifdef INSTALL_UM
    UM_INST := $(INSTALL_UM)
else
    UM_INST := 1
    INSTALL_UM := 0
endif
ifndef dcbx
    dcbx := 0
endif
ifndef ipv6_disable
    ipv6_disable := 0
endif
ifeq ($(ipv6_disable),1)
    ipv6_enable := 0
else
    ifeq ($(filter ipv6,$(ipv6_chk)),ipv6)
        ipv6_enable := 1
    endif
endif
ifeq ($(dcbx),1)
    enable_dcb := 1
else
    enable_dcb := 0
endif
ifdef CONF
    ifeq ($(CONF),T4_CONF_UWIRE)
        CONF := UNIFIED_WIRE
    endif 
    ifeq ($(CONF),T4_CONF_HCTOE)
        CONF := HIGH_CAPACITY_TOE
    endif 
    ifeq ($(CONF),T4_CONF_LL)
        CONF := LOW_LATENCY
    endif 
    ifeq ($(CONF),T4_CONF_HCRDMA)
        CONF := HIGH_CAPACITY_RDMA
    endif 
    ifeq ($(CONF),T4_CONF_USO)
        CONF := UDP_OFFLOAD
    endif 
    ifeq ($(CONF),T5_WIRE_DIRECT_LATENCY)
        CONF := WIRE_DIRECT_LATENCY
    endif 
    ifeq ($(CONF),T5_HASH_FILTER)
        CONF := HIGH_CAPACITY_HASH_FILTER
    endif 
endif
define \n


endef
ifeq ($(filter $(MAKECMDGOALS),clean prep distclean rpmclean help list_kernels list_supported), )
    k := 0
    chk := $(strip $(shell ${pwd}/scripts/chk_disk.sh))
    #$(info $(chk) )
    k := $(firstword $(chk))
    #$(info $(k))
    ifneq ($(k),0)
        $(error Requires $(word 1,$(chk)) MB more disk space in $(word 2,$(chk)) )
    endif
endif
 
r6x_kernels := 2.6.32-279.el6 2.6.32-358.el6 2.6.32-431.el6 2.6.32-504.el6 2.6.32-573.el6 2.6.32-642.el6 2.6.32-696.el6 2.6.32-754.el6
r7x_kernels := 3.10.0-123.el7 3.10.0-229.el7 3.10.0-229.el7.ppc64 3.10.0-229.ael7b.ppc64le 3.10.0-327.el7 3.10.0-327.el7.ppc64
r73_kernels := 3.10.0-514.el7 3.10.0-514.el7.ppc64le 3.10.0-693.el7 3.10.0-693.el7.ppc64le 3.10.0-862.el7 3.10.0-862.el7.ppc64le 3.10.0-957.el7 3.10.0-957.el7.ppc64le 3.10.0-1062.el7 3.10.0-1127.el7 3.10.0-1160.el7
r8x_kernels := 4.18.0-80.el8 4.18.0-147.el8 4.18.0-193.el8 4.18.0-240.el8
s11x_kernels := 3.0.13-0.27 3.0.76-0.11 3.0.101-63-default
s12_kernel := 3.12.28-4 3.12.49-11
s12sp2_kernel := 4.4.21-69-default 4.4.73-5-default
s15_kernel := 4.12.14-23-default 4.12.14-94.41-default 4.12.14-195-default
u14043_kernel := 3.19.0-25-generic
u14044_kernel := 4.2.0-27-generic
u1604x_kernel := 4.4.0-21-generic 4.4.0-31-generic 4.4.0-116-generic 4.4.0-131-generic 4.4.0-142-generic
u1804x_kernel := 4.15.0-29-generic 4.15.0-45-generic 4.15.0-55-generic 4.15.0-76-generic 4.15.0-126-generic
u2004x_kernel := 5.4.0-26-generic 5.4.0-54-generic 5.4.0-65-generic
sw_kernels := 5.10
v3x_kernels := 3.6 3.7 3.8 3.9 3.10 3.11 3.12 3.13 3.14 3.15 3.16 3.17 3.18
ex_kernels := 3.4
v41_kernels := 4.1 4.2
v44_kernels := 4.4 4.5
v49_kernels := 4.8 4.9
v414_kernels := 4.14
v419_kernels := 4.19 5.0 5.2
v54_kernels := 5.4 5.6
aarch_kernels := 4.14.0-49.el7a.aarch64 4.14.0-115.el7a.aarch64

supported_kernels := $(r6x_kernels) $(r7x_kernels) $(r8x_kernels) $(r73_kernels) $(s11x_kernels) $(s12_kernel) $(s12sp2_kernel) $(s15_kernel) $(u14043_kernel) $(u14044_kernel) $(sw_kernels) $(u1604x_kernel) $(u1804x_kernel) $(u2004x_kernel) $(v3x_kernels) \
                    $(v41_kernels) $(v44_kernels) $(v49_kernels) $(v414_kernels) $(v419_kernels) $(v54_kernels) $(aarch_kernels)

supported_config := UNIFIED_WIRE HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY UDP_OFFLOAD WIRE_DIRECT_LATENCY \
                    HIGH_CAPACITY_WD HIGH_CAPACITY_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE HIGH_CAPACITY_VF NVME_PERFORMANCE T4_UN

# Checking whether kernel we are running on is supported or not.

sles12sp4_check := $(shell  cat /etc/os-release 2>&1 | grep -i VERSION_ID | awk -F "=" '{print $$2}' | tr -d '"'  | awk -F "." '{print $$1}')

ifndef UNAME_R
  UNAME_R := $(shell uname -r)
endif
ifndef UNAME_RPM
  UNAME_RPM := $(shell uname -r)
endif
$(info Building for kernel $(UNAME_RPM))
error_exit := $(foreach var,$(supported_kernels),$(if $(findstring $(UNAME_R),$(var)),0))
#$(info value=$(error_exit))
ifeq ($(strip $(error_exit)),)
UNAMEVR := $(shell if [ `echo ${UNAME_R} | grep -c el6` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 279 ]; then \
        echo "2.6.32-642.el6" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 123 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 514 ]; then \
        echo "3.10.0-327.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 514 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 693 ]; then \
        echo "3.10.0-514.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 693 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 862 ] ; then \
        echo "3.10.0-693.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 862 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 957 ] ; then \
        echo "3.10.0-862.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 957 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 1062 ] ; then \
        echo "3.10.0-957.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 1062 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 1127 ] ; then \
        echo "3.10.0-1062.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 1127 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 1160 ] ; then \
        echo "3.10.0-1127.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 1160 ]  ; then \
        echo "3.10.0-1160.el7" ; \
    elif [ `echo ${UNAME_R} | grep -c el8` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 80 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 147 ] ; then \
        echo "4.18.0-80.el8" ; \
    elif [ `echo ${UNAME_R} | grep -c el8` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 147 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 193 ] ; then \
        echo "4.18.0-147.el8" ; \
    elif [ `echo ${UNAME_R} | grep -c el8` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 193 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 240 ] ; then \
        echo "4.18.0-193.el8" ; \
    elif [ `echo ${UNAME_R} | grep -c el8` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 240 ]  ; then \
        echo "4.18.0-240.el8" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SuSE-release ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 3.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 13 ]; then \
        echo "3.0.101-63" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SuSE-release ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 3.12 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 28 ]; then \
        echo "3.12.49-11" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SuSE-release ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.4 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 21 ] && [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -lt 73 ]; then \
        echo "4.4.21-69-default" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SuSE-release ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.4 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 73 ]; then \
        echo "4.4.73-5-default" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SuSE-release ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.12 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 14 ] && [ ${sles12sp4_check} == "12" ] ; then \
        echo "4.12.14-94.41-default" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SUSE-brand ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.12 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 14 ] && [ `echo ${UNAME_R} | cut -d- -f2 ` -ge 23] && \
         [ `echo ${UNAME_R} | cut -d- -f2 ` -lt 195 ]; then \
        echo "4.12.14-23-default" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ -f /etc/SUSE-brand ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.12 ] && \
         [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 14 ] && [ `echo ${UNAME_R} | cut -d- -f2 ` -ge 195]; then \
        echo "4.12.14-195-default" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 3.19.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2` -ge 25 ]; then \
        echo "3.19.0-25-generic" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.2.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2` -ge 27 ]; then \
        echo "4.2.0-27-generic" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.4.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2` -ge 21 ]; then \
        echo "4.4.0-21-generic" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.15.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2` -ge 29 ]; then \
        echo "4.15.0-29-generic" ; \
    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 5.4.0 ] && \
         [ `echo ${UNAME_R} | cut -d- -f2` -ge 26 ]; then \
        echo "5.4.0-26-generic" ; \
    elif [ `echo ${UNAME_R} | grep -c ^3"\."[6789]` -eq 1 ] || [ `echo ${UNAME_R} | grep -c ^3"\.1"\[012345678\]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^4"\."[1][9]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^4"\."[1][4]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^4"\."[8-9]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^4"\."[1-2]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^4"\."[4-5]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^5"\."[0]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^5"\."[2]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^5"\."[4]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^5"\."[6]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    elif [ `echo ${UNAME_R} | grep -c ^5"\."[1][0]` -eq 1 ]; then \
        echo ${UNAME_R} ; \
    else \
        echo ; \
    fi ; )
  ifneq ($(UNAMEVR),)
    override UNAME_R := $(UNAMEVR)
    error_exit := $(foreach var,$(supported_kernels),$(if $(findstring $(var),$(UNAME_R)),0))
  else
      $(info Error: The kernel version ${UNAME_R} is not supported. Refer to README for supported kernel versions or run make list_kernels.)
      $(info List of supported kernel Versions)
      $(foreach var,$(supported_kernels),$(info $(var)))
      $(error )
  endif
else
  UNAMEVR := $(UNAME_R)
endif

ifeq ($(shell echo $(UNAME_R) | cut -d. -f1,2 | grep -c 4.9 ),1)
  #$(info $(UNAME_R) $(shell echo $(UNAME_R) |  cut -d- -f1 | cut -d. -f3 | grep -o -E '^[0-9]*'))
  error_exit = $(shell  if [ `echo $(UNAME_R) |  cut -d- -f1 | cut -d. -f3 | grep -o -E '^[0-9]*'` -lt 13 ] && [ `echo $(UNAME_R) |  cut -d- -f1 | cut -d. -f3 | grep -o -E '^[0-9]*'` -ne 0 ] ; then echo "" ; else echo "1" ; fi )
  ifneq ($(strip $(error_exit)),1)
    $(info Error: The kernel version ${UNAME_R} is not supported. This package supports kernel version 4.9.X >= 4.9.13 )
    $(error )
  endif
  ifeq ($(shell uname -r |  cut -d- -f1 | cut -d. -f3 | grep -o -E '^[0-9]*'),0)
    ipv6_enable := 0
    ipv6_disable := 1
  endif
endif


ifeq ($(shell echo $(UNAME_R) | cut -d. -f1,2 | grep -c 4.9 ),1)
  error_exit = $(shell  if [ `echo $(UNAME_R) |  cut -d- -f1 | cut -d. -f3 | grep -o -E '^[0-9]*'` -lt 136 ] ; then echo "" ; else echo "1" ; fi )
  ifneq ($(strip $(error_exit)),1)
    kernel4u9_bonding := 0
  else
    kernel4u9_bonding := 1
  endif
endif
#ifeq ($(strip $(error_exit)),)
#endif

export OVS_VERSION
export UNAME_R
export ARCH64
export UNAME_RPM

#Determine which OS we are running on.
os_kernel_matrix = 2.6.18-128.el5|RHEL5.3|rhel5u3 \
                   2.6.18-164.el5|RHEL5.4|rhel5u4 \
                   2.6.18-194.el5|RHEL5.5|rhel5u5 \
                   2.6.18-238.el5|RHEL5.6|rhel5u6 \
                   2.6.18-274.el5|RHEL5.7|rhel5u7 \
                   2.6.18-308.el5|RHEL5.8|rhel5u8 \
                   2.6.18-348.el5|RHEL5.9|rhel5u9 \
                   2.6.18-371.el5|RHEL5.10|rhel5u10 \
                   2.6.18-398.el5|RHEL5.11|rhel5u11 \
                   2.6.32-71.el6|RHEL6.0|rhel6 \
                   2.6.32-131.0.15.el6|RHEL6.1|rhel6u1 \
                   2.6.32-220.el6|RHEL6.2|rhel6u2 \
                   2.6.32-279.el6|RHEL6.3|rhel6u3 \
                   2.6.32-358.el6|RHEL6.4|rhel6u4 \
                   2.6.32-431.el6|RHEL6.5|rhel6u5 \
                   2.6.32-504.el6|RHEL6.6|rhel6u6 \
                   2.6.32-573.el6|RHEL6.7|rhel6u7 \
                   2.6.32-642.el6|RHEL6.8|rhel6u8 \
                   2.6.32-696.el6|RHEL6.9|rhel6u9 \
                   2.6.32-754.el6|RHEL6.10|rhel6u10 \
                   3.10.0-123.el7|RHEL7.0|rhel7 \
                   3.10.0-229|RHEL7.1|rhel7u1 \
                   3.10.0-327.el7|RHEL7.2|rhel7u2 \
                   3.10.0-514.el7|RHEL7.3|rhel7u3 \
                   3.10.0-693.el7|RHEL7.4|rhel7u4 \
                   3.10.0-862.el7|RHEL7.5|rhel7u5 \
                   3.10.0-957.el7|RHEL7.6|rhel7u6 \
                   3.10.0-1062.el7|RHEL7.7|rhel7u7 \
                   3.10.0-1127.el7|RHEL7.8|rhel7u8 \
                   3.10.0-1160.el7|RHEL7.9|rhel7u9 \
                   4.18.0-80.el8|RHEL8.0|rhel8 \
                   4.18.0-147.el8|RHEL8.1|rhel8u1 \
                   4.18.0-193.el8|RHEL8.2|rhel8u2 \
                   4.18.0-240.el8|RHEL8.3|rhel8u3 \
                   2.6.16.60-0.54.5|SLES10.3|sles10sp3 \
                   2.6.27.19-5|SLES11|sles11 \
                   2.6.32.12|SLES11sp1|sles11sp1 \
                   3.0.13|SLES11sp2|sles11sp2 \
                   3.0.76|SLES11sp3|sles11sp3 \
                   3.0.101|SLES11sp4|sles11sp4 \
                   3.12.28-4|SLES12|sles12 \
                   3.12.49-11|SLES12sp1|sles12sp1 \
                   4.4.21-69|SLES12sp2|sles12sp2 \
                   4.4.73-5|SLES12sp3|sles12sp3 \
                   4.12.14-94.41|SLES12sp4|sles12sp4 \
                   4.12.14-23|SLES15|sles15 \
                   4.12.14-195|SLES15sp1|sles15sp1 \
                   2.6.33.3-85.fc|fedora13|fedora13 \
                   2.6.35.6-45.fc|fedora14|fedora14 \
                   3.2.0-23-generic|ubuntu-12.04|ubuntu12u04 \
                   3.5.0-23-generic|ubuntu-12.04.2|ubuntu12u042 \
                   3.13.0-32-generic|ubuntu-14.04.1|ubuntu14u041 \
                   3.16.0-30-generic|ubuntu-14.04.2|ubuntu14u042 \
                   3.19.0-25-generic|ubuntu-14.04.3|ubuntu14u043 \
                   4.2.0-27-generic|ubuntu-14.04.4|ubuntu14u044 \
                   4.4.0-21-generic|ubuntu-16.04|ubuntu16u04 \
                   4.4.0-31-generic|ubuntu-16.04.1|ubuntu16u041 \
                   4.4.0-116-generic|ubuntu-16.04.4|ubuntu16u044 \
                   4.4.0-131-generic|ubuntu-16.04.5|ubuntu16u045 \
                   4.4.0-142-generic|ubuntu-16.04.6|ubuntu16u046 \
                   4.15.0-29-generic|ubuntu-18.04.1|ubuntu18u041 \
                   4.15.0-45-generic|ubuntu-18.04.2|ubuntu18u042 \
                   4.15.0-55-generic|ubuntu-18.04.3|ubuntu18u043 \
                   4.15.0-76-generic|ubuntu-18.04.4|ubuntu18u044 \
                   4.15.0-126-generic|ubuntu-18.04.5|ubuntu18u045 \
                   5.4.0-26-generic|ubuntu-20.04|ubuntu20u04 \
                   5.4.0-54-generic|ubuntu-20.04.1|ubuntu20u041 \
                   5.4.0-65-generic|ubuntu-20.04.2|ubuntu20u042 \
                   2.6.34|2.6.34|kernel26u34 \
                   2.6.35|2.6.35|kernel26u35 \
                   2.6.36|2.6.36|kernel26u36 \
                   2.6.37|2.6.37|kernel26u37 \
                   2.6.39|2.6.39|kernel26u39 \
                   3.16|3.16|kernel3u16 \
                   3.18|3.18|kernel3u18 \
                   3.17|3.17|kernel3u17 \
                   3.14|3.14|kernel3u14 \
                   3.13|3.13|kernel3u13 \
                   3.12|3.12|kernel3u12 \
                   3.11|3.11|kernel3u11 \
                   3.10|3.10|kernel3u10 \
                   3.9|3.9|kernel3u9 \
                   3.8|3.8|kernel3u8 \
                   3.7|3.7|kernel3u7 \
                   3.6|3.6|kernel3u6 \
                   3.5|3.5|kernel3u5 \
                   3.4|3.4|kernel3u4 \
                   3.1|3.1|kernel3u1 \
                   4.19|4.19|kernel4u19 \
                   4.14|4.14|kernel4u14 \
                   5.6|5.6|kernel5u6 \
                   5.4|5.4|kernel5u4 \
                   4.1|4.1|kernel4u1 \
                   4.2|4.2|kernel4u2 \
                   4.4|4.4|kernel4u4 \
                   4.5|4.5|kernel4u5 \
                   4.8|4.8|kernel4u8 \
                   4.9|4.9|kernel4u9 \
                   5.0|5.0|kernel5u0 \
                   5.2|5.2|kernel5u2 \
                   5.10|5.10|kernel5u10 \
                   2.6.16.60-0.21|SLES10.2|sles10sp2

KEDISTRO := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 1,\
                                              $(subst |, ,$(entry))))))
KEDISTRO := $(firstword $(KEDISTRO))
DISTRO := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 2,\
                                              $(subst |, ,$(entry))))))
dist := $(strip $(foreach entry, $(os_kernel_matrix), $(if $(findstring $(firstword \
                                              $(subst |, ,$(entry))),$(UNAME_R)),$(word 3,\
                                              $(subst |, ,$(entry))))))
DISTRO := $(firstword $(DISTRO))
dist := $(firstword $(dist))
kdist := $(DISTRO)
isKernel := $(firstword $(subst l,l ,$(dist)))
ifeq ($(isKernel),kernel)
  kerFlag := 1
  out := $(shell rpm -qf /etc/issue 2>&1 > /dev/null ; echo $$? )
  ifeq ($(out),0)
  distName := $(shell rpm -qf /etc/issue 2>/dev/null )
   ifdef distName
    checkos := $(findstring red,$(distName))
    ifdef checkos
      checkos := red
      distVersion := $(shell cat /etc/redhat-release | awk -F "release" '{print $$2}' | awk '{print $$1}')
    else
      checkos := $(findstring centos,$(distName))
      ifdef checkos
        checkos := red
        distVersion := $(shell cat /etc/redhat-release | awk -F "release" '{print $$2}' | awk '{print $$1}' | awk -F "." '{print $$1"."$$2 }' )
      else
        checkos := $(findstring sles, $(distName))
        ifdef checkos
          checkos := sles
          distVersion := $(shell cat /etc/issue | grep -i Server | head -1 | awk '{print $$7 $$8}')
          NORPMKERNELFLAG := 1
        else
          checkos := $(findstring fedora, $(distName))
          ifdef checkos
            checkos := fedora
            distVersion := $(shell cat /etc/issue | head -1 | awk '{print $$3}') 
          endif
        endif 
      endif               
     endif
   endif
  else
    distName := $(shell cat /etc/issue | head -1 )
    checkos := $(findstring Ubuntu, $(distName))
    ifdef checkos
      checkos := ubuntu
      distVersion := 
      DEBIAN := 1
    else
      #checkos := $(findstring Debian, $(distName))
      #ifdef checkos
      ifneq ($(filter Debian Kylin,$(findstring Debian,$(distName)) $(findstring Kylin,$(distName))), )
          checkos := Debian
          distVersion := 
          DEBIAN := 1
          PDEB := 1
      endif
    endif
  endif

  ifeq ($(checkos),red)
   distC := RHEL
   kdist := $(distC)$(firstword $(distVersion))
  endif
  ifeq ($(checkos),sles)
    distpostfix := $(firstword $(distVersion))
    distpostfix := $(shell tr '[:upper:]' '[:lower:]' <<< $(distpostfix))
    ifeq ($(findstring 15,$(distVersion)),15)
      kdist := SLES15
    else
       ifeq ($(findstring 12,$(distVersion)),12)
         kdist := SLES12
       else 
         kdist := SLES11
       endif
    endif
    kdist := $(kdist)$(distpostfix)
  endif 
  ifeq ($(checkos),fedora)
    distC := fedora
    kdist := $(distC)$(firstword $(distVersion))
  endif
  ifeq ($(checkos),ubuntu)
    distC := ubuntu-
    kdist := $(distC)$(firstword $(distVersion))
  endif

endif

ifneq ($(filter ${dist},$(debDistros)), )
    DEBIAN := 1
endif

ifneq ($(filter $(DISTRO),$(sw_kernels)), )
  patchSrc := 0
else
  patchSrc := 1
endif

ifneq ($(filter $(kdist),RHEL5.3 RHEL5.4 RHEL5.5 RHEL5.6 RHEL6.1 RHEL6.2 RHEL6.0 fedora13 fedora14 SLES11), )
  kdist_lib := 
else
  kdist_lib :=
endif

lio_tgtcli := 0
#ifneq ($(findstring RHEL6,$(kdist)), )
#  lio_tgtcli := 1
#endif
#
#ifneq ($(filter $(kdist),RHEL7.0 RHEL7.1 RHEL7.2), )
#  lio_tgtcli := 1
#endif
#

ifeq ($(shell which targetcli 2>/dev/null),)
 lio_tgtcli := 1
else
 lio_tgtcli := $(strip $(shell ${pwd}/scripts/check_targetcli.sh)) 

# tgt_ver := $(shell targetcli -v 2>&1| awk '{print $$3}';)
# $(info $(tgt_ver))
# TGT_MAJVER := $(word 1, $(subst ., ,$(tgt_ver)))
# TGT_MINVER := $(word 2, $(subst ., ,$(tgt_ver)))
# TGT_BUILD := $(word 3, $(subst ., ,$(tgt_ver)))
# TGT_SBUILD := $(shell echo $(TGT_BUILD) | awk -F 'fb' '{print $$2}' ) 
#TGT_SBUILD := 2
# TGTCHK = $(shell echo $(TGT_MAJVER) | grep -c "^[0-9]" )
# ifneq ($(TGTCHK),0)
#   lio_tgtcli := $(shell [ \( $(TGT_MAJVER) -eq 2 \) ] && [ \( $(TGT_MINVER) -lt 1  -o  $(TGT_SBUILD) -lt 41 \) ] && echo 1 || echo 0 ; )
#   lio_tgtcli := $(shell [ \( $(TGT_MAJVER) -lt 2 \) ] && echo 1 || echo $(lio_tgtcli) ; )
# else
#   lio_tgtcli := 1 
# endif
#$(info $(TGT_MAJVER) $(TGT_MINVER) $(TGT_BUILD) $(TGT_SBUILD)  = $(lio_tgtcli))

endif

cxgbtool_msg := cxgbtool/cop
ifneq ($(filter $(arch),ppc64 ppc64le aarch64),)
  ifneq ($(filter $(arch),aarch64),)
   ifeq ($(kdist),RHEL7.3)
    aarch_7u3_dist := $(dist)
   else
     ifeq ($(kdist),RHEL7.5)
      aarch_7u5_dist := $(dist)
     else
      aarch_7u6_dist := $(dist)
     endif
   endif
  else
   ppc_dist := $(dist)
  endif
  udp_libs := 
  dcbx := 0
  enable_dcb := 0
  cxgbtool_msg := cxgbtool    
  IWARP_WPM := 0
  ifneq ($(filter $(arch),ppc64 ppc64le),)
    crypt_dist := $(dist)
  endif
endif

ifeq ($(filter $(kdist),RHEL6.8 RHEL6.9 RHEL6.10 RHEL7.2 RHEL7.3 RHEL7.4 RHEL7.5 RHEL7.6 RHEL7.7 RHEL7.8 RHEL7.9 RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 SLES12sp1 SLES12sp2 SLES12sp3 SLES12sp4 SLES15),)
  IWARP_WPM := 0
endif
#ifeq ($(filter kernel4u8 kernel4u9 kernel4u14 rhel6u8 rhel6u9 rhel7u2 rhel7u3 rhel7u4 rhel7u5 sles12sp1 sles12sp2 sles12sp3,$(kdist)),)
#  IWARP_WPM := 0
#endif

ifeq ($(wildcard $(initimg)),)
  initimg=/boot/initrd-$(shell uname -r)
endif

ifeq ($(DEBIAN),1)
  IWARP_WPM := 0
  initimg=/boot/initrd.img-$(shell uname -r)
  chsslbin :=
  cp_tls := 1
endif

ifeq ($(IWARP_WPM),1)
  udp_libs := $(udp_libs)
  iser_libs :=
endif

#ifneq ($(filter $(kdist),ubuntu-16.04.1),) 
#  BENCHMARK_FLAG := 0
#endif
export BENCHMARK_FLAG
ifeq ($(DEBUG),1)
  $(info DISTRO : $(DISTRO))
  $(info DIST : $(dist))
endif
ifndef CONF
  CONF := UNIFIED_WIRE
endif
ifneq ($(findstring udp_offload,$(MAKECMDGOALS)),)
  CONF := UDP_OFFLOAD
endif
ifneq ($(findstring ovs,$(MAKECMDGOALS)),)
  CONF := HIGH_CAPACITY_HASH_FILTER
endif
#error_exit = $(foreach var,$(supported_config),$(if $(findstring $(var),$(CONF)),0))
#ifeq ($(strip $(error_exit)),)
ifeq ($(filter $(CONF),$(supported_config)),)
    $(info Error: Unknown config option ${CONF}.)
    $(info List of supported configurations: )
    $(foreach var,$(filter-out T4_UN, ${supported_config}),$(info $(var)))
    $(error )
endif

ifeq ($(CONF),NVME_PERFORMANCE)
    ifneq ($(filter kernel5u0 kernel5u2 rhel6u9 rhel6u10 sles12sp2 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046,$(dist)),)
      $(info Error: NVME_PERFORMANCE configuration file is not supported with ${dist}.)
      $(error )
    endif
    ifneq ($(ppc_dist),)
      $(info Error: NVME_PERFORMANCE configuration file is not supported with ${ppc_dist}.)
      $(error )
    endif
endif

ifeq ($(dist),kernel5u0)
    ifneq ($(filter HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY UDP_OFFLOAD WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD HIGH_CAPACITY_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE HIGH_CAPACITY_VF NVME_PERFORMANCE ,$(CONF)),)
       $(info Error: ${CONF} configuration file is not supported with ${dist}.)
       $(error )
    endif
endif

ifeq ($(dist),kernel5u2)
    ifneq ($(filter HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY UDP_OFFLOAD WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD HIGH_CAPACITY_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE HIGH_CAPACITY_VF NVME_PERFORMANCE ,$(CONF)),)
       $(info Error: ${CONF} configuration file is not supported with ${dist}.)
       $(error )
    endif
endif
 
ifeq ($(dist),kernel5u6)
    ifneq ($(filter HIGH_CAPACITY_RDMA UDP_OFFLOAD WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD HIGH_CAPACITY_HASH_FILTER RDMA_PERFORMANCE ISCSI_PERFORMANCE HIGH_CAPACITY_VF NVME_PERFORMANCE ,$(CONF)),)
       $(info Error: ${CONF} configuration file is not supported with ${dist}.)
       $(error )
    endif
endif
 
ifeq ($(KDIR),)
  ifeq ($(KSRC),)
    ifneq ($(KOBJ),)
      $(warning When using KOBJ=<path>, the KSRC=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: kernel source path not specified)
    endif
  else
    ifeq ($(KOBJ),)
      $(warning When using KSRC=<path>, the KOBJ=<path> must also be defined.)
      $(warning Use KDIR=<path> when KSRC and KOBJ are the same.)
      $(error ERROR: KOBJ path not specified)
    endif
  endif
else
  override KSRC := $(KDIR)
  override KOBJ := $(KDIR)
endif

ifeq ($(wildcard $(pathssl)),)
  openssl := 0
else
  openssl := 1
endif

ifeq ($(wildcard $(pathnl)),)
  flibnl := 0
  ifeq ($(wildcard $(pathnl3)),)
    flibnl := 0
  else
    flibnl := 1
  endif
else
  flibnl := 1
endif

ifeq ($(DEBIAN),1)
  out := $(shell find  debrules/ -name control -type f ; ) 
  $(foreach cfile,$(out),$(shell sed -i s"/Architecture: .*/Architecture: `dpkg --print-architecture`/"g ${cfile}))
  $(foreach cfile,$(out),$(shell sed -i s"/Version: .*/Version: ${vers}/"g ${cfile}))
  #out := $(shell if [[ $$(grep -c chsbinpath ~/.bashrc) -eq 0 ]] ; then echo "PATH=/sbin:\$$PATH  \#chsbinpath" >> ~/.bashrc && . ~/.bashrc ; fi )
endif

# Only if KSRC/KOBJ were not defined on the command line.
ifeq ($(DEBIAN),1)
  ifneq ($(PDEB),1)
    KSRC ?= $(wildcard /lib/modules/$(shell uname -r)/build)
  endif
endif
KSRC ?= $(wildcard /lib/modules/$(shell uname -r)/source)
KOBJ ?= $(wildcard /lib/modules/$(shell uname -r)/build)

export KDIR
export KSRC
export KOBJ
export OFA_DIR
export logpath
export rhel6
export sles11
export libcm
export libverbs
export CONF
export cxgbtool_msg
export DEBIAN
export lio_tgtcli

uwire_supports  := bonding nvme_toe_spdk nic nic_offload toe iwarp vnic sniffer fcoe_full_offload_initiator \
                  iscsi_pdu_target iscsi_pdu_initiator fcoe_pdu_offload_target \
                  toe_ipv4 libibverbs_rpm librdmacm_rpm removeallPrevious \
                  nvme nvme_toe_install nvme_toe_uninstall wdtoe_wdudp crypto lio iser dpdk dpdk_utils tools ovs \
                  autoconf_install kernel_install
hctoe_supports := bonding nic_offload toe tools toe_ipv4  
hcrdma_supports := nic_offload iwarp tools
ll_supports := bonding nic_offload toe iwarp tools toe_ipv4 wdtoe_wdudp
un_supports := removeall uninstall_all
#nic toe ipv6 iwarp bonding vnic sniffer fcoe_full_offload_initiator\
              iscsi_pdu_target iscsi_pdu_initiator libs tools bypass fcoe_full_offload_target uninstall_all
uso_supports := bonding nic_offload udp_offload tools 
edc_only_supports := nic_offload toe iwarp tools wdtoe_wdudp 
t5_hcllwd_supports := nic_offload iwarp tools  wdtoe_wdudp 
hchashfilter_supports := nic_offload ovs tools
rdmaperf_supports := nic_offload iwarp tools nvme iser 
ifneq ($(filter $(dist),rhel7u5 rhel7u6 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 sles12sp3 sles12sp4 sles15 sles15sp1 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel4u9 kernel4u14 kernel4u19 kernel5u4 kernel5u6 kernel5u10 ),)
  iscsiperf_supports := nic_offload lio iscsi_pdu_target iscsi_pdu_initiator tools
else
  iscsiperf_supports := nic_offload toe bonding lio iscsi_pdu_target iscsi_pdu_initiator tools
endif
memfree_supports := nic_offload toe iwarp tools toe_ipv4
#ring_supports  := bonding nic nic_offload toe iwarp vnic sniffer \
                  iscsi_pdu_target iscsi_pdu_initiator fcoe_pdu_offload_target \
                  toe_ipv4 nvme crypto lio iser dpdk dpdk_utils tools ovs
hcvf_supports := nic vnic tools
nvmeperf_supports := nic_offload iwarp tools nvme nvme_toe_spdk

USER_MAKECMDGOALS := $(MAKECMDGOALS)
k=$(words $(MAKECMDGOALS))
j=0
ifeq ($(MAKELEVEL),0)
    ifeq ($(k),0)
        ifeq ($(CONF),UNIFIED_WIRE)
            MAKECMDGOALS = $(filter-out nvme_toe_install nvme_toe_uninstall nvme_toe_spdk nic bypass fcoe_pdu_offload_target toe_ipv4 nic_ipv4 crypto wdtoe_wdudp dpdk dpdk_utils ovs libibverbs_rpm librdmacm_rpm autoconf_install kernel_install removeallPrevious, ${uwire_supports})
        endif
        #ifeq ($(CONF),RING)
        #    MAKECMDGOALS = $(filter-out  nic bypass fcoe_pdu_offload_target toe_ipv4 nic_ipv4 crypto dpdk dpdk_utils ovs libibverbs_rpm librdmacm_rpm autoconf_install kernel_install removeallPrevious, ${ring_supports})
        #endif
        ifeq ($(CONF),HIGH_CAPACITY_TOE)
           MAKECMDGOALS = $(filter-out nic bypass toe_ipv4 nic_ipv4 wdtoe_wdudp ipv6, ${hctoe_supports} )
        endif
        ifeq ($(CONF),HIGH_CAPACITY_RDMA)
           MAKECMDGOALS = $(filter-out  nic toe_ipv4 nic_ipv4 wdtoe_wdudp ipv6 , ${hcrdma_supports} )
        endif
        ifeq ($(CONF),RDMA_PERFORMANCE)
           MAKECMDGOALS = $(filter-out  nic toe_ipv4, ${rdmaperf_supports} )
        endif
        ifeq ($(CONF),NVME_PERFORMANCE)
           MAKECMDGOALS = $(filter-out  nic toe_ipv4, ${nvmeperf_supports} )
        endif
        ifeq ($(CONF),LOW_LATENCY)
           MAKECMDGOALS = $(filter-out nic toe nic_offload toe_ipv4 nic_ipv4 ipv6 , ${ll_supports})
        endif
        ifeq ($(CONF),UDP_OFFLOAD)
           MAKECMDGOALS = $(filter-out nic toe_ipv4 nic_ipv4 wdtoe_wdudp, ${uso_supports})
        endif
        ifeq ($(CONF),WIRE_DIRECT_LATENCY)
           MAKECMDGOALS = $(filter-out nic toe nic_offload wdtoe_wdudp, ${edc_only_supports})
        endif
        ifeq ($(CONF),HIGH_CAPACITY_WD)
           MAKECMDGOALS = $(filter-out nic toe nic_offload wdtoe_wdudp, ${t5_hcllwd_supports})
        endif
        ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
           MAKECMDGOALS = $(filter-out ovs, ${hchashfilter_supports})
        endif
        ifeq ($(CONF),ISCSI_PERFORMANCE)
           MAKECMDGOALS = $(filter-out nic, ${iscsiperf_supports})
        endif
        ifeq ($(CONF),MEMORY_FREE)
           MAKECMDGOALS = $(filter-out nic toe_ipv4, ${memfree_supports})
        endif
        ifeq ($(CONF),HIGH_CAPACITY_VF)
           MAKECMDGOALS = ${hcvf_supports}
        endif
    endif
    ifneq ($(filter $(MAKECMDGOALS),install rpm deb), )
        ifeq ($(CONF),UNIFIED_WIRE)
           GOALS := $(foreach goal,$(filter-out nvme_toe_install nvme_toe_uninstall ovs libibverbs_rpm librdmacm_rpm autoconf_install kernel_install removeallPrevious, ${uwire_supports}),$(goal)_$(MAKECMDGOALS))
        endif
        #ifeq ($(CONF),RING)
        #   GOALS := $(foreach goal,$(filter-out ovs libibverbs_rpm librdmacm_rpm autoconf_install kernel_install removeallPrevious, ${ring_supports}),$(goal)_$(MAKECMDGOALS))
        #endif
        ifeq ($(CONF),HIGH_CAPACITY_TOE)
           GOALS := $(foreach goal,$(hctoe_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_RDMA)
           GOALS := $(foreach goal,$(hcrdma_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),RDMA_PERFORMANCE)
           GOALS := $(foreach goal,$(rdmaperf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),NVME_PERFORMANCE)
           GOALS := $(foreach goal,$(nvmeperf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),LOW_LATENCY)
           GOALS := $(foreach goal,$(ll_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),UDP_OFFLOAD)
           GOALS := $(foreach goal,$(uso_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),WIRE_DIRECT_LATENCY)
           GOALS := $(foreach goal,$(edc_only_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_WD)
           GOALS := $(foreach goal,$(t5_hcllwd_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
           GOALS := $(foreach goal,$(hchashfilter_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),ISCSI_PERFORMANCE)
           GOALS := $(foreach goal,$(iscsiperf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),MEMORY_FREE)
           GOALS := $(foreach goal,$(memfree_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifeq ($(CONF),HIGH_CAPACITY_VF)
           GOALS := $(foreach goal,$(hcvf_supports),$(goal)_$(MAKECMDGOALS))
        endif
        ifneq ($(filter $(MAKECMDGOALS),rpm deb), )
             ifneq ($(filter $(CONF),WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD LOW_LATENCY), )
                 #ifneq ($(filter $(dist),ubuntu12u04 ubuntu12u042 kernel26u35), )
                     MAKECMDGOALS := $(filter-out nic_offload_$(MAKECMDGOALS) toe_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
             else
              ifeq ($(CONF),HIGH_CAPACITY_VF)
                  MAKECMDGOALS := ${GOALS}
              else
                 MAKECMDGOALS := $(filter-out nic_offload_$(MAKECMDGOALS)  bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) crypto_$(MAKECMDGOALS) dpdk_$(MAKECMDGOALS) dpdk_utils_$(MAKECMDGOALS) ovs_$(MAKECMDGOALS),${GOALS})
              endif
             endif
        else
              ifeq ($(CONF),HIGH_CAPACITY_VF)
                  MAKECMDGOALS := ${GOALS}
              else
             ifneq ($(filter $(CONF),WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD LOW_LATENCY), )
                 #ifneq ($(filter $(dist),ubuntu12u04 ubuntu12u042 kernel26u35), )
                     ifneq ($(filter $(CONF),WIRE_DIRECT_LATENCY ), )
                        MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) nic_offload_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS)  toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS)  fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
                     else
                        MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) nic_offload_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS)  fcoe_pdu_offload_target_$(MAKECMDGOALS),${GOALS})
                     endif
             else
                 MAKECMDGOALS := $(filter-out nic_$(MAKECMDGOALS) bypass_$(MAKECMDGOALS) toe_ipv4_$(MAKECMDGOALS) nic_ipv4_$(MAKECMDGOALS) wdtoe_wdudp_$(MAKECMDGOALS) fcoe_pdu_offload_target_$(MAKECMDGOALS) crypto_$(MAKECMDGOALS) dpdk_$(MAKECMDGOALS) dpdk_utils_$(MAKECMDGOALS) ovs_$(MAKECMDGOALS),${GOALS})
             endif
             endif
        endif
    endif
    ifneq ($(filter $(MAKECMDGOALS), uninstall), )
        GOALS := $(foreach goal,$(un_supports),$(goal))
        CONF := T4_UN
        MAKECMDGOALS := ${GOALS}
    endif
    ifneq ($(k),0)
        ifneq ($(filter $(CONF),UNIFIED_WIRE HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA LOW_LATENCY WIRE_DIRECT_LATENCY HIGH_CAPACITY_WD UDP_OFFLOAD HIGH_CAPACITY_HASH_FILTER RDMA_PERFORMANCE NVME_PERFORMANCE ISCSI_PERFORMANCE MEMORY_FREE HIGH_CAPACITY_VF), )

            ifeq ($(CONF),UNIFIED_WIRE)
                conf_supports := $(uwire_supports)
            endif
            #ifeq ($(CONF),RING)
            #    conf_supports := $(ring_supports)
            #endif
            ifeq ($(CONF),HIGH_CAPACITY_TOE)
                conf_supports := $(hctoe_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_RDMA)
                conf_supports := $(hcrdma_supports)
            endif
            ifeq ($(CONF),RDMA_PERFORMANCE)
                conf_supports := $(rdmaperf_supports)
            endif
            ifeq ($(CONF),NVME_PERFORMANCE)
                conf_supports := $(nvmeperf_supports)
            endif
            ifeq ($(CONF),LOW_LATENCY)
                conf_supports := $(ll_supports)
            endif
            ifeq ($(CONF),WIRE_DIRECT_LATENCY)
                conf_supports := $(edc_only_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_WD)
                conf_supports := $(t5_hcllwd_supports)
            endif
            ifeq ($(CONF),UDP_OFFLOAD)
                conf_supports := $(uso_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
                conf_supports := $(hchashfilter_supports)
            endif
            ifeq ($(CONF),T4_CONF_TGT)
                conf_supports := $(tgt_uwire_supports)
            endif
            ifeq ($(CONF),ISCSI_PERFORMANCE)
                conf_supports := $(iscsiperf_supports)
            endif
            ifeq ($(CONF),MEMORY_FREE)
                conf_supports := $(memfree_supports)
            endif
            ifeq ($(CONF),HIGH_CAPACITY_VF)
                conf_supports := $(hcvf_supports)
            endif

            COMPILEGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(goal),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(COMPILEGOALS),$(MAKECMDGOALS))
            INSTALLGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _install, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(INSTALLGOALS),$(MAKECMDGOALS))
            UNINSTALLGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _uninstall, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(UNINSTALLGOALS),$(MAKECMDGOALS))
            RPMGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _rpm, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(RPMGOALS),$(MAKECMDGOALS))
            DEBGOALS := $(foreach goal,$(MAKECMDGOALS),\
                            $(if $(findstring $(firstword \
                            $(subst _deb, ,$(goal))),\
                            $(conf_supports)),$(goal)))
            MAKECMDGOALS := $(filter-out $(DEBGOALS),$(MAKECMDGOALS))
        endif

        ifeq ($(CONF),T4_UN)
             UNINSTALLGOALS := $(MAKECMDGOALS)
             MAKECMDGOALS := $(filter-out $(UNINSTALLGOALS),$(MAKECMDGOALS))
        endif
    endif
    UNSUPPORTEDGOALS = ${MAKECMDGOALS}
    ifneq ($(words $(UNSUPPORTEDGOALS)),0)
        ifeq ($(filter $(UNSUPPORTEDGOALS),clean prep distclean rpmclean help list_kernels list_supported), )
              $(info The $(UNSUPPORTEDGOALS) is not supported with $(CONF) configuration.)
              $(info The following targets are supported with $(CONF))
              ifeq ($(CONF),UNIFIED_WIRE)
                conf_supports := $(filter-out kernel_install autoconf_install,$(uwire_supports))
              endif
              #ifeq ($(CONF),RING)
              #  conf_supports := $(filter-out kernel_install autoconf_install,$(ring_supports))
              #endif
              ifeq ($(CONF),HIGH_CAPACITY_TOE)
                conf_supports := $(hctoe_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_RDMA)
                conf_supports := $(hcrdma_supports)
              endif
              ifeq ($(CONF),RDMA_PERFORMANCE)
                conf_supports := $(rdmaperf_supports)
              endif
              ifeq ($(CONF),NVME_PERFORMANCE)
                conf_supports := $(nvmeperf_supports)
              endif
              ifeq ($(CONF),LOW_LATENCY)
                conf_supports := $(ll_supports)
              endif
              ifeq ($(CONF),WIRE_DIRECT_LATENCY)
                conf_supports := $(edc_only_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_WD)
                conf_supports := $(t5_hcllwd_supports)
              endif
              ifeq ($(CONF),UDP_OFFLOAD)
                conf_supports := $(uso_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
                conf_supports := $(hchashfilter_supports)
              endif
              ifeq ($(CONF),T4_CONF_TGT)
                conf_supports := $(tgt_uwire_supports)
              endif
              ifeq ($(CONF),ISCSI_PERFORMANCE)
                conf_supports := $(iscsiperf_supports)
              endif
              ifeq ($(CONF),MEMORY_FREE)
                conf_supports := $(memfree_supports)
              endif
              ifeq ($(CONF),MEMORY_FREE)
                conf_supports := $(hcvf_supports)
              endif
              ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
                $(foreach var,$(conf_supports),$(info $(var)))
              else
                $(foreach var,$(conf_supports),$(if $(filter-out nic_offload,$(var)), $(info $(var))))
              endif
              $(error )
          endif
    endif
    MAKECMDGOALS = $(strip ${COMPILEGOALS}) $(strip ${INSTALLGOALS}) $(strip ${UNINSTALLGOALS}) $(strip ${RPMGOALS}) $(strip ${DEBGOALS})
    k=$(words $(MAKECMDGOALS))
endif

#ifndef wdtoe_mode
#  ifneq ($(findstring wdtoe,$(MAKECMDGOALS)),)
#    wdtoe_mode=1
#  else
#    wdtoe_mode=0
#  endif
#endif

#export wdtoe_mode

ifneq ($(filter nic_install nic_offload_install bonding_install toe_install,$(MAKECMDGOALS)),)
    $(shell rm -f /lib/modules/`uname -r`/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko;)
endif

ifneq ($(filter $(UNAME_R),3.6.11), )
    ifneq ($(filter $(kdist),RHEL6.6 RHEL6.5 RHEL6.4 RHEL6.3 RHEL6.1 RHEL6.2 RHEL6.0), )
        chfcoe_support:=
        ifneq ($(filter fcoe_pdu_offload_target  fcoe_pdu_offload_target_rpm  fcoe_pdu_offload_target_install,$(MAKECMDGOALS)), )
            enable_dcb=1
            po_fcoe=1
            CHFCOE_TARGET:=1
        endif
    else
        chfcoe_support:=kernel3u6
    endif
else
    chfcoe_support:=kernel3u6
endif
ifndef CHFCOE_TARGET
    CHFCOE_TARGET:=0
endif
export CHFCOE_TARGET
export po_fcoe

ifeq ($(filter $(MAKECMDGOALS),clean prep distclean rpmclean help list_kernels list_supported), )
  $(shell if [ -f $(modconf) ] ; then \
          if [ `grep -c "t4_perftune.sh -n" $(modconf) ` -eq 0 ] ; then \
	        sed -i s'|t4_perftune.sh|t4_perftune.sh -n |'g $(modconf) ; fi ; fi)
endif

ifeq ($(inst),)
 inst := 0
endif
nic := 0
vnic := 0
toe := 0
iwarp_libs := 0
iwarp := 0
firmware := 0
ifneq ($(USER_MAKECMDGOALS),help)
  ifndef OFA_DIR
    mod_core := $(shell modinfo ib_core -F filename 2>/dev/null )
    found := $(findstring updates,$(mod_core))
    ifndef found
        found := $(findstring mlnx-ofa_kernel,$(mod_core))
    endif
    ifneq ($(filter $(found),updates mlnx-ofa_kernel), )
        kernel_ib := $(shell rpm -qa | grep kernel-ib-devel -c )
        compat_rdma := $(shell rpm -qa | grep compat-rdma-devel -c )
        mlnx_ofed := $(shell rpm -qa | grep mlnx-ofa_kernel-devel -c )
        is_ofed := $(shell echo "$(($((kernel_ib)) + $((compat_rdma)) + $((mlnx_ofed)) )) " )
        ifeq ($(kernel_ib),1)
            ofa_path_raw := $(shell rpm -ql kernel-ib-devel | grep -w Module.symvers ) 
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
        endif
        ifeq ($(compat_rdma),1)
            ofa_path_raw := $(shell rpm -ql compat-rdma-devel | grep -w Module.symvers )
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
        endif
        ifeq ($(mlnx_ofed),1)
            ofa_path_raw := $(shell rpm -ql mlnx-ofa_kernel-devel | grep -w Module.symvers )
            ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
            OFA_DIR := $(ofa_path_final)
            libs_ofed := 1
            #$(info MLNX_OFED_PATH : $(OFA_DIR))
         endif
         ifeq ($(is_ofed),0)
	    $(warning ib_core modules exists in update path and kernel-ib-devel/compat-rdma-devel/mlnx-ofa_kernel-devel package is not installed)
         endif
         ifeq ($(OFA_DIR),)
            owner_rpm=$(shell rpm -qf $(mod_core))
            ofed_chk_inst:=$(owner_rpm)
            ofed_chk_inst:=$(subst ., ,$(ofed_chk_inst))
            #$(info $(ofed_chk_inst))
            #ifeq ($(findstring compat-rdma-3,$(ofed_chk_inst)),compat-rdma-3)
                #$(error Please Uninstall OFED-3.5 and Restart the Installation)
                #ofa_path_raw := $(shell rpm -ql compat-rdma-devel | grep -w Module.symvers )
                #ofa_path_final := $(shell echo $(ofa_path_raw) | awk -F "Module" '{ print $$1 }' )
                #OFA_DIR := $(ofa_path_final)
                #libs_ofed := 1
            #endif
            ifneq ($(findstring ofed-kmp-default,$(owner_rpm)),ofed-kmp-default)
                $(error Provide OFA_DIR=<Path to OFED Source> to build/install the drivers)
            endif
         endif
    else 
       ifdef OFA_DIR
           OFA_DIR :=
       endif
    endif
  else
       libs_ofed := 1
  endif
endif

ifneq ($(filter 3.14.57,$(UNAME_R)),)
  k31457=
else
  k31457=kernel3u14
endif

#Check whether NVMe/iSER/LIO is enabled or not in the kernel.
lio_enable := 0
iser_init_enable := 0
iser_tgt_enable := 0
nvme_init_enable := 0
nvme_tgt_enable := 0

res := $(shell modinfo nvme-rdma -F filename 2>/dev/null )
found := $(findstring kernel,$(res))
ifdef found
     nvme_init_enable := 1
endif
res := $(shell modinfo nvmet-rdma -F filename 2>/dev/null )
found := $(findstring kernel,$(res))
ifdef found
     nvme_tgt_enable := 1
endif
res := $(shell modinfo ib_iser -F filename 2>/dev/null )
found := $(findstring kernel,$(res))
ifdef found
     iser_init_enable := 1
endif
res := $(shell modinfo ib_isert -F filename 2>/dev/null )
found := $(findstring kernel,$(res))
ifdef found
     iser_tgt_enable := 1
endif
res := $(shell modinfo iscsi_target_mod -F filename 2>/dev/null )
found := $(findstring kernel,$(res))
ifdef found
     lio_enable := 1
endif

# Check NVME supported distros/kernel which allows installtion from package manager

ifneq ($(filter $(dist),ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel5u10 kernel5u6 kernel5u4 kernel5u2 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 sles15 sles15sp1 sles12sp4 kernel4u14 kernel4u19 ), )
  nvme_pkgMgr := 1
else
 nvme_pkgMgr := 0
endif

# Disable iWarp-libs support for latest distros

ifneq ($(filter $(dist),rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 sles15sp1), )
   NOLIBS:= 1
   iser_libcxgb4:= libcxgb4:libcxgb4-devel:
else
   NOLIBS:= 1
   iser_libcxgb4:= libcxgb4:libcxgb4-devel:
endif

#List of all supported Makefile targets
is_bonding := 0
is_vnic := 0
is_toe := 0
is_wdtoe := 0
is_nic := 0
is_ipv6 := 0
is_iwarp := 0
is_wd_udp := 0
is_udp_offload := 0
is_bypass := 0
is_sniffer := 0
is_fcoe_full_offload_initiator := 0
is_iscsi_full_offload_initiator := 0
is_iscsi_pdu_target := 0
is_iscsi_pdu_initiator := 0
is_fcoe_pdu_offload_target := 0
is_nvme := 0
is_nvme_toe := 0
is_crypto := 0
is_lio := 0
is_iser := 0
is_dpdk := 0
is_ovs := 0
is_nvme_toe_spdk := 0
# Below variables contains unsupported kernel for each of the above targets
ifeq ($(kernel4u9_bonding),0)
      is_bonding_kernel_unsupport := sles10sp3 sles10sp2 fedora13 fedora14 kernel26u39 kernel26u37 kernel26u36 \
                           kernel26u35 kernel26u34 kernel4u9
else
      is_bonding_kernel_unsupport := sles10sp3 sles10sp2 fedora13 fedora14 kernel26u39 kernel26u37 kernel26u36 \
                           kernel26u35 kernel26u34 kernel5u0 kernel5u2
endif
is_vnic_kernel_unsupport := kernel5u6 kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 kernel5u0 kernel5u2 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)
is_toe_kernel_unsupport := sles10sp2
is_wdtoe_kernel_unsupport := sles10sp2 sles10sp3 sles11 sles11sp4 sles12sp2 fedora13 fedora14 kernel26u39 kernel26u37 kernel26u36 \
                             rhel5u3 rhel5u4 rhel5u5 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 rhel6 rhel6u1 rhel6u8 rhel6u9  rhel6u10 \
                             rhel6u2 ubuntu12u04 ubuntu14u041 ubuntu12u042 ubuntu14u042 ubuntu14u044 ubuntu16u04 ubuntu16u041 ubuntu16u042 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel4u9 kernel4u14 kernel4u19 kernel5u0 kernel5u2 kernel5u4 kernel5u6 kernel5u10 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 sles12sp3 sles12sp4 sles15 sles15sp1 \
                             kernel3u1 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist)
is_nic_kernel_unsupport :=
is_ipv6_kernel_unsupport := kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 sles10sp3 sles10sp2 fedora13 fedora14 rhel5u3 
is_iwarp_kernel_unsupport := kernel5u6 sles10sp2 sles10sp3 sles11sp4 kernel5u0 kernel5u2 $(kdist_lib)
is_udp_offload_kernel_unsupport := sles10sp2 sles10sp3 kernel3u9 kernel3u10 kernel3u11 kernel3u12 kernel3u13 kernel4u8 ubuntu18u042 ubuntu18u043 sles12sp4 sles15 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  kernel5u0 kernel5u2 kernel5u6
is_bypass_kernel_unsupport := sles10sp3 sles10sp2 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist) ubuntu16u042 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel4u9 kernel4u14 kernel4u19 kernel5u0 rhel6u8 rhel6u10 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 sles12sp3 sles12sp4 sles15 sles15sp1 kernel5u2 kernel5u4 kernel5u6 kernel5u10
is_sniffer_kernel_unsupport :=  kernel5u6 sles10sp3 sles10sp2 sles11sp4 ubuntu12u04 ubuntu12u042 kernel3u8 kernel3u9 kernel3u10 kernel3u11 \
                                     kernel3u12 kernel3u13 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist_lib) kernel5u2 kernel5u0 sles12sp4
is_fcoe_full_offload_initiator_kernel_unsupport := kernel5u6 rhel8u1 sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 fedora14 kernel3u1 kernel26u36 kernel26u37 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu20u041 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u8 kernel4u9 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 sles15sp1 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  kernel4u19 kernel5u0 kernel5u2
is_iscsi_full_offload_initiator_kernel_unsupport := kernel5u10 kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 fedora14 kernel3u1 kernel26u36 kernel26u37 ubuntu18u041 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u8 kernel4u9 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  kernel4u19 kernel5u0 kernel5u2 kernel5u4
is_iscsi_pdu_target_kernel_unsupport := kernel5u10 kernel5u6 sles10sp2 sles10sp3 fedora13 ubuntu12u042 kernel4u9 kernel4u14 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 sles12sp3 sles12sp4 sles15 sles15sp1 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 $(aarch_7u5_dist) $(aarch_7u6_dist)   $(ppc_dist) kernel4u19 kernel5u0 kernel5u2 kernel5u4
is_iscsi_pdu_initiator_kernel_unsupport := kernel5u6 sles10sp3 fedora13 fedora14 rhel5u3 ubuntu12u04 ubuntu12u042 kernel5u0 kernel5u2
is_fcoe_pdu_offload_target_kernel_unsupport := kernel5u10 kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u8 kernel4u9 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 sles15sp1 $(chfcoe_support) $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist) kernel4u19 kernel5u0 kernel5u2 kernel5u4
is_wd_udp_kernel_unsupport := kernel5u6 es10sp2 sles10sp3 sles11sp4 $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist) kernel5u0 kernel5u2
is_rdma_block_device_kernel_unsupport := kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 fedora14 kernel3u1 kernel26u35 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u6 sles11sp1 sles11sp2 sles11sp3 sles11sp4 ubuntu14u042 ubuntu14u043 ubuntu14u044 $(chfcoe_support) $(ppc_dist) $(kdist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  kernel5u0 kernel5u2
is_nvme_kernel_unsupport := kernel5u6 es10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 $(ppc_dist) $(aarch_7u3_dist) kernel5u0
is_nvme_toe_kernel_unsupport := kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u8 kernel4u9 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 sles15sp1 $(chfcoe_support) $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist) kernel4u19 kernel5u0
is_nvme_toe_spdk_kernel_unsupport := kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel7u4 rhel7u5 rhel7u6 rhel7u7 rhel8 rhel8u1 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u8 kernel4u9 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 sles15sp1 $(chfcoe_support) $(ppc_dist) $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(kdist) kernel4u19 kernel5u0
is_crypto_kernel_unsupport :=  kernel5u6 s10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2  $(crypt_dist) kernel5u0 kernel5u2
is_lio_kernel_unsupport :=  kernel5u6 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu16u042 ubuntu16u04 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 \
                                               kernel3u12 kernel3u13 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 $(k31457) $(aarch_7u3_dist) kernel5u0 kernel5u2
is_iser_kernel_unsupport := kernel5u6 sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel7u3 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 ubuntu16u042 ubuntu16u04 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 $(ppc_dist) $(aarch_7u3_dist) kernel5u0 kernel5u2
is_dpdk_kernel_unsupport :=  kernel5u10 kernel5u6 rhel8 rhel8u1 rhel8u2 rhel8u3 rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u041  ubuntu16u044 ubuntu16u045 ubuntu16u046 fedora14 kernel3u1 kernel26u36 kernel26u37 \
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u9 kernel4u14 kernel4u19 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 sles12sp3 sles12sp4 sles15 sles15sp1 $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(ppc_dist) ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel4u19 kernel5u0 kernel5u2 kernel5u4
is_ovs_kernel_unsupport :=  kernel5u10 kernel5u6 sles10sp2 sles10sp3 sles11 rhel5u3 rhel5u4 rhel5u5 rhel6 rhel6u1 rhel6u2 rhel6u3 \
                                               rhel6u4 rhel6u5 rhel6u6 rhel6u7 rhel6u8 rhel6u9 rhel6u10 rhel7 rhel7u1 rhel7u2 rhel8 rhel8u1 rhel8u2 rhel8u3 rhel5u6 rhel5u7 rhel5u8 rhel5u9 rhel5u10 rhel5u11 \
                                               ubuntu12u04 ubuntu14u041 fedora13 ubuntu12u042 ubuntu14u042 ubuntu14u043 ubuntu14u044 ubuntu16u04 ubuntu16u041 ubuntu16u044 ubuntu16u045 ubuntu16u046 fedora14 kernel3u1 kernel26u36 kernel26u37 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042\
                                               kernel26u39 kernel3u4 kernel3u8 kernel3u9 kernel3u5 kernel3u7 kernel3u10 kernel3u11 kernel4u1 kernel4u2 kernel4u4 kernel4u5 kernel4u14 \
                                               kernel3u12 kernel3u13 kernel3u14 kernel3u16 kernel3u17 kernel3u18 sles11sp1 sles11sp2 sles11sp3 sles11sp4 sles12 sles12sp1 sles12sp2 kernel4u8 sles12sp3 sles12sp4 sles15 $(aarch_7u3_dist) $(aarch_7u5_dist) $(aarch_7u6_dist)  $(ppc_dist) kernel4u19 kernel5u0 kernel5u2 kernel5u4


#Set target availablity based on kernel version
all_special_target := is_nic is_nvme_toe_spdk is_vnic is_toe is_ipv6 is_bonding is_iwarp is_wd_udp is_udp_offload \
                     is_bypass is_sniffer is_fcoe_full_offload_initiator\
                     is_iscsi_pdu_target is_iscsi_pdu_initiator is_iscsi_full_offload_initiator \
                     is_fcoe_pdu_offload_target is_wdtoe is_rdma_block_device is_nvme is_nvme_toe is_crypto \
                     is_lio is_iser is_dpdk is_ovs
define enable_tgt 
   override $(1) := 1
endef
define disable_tgt 
   override $(1) := 0
endef

$(foreach tgt,$(all_special_target), $(if $(filter $(dist), $(value $(tgt)_kernel_unsupport)),\
                                $(eval $(call disable_tgt,$(tgt))),$(eval $(call enable_tgt,$(tgt)))))
ifeq ($(DEBUG),1)
    $(info USER command : ${USER_MAKECMDGOALS})
    $(info MAKECMDGOALS : ${MAKECMDGOALS})
    $(info TERMINATOR_CONFIGURATION : $(CONF))
    $(foreach tgt,$(all_special_target), $(info INFO : $(tgt) : $(value $(tgt))))
endif

bonding_mode := 0
ifeq ($(is_bonding),1)
 ifneq ($(filter bonding bonding_install bonding_deb bonding_rpm udp_offload udp_offload_rpm udp_offload_deb udp_offload_install,$(MAKECMDGOALS)), )
 #ifneq ($(filter bonding bonding_install bonding_deb bonding_rpm,$(MAKECMDGOALS)), )
    override bonding_mode=1
    #MAKECMDGOALS := $(filter-out nic_install nic_offload_install toe_install toe_ipv4_install,$(MAKECMDGOALS))
    #MAKECMDGOALS += $(MAKECMDGOALS) nic_offload_install toe_install
 endif
endif
export bonding_mode

NVME := 0
ifeq ($(is_nvme),1)
  ifneq ($(filter nvme nvme_install nvme_deb nvme_rpm,$(MAKECMDGOALS)),)
    ifeq ($(filter iwarp iwarp_install iwarp_deb iwarp_rpm,$(MAKECMDGOALS)),)
    udp_libs := 
    NVME := 1
    endif
  endif
endif
export NVME

ifeq ($(filter ${is_iwarp} ${is_sniffer} ${is_wdtoe} ${is_wd_udp} ${is_rdma_block_device},1),1)
  iwarp_comp := 1
endif
ifneq ($(SKIP_DEPS),1)
ifneq ($(INST_DEPS),1)
ifeq ($(filter $(USER_MAKECMDGOALS),clean distclean rpmclean help list_kernels list_supported uninstall), )
  ifeq ($(findstring uninstall,$(MAKECMDGOALS)), )
    TGTCLI:=0
    rdma_support:=0
    SLES:=0
    RHEL:=0
    DPDK_DEP := 0
    CHSPDK_DEP := 0
    SLES:=$(if $(findstring SLES,$(kdist)),1)
    RHEL:=$(if $(findstring RHEL,$(kdist)),1)
    #$(info $(findstring iscsi_pdu_initiator, $(MAKECMDGOALS)))
    ifneq ($(findstring nvme_toe_spdk, $(MAKECMDGOALS)), )
      CHSPDK_DEP := 1
    endif
    ifneq ($(findstring dpdk, $(MAKECMDGOALS)), )
      DPDK_DEP := 1
    endif
    ifneq ($(findstring iscsi_pdu_initiator, $(MAKECMDGOALS)), )
      ISCSI_INIT:= 1
    endif
    ifneq ($(findstring iser, $(MAKECMDGOALS)), )
      ISCSI_INIT:= 1
    endif
    ifeq ($(openssl),0)
      ifneq ($(filter crypto kernel,$(findstring crypto, $(MAKECMDGOALS)) $(findstring kernel, $(MAKECMDGOALS))), )
        ISCSI_INIT:= 1
      endif
    endif
    ifneq ($(filter crypto kernel,$(findstring crypto, $(MAKECMDGOALS)) $(findstring kernel, $(MAKECMDGOALS))), )
      #ifneq ($(findstring crypto, $(MAKECMDGOALS)), )
      ifeq ($(kdist),RHEL7.3)
        CRYPTO_SSL := 1
      endif
      KERN_DEPS := 1
    endif
    ifneq ($(findstring SLES11,$(kdist)),)
      dracut := 0
    endif
    ifeq ($(lio_tgtcli),1)
      ifneq ($(filter $(kdist),RHEL7.3 RHEL7.4 RHEL7.5 RHEL7.6 RHEL7.7 RHEL7.8 RHEL7.9 RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 SLES12sp3 SLES12sp4 SLES15 SLES15sp1 ubuntu-18.04.1 ubuntu-18.04.2 ubuntu-18.04.3 ubuntu-18.04.4 ubuntu-18.04.5 ubuntu-20.04 ubuntu-20.04.1 ubuntu-20.04.2 ), )
        ifneq ($(filter iser nvme lio,$(findstring iser,$(MAKECMDGOALS)) $(findstring nvme,$(MAKECMDGOALS)) $(findstring lio,$(MAKECMDGOALS))), )
          TGTCLI := 1
          lio_tgtcli := 0
        endif
      endif
    endif
    #$(info $(openssl) $(ISCSI_INIT))
    ifneq ($(filter iwarp sniffer iser nvme wdtoe_wdudp,$(findstring iwarp,$(MAKECMDGOALS)) $(findstring sniffer,$(MAKECMDGOALS)) $(findstring iser,$(MAKECMDGOALS)) $(findstring nvme,$(MAKECMDGOALS)) $(findstring wdtoe_wdudp,$(MAKECMDGOALS))), )
      rdma_support := 1
    endif
    #$(info d$(DEBIAN) r$(RHEL) s$(SLES))
    #$(info set -e ; export KOBJ=$(KOBJ) ; export lib_support=$(iwarp_comp) ; export DEB=$(DEBIAN) ; export SLES=$(SLES) ; export RHEL=$(RHEL) ; ${pwd}/scripts/res_deps.sh )
    tmp := $(shell export initimg=${initimg} vers=${vers} ; ${pwd}/scripts/init_bk.sh ; echo " $$?")
    ret := $(shell export KOBJP=$(KOBJ) CHSPDK_DEP=$(CHSPDK_DEP) rdma_support=$(rdma_support)  lib_support=$(iwarp_comp) IWARP_WPM=$(IWARP_WPM) ISCSI_INIT=$(ISCSI_INIT) CRYPTO_SSL=$(CRYPTO_SSL) DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) SRPM=$(NORPMKERNELFLAG) DRACUT=$(dracut) KERN_DEPS=${KERN_DEPS} DIST=${dist} KDIST=${kdist} tgt_cli=${TGTCLI} DPDK_DEP=${DPDK_DEP} ; ${pwd}/scripts/res_deps.sh ; echo " $$?")
    #ifneq ($(depsout),0)
    #  $(error )
    #endif
    depstr := $(wordlist 1,$(shell echo $$(($(words $(ret))-1))),$(ret))
    depstr := $(subst |,${\n},${depstr})
    $(info $(depstr))
    ifneq ($(lastword $(ret)),0)
       $(error )
    endif
    INST_DEPS:=1
  endif
endif
endif
endif
export INST_DEPS

#No need to install iwpmd via binary
IWARP_WPM := 0

ifneq ($(filter $(arch),$(ARCH64)),)
  ifeq ($(wildcard $(pathverbs64)),)
      libverbs := 0
  else
      libverbs := 1
  endif 
  ifeq ($(wildcard $(pathcm64)),)
      libcm := 0
  else 
      libcm := 1
  endif 
else 
  ifeq ($(wildcard $(pathverbs)),)
      libverbs := 0
  else
      libverbs := 1
  endif 
  ifeq ($(wildcard $(pathcm)),)
      libcm := 0
  else 
      libcm := 1
  endif 
endif

ifneq ($(firstword $(filter 1,$(NORPMKERNELFLAG) $(DEBIAN))),1)
    ifeq ($(shell rpm -qa | grep rdma-core -c),0)
    ifeq (${libverbs},1)
        verbs_rpm := $(shell rpm -qa | grep libibverbs-devel -c )
        ifeq ($(verbs_rpm),0)
            libverbs := 0
        endif
    endif
    ifeq (${libcm},1)
        cm_rpm := $(shell rpm -qa | grep librdmacm-devel -c )
        ifeq ($(cm_rpm),0)
            libcm := 0
        endif
    endif
    endif
endif
ifeq ($(firstword $(filter 1,$(NORPMKERNELFLAG) $(DEBIAN))),1)
  # set NORPMKERNELFLAG if Ubuntu or Kernel compiled on SLES.
  ifeq ($(wildcard $(pathverbs)),)
      libverbs := 0
  else
      libverbs := 1
  endif
  ifeq ($(wildcard $(pathcmu)),)
      libcm := 0
      ifeq  ($(wildcard $(pathcm)),)
          libcm := 0
      else
          libcm := 1 
      endif
  else
      libcm := 1
  endif
endif

ifeq ($(wildcard $(pathssl)),)
  openssl := 0
else
  openssl := 1
endif

ifeq ($(wildcard $(pathnl)),)
  flibnl := 0
  ifeq ($(wildcard $(pathnl3)),)
    flibnl := 0
  else
    flibnl := 1
  endif
else
  flibnl := 1
endif

# The following block of code checks for libibverbs/librdmacm on system and install 
# libibverbs/librdmacm RPM if not present on machine.
#ifneq ($(filter $(dist),rhel7u7 rhel7u8 rhel7u9 rhel8 sles15sp1 ), )
# nothing :=0
#else
 ifneq ($(filter $(MAKECMDGOALS),iwarp libs sniffer iwarp_install libs_install \
                sniffer_install sniffer_rpm iwarp_rpm libs_rpm \
                wdtoe_wdudp wdtoe_wdudp_install wdtoe_wdudp_rpm rdma_block_device rdma_block_device_install), )
    ifeq ($(is_iwarp),1)
        # Start:: Check for rdma-core Version > 28
        ifeq ($(DEBIAN),1)
          deb_arch := $(strip $(shell dpkg --print-architecture))
          rdma_core_version := $(strip $(shell dpkg-query -l rdma-core|grep ii|grep -i $(deb_arch)|awk '{print $$3}' | awk -F '.' {'print $$1'} | awk -F ' ' {'print $$1'} ))
        else
          rdma_core_version := $(strip $(shell rpm -qi rdma-core.$arch |grep Version | awk '{print $$3}' | awk -F "." '{print $$1}' | awk -F ' ' {'print $$1'} ))
        endif
        ifneq (${rdma_core_version},)
         ifeq ($(shell [[ $(rdma_core_version) -gt 28 ]] && echo 0 || echo 1 ),0)
           $(info Error: libcxgb4 does not support rdma-core version > 28)
           $(error )
         endif
        endif
        # End:: Check for rdma-core Version > 28
       ifeq ($(AUTO_INST),1)
          $(info Installing autoconf-2.63 )
          out := $(shell make --no-print-directory -C $(pwd) autoconf_install  )
        endif
        ifeq ($(DEBUG),1)
             $(info Found iWARP components in MAKECMDGOALS)
        endif
        ifeq ($(rpmgen),1)
             ifneq ($(firstword $(filter 1,$(DEBIAN) $(NORPMKERNELFLAG))),1)
                 out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R})
                 out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R})
             endif
        endif
        ifeq ($(filter 0,$(libverbs) $(libcm)),0)
             libverbs = 0
             libcm = 0
        endif
        ifeq ($(libverbs),0)
             libs_ofed := 1
             ifeq ($(firstword $(filter 1,$(NORPMKERNELFLAG) $(DEBIAN))),1)
                 $(info libibverbs devel packages are not installed on system.)
                 $(info Installing libibverbs & libibverbs-devel on System)
                 out := $(shell make libibverbs_install UNAME_R=${UNAME_R} SKIP_RPM=1 2>/dev/null )
             else
                 $(info libibverbs-devel not installed on System)
                 $(info Installing libibverbs & libibverbs-devel on System)
                 out := $(shell rpm -e libibverbs1 --allmatches --nodeps &> /dev/null)
                 out := $(shell rpm -e libibverbs --allmatches --nodeps &> /dev/null)
                 ifeq ($(DEBUG),1)
                     out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R} DEBUG=1)
                 else
                     out := $(shell make --no-print-directory libibverbs_rpm UNAME_R=${UNAME_R})
                 endif
             endif
        endif
        ifeq ($(libcm),0)
             ifeq ($(firstword $(filter 1,$(NORPMKERNELFLAG) $(DEBIAN))),1)
                 $(info librdmacm devel packages are not installed on system.)
                 $(info Installing librdmacm & librdmacm-devel on System)
                 out := $(shell make  librdmacm_install UNAME_R=${UNAME_R} SKIP_RPM=1 2>/dev/null )
             else
                 $(info librdmacm-devel not installed on System)
                 $(info Installing librdmacm & librdmacm-devel on System)
                 out := $(shell rpm -e librdmacm1 --allmatches --nodeps &> /dev/null )
                 out := $(shell rpm -e librdmacm --allmatches --nodeps &> /dev/null )
                 ifeq ($(DEBUG),1)
                     out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R} DEBUG=1)
                 else
                     out := $(shell make --no-print-directory librdmacm_rpm UNAME_R=${UNAME_R}))
                 endif
             endif
        endif
    endif
 endif
#endif
# The following block of code checks for a specific target avialablity and then changes
# the target prerequisites. If a target is not supported on a platform it clears the target
# prequisites.
ifneq ($(filter iscsi_pdu_initiator iscsi_pdu_initiator_rpm iscsi_pdu_initiator_deb iscsi_pdu_initiator_install,$(MAKECMDGOALS)),)
    installOISCSI = 0
    oiscsi_iser := 
else
    ifeq ($(shell which iscsiadm 2>/dev/null),)
      #installOISCSI = 1
      #oiscsi_iser := oiscsi-utils
      installOISCSI = 0
      oiscsi_iser :=
    else
      installOISCSI = 0
    endif
endif
export installOISCSI

ifeq ($(is_ipv6),0)
    ipv6_enable := 0
endif

ifeq ($(CONF),UNIFIED_WIRE)
    firm_config := UNIFIED_WIRE
endif
#ifeq ($(CONF),RING)
#    firm_config := RING
#endif
ifeq ($(CONF),LOW_LATENCY)
    firm_config := LOW_LATENCY_NETWORKING
endif
ifeq ($(CONF),HIGH_CAPACITY_RDMA)
    firm_config := HIGH_CAPACITY_RDMA
endif
ifeq ($(CONF),RDMA_PERFORMANCE)
    firm_config := RDMA_PERFORMANCE_CONFIGURATION
endif
ifeq ($(CONF),NVME_PERFORMANCE)
    firm_config := NVME_PERFORMANCE_CONFIGURATION
endif
ifeq ($(CONF),HIGH_CAPACITY_TOE)
    firm_config := HIGH_CAPACITY_TOE
endif
ifeq ($(CONF),ISCSI_PERFORMANCE)
    firm_config := ISCSI_PERFORMANCE_CONFIGURATION
endif
ifeq ($(CONF),MEMORY_FREE)
    firm_config := MEMORY_FREE_CONFIGURATION
endif
ifeq ($(CONF),HIGH_CAPACITY_VF)
    firm_config := HIGH_CAPACITY_VF_CONFIGURATION
    $(shell echo -e "\n* Please ensure that the adapter configuration is updated using chelsio_adapater_config.py script" >> deps.log ; )
endif
ifeq ($(CONF),UDP_OFFLOAD)
    firm_config := UDP_SEGEMENTATION_OFFLOAD
endif
ifeq ($(CONF),HIGH_CAPACITY_WD)
    firm_config := HIGH_CAPACITY_WD
endif
ifeq ($(CONF),WIRE_DIRECT_LATENCY)
    firm_config := WIRE_DIRECT_LATENCY_CONFIGURATION
    $(shell echo -e "\n* WIRE_DIRECT_LATENCY config tuning option is NOT SUPPORTED for Terminator 4 adapters" >> deps.log ; )
    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
endif
ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
    firm_config := HIGH_CAPACITY_HASH_FILTER_CONFIGURATION
    $(shell echo -e "\n* HIGH_CAPACITY_HASH_FILTER config tuning option is NOT SUPPORTED for Terminator 4 adapters" >> deps.log ; )
    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
endif

ifeq ($(CONF),T4_UN)
    firm_config := UNINSTALL   
endif

ifneq ($(findstring dpdk,$(MAKECMDGOALS)),)
  cop_dpdk := 0
endif
ifneq ($(filter $(arch),x86_64),)
 ifneq ($(filter uninstall_all,$(MAKECMDGOALS)),)
   cop_dpdk := 0
 endif
endif
export cop_dpdk
ifneq ($(filter tools_install,$(MAKECMDGOALS)),)
  ifeq ($(words $(MAKECMDGOALS)),1)
    TOOLS_UNINST := 1
  endif
endif
export TOOLS_UNINST

#ifeq ($(shell echo ${UNAME_RPM} | grep -c ^4"\."[9]),1)
ifneq ($(filter rhel7u5 rhel7u6 rhel7u7 rhel7u8 rhel7u9 rhel8 rhel8u1 rhel8u2 rhel8u3 rhel7u4 sles12sp3 sles12sp4 sles15 sles15sp1 ubuntu18u041 ubuntu18u042 ubuntu18u043 ubuntu18u044 ubuntu18u045 ubuntu20u04 ubuntu20u041 ubuntu20u042 kernel4u19 kernel4u14 kernel4u9 kernel5u4 kernel5u6 kernel5u10,$(dist)), )
  SETPTP := 1
endif
ifneq ($(filter $(arch),ppc64 ppc64le aarch64),)
  SETPTP := 0
endif
export SETPTP

ifneq ($(filter ubuntu-16.04.1 ubuntu-16.04.4 ubuntu-16.04.5 ubuntu-16.04.6  ,$(kdist)), )
  chcr :=
  INSTCHCR := 0
  chcr_sum := TLS
endif
export chcr
export INSTCHCR
export chcr_sum

#depsout := $(shell ${pwd}/scripts/check_deps.sh $(iwarp_comp))
#ifdef depsout
#    build_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$1 }' | awk -F ':' '{ print $$1 }' ))
#    ifneq ($(build_deps),0)
#        build_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$1 }' | awk -F ':' '{ print $$2 }' ))
#    endif
#    rpm_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$2 }' | awk -F ':' '{ print $$1 }' ))
#    ifneq ($(rpm_deps),0)
#        rpm_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$2 }' | awk -F ':' '{ print $$2 }' ))
#    endif
#    install_deps := $(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$3 }' | awk -F ':' '{ print $$1 }' ))
#    ifneq ($(install_deps),0)
#        install_deps_goals=$(strip $(shell echo "${depsout}" | awk -F '|' '{ print $$3 }' | awk -F ':' '{ print $$2 }' ))
#    endif
#endif
#ifeq ($(filter $(USER_MAKECMDGOALS),clean distclean rpmclean help list_kernels), )
#ifeq ($(findstring install,$(MAKECMDGOALS)),install)
#    buildprecheck=1
#    rpmprecheck=1
#    installprecheck=1
#else
#    ifeq ($(findstring rpm,$(MAKECMDGOALS)),rpm)
#        buildprecheck=1
#        rpmprecheck=1
#    else
#        buildprecheck=1
#    endif
#endif
#endif
#
#ifeq ($(buildprecheck),1)
#    ifneq ($(build_deps),0)
#        $(info Following tools are required by the package : $(build_deps_goals))
#        $(info Please install them and restart the installation.)
#        $(error )
#    endif
#endif
#
#ifeq ($(filter 1,$(NORPMKERNELFLAG) $(DEBIAN)), )
#ifeq ($(buildprecheck),1)
#    ifneq ($(rpm_deps),0)
#        $(info Following tools are required for RPM generation : $(rpm_deps_goals))
#        $(info Use SKIP_RPM=1 to continue installation without RPM generation)
#        $(error )
#    endif
#endif
#endif
#
#ifeq ($(installprecheck),1)
#    ifneq ($(install_deps),0)
#        $(info Following tools are required for installation : $(install_deps_goals))
#        $(error )
#    endif
#endif 
#
#ifneq ($(filter $(CONF),HIGH_CAPACITY_TOE HIGH_CAPACITY_RDMA), )
#    $(shell echo -e "* High Capacity Config tuning options are NOT SUPPORTED for Terminator 5 adapters" >> deps.log ; )
#    $(shell echo -e "  Please refer to README for supported config tuning options." >> deps.log ; )
#endif

define get_prerequisites
	  $(strip $(shell ${pwd}/scripts/get_prerequisites.sh $(1) $(2) ${bonding_mode} ${NORPMKERNELFLAG} ))
endef

export is_bonding 
export is_nvme_toe_spdk
export is_vnic
export is_toe
export is_nic
export is_ipv6
export is_iwarp
export is_wd_udp
export is_udp_offload
export is_bypass
export is_sniffer
export is_fcoe_full_offload_initiator
export is_iscsi_pdu_target
export is_iscsi_pdu_initiator
export is_fcoe_pdu_offload_target
export is_crypto
export is_nvme
export is_lio
export is_iser
export is_dpdk
export is_ovs
export dist
export aarch_7u5_dist
export aarch_7u6_dist
export DISTRO
export DEBUG
export vers
export libs_ofed
export kdist
export ipv6_enable
export dcb
export UM_VERSION
export enable_dcb
export ppc_dist

.DEFAULT:
	@echo "Build Targets:";\
	 echo ;\
	 echo " nic                                    - Build NIC drivers, disables all offload capablities.";\
	 echo " bonding                                - Build Bonding driver (offload).";\
	 echo " nvme_toe_spdk                          - Build chtcp driver.";\
	 echo " vnic                                   - Build vNIC driver.";\
	 echo " toe                                    - Build TOE driver (offload).";\
	 echo " toe_ipv4                               - Build TOE driver without ipv6 offload support (offload).";\
	 echo " iwarp                                  - Build iWARP driver and WD-UDP Libraries.";\
	 echo " udp_offload                            - Build UDP segmentaion offload & pacing drivers.";\
	 echo " sniffer                                - Build Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_full_offload_initiator            - Build FCoE full offload initiator driver.";\
	 echo " iscsi_pdu_target                       - Build iSCSI-target driver, firmware and utilities.";\
	 echo " iscsi_pdu_initiator                    - Build open-iSCSI Data path accelerator driver.";\
	 echo " nvme                                   - Build iWARP driver and NVMe utilities.";\
	 echo " crypto                                 - Build Crypto driver and Chelsio Openssl modules.";\
	 echo " lio                                    - Build Chelsio LIO driver and targetcli utils.";\
	 echo " iser                                   - Build Chelsio iWARP driver, iSER libraries and targetcli utils.";\
	 echo " ovs                                    - Build OVS modules and NIC driver with offload support.";\
	 echo " tools                                  - Build Chelsio utilities.";\
	 echo ;\
	 echo "Install Targets :";\
	 echo ;\
	 echo " install                                - Install all available drivers (offload).";\
	 echo " nic_install                            - Install NIC drivers and firmware, disables all offload capablities.";\
	 echo " bonding_install                        - Install Bonding driver and firmware (offload).";\
	 echo " nvme_toe_spdk_install                  - Install chtcp driver.";\
	 echo " vnic_install                           - Install vNIC driver and firmware.";\
	 echo " toe_install                            - Install TOE driver and firmware (offload).";\
	 echo " toe_ipv4_install                       - Install TOE driver without ipv6 offload support and firmware (offload).";\
	 echo " iwarp_install                          - Install iWARP driver, WD-UDP Libraries and firmware.";\
	 echo " udp_offload_install                    - Install UDP segmentaion offload & pacing driver.";\
	 echo " sniffer_install                        - Install Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_full_offload_initiator_install    - Install FCoE full offload initiator driver and firmware.";\
	 echo " iscsi_pdu_target_install               - Install iSCSI-target driver, firmware and utils.";\
	 echo " iscsi_pdu_initiator_install            - Install open-iSCSI, iSCSI-initiator, firmware and utils.";\
	 echo " nvme_install                           - Install iWARP driver and NVMe utilities.";\
	 echo " nvme_toe_install                       - Install TOE driver and NVMe utilities.";\
	 echo " crypto_install                         - Install Crypto driver and Chelsio Openssl modules.";\
	 echo " lio_install                            - Install Chelsio LIO driver and targetcli utils.";\
	 echo " iser_install                           - Install Chelsio iWARP driver, iSER libraries and targetcli utils.";\
	 echo " ovs_install                            - Install OVS modules and NIC driver with offload support.";\
	 echo " tools_install                          - Install Chelsio utilities.";\
	 echo " kernel_install                         - Install Linux-5.4.105 kernel configured for Chelsio Crypto, NVMe, LIO & ARM.";\
	 echo ;\
	 echo "Uninstall Targets :";\
	 echo ;\
	 echo " uninstall                              - Uninstall all drivers (offload).";\
	 echo " nic_uninstall                          - Uninstall NIC driver and firmware.";\
	 echo " bonding_uninstall                      - Uninstall Bonding driver and firmware (offload).";\
	 echo " nvme_toe_spdk_uninstall                - Uninstall chtcp driver.";\
	 echo " vnic_uninstall                         - Uninstall vNIC driver and firmware.";\
	 echo " toe_uninstall                          - Uninstall TOE driver and firmware (offload).";\
	 echo " toe_ipv4_uninstall                     - Uninstall TOE driver without ipv6 offload support and firmware (offload).";\
	 echo " iwarp_uninstall                        - Uninstall iWARP driver, WD-UDP Libraries and firmware.";\
	 echo " udp_offload_uninstall                  - Uninstall UDP segmentaion offload & pacing driver.";\
	 echo " sniffer_uninstall                      - Uninstall Sniffer tracing & filtering tcpdump and iwarp driver.";\
	 echo " fcoe_full_offload_initiator_uninstall  - Uninstall FCoE full offload initiator driver and firmware.";\
	 echo " iscsi_pdu_target_uninstall             - Uninstall iSCSI-target driver, firmware and utils.";\
	 echo " iscsi_pdu_initiator_uninstall          - Uninstall open-iSCSI, iSCSI-initiator, firmware and utils.";\
	 echo " nvme_uninstall                         - Uninstall NVMe utilities.";\
	 echo " nvme_toe_uninstall                     - Uninstall TOE driver and NVMe utilities.";\
	 echo " crypto_uninstall                       - Uninstall Crypto driver and Chelsio Openssl modules.";\
	 echo " lio_uninstall                          - Uninstall Chelsio LIO driver and targetcli utils.";\
	 echo " iser_uninstall                         - Uninstall Chelsio iWARP driver, iSER libraries and targetcli utils.";\
	 echo " ovs_uninstall                          - Uninstall OVS modules.";\
	 echo " tools_uninstall                        - Uninstall Chelsio utilities.";\
	 echo ;\
	 if [ $(DEBIAN) == 1 ] ; then \
	    echo "DEB Targets :";\
	    echo ;\
	    echo " deb                                    - Generate DEB for all drivers (offload).";\
	    echo " nic_deb                                - Generate DEB for NIC driver and firmware.";\
	    echo " bonding_deb                            - Generate DEB for Bonding Driver (offload).";\
	    echo " vnic_deb                               - Generate DEB for vNIC driver and firmware.";\
	    echo " toe_deb                                - Generate DEB for TOE driver and firmware (offload).";\
	    echo " toe_ipv4_deb                           - Generate DEB for TOE driver without ipv6 offload support and firmware (offload).";\
	    echo " iwarp_deb                              - Generate DEB for iWARP driver, WD-UDP Libraries and firmware.";\
	    echo " udp_offload_deb                        - Generate DEB for UDP segmentaion offload & pacing  driver.";\
	    echo " sniffer_deb                            - Generate DEB for Sniffer tracing & filtering tcpdump and iwarp driver.";\
	    echo " fcoe_full_offload_initiator_deb        - Generate DEB for full offload FCoE initiator driver and firmware.";\
	    echo " iscsi_pdu_target_deb                   - Generate DEB for iSCSI-target driver, firmware and utils.";\
	    echo " iscsi_pdu_initiator_deb                - Generate DEB for open-iSCSI, iSCSI-initiator, firmware and utils.";\
	    echo " crypto_deb                             - Generate DEB for Crypto driver.";\
	    echo " lio_deb                                - Generate DEB for Chelsio LIO driver and targetcli utils.";\
	    echo " tools_deb                              - Generate DEB for Chelsio utilities.";\
	 else \
	    echo "RPM Targets :";\
	    echo ;\
	    echo " rpm                                    - Generate RPM for all drivers (offload).";\
	    echo " nic_rpm                                - Generate RPM for NIC driver and firmware.";\
	    echo " bonding_rpm                            - Generate RPM for Bonding Driver (offload).";\
	    echo " vnic_rpm                               - Generate RPM for vNIC driver and firmware.";\
	    echo " toe_rpm                                - Generate RPM for TOE driver and firmware (offload).";\
	    echo " toe_ipv4_rpm                           - Generate RPM for TOE driver without ipv6 offload support and firmware (offload).";\
	    echo " iwarp_rpm                              - Generate RPM for iWARP driver, WD-UDP Libraries and firmware.";\
	    echo " udp_offload_rpm                        - Generate RPM for UDP segmentaion offload & pacing  driver.";\
	    echo " sniffer_rpm                            - Generate RPM for Sniffer tracing & filtering tcpdump and iwarp driver.";\
	    echo " fcoe_full_offload_initiator_rpm        - Generate RPM for full offload FCoE initiator driver and firmware.";\
	    echo " iscsi_pdu_target_rpm                   - Generate RPM for iSCSI-target driver, firmware and utils.";\
	    echo " iscsi_pdu_initiator_rpm                - Generate RPM for open-iSCSI, iSCSI-initiator, firmware and utils.";\
	    echo " crypto_rpm                             - Generate RPM for Crypto driver and Chelsio Openssl modules.";\
	    echo " lio_rpm                                - Generate RPM for Chelsio LIO driver and targetcli utils.";\
	    echo " nvme_rpm                               - Generate RPM for Chelsio iWARP driver, libraries and NVMe utils.";\
	    echo " nvme_toe_spdk_rpm                      - Generate RPM for Chelsio chtcp driver.";\
	    echo " tools_rpm                              - Generate RPM for Chelsio utilities.";\
	 fi ;\
	 echo ;\
	 echo "Other Targets :" ;\
	 echo ;\
	 echo " clean                                  - Removes all generated files.";\
	 echo " distclean                              - Removes all generated files and rpms.";\
	 echo " help                                   - Display this message.";\
	 echo ;\
	 echo "Options: These are optional args";\
	 echo ;\
	 echo " KSRC                                   - KSRC=<kernel source path> Provide the kernel source path " ;\
	 echo "                                          Note: If the option is used KOBJ should also be provided " ;\
	 echo " KOBJ                                   - KOBJ=<kernel object path> Provide the kernel object path " ;\
	 echo "                                          Note: If the option is used KSRC should also be provided " ;\
	 echo " KDIR                                   - KDIR=<kernel directory path> Provide the kernel directory path " ;\
	 echo "                                          Note: Use this option if both KSRC,KOBJ are in the same path" ;\
	 echo " CONF                                   - CONF=<Terminator configuration> Provide the Terminator configuration, available options are :";\
	 echo "                                                UNIFIED_WIRE, HIGH_CAPACITY_TOE, HIGH_CAPACITY_RDMA, HIGH_CAPACITY_VF, LOW_LATENCY, UDP_OFFLOAD,";\
         echo "                                                WIRE_DIRECT_LATENCY, HIGH_CAPACITY_WD, HIGH_CAPACITY_HASH_FILTER" ;\
	 echo "                                                RDMA_PERFORMANCE, ISCSI_PERFORMANCE, NVME_PERFORMANCE" ;\
	 echo " ipv6_disable                           - ipv6_disable=<1|0> 1 - Build all drivers without IPv6 support" ; \
	 echo "                                                             0 - Build all drivers with IPv6 support" ; \
	 echo " dcbx                                   - dcbx=<1|0> 1 - Build all drivers with DCBX support" ; \
         echo "                                                     0 - Build all drivers without DCBX support" ; \
	 echo " list_kernels                           - List all the supported kernels." ;\
	 echo " BENCHMARKS                             - BENCHMARKS=<1|0> 1 - Install Drivers with Benchmark tools" ; \
         echo "                                                           0 - Install Drivers without Benchmark tools" ;\
         echo "                                          Note: This Option can be used only with tools" ;\
         echo " SKIP_RPM                               - SKIP_RPM=1 - Install driver binaries without generating RPM/DEB packages" ; \
         echo " SKIP_INIT                              - SKIP_INIT=1 - Skip initrd/initramfs changes from package" ; \
         echo " SKIP_DEPS                              - SKIP_DEPS=1 - Skip dependency check & installation from package" ; \
         echo " SKIP_ALL                               - SKIP_ALL=1 - Selects SKIP_RPM, SKIP_INIT, SKIP_DEPS options" ; \
	 echo; 

.PHONY: all	
all: $(MAKECMDGOALS)
	
.PHONY: list_kernels
list_kernels:
	$(info List of supported kernel Versions)
	$(foreach var,$(supported_kernels),$(info $(var)))
	@ echo

.PHONY: list_supported
list_supported:
	$(info List of supported modules for ${CONF})
	$(foreach var,$(conf_supports),$(info $(var)))
	@ echo

.PHONY: nic
nic:
ifeq ($(nic),0)
	$(call prepdir) \
	  if [ $(is_nic) -eq 1 ] && [ $(CONF) != "T5_HASH_FILTER" ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic ;\
	      if [[ $(SETPTP) -eq 1 ]] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) ptp ;\
	      fi ;\
	  else \
	      echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	      echo -e "Network(NIC)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
nic = 1
endif 

.PHONY: nic_offload
nic_offload:
ifeq ($(nic),1)
	$(call prepdir) \
	  if [ $(is_nic) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic_offload ;\
	      if [[ $(SETPTP) -eq 1 ]] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) ptp ;\
	      fi ;\
	  else \
	      echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	      echo -e "Network(NIC)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
nic = 2
endif 

.PHONY: nic_ipv4
nic_ipv4:
	$(call prepdir) \
          if [ $(is_nic) -eq 1 ] ; then \
              $(MAKE) --no-print-directory -C $(NwSrc) nic_ipv4 ;\
          else \
              echo -e "INFO : \t\tNIC [ Not supported ]" ; \
              echo -e "Network(NIC_IPV4)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
          fi;\
          $(call displaysummary,$(@),Build)

.PHONY: bonding
bonding:
	$(call prepdir)\
	  if [ $(is_bonding) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) bonding ;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-Offload\t\tbonding\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 

.PHONY: vnic
vnic:
	$(call prepdir) \
	  if [ $(is_vnic) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) vnic ; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: nvme_toe_spdk
nvme_toe_spdk: $(strip $(call get_prerequisites,nvme_toe_spdk,${is_nvme_toe_spdk}))
	$(call prepdir) \
	  if [ -f  /usr/local/bin/ninja.chbak ]; then \
	        mv /usr/local/bin/ninja.chbak /usr/local/bin/ninja  2>/dev/null; \
	  fi;\
	  if [ $(is_nvme_toe_spdk) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) nvme_toe_spdk ; \
	  else\
	       echo -e "INFO : \t\tSPDK_NVMe/TOE  [ Not supported ]" ; \
	       echo -e "SPDK_NVMe/TOE\t\tchtcp\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: toe
toe: $(strip $(call get_prerequisites,toe,${is_toe}))
ifeq ($(toe),0)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) toe ;\
	  if [ $(ipv6_enable) -eq 0 ] ; then \
	       echo -e "IPv6-Offload\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-Offload(TOE)\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)
toe = 1
endif 

.PHONY: wdtoe
wdtoe: $(strip $(call get_prerequisites,wdtoe,${is_wdtoe}))
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	$(call prepdir) \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       $(MAKE) --no-print-directory -C $(NwSrc) wdtoe ;\
	  else \
	       echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	       echo -e "WD-TOE\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: wdtoe_wdudp
wdtoe_wdudp: wdtoe 
	@ if [ ${arch} != "aarch64" ] || [ ${arch} != "ppc64le" ] ; then \
	      make --no-print-directory iwarp ; \
	  else \
	       echo -e "INFO : \t\tWD-UDP [ Not supported ]" ; \
	       echo -e "WD-UDP\t\tlibcxgb4_sock\t\tBuild\tNot-supported" >> temp.log ; \
	      $(call displaysummary,$(@),Build) \
	  fi ;


.PHONY: toe_ipv4
toe_ipv4:$(strip $(call get_prerequisites,toe_ipv4,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4 ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-Offload(TOE)\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: ipv6
ipv6:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	$(call prepdir) 
	@ if [ $(is_ipv6) -eq 1 ] ; then \
		echo -e "INFO : \t\tipv6 " ;\
		echo -e "IPv6-Offload\t\tipv6\t\tBuild\tSuccessful" >> temp.log ; \
	  else \
		echo -e "INFO : \t\tipv6 [ Not supported ]" ;\
		echo -e "IPv6-Offload\t\tipv6\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: bypass
bypass:$(strip $(call get_prerequisites,bypass,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 $(call prepdir)\
	 if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) nic_bypass ;\
	 else \
	     echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	     echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	 fi ; \
	 $(call displaysummary,$(@),Build)

.PHONY: iwarp
iwarp: $(strip $(call get_prerequisites,iwarp,${is_iwarp}))
ifeq ($(iwarp),0)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_iwarp) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) iwarp ; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 
iwarp = 1
endif

.PHONY: nvme
nvme: iwarp
	$(call prepdir) \
	  if [ $(is_nvme) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils nvmecli ;\
	        $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils nvmetcli ;\
	  else \
		echo -e "INFO : \t\tnvme [ Not supported ]" ; \
		echo -e "nvme\t\tnvme\t\tBuild\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),Build)

.PHONY: lio
lio: $(strip $(call get_prerequisites,lio,${is_lio}))
	$(call prepdir) \
	  if [ $(is_lio) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(NwSrc) cxgbit ; \
	  else \
	        echo -e "INFO : \t\tlio [ Not supported ]" ; \
	        echo -e "lio\t\tLIO-Target\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: lio_utils
lio_utils:
	$(call prepdir) \
	if [ $(lio_tgtcli) -eq 1 ] ; then \
	  if [ $(is_lio) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils tgtcli tgtsum=0 ; \
	  else \
	        echo -e "INFO : \t\tLIO-Utils [ Not supported ]" ; \
	        echo -e "LIO-Utils\t\ttargetcli\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: iser
iser: iwarp
	$(call prepdir) \
	  if [ $(is_iser) -eq 1 ] ; then \
	        if [ ${IWARP_WPM} -eq 1 ] ; then \
	               $(call checklibibverbs,libiwpm,Build,,iSER) \
	        fi ; \
	        if [ $(flibnl) -eq 0 ] ; then \
	                echo -e "* iWARP Port Mapper requires libnl-devel to be installed." >> deps.log ; \
	                echo -e "  Please refer to README for the dependencies." >> deps.log ; \
	        fi ; \
	        if [ $(lio_tgtcli) -eq 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils tgtcli tgtsum=1; \
	        fi ; \
	        if [ $(installOISCSI) -ne 0 ] ; then \
	           $(MAKE) --no-print-directory -C $(NwSrc) oiscsi ; \
	        fi ; \
	  else \
	        echo -e "INFO : \t\tiSER [ Not supported ]" ; \
	        echo -e "iSER\t\tiSER\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: udp_offload
udp_offload:$(strip $(call get_prerequisites,udp_offload,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) udp_offload ; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 

.PHONY: fcoe_full_offload_initiator
fcoe_full_offload_initiator:$(strip $(call get_prerequisites,fcoe_full_offload_initiator,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: fcoe_pdu_offload_target
fcoe_pdu_offload_target:$(strip $(call get_prerequisites,fcoe_pdu_offload_target,${is_fcoe_pdu_offload_target}))
	$(call prepdir,CHFCOE_TARGET=1) \
	  if [ $(is_fcoe_pdu_offload_target) -eq 1  ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) chfcoe ; \
	  else \
                echo -e "INFO : \t\tfcoe_pdu_offload_target  [ Not supported ]" ; \
                echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: iscsi_full_offload_initiator
iscsi_full_offload_initiator:$(strip $(call get_prerequisites,iscsi_full_offload_initiator,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Build)

.PHONY: fcoe_full_offload_target
fcoe_full_offload_target:nic_offload
	$(call prepdir) \
	  if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  elif [ $(shell echo ${UNAME_R} | grep 2.6.32.12 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  elif [ $(shell echo ${UNAME_R} | grep 2.6.32-71 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] ||\
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_target [ Not supported ]" ; \
		echo -e "FCoE(full-offload-target)\t\tcsioscst\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: iscsi_pdu_target
iscsi_pdu_target: $(strip $(call get_prerequisites,iscsi_pdu_target,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) iscsi_target ; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)


.PHONY: iscsi_pdu_initiator
iscsi_pdu_initiator:$(strip $(call get_prerequisites,iscsi_pdu_initiator,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tBuild\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) cxgbi ; \
	  else \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tBuild\tNot-supported" >> temp.log ; \
		echo -e "* iSCSI PDU initiator requires openssl-devel to be installed." >> deps.log ; \
		echo -e "  Please refer to README for the dependencies." >> deps.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)


.PHONY: libs
libs:
ifeq ($(iwarp_libs),0)
	$(call prepdir) \
	  if [ $(is_iwarp) -eq 1 ] && [ $(NOLIBS) -eq 1 ]; then \
	        $(call checklibibverbs,all,Build,,libcxgb4) \
	        if [ ${IWARP_WPM} -eq 1 ] ; then \
	            $(call checklibibverbs,libiwpm,Build,,iwpm) \
	            if [ $(flibnl) -eq 0 ] ; then \
	                echo -e "* iWARP Port Mapper requires libnl-devel to be installed." >> deps.log ; \
	                echo -e "  Please refer to README for the dependencies." >> deps.log ; \
	            fi ; \
	        fi ;\
	  else \
		echo -e "INFO : \t\tiwarp-libraries  [ Not supported ]" ; \
		echo -e "RDMA(iWARP-Lib)\t\tlibcxgb4\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)
iwarp_libs = 1
endif 

.PHONY: wdtoe_libs
wdtoe_libs:
	$(call prepdir) \
	  if [ $(is_wdtoe) -eq 1 ] ; then \
	        $(call checklibibverbs,libwdtoe,Build,,libwdtoe) \
	        $(call checklibibverbs,libwdtoe_dbg,Build,,libwdtoe_dbg) \
	  else \
		echo -e "INFO : \t\twdtoe-libraries  [ Not supported ]" ; \
		echo -e "WDTOE-lib\t\tlibwdtoe\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: sniffer
sniffer: $(strip $(call get_prerequisites,sniffer,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_sniffer) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(ToolSrc) sniffer ; \
	  else \
	        echo -e "INFO : \t\tsniffer-libraries  [ Not supported ]" ; \
	        echo -e "Sniffer\t\twd_tcpdump\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: rdma_block_device
rdma_block_device: $(strip $(call get_prerequisites,rdma_block_device,${is_rdma_block_device}))
	$(call prepdir) \
	  if [ $(is_rdma_block_device) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(NwSrc) rdma_block ; \
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
		echo -e "RDMA-Block-Device\t\tRDMA\t\tBuild\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Build)

.PHONY: dpdk
dpdk:
	$(call prepdir) \
	if [ $(is_dpdk) -eq 1 ] ; then \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk ; \
	else \
	    echo -e "INFO : \t\tDPDK [ Not supported ]" ; \
	    echo -e "DPDK\t\t\tDPDK\t\tBuild\tNot-supported" >> temp.log ;\
	fi ; \
	$(call displaysummary,$(@),Build)

.PHONY: ovs
ovs: $(strip $(call get_prerequisites,ovs,${is_ovs}))
	@ if [ ! -d "build" ] ; then \
	      $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_ovs) -eq 1 ]; then \
	      $(MAKE) --no-print-directory -C $(NwSrc) ovs ; \
	  else\
	      echo -e "INFO : \t\tOVS [ Not supported ]" ; \
	      echo -e "OVS\t\topenvswitch\t\tBuild\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Build)

.PHONY: tools
tools:
	$(call prepdir) \
	  $(MAKE) --no-print-directory -C $(ToolSrc) ;\
	  $(call displaysummary,$(@),Build)

.PHONY: ba_tools
ba_tools:
	$(call prepdir) \
	  if [ $(is_bypass) -eq 1 ] ; then \
	       $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools ;\
	  else \
	       echo -e "Bypass_tools\t\tba_*\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Build)
	
.PHONY: crypto
crypto: $(strip $(call get_prerequisites,crypto,${is_crypto}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_crypto) -eq 1 ] ; then \
	        if [ ${INSTCHCR} -eq 1 ] ; then \
		    $(MAKE) --no-print-directory -C $(NwSrc) crypto ; \
		fi ; \
	  else \
		echo -e "INFO : \t\tCrypto [ Not supported ]" ; \
		echo -e "Chelsio-Crypto\t\tchcr/TLS\t\tBuild\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Build) 

.PHONY: install
install: $(MAKECMDGOALS)

.PHONY: nic_install
nic_install:$(strip $(call get_prerequisites,nic_install,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	if [ $(is_nic) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) nic_install ;\
	          if [[ $(SETPTP) -eq 1 ]] ; then \
	              $(MAKE) --no-print-directory -C $(NwSrc) ptp_install ;\
	          fi ;\
	          $(call copyconfigfile) \
	     else \
		  ( $(call installdrvrpm,nic) )  && \
	          ( $(call ptpinstall) )  &&  ( $(call copyconfigfile) )  &&  ( $(call delwdbins) ) &&  ( $(call logs,Network(NIC),cxgb4,Install ))  \
	          || $(call logtemp,Network(NIC),cxgb4,Install) \
	     fi;\
	else \
	    echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	    echo -e "Network(NIC)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	fi;\
	$(call displaysummary,$(@),Install) 

.PHONY: nic_offload_install
nic_offload_install:$(strip $(call get_prerequisites,nic_offload_install,${is_nic}))
ifeq ($(nic),2)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif

	$(call prepdir) \
	if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	if [ $(is_nic) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) nic_offload_install ;\
	          if [[ $(SETPTP) -eq 1 ]] ; then \
	              $(MAKE) --no-print-directory -C $(NwSrc) ptp_install ;\
	          fi ;\
	         $(call copyconfigfile) \
	     else \
	         ( $(call installdrvrpm,nic_offload) ) && \
	         ( $(call ptpinstall) )  &&  ( $(call copyconfigfile) ) &&  ( $(call logs,Network(NIC),cxgb4,Install ))  \
	         || $(call logtemp,Network(NIC),cxgb4,Install) \
	     fi;\
	else \
	    echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	    echo -e "Network(NIC)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	fi;\
	$(call displaysummary,$(@),Install) 
nic = 3
endif

.PHONY: nic_ipv4_install
nic_ipv4_install:$(strip $(call get_prerequisites,nic_ipv4_install,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
        if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
             rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
        fi ; \
        if [ $(is_nic) -eq 1 ] ; then \
             if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                 $(MAKE) --no-print-directory -C $(NwSrc) nic_ipv4_install ;\
                 $(call copyconfigfile) \
             else \
                 ( $(call installdrvrpm,nic_offload) ) && \
                 ( $(call copyconfigfile) ) &&  ( $(call logs,Network(NIC_IPV4),cxgb4,Install ))  \
                 || $(call logtemp,Network(NIC_IPV4),cxgb4,Install) \
             fi;\
        else \
            echo -e "INFO : \t\tNIC [ Not supported ]" ; \
            echo -e "Network(NIC_IPV4)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
        fi;\
        $(call displaysummary,$(@),Install)

.PHONY: bonding_install
bonding_install:$(strip $(call get_prerequisites,bonding_install,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)\
	  if [ $(is_bonding) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) bonding_install ;\
		  $(call copyconfigfile) \
	     else \
	         ( $(call installdrvrpm,bonding) ) && \
	         ( $(call logs,Bonding-Offload,bonding,Install)) \
	         || $(call logtemp,Bonding-Offload,bonding,Install) \
	     fi;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-Offload\t\tbonding\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: vnic_install
vnic_install:$(strip $(call get_prerequisites,vnic_install,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_vnic) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) vnic_install ;\
	          $(call copyconfigfile) \
	     else \
	       ( $(call installdrvrpm,vnic) ) && ( $(call logs,SR-IOV_networking(vNIC),cxgb4vf,Install) ) \
	       || ( $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Install) )\
	    fi;\
	  else \
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: nvme_toe_spdk_install
nvme_toe_spdk_install: $(strip $(call get_prerequisites,nvme_toe_spdk_install,${is_nvme_toe_spdk}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_nvme_toe_spdk) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] || [ ${DEBIAN} -eq 1 ] ; then \
		  $(MAKE) --no-print-directory -C $(NwSrc) nvme_toe_spdk_install ;\
	          $(call copyconfigfile) \
	     else \
	       ( $(call installdrvrpm,nvme_toe_spdk) ) && ( $(call logs,SPDK_NVMe/TOE,chtcp,Install) ) \
	       || ( $(call logtemp,SPDK_NVMe/TOE,chtcp,Install) )\
	    fi;\
	  else \
	       echo -e "INFO : \t\tSPDK_NVMe/TOE [ Not supported ]" ; \
	       echo -e "SPDK_NVMe/TOE\t\tchtcp\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: toe_install
toe_install: $(strip $(call get_prerequisites,toe_install,${is_toe}))
ifeq ($(toe),1)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) toe_install ;\
		  $(call copyconfigfile) \
	     else\
	          ( $(call installdrvrpm,toe) ) && ( $(call logs,Network-Offload(TOE),t4_tom,Install) \
                      if [ $(is_udp_offload) -eq 1 ] && [ "$(CONF)" != "ISCSI_PERFORMANCE" ]; then \
			 $(call logs,UDP-Offload,t4_tom,Install) \
		      fi ; \
                  if [ $(ipv6_enable) -eq 0 ] ; then \
		      echo -e "IPv6-Offload\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
		  else \
			$(call logs,IPv6-Offload,t4_tom,Install) \
		  fi; ) \
                  || ( $(call logtemp,Network-Offload(TOE),t4_tom,Install) )\
	     fi;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-Offload(TOE)\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)
toe = 2
endif 

.PHONY: wdtoe_install
wdtoe_install: $(strip $(call get_prerequisites,wdtoe_install,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) wdtoe_install ;\
		  $(call copyconfigfile) \
	       else\
	          ( $(call installdrvrpm,wdtoe) ) && ( $(call logs,WD-TOE,t4_tom,Install) )\
	          || ( $(call logtemp,WD-TOE,t4_tom,Install) )\
	       fi;\
	  else \
	       echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	       echo -e "WD-TOE\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: wdtoe_wdudp_install
wdtoe_wdudp_install: $(strip $(call get_prerequisites,wdtoe_wdudp_install,${is_wd_udp}))
	@ if [ $(is_wd_udp) -eq 0 ] || [ ${arch} != "x86_64" ] ; then \
	       echo -e "INFO : \t\tWD-UDP [ Not supported ]" ; \
	       echo -e "WD-UDP\t\tlibcxgb4_sock\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: wdtoe_libs_install
wdtoe_libs_install: $(strip $(call get_prerequisites,wdtoe_libs_install,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                 $(call checklibibverbs,libwdtoe_install,Install,wdtoe-Libraries,libwdtoe) \
                 $(call checklibibverbs,libwdtoe_dbg_install,Install,wdtoe-Libraries,libwdtoe_debug) \
	     else\
		  ( $(call installdrvrpm,wdtoe_lib) ) && ( $(call logs,Lib-WD-TOE,libwdtoe,Install) )\
	          || ( $(call logtemp,Lib-WD-TOE,libwdtoe,Install) )\
	     fi;\
	  else \
	       echo -e "INFO : \t\tLib WD-TOE [ Not supported ]" ; \
	       echo -e "Lib-WD-TOE\t\tlibwdtoe\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)


.PHONY: toe_ipv4_install
toe_ipv4_install: $(strip $(call get_prerequisites,toe_ipv4_install,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		 $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4_install ;\
	     else \
	          ( $(call installdrvrpm,toe_ipv4) ) &&  ( $(call logs,Network-Offload(TOE),t4_tom,Install) \
			if [ $(is_udp_offload) -eq 1 ] && [ "$(CONF)" != "ISCSI_PERFORMANCE" ]; then \
	                      $(call logs,UDP-Offload,t4_tom,Install) \
			fi ; \
	        ) || ( $(call logtemp,Network-Offload(TOE),t4_tom,Install) )\
	     fi;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       echo -e "Network-Offload(TOE)\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: ipv6_install
ipv6_install: $(strip $(call get_prerequisites,ipv6_install,${is_ipv6}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv6_install ;\
	      else\
		echo "Install IPv6"
	      fi;\
	  else  \
		echo -e "INFO : \t\tipv6 " ; \
	  fi; \
	  $(call displaysummary,$(@),Install)

.PHONY: bypass_install
bypass_install: $(strip $(call get_prerequisites,bypass_install,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 $(call prepdir)\
	if [ -f /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ] ; then \
	     rm -rf /lib/modules/$(shell uname -r)/updates/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ; \
	fi ; \
	  if [ $(is_bypass) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) nic_bypass_install ;\
		 $(call copyconfigfile) \
	     else\
	         ( $(call installdrvrpm,bypass) ) && ( $(call logs,Network-Offload(Bypass),cxgb4,Install) \
	      )  || ( $(call logtemp,Network-Offload(Bypass),cxgb4,Install) )\
	     fi;\
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call copyconfigfile) \
	  $(call displaysummary,$(@),Install)

.PHONY: iwarp_install
iwarp_install: $(strip $(call get_prerequisites,iwarp_install,${is_iwarp}))
ifeq ($(iwarp),1)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	        if [ -f /lib/modules/$(shell uname -r)/updates/drivers/infiniband/hw/cxgb4/iw_cxgb4.ko ] ; then \
	              rm -f /lib/modules/$(shell uname -r)/updates/drivers/infiniband/hw/cxgb4/iw_cxgb4.ko ;\
	        fi ; \
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		    $(MAKE) --no-print-directory -C $(NwSrc) iwarp_install; \
		    $(call copyconfigfile) \
		else \
		   $(call libcxgb4_cleanup) \
	           $(call installdrvrpm,iwarp) && ( $(call logs,RDMA(iWARP),iw_cxgb4,Install) ) || ( $(call logtemp,RDMA(iWARP),iw_cxgb4,Install) ) ; \
	            if [[ ${kdist} != "RHEL8.3" ]] && [[ ${kdist} != "RHEL8.2" ]] && [[ ${kdist} != "RHEL8.1" ]] && [[ ${kdist} != "RHEL8.0" ]] && [[ ${kdist} != "RHEL7.7" ]] && [[ ${kdist} != "RHEL7.8" ]] && [[ ${kdist} != "RHEL7.9" ]] && [[ ${kdist} != "SLES15sp1" ]] ; then \
	               ( $(call installdrvrpm,libcxgb4) ) && ( $(call logs,iWARP-lib,libcxgb4,Install) ) || ( $(call logtemp,iWARP-lib,libcxgb4,Install) )   ; \
	            else \
	               ( $(call installdrvrpm,libcxgb4) ) && ( $(call logs,iWARP-lib,libcxgb4,Install) ) || ( $(call logtemp,iWARP-lib,libcxgb4,Install) )   ; \
	            fi ;  \
	           [[ $(shell echo $(udp_libs) | grep -c libcxgb4_udp ) -gt 0 ]] && ( ( $(call installdrvrpm,libcxgb4_udp) ) && ( $(call logs,WD-UDP,libcxgb4_udp,Install) ) || \
	           ( $(call logtemp,WD-UDP,libcxgb4_udp,Install) ) ) ; \
	           [[ $(shell echo $(udp_libs) | grep -c libcxgb4_sock ) -gt 0 ]] && ( ( $(call installdrvrpm,libcxgb4_sock) ) && ( $(call logs,WD-UDP,libcxgb4_sock,Install) ) || \
	           ( $(call logtemp,WD-UDP,libcxgb4_sock,Install) ) ) ; \
	           [[ ${kdist} == "SLES15" ]] || [[ ${kdist} == "SLES15sp1" ]] || [[ ${kdist} == "SLES12sp3" ]] || [[ ${kdist} == "SLES12sp4" ]] || [[ ${kdist} == "RHEL7.4" ]] || [[ ${kdist} == "RHEL7.5" ]] || [[ ${kdist} == "RHEL7.6" ]] || [[ ${kdist} == "RHEL7.7" ]] || [[ ${kdist} == "RHEL7.8" ]] || [[ ${kdist} == "RHEL7.9" ]] || [[ ${kdist} == "RHEL8.0" ]] || [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] || [[ ${kdist} == "RHEL8.3" ]] && (( export KOBJP=$(KOBJ) lib_support=$(iwarp_comp) IWARP_WPM=$(IWARP_WPM) ISCSI_INIT=$(ISCSI_INIT) CRYPTO_SSL=$(CRYPTO_SSL) DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) SRPM=$(NORPMKERNELFLAG) DRACUT=$(dracut) KERN_DEPS=${KERN_DEPS} KDIST=${kdist} tgt_cli=${TGTCLI} DPDK_DEP=${DPDK_DEP} ; ${pwd}/scripts/iwpmd.sh ) && ( $(call logs,iWARP-lib,libiwpm,Install) ) || ( $(call logtemp,iWARP-lib,libiwpm,Install) )) ; \
	        fi;\
	           [[ ${kdist} == "RHEL6.8" ]] && (( ${pwd}/scripts/iwpmd_2.sh ) && ( $(call logs,iWARP-lib,libiwpm,Install) ) || ( $(call logtemp,iWARP-lib,libiwpm,Install) )) ; \
	        if [ ! -f /etc/udev/rules.d/90-rdma.rules ] || [ ! -f  /etc/udev/rules.d/90-ib.rules ]; then \
	             cp build/tools/90-rdma.rules /etc/udev/rules.d/ ;\
	        fi ; \
	        if [ -f /usr/local/bin/ninja.chbak ]; then \
	             mv /usr/local/bin/ninja.chbak /usr/local/bin/ninja  ;\
	        fi ; \
	       $(call installrdmatools) \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install) 
iwarp = 2
endif

.PHONY: nvme_install
nvme_install:$(strip $(call get_prerequisites,nvme_install,${is_nvme}))
	$(call prepdir) \
	  if [ $(is_nvme) -eq 1 ] ; then \
	     if [ $(nvme_tgt_enable) -eq 0 ] ; then \
	        echo -e "* NVMe Target module is not enabled/present in the current kernel." >> deps.log ;\
	     else \
	        echo "" ; \
	     fi;\
	     if [ ${nvme_pkgMgr} -eq 1 ] ; then \
	        ( export DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) ; ${pwd}/scripts/nvme_install.sh ) && ( $(call logs,NVMe-Utils,nvme,Install) ) || ( $(call logtemp,NVMe-Utils,nvme,Install) ) ;\
	       if [ ${kdist} == "ubuntu-18.04.4" ] || [[ ${kdist} == "ubuntu-18.04.5" ]]; then \
	  	  $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils nvmetcli_install ; \
	       fi;\
	     else \
	       if [ ${NORPMKERNELFLAG} == 1 ] || [ ${DEBIAN} -eq 1 ] ; then \
	  	  $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils install ; \
	       else \
	          ( $(call installdrvrpm,nvme) ) && ( $(call logs,NVMe-Utils,nvme,Install) ) || \
	          ( $(call logtemp,NVMe-Utils,nvme,Install) )\
	       fi;\
	     fi;\
	     if [ $(nvme_init_enable) -eq 0 ] ; then \
	        echo -e "* NVMe Initiator module is not enabled/present in the current kernel." >> deps.log ;\
	     fi;\
	  else \
		echo -e "INFO : \t\tnvme [ Not supported ]" ; \
		echo -e "nvme\t\tnvme\t\tInstall\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),Install)

.PHONY: nvme_toe_install
nvme_toe_install:$(strip $(call get_prerequisites,nvme_toe_install,${is_nvme_toe}))
	$(call prepdir) \
	  if [ $(is_nvme_toe) -eq 1 ] ; then \
	     if [ $(nvme_tgt_enable) -eq 0 ] ; then \
	        echo -e "* NVMe Target module is not enabled/present in the current kernel." >> deps.log ;\
	     else \
	        echo "" ; \
	     fi;\
	     if [ ${nvme_pkgMgr} -eq 1 ] ; then \
	        ( export DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) ; ${pwd}/scripts/nvme_install.sh ) && ( $(call logs,NVMe-Utils,nvme,Install) ) || ( $(call logtemp,NVMe-Utils,nvme,Install) ) ;\
	     else \
	       if [ ${NORPMKERNELFLAG} == 1 ] || [ ${DEBIAN} -eq 1 ] ; then \
	  	  $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils install ; \
	       else \
	          ( $(call installdrvrpm,nvme) ) && ( $(call logs,NVMe-Utils,nvme,Install) ) || \
	          ( $(call logtemp,NVMe-Utils,nvme,Install) )\
	       fi;\
	     fi;\
	     if [ $(nvme_init_enable) -eq 0 ] ; then \
	        echo -e "* NVMe Initiator module is not enabled/present in the current kernel." >> deps.log ;\
	     fi;\
	  else \
		echo -e "INFO : \t\tnvme-toe [ Not supported ]" ; \
		echo -e "nvme\t\tnvme-toe\t\tInstall\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),Install)

.PHONY: udp_offload_install
udp_offload_install:$(strip $(call get_prerequisites,udp_offload_install,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(NwSrc) udp_offload_install ; \
		 $(call copyconfigfile) \
	     else\
		 ( $(call installdrvrpm,udp_offload) ) && ( $(call logs,UDP-Offload,t4_tom,Install) ) && ( $(call logs,Network-Offload(TOE),t4_tom,Install) \
		  if [ $(ipv6_enable) -eq 1 ] ; then \
			$(call logs,IPv6-Offload,t4_tom,Install) \
		  fi ; )\
	         || ( $(call logtemp,UDP-Offload,t4_tom,Install) )\
	     fi;\
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Install) 

.PHONY: sniffer_install
sniffer_install:$(strip $(call get_prerequisites,sniffer_install,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_sniffer) -eq 1 ] ; then \
		if [ ${NORPMKERNELFLAG} == 1 ] ; then \
			$(MAKE) --no-print-directory -C $(ToolSrc) sniffer_install ; \
			$(call copyconfigfile) \
		else \
			( $(call installdrvrpm,sniffer) ) &&  \
		        ( $(call logs,Sniffer,wd_tcpdump,Install) ) || \
	        	( $(call logtemp,Sniffer,wd_tcpdump,Install) )\
		fi ; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: fcoe_full_offload_initiator_install
fcoe_full_offload_initiator_install:$(strip $(call get_prerequisites,fcoe_full_offload_initiator_install,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
          	if [ ${NORPMKERNELFLAG} == 1 ] ; then \
          		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_install ; \
			$(call copyconfigfile) \
          	else \
			( $(call installdrvrpm,fcoe_full_offload_initiator) ) && \
			( $(call logs,FCoE(full-offload-initiator),csiostor,Install) ) || \
		        ( $(call logtemp,FCoE(full-offload-initiator),csiostor,Install) )\
		fi ; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: iscsi_full_offload_initiator_install
iscsi_full_offload_initiator_install:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_install,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Install)

.PHONY: fcoe_full_offload_target_install
fcoe_full_offload_target_install:nic_offload_install
	$(call prepdir)
	@ if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  elif [ $(sles11) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  elif [ $(rhel6) ]  || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_install; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_target [ Not supported ]" ; \
		echo -e "FCoE(full-offload-target)\t\tcsioscst\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: fcoe_pdu_offload_target_install
fcoe_pdu_offload_target_install:$(strip $(call get_prerequisites,fcoe_pdu_offload_target_install,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ${NORPMKERNELFLAG} == 1 ] ; then \
			$(MAKE) --no-print-directory -C $(NwSrc) chfcoe_install ; \
		else \
			( $(call installdrvrpm,chfcoe) ) && \
			( $(call logs,FCoE(PDU-Offload-Target),chfcoe,Install) ) || \
			( $(call logtemp,FCoE(PDU-Offload-Target),chfcoe,Install) )\
		fi ; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target  [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: scst_chfcoe_install
scst_chfcoe_install: scst_chfcoe_rpm
	@ $(call installdrvrpm,scst_chfcoe)

.PHONY: iscsi_pdu_target_install
iscsi_pdu_target_install:$(strip $(call get_prerequisites,iscsi_pdu_target_install,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
                if [ ${NORPMKERNELFLAG} == 1 ] ; then \
                    $(MAKE) --no-print-directory -C $(NwSrc) iscsi_target ; \
                    $(MAKE) --no-print-directory -C $(NwSrc) iscsi_target_install ; \
		    $(call copyconfigfile) \
                else \
 	            ( $(call installdrvrpm,iscsi_pdu_target) ) && \
	            ( $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,Install) ) ||\
	            ( $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Install) ) \
                fi; \
	  else \
		echo -e "INFO : \t\tchiscsi_t4 [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: iscsi_pdu_initiator_install
iscsi_pdu_initiator_install:$(strip $(call get_prerequisites,iscsi_pdu_initiator_install,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir)
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ] " ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tInstall\tNot-supported" >> temp.log ;\
	  elif [ $(openssl) == "1" ] ; then \
	      if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) cxgbi ; \
	          $(MAKE) --no-print-directory -C $(NwSrc) cxgbi_install ; \
		  $(call copyconfigfile) \
	      else\
	       ( $(call installdrvrpm,iscsi_pdu_initiator) ) && \
	       ($(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,Install) \
	             if [ ${DEBIAN} == 1 ]; then \
			$(call copyiscsiconffile)\
	             fi ; \
	       ) || ($(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Install)) \
	       fi;\
	  else \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: rdma_block_device_install
rdma_block_device_install: $(strip $(call get_prerequisites,rdma_block_device_install,${is_rdma_block_device}))
	$(call prepdir) \
	  if [ $(is_rdma_block_device) -eq 1 ] ; then \
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	            $(MAKE) --no-print-directory -C $(NwSrc) rdma_block ; \
	            $(MAKE) --no-print-directory -C $(NwSrc) rdma_block_install ; \
	        else \
	           ( $(call installdrvrpm,rdma_block_device) ) && \
	           ($(call logs,RDMA-Block-Device,RDMA,Install)) || \
	           ($(call logtemp,RDMA-Block-Device,RDMA,Install)) \
	        fi ; \
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
		echo -e "RDMA-Block-Device\t\tRDMA\t\tInstall\tNot-supported" >> temp.log ;\
	  fi ;\
	  $(call displaysummary,$(@),Install)

.PHONY: libs_debug_install
libs_debug_install:
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        $(call installwdudpdebug,install_dbg) \
	  else \
	        echo -e " "  ;\
	  fi; \

.PHONY: lio_install
lio_install: $(strip $(call get_prerequisites,lio_install,${is_lio}))
	$(call prepdir) \
	  if [ $(is_lio) -eq 1 ] ; then \
	        if [ $(lio_enable) -eq 0 ] ; then \
	            echo -e "* LIO module is not enabled/present in the current kernel." >> deps.log ;\
	        else \
	            echo ""  ;\
	        fi;\
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	            $(MAKE) --no-print-directory -C $(NwSrc) cxgbit_install ; \
	        else \
	            ( $(call installdrvrpm,lio) ) && \
	            ($(call logs,LIO-Target,cxgbit,Install)) || \
	            ($(call logtempc,LIO-Target,cxgbit,Install) \
	            if [[ ${kdist} == "RHEL7.4" ]] || [[ ${kdist} == "RHEL7.5" ]] || [[ ${kdist} == "RHEL7.6" ]] || [[ ${kdist} == "RHEL7.7" ]] || [[ ${kdist} == "RHEL7.8" ]] || [[ ${kdist} == "RHEL7.9" ]] || [[ ${kdist} == "RHEL8.0" ]] || [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] || [[ ${kdist} == "RHEL8.3" ]] || [[ ${kdist} == "ubuntu-18.04.1" ]] || [[ ${kdist} == "ubuntu-18.04.2" ]] || [[ ${kdist} == "ubuntu-18.04.3" ]] || [[ ${kdist} == "ubuntu-18.04.4" ]] || [[ ${kdist} == "ubuntu-18.04.5" ]] || [[ ${kdist} == "ubuntu-20.04" ]] || [[ ${kdist} == "ubuntu-20.04.1" ]] || [[ ${kdist} == "ubuntu-20.04.2" ]] ; then \
	              echo -e "* LIO compilation has failed since its header files are not present in the current kernel," >> deps.log ;\
	              echo -e "  Please specify a Kernel Source[KSRC] path with LIO headers." >> deps.log ; \
	              echo -e "  Please refer to README/User Guide for more information." >> deps.log ; \
	            else \
	              echo -e "* Please ensure that the kernel is compiled with LIO parameters and target patch." >> deps.log ; \
	              echo -e "  Please refer to README/User Guide for more information." >> deps.log ; \
	            fi ; ) \
	        fi ; \
	  else \
	        echo -e "INFO : \t\tLIO-Target [ Not supported ]" ; \
	        echo -e "lio\t\tLIO-Target\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: lio_utils_install
lio_utils_install:
	$(call prepdir) \
	if [ $(lio_tgtcli) -eq 1 ] ; then \
	  [[ -f /usr/bin/targetcli ]] && [[ ! -f /usr/bin/targetcli.chold ]] && mv /usr/bin/targetcli /usr/bin/targetcli.chold || echo "" ; \
	  if [ $(is_lio) -eq 1 ] ; then \
	            $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils tgtcli_install tgtsum=0 ; \
	  else \
	        echo -e "INFO : \t\tLIO-Utils [ Not supported ]" ; \
	        echo -e "LIO-Utils\t\ttargetcli\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: iser_install
iser_install: $(strip $(call get_prerequisites,iser_install,${is_iser}))
	$(call prepdir) \
	  if [ $(is_iser) -eq 1 ] ; then \
	        if [ $(iser_init_enable) -eq 0 ] ; then \
	           echo -e "* iSER Initiator module is not enabled/present in the current kernel." >> deps.log ;\
	        else \
	           echo "" ; \
	        fi;\
	        if [ $(iser_tgt_enable) -eq 0 ] ; then \
	           echo -e "* iSER Target module is not enabled/present in the current kernel." >> deps.log ;\
	        else \
	           echo "" ; \
	        fi;\
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	             if [ ${IWARP_WPM} -eq 1 ] ; then \
	                 $(call checklibibverbs,libiwpm_install,Install,iSER-Libraries,libiwpm) \
	             fi ; \
	             if [ $(lio_tgtcli) -eq 1 ] ; then \
	               $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils tgtcli_install tgtsum=1 ; \
	             fi ; \
	             if [ $(installOISCSI) -ne 0 ] ; then \
	                 $(MAKE) --no-print-directory -C $(NwSrc) oiscsi_install ; \
	             fi ; \
	        else \
	             ( if [ $(lio_tgtcli) -eq 1 ] ; then \
	               $(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils tgtcli_install tgtsum=1 ; \
	             fi ;\
	             ( $(call installdrvrpm,iser) ) && \
	             ( $(call logs,iSER,iSER,Install) ) || \
	             ( $(call logtemp,iSER,iSER,Install) ) ); \
	        fi ; \
	  else \
	        echo -e "INFO : \t\tiSER [ Not supported ]" ; \
	        echo -e "iSER\t\tiSER\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: libs_install
libs_install:$(strip $(call get_prerequisites,libs_install,${is_iwarp}))
	@ echo " ";
ifeq ($(iwarp_libs),1)
	$(call prepdir)
	@ if [ $(is_iwarp) -eq 1 ] && [ $(NOLIBS) -eq 1 ]; then \
	        if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	           $(call checklibibverbs,libcxgb4_install,Install,iwarp-Libraries,libcxgb4) \
	           $(call checklibibverbs,install,Install,,WD_UDP) \
	           if [ ${IWARP_WPM} -eq 1 ] ; then \
	              $(call checklibibverbs,libiwpm_install,Install,iwarp-Libraries,libiwpm) \
	           fi ; \
	        else\
	            ( ( $(call installdrvrpm,libs) ) && \
	            ( $(call logs,iWARP-lib,libcxgb4,Install) ) || \
	            ( $(call logtemp,iWARP-lib,libcxgb4,Install) )) ; \
	        fi;\
	  else \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "RDMA(iWARP-Lib)\t\tlibcxgb4\t\tInstall\tNot-supported" >> temp.log ;\
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\tInstall\tNot-supported" >> temp.log ;\
	  fi; \
	  $(call displaysummary,$(@),Install)
iwarp_libs = 2
endif

.PHONY: crypto_install
crypto_install: $(strip $(call get_prerequisites,crypto_install,${is_crypto}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_crypto) -eq 1 ] ; then \
	       if [ ${NORPMKERNELFLAG} == 1 ] || [[ ${kdist} == "RHEL8.0" ]] || [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] || [[ ${kdist} == "RHEL8.3" ]]; then \
	           if [ ${INSTCHCR} -eq 1 ] ; then \
	               $(MAKE) --no-print-directory -C $(NwSrc) crypto_install ; \
	           fi ; \
	           $(pwd)/scripts/instKernel.sh $(kdist) 1 ; \
	       else \
                 ( $(call installdrvrpm,crypto) ) && \
	         ( $(pwd)/scripts/instKernel.sh $(kdist) 1 ) && \
                 ( $(call logs,Chelsio-Crypto,${chcr_sum},Install ))  \
                 || ($(call logtemp,Chelsio-Crypto,${chcr_sum},Install)) \
	       fi ; \
	       if [[ ${kdist} == "ubuntu-16.04.6" ]] || [[ ${kdist} == "RHEL7.4" ]] ; then \
	             [[ -d /usr/chssl/openssl/ ]] && install -Dv -m 644 $(NwSrc)/chopenssl-1.0.2d/apps/openssl-tls.cnf /usr/chssl/openssl/openssl.cnf && \
	             [[ ${kdist} == "RHEL7.4" ]] && sed -i s'|^#openssl_conf = openssl_def|openssl_conf = openssl_def|'g /usr/chssl/openssl/openssl.cnf || echo ; \
	       fi ; \
	       if [[ `echo "${kdist}" | grep -ic "ubuntu-20.04"` -gt 0 ]]  ; then \
	             $(pwd)/scripts/copysslLibs.sh $(kdist) ; \
	       fi ; \
	       if [[ `echo "${kdist}" | grep -ic "ubuntu-18.04"` -gt 0 ]]  ; then \
	             $(pwd)/scripts/copysslLibs-u18.sh $(kdist) ; \
	       fi ; \
	       if [[ ${kdist} == "RHEL7.5" ]] || [[ ${kdist} == "RHEL7.6" ]] || [[ ${kdist} == "RHEL7.7" ]] || [[ ${kdist} == "RHEL7.8" ]] || [[ ${kdist} == "RHEL7.9" ]] ; then \
	             sed -i s'|^openssl_conf = openssl_def|#openssl_conf = openssl_def|'g /usr/chssl/openssl/openssl.cnf || echo ; \
	       fi ; \
	       depmod -a ; \
	  else \
		echo -e "INFO : \t\tCrypto [ Not supported ]" ; \
		echo -e "Chelsio-Crypto\t\tchcr/TLS\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),Install) 

.PHONY: chssl_install
chssl_install:
	$(call prepdir) \
	  if [ $(is_crypto) -eq 1 ] ; then \
	        $(MAKE) --no-print-directory -C $(NwSrc) chssl_install ; \
	  fi ;\
	  $(call displaysummary,$(@),Install) 

.PHONY: dpdk_install
dpdk_install: $(strip $(call get_prerequisites,dpdk_install,${is_dpdk}))
	$(call prepdir) \
	if [ $(is_dpdk) -eq 1 ] ; then \
	    $(MAKE) --no-print-directory -C $(LibSrc) libpcap_install ; \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk_install ; \
	    $(MAKE) --no-print-directory -C $(NwSrc) pktgen ; \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk_tools_install ; \
	    depmod -a ; \
	else \
	    echo -e "INFO : \t\tDPDK [ Not supported ]" ; \
	    echo -e "DPDK\t\tDPDK\t\tInstall\tNot-supported" >> temp.log ;\
	fi; \
	$(call displaysummary,$(@),Install)

.PHONY: dpdk_utils_install
dpdk_utils_install:
	$(call prepdir) \
	if [ $(is_dpdk) -eq 1 ] ; then \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk_tools_install ; \
	fi ; \
	$(call displaysummary,$(@),Install)

.PHONY: ovs_install
ovs_install:$(strip $(call get_prerequisites,ovs_install,${is_ovs}))
 ifeq ($(DEBUG),1)
        $(info TGT : $@)
        $(info PRE : $<)
 endif
	@ if [ ! -d "build" ] ; then \
	      $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_ovs) -eq 1 ]; then \
	      if [ 1 == 1 ] ; then \
	          $(MAKE) --no-print-directory -C $(NwSrc) ovs_install ;\
	      else \
	          ( $(call installdrvrpm,ovs) ) && ( $(call logs,OVS,openvswitch,Install) ) \
	          || ( $(call logtemp,OVS,openvswitch,Install) )\
	      fi;\
	  else \
	      echo -e "INFO : \t\topenvswitch [ Not supported ]" ; \
	      echo -e "OVS\t\topenvswitch\t\tInstall\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),Install)

.PHONY: tools_install
tools_install:$(strip $(call get_prerequisites,tools_install,1))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ ${NORPMKERNELFLAG} == 1 ] ; then \
	       $(MAKE) --no-print-directory -C $(ToolSrc) install ;\
	       if [ ${BENCHMARK_FLAG} == 1 ] ; then \
	           $(MAKE) --no-print-directory -C $(ToolSrc) benchmarks_install ;\
	       fi ; \
	  else \
	       ( $(call installdrvrpm,tools) ) &&  \
	       ( $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),Install) ) || \
	       ( $(call logtemp,Chelsio-utils(tools),$(cxgbtool_msg),Install) ) ;\
	  fi;\
	  if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
	     if [ ${UM_INST} -eq 1 ] ; then \
	         $(MAKE) --no-print-directory -C $(ToolSrc) um_install ;\
	     fi; \
	  elif [ ${INSTALL_UM} -eq 1 ] ; then \
	     echo -e "Chelsio-Mgmt\t\tUM\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call delwdbins) \
	  $(call displaysummary,$(@),Install)

.PHONY: ba_tools_install
ba_tools_install:
	$(call prepdir) \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools_install ;\
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\tInstall\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),Install)

.PHONY: libibverbs_install
libibverbs_install: prep
	@ echo "################################################" ;\
          echo "#         Installing libibverbs Library        #" ;\
          echo "################################################" ;
	@ $(MAKE) --no-print-directory -C $(LibSrc) libibverbs_install ; 

.PHONY: librdmacm_install
librdmacm_install: prep
	@ echo "################################################" ;\
          echo "#         Installing librdmacm Library         #" ;\
          echo "################################################" ;
	@ $(MAKE) --no-print-directory -C $(LibSrc) librdmacm_install ;

.PHONY: autoconf_install
autoconf_install: prep 
	$(call prepdir)
	@ if [ $(AUTO_INST) -eq 1 ] ; then \
	     $(MAKE) --no-print-directory -C $(ToolSrc) autoconf ; \
	  fi ;

.PHONY: kernel_install
kernel_install:
	@ $(pwd)/scripts/instKernel.sh $(kdist) 0 ;

.PHONY: uninstall
uninstall: $(MAKECMDGOALS)
#uninstall: nic_uninstall vnic_uninstall toe_uninstall bonding_uninstall ipv6_uninstall iwarp_uninstall fcoe_full_offload_initiator_uninstall\
	iscsi_pdu_target_uninstall iscsi_pdu_initiator_uninstall libs_uninstall sniffer_uninstall tools_uninstall
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: nic_uninstall
nic_uninstall:
ifeq ($(nic),3)
	$(call prepdir) \
	  if [ $(is_nic) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,nic)) && ( $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ) \
	       || ($(call logtemp,Network(NIC),cxgb4,Uninstall) ) ) ;\
	  else \
	       echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Network(NIC)\t\tcxgb4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
 	  fi;\
	  $(call displaysummary,$(@),Uninstall)
nic = 4
endif

.PHONY:nic_offload_uninstall
nic_offload_uninstall:
ifeq ($(nic),4)
	$(call prepdir) \
	  if [ $(is_nic) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,nic_offload) ) && ( $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ) || \
	       ($(call logtemp,Network(NIC),cxgb4,Uninstall))) ;\
	       if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
                   if [ ${UM_UNINST} == 1 ] ; then \
	               $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
                   fi; \
	       fi ; \
	  else \
	       echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Network(NIC)\t\tcxgb4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)
nic = 5
endif

.PHONY:nic_ipv4_uninstall
nic_ipv4_uninstall:
	$(call prepdir) \
          if [ $(is_nic) -eq 1 ] ; then \
               $(call uninstalldrvrpm,nic_offload) \
               $(MAKE) --no-print-directory -C $(NwSrc) nic_uninstall ;\
               if [ ${DISTRO} == "SLES11sp2" ] || [ ${DISTRO} == "RHEL6.3" ] ||\
                   [ ${DISTRO} == "RHEL5.8" ]; then \
                   $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
               fi ; \
          else \
               echo -e "INFO : \t\tNIC [ Not supported ]" ; \
          fi;\
          $(call displaysummary,$(@),Uninstall)

.PHONY: bonding_uninstall
bonding_uninstall:
	$(call prepdir)\
	  if [ $(is_bonding) -eq 1 ] ; then \
	        ( ( $(call uninstalldrvrpm,bonding) ) && ($(MAKE) --no-print-directory -C $(NwSrc) bonding_uninstall) \
	        || ($(call logtemp,Bonding-Offload,bonding,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Bonding-Offload\t\tbonding\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: vnic_uninstall
vnic_uninstall:
	$(call prepdir) \
	  if [ $(is_vnic) -eq 1 ]; then \
	       ( ( $(call uninstalldrvrpm,vnic)) && ($(MAKE) --no-print-directory -C $(NwSrc) vnic_uninstall) || \
               ($(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,Uninstall))) ;\
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: nvme_toe_spdk_uninstall
nvme_toe_spdk_uninstall: nic_offload_uninstall
	$(call prepdir) \
	  if [ $(is_nvme_toe_spdk) -eq 1 ]; then \
	       ( ( $(call uninstalldrvrpm,nvme_toe_spdk)) && ($(MAKE) --no-print-directory -C $(NwSrc) nvme_toe_spdk_uninstall) || \
               ($(call logtemp,SPDK_NVMe/TOE,chtcp,Uninstall))) ;\
	  else\
	       echo -e "INFO : \t\tchtcp [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "SPDK_NVMe/TOE\t\tchtcp\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  /bin/rm -f /usr/local/bin/nvmf_tgt  2>/dev/null; \
	  if [ -f  /usr/local/bin/ninja ]; then \
	        mv /usr/local/bin/ninja /usr/local/bin/ninja.chbak  2>/dev/null; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: toe_uninstall
toe_uninstall:
ifeq ($(toe),2)
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	       ( ( $(call uninstalldrvrpm,toe)) && ($(MAKE) --no-print-directory -C $(NwSrc) toe_uninstall) || \
	       ($(call logtemp,Network-Offload(TOE),t4_tom,Uninstall))) ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Network-Offload(TOE)\t\tt4_tom\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)
toe = 3
endif

.PHONY: wdtoe_uninstall
wdtoe_uninstall:
	$(call prepdir) \
	  if [ $(is_wdtoe) -eq 1 ]; then \
	       if [ ${NORPMKERNELFLAG} == 1 ] ; then \
		   $(MAKE) --no-print-directory -C $(NwSrc) wdtoe_uninstall ;\
	           $(MAKE) --no-print-directory -C $(LibSrc) libwdtoe_uninstall ;\
	       else \
	           ( ( $(call uninstalldrvrpm,wdtoe) ) && ($(MAKE) --no-print-directory -C $(NwSrc) wdtoe_uninstall) || \
	           ($(call logtemp,WD-TOE,t4_tom,Uninstall))) ;\
               fi ; \
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "WD-TOE\t\tt4_tom\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: wdtoe_wdudp_uninstall
wdtoe_wdudp_uninstall: iwarp_uninstall wdtoe_uninstall
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: toe_ipv4_uninstall
toe_ipv4_uninstall:
	$(call prepdir) \
	  if [ $(is_toe) -eq 1 ]; then \
	      ( (  $(call uninstalldrvrpm,toe_ipv4)) && ($(MAKE) --no-print-directory -C $(NwSrc) toe_ipv4_uninstall) || \
	      ($(call logtemp,Network-Offload(TOE),t4_tom,Uninstall) )) ;\
	  else \
	       echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Network-Offload(TOE)\t\tt4_tom\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: bypass_uninstall
bypass_uninstall:$(strip $(call get_prerequisites,bypass_uninstall,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 $(call prepdir)\
	  if [ $(is_bypass) -eq 1 ] ; then \
	        ( ($(call uninstalldrvrpm,bypass)) && ($(MAKE) --no-print-directory -C $(NwSrc) nic_bypass_uninstall) || \
	        ($(call logtemp,Network-Offload(Bypass),cxgb4,Uninstall))) ;\
	   else \
	       echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	   fi ; \
	   $(call displaysummary,$(@),Uninstall)

.PHONY: ipv6_uninstall
ipv6_uninstall: 
	$(call prepdir)
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ $(shell echo $$(uname -r) | grep 2\.6\.34 ) ]; then \
	           $(MAKE) --no-print-directory -C $(NwSrc) ipv6_uninstall ; \
	      else\
	           $(MAKE) --no-print-directory -C $(NwSrc) toe_ipv6_uninstall ;\
	      fi;\
	      $(call uninstalldrvrpm,ipv6) \
	  else  \
		echo -e "INFO : \t\tipv6 " ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "IPv6-Offload\t\tipv6\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  /bin/rm -f /lib/modules/$(shell uname -r)/updates/kernel/net/ipv6/ipv6.ko 2>/dev/null; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iwarp_uninstall
iwarp_uninstall:$(strip $(call get_prerequisites,iwarp_uninstall,${is_iwarp}))
ifeq ($(iwarp),2)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	         $(call libcxgb4_cleanup) \
	         ( ( $(call uninstalldrvrpm,iwarp) ) &&  ( $(MAKE) --no-print-directory -C $(NwSrc) iwarp_uninstall; ) \
                   && ( $(call uninstallrdmatools) ) || ( $(call logtemp,RDMA(iWARP),iw_cxgb4,Uninstall) ) ) ; \
	  else \
	        echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)
iwarp = 3
endif

.PHONY: udp_offload_uninstall
udp_offload_uninstall: bonding_uninstall
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	$(call prepdir) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	      ( ($(call uninstalldrvrpm,udp_offload)) && ($(MAKE) --no-print-directory -C $(NwSrc) udp_offload_uninstall ) && \
	      ( $(call logs,Bonding-Offload,bonding,Uninstall) ) || \
	      ($(call logtemp,UDP-Offload,t4_tom,Uninstall))); \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "UDP-Offload\t\tt4_tom\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall) 

.PHONY: sniffer_uninstall
sniffer_uninstall: 
	$(call prepdir) \
	  if [ $(is_sniffer) -eq 1 ] ; then \
	       $(call uninstalldrvrpm,sniffer) \
	       $(MAKE) --no-print-directory -C $(ToolSrc) sniffer_uninstall ; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Sniffer\t\twd_tcpdump\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_full_offload_initiator_uninstall
fcoe_full_offload_initiator_uninstall:
	$(call prepdir)
	-@ find /etc/modprobe.d/ -name csiostor.conf -exec rm -f {} \+
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	     ( ($(call uninstalldrvrpm,fcoe_full_offload_initiator)) && ($(MAKE) --no-print-directory -C $(NwSrc) fcoe_uninstall) \
	       || ($(call logtemp,FCoE(full-offload-initiator),csiostor,Uninstall))); \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_full_offload_initiator_uninstall
iscsi_full_offload_initiator_uninstall:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_uninstall,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_pdu_offload_target_uninstall
fcoe_pdu_offload_target_uninstall:
	$(call prepdir)
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		( ($(call uninstalldrvrpm,chfcoe) ) && ($(MAKE) --no-print-directory -C $(NwSrc) chfcoe_uninstall) && \
	        ($(call uninstalldrvrpm,scst_chfcoe)) || ($(call logtemp,FCoE(pdu-offload-target),chfcoe,Uninstall))); \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: fcoe_full_offload_target_uninstall
fcoe_full_offload_target_uninstall:
	$(call prepdir)
	@ if [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  elif [ $(sles11) ] ; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  elif [ $(rhel6) ]  || [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) --no-print-directory -C $(NwSrc) fcoe_target_uninstall; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_pdu_initiator_uninstall
iscsi_pdu_initiator_uninstall:
	$(call prepdir)
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ] " ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  else \
	       ( ($(call uninstalldrvrpm,iscsi_pdu_initiator)) && ($(MAKE) --no-print-directory -C $(NwSrc) oiscsi_uninstall) || \
	       ($(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,Uninstall))) ;\
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: iscsi_pdu_target_uninstall
iscsi_pdu_target_uninstall:
	$(call prepdir)
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,iscsi_pdu_target)) && ($(MAKE) --no-print-directory -C $(NwSrc) iscsi_target_uninstall) || \
	       ($(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\tchiscsi_t4 [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: scst_chfcoe_uninstall
scst_chfcoe_uninstall:
	@ $(call uninstalldrvrpm,scst_chfcoe)

.PHONY: rdma_block_device_uninstall
rdma_block_device_uninstall:
	$(call prepdir)
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	       ( ($(call uninstalldrvrpm,rdma_block_device)) && ($(MAKE) --no-print-directory -C $(NwSrc) rdma_block_uninstall) || \
	       ($(call logtemp,RDMA-Block-Device,rbd,Uninstall))) ;\
	  else \
		echo -e "INFO : \t\trdma_block_device [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "RDMA-Block-Device\t\trbd\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: libs_uninstall
libs_uninstall:
ifeq ($(iwarp_libs),2)
	$(call prepdir)
	@ if [ $(is_iwarp) -eq 1 ] && [ $(NOLIBS) -eq 1 ]; then \
	        ( ( $(call uninstalldrvrpm,libs) ) && ( $(call checklibibverbs,uninstall,Uninstall,,libcxgb4/WD_UDP) ) || ( $(call logtemp,iWARP-lib,libcxgb4,Uninstall) ) ) ; \
	  else \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "iWARP-lib\t\tlibcxgb4\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall) 
iwarp_libs = 3
endif

.PHONY: crypto_uninstall
crypto_uninstall:
	$(call prepdir) \
	  if [ $(is_crypto) -eq 1 ] ; then \
                 ( $(call uninstalldrvrpm,crypto) ) && ( $(MAKE) --no-print-directory -C $(NwSrc) crypto_uninstall ) \
                 || ($(call logtemp,Chelsio-Crypto,${chcr_sum},Uninstall)) ;\
	         if [ -f /etc/ssh/sshd_config.chbak ] ; then \
	             mv /etc/ssh/sshd_config.chbak /etc/ssh/sshd_config ; \
	         fi ; \
	         if [ -f /etc/ssl/openssl.cnf.chbak ] ; then \
	             mv /etc/ssl/openssl.cnf.chbak /etc/ssl/openssl.cnf ; \
	         fi ; \
	         if [ -f /etc/httpd/conf.d/ssl.conf.orig ] ; then \
	             mv /etc/httpd/conf.d/ssl.conf.orig /etc/httpd/conf.d/ssl.conf ; \
	         fi ; \
	         if [ -f /usr/lib64/engines-1.1/afalg.so.orig ] ; then \
	             mv /usr/lib64/engines-1.1/afalg.so.orig /usr/lib64/engines-1.1/afalg.so ; \
	         fi ; \
	         if [ -f /lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig ] ; then \
	             mv /lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig /lib/x86_64-linux-gnu/engines-1.1/afalg.so ; \
	         fi ; \
	         if [ -f /lib/x86_64-linux-gnu/libcrypto.so.1.1.orig ] ; then \
	             mv /lib/x86_64-linux-gnu/libcrypto.so.1.1.orig /lib/x86_64-linux-gnu/libcrypto.so.1.1 ; \
	         fi ; \
	         if [ -f /lib/x86_64-linux-gnu/libssl.so.1.1.orig ] ; then \
	             mv /lib/x86_64-linux-gnu/libssl.so.1.1.orig /lib/x86_64-linux-gnu/libssl.so.1.1 ; \
	         fi ; \
	         if [ -f /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig ] ; then \
	             mv /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so ; \
	         fi ; \
	         if [ -f /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1.orig ] ; then \
	             mv /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1.orig /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1 ; \
	         fi ; \
	         if [ -f /usr/lib/x86_64-linux-gnu/libssl.so.1.1.orig ] ; then \
	             mv /usr/lib/x86_64-linux-gnu/libssl.so.1.1.orig /usr/lib/x86_64-linux-gnu/libssl.so.1.1 ; \
	         fi ; \
	         rm -rf /usr/chssl;\
	         if [[ ${kdist} == "RHEL7.5" ]] || [[ ${kdist} == "RHEL7.6" ]] || [[ ${kdist} == "RHEL7.7" ]] || [[ ${kdist} == "RHEL7.8" ]] || [[ ${kdist} == "RHEL7.9" ]] ; then \
	              ( echo -n "Restarting ssh service : " ; service sshd restart &> /dev/null && echo "Done") || echo "" ; \
	         fi ; \
	         [[ ! -f /usr/bin/dpkg ]] && $(pwd)/scripts/instOpenssl.sh $(kdist)  || echo ""; \
	         if [ -f /etc/pki/tls/openssl.cnf.chbak ] ; then \
	             mv /etc/pki/tls/openssl.cnf.chbak /etc/pki/tls/openssl.cnf ; \
	         fi ; \
	         if [ -f /usr/lib/ssl/openssl.cnf.chbak ] ; then \
	             mv /usr/lib/ssl/openssl.cnf.chbak /usr/lib/ssl/openssl.cnf ; \
	         fi ; \
	  else \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "Chelsio-Crypto\t\t${chcr_sum}\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ;\
	  $(call displaysummary,$(@),Uninstall) 

.PHONY: tools_uninstall
tools_uninstall:
	$(call prepdir) \
	  $(call uninstalldrvrpm,tools) \
	  $(MAKE) --no-print-directory -C $(ToolSrc) uninstall ;\
	  rm -rf /sbin/chelsio_adapter_config.py ;\
	  if [ ${DISTRO} == "SLES11sp3" ] || [ ${DISTRO} == "RHEL6.6" ]; then \
	      if [ ${UM_UNINST} == 1 ]; then \
	         $(MAKE) --no-print-directory -C $(ToolSrc) um_uninstall ;\
	      fi;\
	  fi ;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: ba_tools_uninstall
ba_tools_uninstall:
	$(call prepdir) \
	  if [ $(is_bypass) -eq 1 ] ; then \
	      $(MAKE) --no-print-directory -C $(ToolSrc)/ba_server/ bypass_tools_uninstall ;\
	  else \
	      echo -e "INFO : \t\tBypass_tools [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: nvme_uninstall
nvme_uninstall: iwarp_uninstall
	$(call prepdir) \
	  if [ $(is_nvme) -eq 1 ] ; then \
	     if [ ${nvme_pkgMgr} -eq 1 ] ; then \
	        ( export DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) ; ${pwd}/scripts/nvme_uninstall.sh ) && ( $(call logs,NVMe-Utils,nvme,Uninstall) ) || ( $(call logtemp,NVMe-Utils,nvme,Uninstall) ) ;\
	     else \
		$(call uninstalldrvrpm,nvme) \
	        [[ -f /usr/bin/targetcli.chold ]] && mv /usr/bin/targetcli.chold /usr/bin/targetcli || echo "" ; \
		rm -f $(shell which nvmetcli) && \
	        ( $(call logs,NVMeF-utils,nvme,Uninstall) ) || ( $(call logtemp,NVMeF-utils,nvme,Uninstall)) ;  \
	     fi ; \
	  else \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "NVMeF-utils\t\tnvme\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: nvme_toe_uninstall
nvme_toe_uninstall: toe_uninstall
	$(call prepdir) \
	  if [ $(is_nvme) -eq 1 ] || [ ${nvme_pkgMgr} -eq 1 ] ; then \
	     if [ ${nvme_pkgMgr} -eq 1 ] ; then \
	        ( export DEB=$(DEBIAN) SLES=$(SLES) RHEL=$(RHEL) ; ${pwd}/scripts/nvme_uninstall.sh ) && ( $(call logs,NVMe-Utils,nvme,Uninstall) ) || ( $(call logtemp,NVMe-Utils,nvme,Uninstall) ) ;\
	     else \
		$(call uninstalldrvrpm,nvme) \
	        [[ -f /usr/bin/targetcli.chold ]] && mv /usr/bin/targetcli.chold /usr/bin/targetcli || echo "" ; \
		rm -f $(shell which nvmetcli) && \
	        ( $(call logs,NVMeF-utils,nvme,Uninstall) ) || ( $(call logtemp,NVMeF-utils,nvme,Uninstall)) ;  \
	     fi ; \
	  else \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "NVMeF-utils\t\tnvme\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: lio_uninstall
lio_uninstall:
	$(call prepdir) \
	  if [ $(is_lio) -eq 1 ] ; then \
	            [[ -f /usr/bin/targetcli.chold ]] && mv /usr/bin/targetcli.chold /usr/bin/targetcli || echo "" ; \
	             $(MAKE) --no-print-directory -C $(NwSrc) cxgbit_uninstall && \
	            ( $(call uninstalldrvrpm,lio) ) && \
	            ($(call logs,LIO-Target,cxgbit,Uninstall)) || \
	            ($(call logtemp,LIO-Target,cxgbit,Uninstall)) \
	  else \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "LIO-Target\t\tcxgbit\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Build)

.PHONY: iser_uninstall
iser_uninstall: iwarp_uninstall
	$(call prepdir) \
	  if [ $(is_iser) -eq 1 ] ; then \
	            ( [[ -f /usr/bin/targetcli.chold ]] && mv /usr/bin/targetcli.chold /usr/bin/targetcli || echo "" && \
	            ( $(call uninstalldrvrpm,iser) ) && \
	            ( $(call logs,iSER,iSER,Uninstall) ) ) || \
	            ( $(call logtemp,iSER,iSER,Uninstall) ) \
	  else \
	        echo -e "INFO : \t\tiSER [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "iSER\t\tiSER\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi ; \
	  $(call displaysummary,$(@),Uninstall)

.PHONY: dpdk_uninstall
dpdk_uninstall: dpdk_utils_uninstall
	$(call prepdir) \
	if [ ${is_dpdk} -eq 1 ] ; then \
	    $(MAKE) --no-print-directory -C $(LibSrc) libpcap_uninstall ; \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk_uninstall ; \
	    depmod -a ; \
	else \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "DPDK\t\tDPDK\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	fi ; \
	$(call displaysummary,$(@),Uninstall)

.PHONY: dpdk_utils_uninstall
dpdk_utils_uninstall:
	$(call prepdir) \
	if [ ${is_dpdk} -eq 1 ] ; then \
	    $(MAKE) --no-print-directory -C $(NwSrc) dpdk_tools_uninstall ; \
	fi ; \
	$(call displaysummary,$(@),Uninstall)

.PHONY: ovs_uninstall
ovs_uninstall:
	$(call prepdir) 
	@ if [ ! -d "build" ] ; then \
	      $(MAKE) --no-print-directory prep;\
	  fi ; \
	  if [ $(is_ovs) -eq 1 ]; then \
	      ( ( $(call uninstalldrvrpm,ovs)) && ($(MAKE) --no-print-directory -C $(NwSrc) ovs_uninstall) || \
	      ($(call logtemp,OVS,openvswitch,Uninstall))) ;\
	      rm -rf  /lib/modules/$(shell uname -r)/extra/openvswitch.ko ; \
	      depmod -a ; \
	  else\
	      echo -e "INFO : \t\tOVS [ Not supported ]" ; \
	       [[ ${CONF} != "T4_UN" ]] && echo -e "OVS\t\topenvswitch\t\tUninstall\tNot-supported" >> temp.log || echo ; \
	  fi;\
	  $(call displaysummary,$(@),Uninstall)

.PHONY: rpm
rpm:$(MAKECMDGOALS)

.PHONY: firmware_rpm
firmware_rpm:
ifeq ($(firmware),0)
	@ if [ ! -f chelsio-series4-firmware-$(vers)-*.${arch}.rpm ]  ; then \
	       $(MAKE) -C $(specs) firmware ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "FW rpm already present skipping the build"; \
	  else \
	       $(call logs,Firmware,t4fw-X.Y.Z.bin,rpm) \
	  fi;\
	  $(call displaysummary,$(@),rpm)
firmware = 1
endif

.PHONY: nic_rpm
nic_rpm:$(strip $(call get_prerequisites,nic_rpm,${is_nic}))
ifeq ($(nic),5)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4nic-$(vers)-*.${arch}.rpm ]  ; then \
	        $(MAKE) -C $(specs) nic ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC rpm already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,rpm) \
	     fi;\
	 else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
 	 fi;\
	 $(call displaysummary,$(@),rpm)
nic = 6
endif 

.PHONY: nic_offload_rpm
nic_offload_rpm: $(strip $(call get_prerequisites,nic_offload_rpm,${is_nic}))
ifeq ($(nic),6)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4-$(vers)-*.${arch}.rpm ]  ; then \
	        $(MAKE) -C $(specs) nic_offload ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC-OFFLOAD rpm already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,rpm) \
	     fi; \
	else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)
nic = 7
endif

.PHONY: nic_ipv4_rpm
nic_ipv4_rpm: $(strip $(call get_prerequisites,nic_ipv4_rpm,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
             if [ ! -f cxgb4-$(vers)-*.${arch}.rpm ]  ; then \
                $(MAKE) -C $(specs) nic_ipv4 ;\
             elif [ ${DEBUG} -eq 1 ] ; then\
                echo -e "Cxgb4 NIC-OFFLOAD-IPV4 rpm already present skipping the build"; \
             else \
                $(call logs,Network(NIC),cxgb4,rpm) \
             fi; \
        else \
             echo -e "INFO : \t\tNIC [ Not supported ]" ; \
             echo -e "Network(NIC_IPV4)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
         fi;\
         $(call displaysummary,$(@),rpm)

.PHONY: vnic_rpm
vnic_rpm: $(strip $(call get_prerequisites,vnic_rpm,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_vnic) -eq 1 ]; then \
	      if [ ! -f cxgb4vf-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) vnic ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4vf rpm already present skipping the build"; \
	     else \
	        $(call logs,SR-IOV_networking(vNIC),cxgb4vf,rpm)\
	     fi; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\trpm\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),rpm)

.PHONY: toe_rpm
toe_rpm: $(strip $(call get_prerequisites,toe_rpm,${is_toe}))
ifeq ($(toe),3)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	      if [ ! -f cxgb4toe-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) toe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE rpm already present skipping the build"; \
	      else \
	        $(call logs,Network-Offload(TOE),t4_tom,rpm) \
	      fi; \
	      if [ $(ipv6_enable) -eq 0 ] ; then \
		echo -e "IPv6-Offload\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	      fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-Offload(TOE)\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	$(call displaysummary,$(@),rpm)
toe = 4
endif 

.PHONY: wdtoe_rpm
wdtoe_rpm: $(strip $(call get_prerequisites,wdtoe_rpm,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_wdtoe) -eq 1 ]; then \
	      if [ ! -f cxgb4wdtoe-${vers}-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) wdtoe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE rpm already present skipping the build"; \
	      else \
	          $(call logs,WD-TOE,t4_tom,rpm) \
	      fi; \
	 else \
	      echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	      echo -e "WD-TOE\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: wdtoe_wdudp_rpm
wdtoe_wdudp_rpm: wdtoe_rpm iwarp_rpm 
	@ $(call displaysummary,$(@),rpm)

.PHONY: toe_ipv4_rpm
toe_ipv4_rpm: $(strip $(call get_prerequisites,toe_ipv4_rpm,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	     if [ ! -f cxgb4toe-ipv4-$(vers)-*.${arch}.rpm ]  ; then \
	         $(MAKE) -C $(specs) toe_ipv4 ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	         echo -e "Cxgb4 TOE-ipv4 rpm already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(TOE),t4_tom,rpm) \
	     fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-Offload(TOE)\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: bypass_rpm
bypass_rpm: $(strip $(call get_prerequisites,bypass_rpm,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 $(call prepdir)\
	  if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f bypass-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) --no-print-directory -C $(specs) bypass ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass rpm already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(Bypass),cxgb4,rpm) \
	     fi; \
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: ipv6_rpm
ipv6_rpm: $(strip $(call get_prerequisites,ipv6_rpm,${is_ipv6}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_ipv6) -eq 1 ] ; then \
	      if [ $(shell echo $$(uname -r) | grep 2\.6\.34 ) ]; then \
	          if [ ! -f cxgb4ipv6-$(vers)-*.${arch}.rpm ]  ; then \
	              $(MAKE) -C $(specs) ipv6 ; \
		  elif [ ${DEBUG} -eq 1 ] ; then\
	              echo -e "IPv6 rpm already present skipping the build"; \
	          else \
		      $(call logs,IPv6-Offload,ipv6,rpm) \
	          fi; \
	      else\
	          if [ ! -f cxgb4ipv6-$(vers)-*.${arch}.rpm ]  ; then \
	              $(MAKE) -C $(specs) toe_ipv6 ;\
		  elif [ ${DEBUG} -eq 1 ] ; then\
	              echo -e "Ipv6 rpm already present skipping the build"; \
	          else \
	              $(call logs,IPv6-Offload,ipv6,rpm) \
	          fi; \
	      fi; \
	  else  \
		echo -e "INFO : \t\tipv6 " ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iwarp_rpm
iwarp_rpm: $(strip $(call get_prerequisites,iwarp_rpm,${is_iwarp}))
ifeq ($(iwarp),3)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	       if [ ! -f chiwarp-$(vers)-*.${arch}.rpm ]  ; then \
	  	   $(MAKE) -C $(specs) chiwarp ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iWARP rpm already present skipping the build"; \
	       else \
	           $(call logs,RDMA(iWARP),iw_cxgb4,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)
iwarp = 4
endif 

.PHONY: udp_offload_rpm
udp_offload_rpm:$(strip $(call get_prerequisites,udp_offload_rpm,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	       if [ ! -f cxgb4toe-$(vers)-*.${arch}.rpm ]  ; then \
		   $(MAKE) --no-print-directory -C $(specs) udp_offload ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "UDP-SO rpm already present skipping the build"; \
	       else \
	           $(call logs,UDP-Offload,t4_tom,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\trpm\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),rpm) 

.PHONY: sniffer_rpm
sniffer_rpm: $(strip $(call get_prerequisites,sniffer_rpm,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_sniffer) -eq 1 ] ; then \
	       if [ ! -f sniffer-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) sniffer ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "sniffer rpm already present skipping the build"; \
	       else \
	           $(call logs,Sniffer,wd_tcpdump,rpm)\
	       fi; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: bonding_rpm 
bonding_rpm: $(strip $(call get_prerequisites,bonding_rpm,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_bonding) -eq 1 ] ; then \
	      if [ ! -f bonding-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) bonding ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bonding rpm already present skipping the build"; \
	       else \
	           $(call logs,Bonding-Offload,bonding,rpm)\
	       fi; \
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-Offload\t\tbonding\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: fcoe_full_offload_initiator_rpm
fcoe_full_offload_initiator_rpm: $(strip $(call get_prerequisites,fcoe_full_offload_initiator_rpm,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	      if [ ! -f csiostor-initiator-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) fcoe ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "FCoE initiator rpm already present skipping the build"; \
	       else \
	           $(call logs,FCoE(full-offload-initiator),csiostor,rpm) \
	       fi; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "INFO : \t\tiscsi_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_full_offload_initiator_rpm
iscsi_full_offload_initiator_rpm:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_rpm,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),rpm)

.PHONY: fcoe_pdu_offload_target_rpm
fcoe_pdu_offload_target_rpm: $(strip $(call get_prerequisites,fcoe_pdu_offload_target_rpm,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ! -f chfcoe-$(vers)-*.${arch}.rpm ]  ; then \
			$(MAKE) -C $(specs) chfcoe ;\
		elif [ ${DEBUG} -eq 1 ] ; then\
			echo -e "fcoe_pdu_offload_target rpm already present skipping the build"; \
		else \
			$(call logs,FCoE(PDU-Offload-Target),chfcoe,rpm) \
		fi; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
          $(call displaysummary,$(@),rpm)

.PHONY: fcoe_full_offload_target_rpm
fcoe_full_offload_target_rpm : fcoe_full_offload_target nic_offload_rpm
	@ if [ $(sles11) ] || [ $(rhel6) ] || [ $(shell echo ${UNAME_R} | grep 2.6.34 ) ]  ||\
	         [ $(shell echo ${UNAME_R} | grep 2.6.32-131 ) ] || \
		[ $(shell echo ${UNAME_R} | grep 2.6.32-220.el6 ) ] || [ $(shell echo ${UNAME_R} | grep 2.6.32-279.el6 ) ]; then \
		$(MAKE) -C $(specs) fcoe_target ;\
	  else \
		echo -e "FCoE(full-offload-target)\t\tcsiostor\t\trpm\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_pdu_target_rpm
iscsi_pdu_target_rpm: $(strip $(call get_prerequisites,iscsi_pdu_target_rpm,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	      if [ ! -f chiscsi-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) chiscsi ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iSCSI target rpm already present skipping the build"; \
	      else \
	           $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,rpm)\
	      fi; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iscsi_pdu_initiator_rpm
iscsi_pdu_initiator_rpm: $(strip $(call get_prerequisites,iscsi_pdu_initiator_rpm,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\trpm\tNot-supported" >> temp.log ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\trpm\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
	        if [ ! -f cxgb4i-$(vers)-*.${arch}.rpm ]  ; then \
		    $(MAKE) -C $(specs) cxgbi ;\
	        elif [ ${DEBUG} -eq 1 ] ; then\
	            echo -e "iSCSI initiator rpm already present skipping the build"; \
	       else \
	           $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm)\
	       fi; \
	  else \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: scst_chfcoe_rpm
scst_chfcoe_rpm:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@ echo "###########################################" ;\
	  echo "#         Building scst modules           #" ;\
	  echo "###########################################" ;
	@ ( cd $(NwSrc)/scst && $(MAKE) 2release KDIR=$(KOBJ) && $(MAKE) rpm KDIR=$(KOBJ) ) ;  \
	  ( if [ ! -d $(shell pwd)/rpmbuild/RPMS/$(arch)/ ] ; then \
	        mkdir -p $(shell pwd)/rpmbuild/RPMS/$(arch) ; \
	    fi ; \
	  cp -f $(NwSrc)/scst/rpmbuilddir/RPMS/$(arch)/*.rpm $(shell pwd)/rpmbuild/RPMS/$(arch)/ && \
	  cp -f $(NwSrc)/scst/scstadmin/rpmbuilddir/RPMS/$(arch)/*.rpm $(shell pwd)/rpmbuild/RPMS/$(arch)/ ) ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: rdma_block_device_rpm
rdma_block_device_rpm: $(strip $(call get_prerequisites,rdma_block_device_rpm,${is_rdma_block_device}))
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	      if [ ! -f rdma-block-device-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) rdma_block ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "RDMA Block Device rpm already present skipping the build"; \
	      else \
	           $(call logs,RDMA-Block-dev,rbd,rpm)\
	      fi; \
	  else \
		echo -e "INFO : \t\tRDMA-Block-Device [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: libs_rpm
libs_rpm: libs
ifeq ($(iwarp_libs),3)
	@ if [ $(is_iwarp) -eq 1 ] && [ $(NOLIBS) -eq 1 ]; then \
	        $(MAKE) -C $(specs) libs ; \
	        if [ $(IWARP_WPM) -eq 1 ] ; then \
	            $(MAKE) -C $(specs) libiwpm ; \
	        fi ; \
	  else  \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "iWARP-lib\t\tlibcxgb4\t\trpm\tNot-supported" >> temp.log ; \
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\trpm\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),rpm)
iwarp_libs = 4
endif

.PHONY: crypto_rpm
crypto_rpm: $(strip $(call get_prerequisites,crypto_rpm,${is_crypto}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_crypto) -eq 1 ] ; then \
	     if [ ${INSTCHCR} -eq 1 ] ; then \
	       if [ ! -f chcr-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) crypto ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Crypto rpm already present skipping the build"; \
	       else \
	          $(call logs,Chelsio-Crypto,${chcr_sum},rpm) \
	       fi; \
	     fi ;\
	else \
	     echo -e "INFO : \t\tCrypto [ Not supported ]" ; \
	     echo -e "Chelsio-Crypto\t\tchcr/TLS\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: nvme_toe_spdk_rpm
nvme_toe_spdk_rpm: nic_offload_rpm nvme_toe_spdk
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nvme_toe_spdk) -eq 1 ] ; then \
	       if [ ! -f chtcp-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) chspdk ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "CHTCP rpm already present skipping the build"; \
	       else \
	          $(call logs,SPDK_NVMe/TOE,chtcp,rpm) \
	       fi; \
	else \
	     echo -e "INFO : \t\tSPDK_NVMe/TOE [ Not supported ]" ; \
	     echo -e "SPDK_NVMe/TOE\t\tchtcp\t\trpm\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: chssl_rpm
chssl_rpm:
ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
endif
	@if [ $(is_crypto) -eq 1 ] ; then \
	     if [ ! -f chopenssl-$(vers)-*.${arch}.rpm ]  ; then \
	        if [[ ${kdist} == "SLES15" ]] || [[ ${kdist} == "SLES15sp1" ]] || [[ ${kdist} == "RHEL8.0" ]] || [[ ${kdist} == "RHEL8.1" ]] || [[ ${kdist} == "RHEL8.2" ]] || [[ ${kdist} == "RHEL8.3" ]] ; then \
	           $(MAKE) -C $(specs) chssl_sles15 ;\
	        else\
	           $(MAKE) -C $(specs) chssl ;\
	        fi;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Chopenssl rpm already present skipping the build"; \
	     else \
	        $(call logs,Chelsio-Crypto(libs),chopenssl,rpm) \
	     fi; \
	 fi;\
	 $(call displaysummary,$(@),rpm)

.PHONY: wdtoe_libs_rpm
wdtoe_libs_rpm: wdtoe_libs
	@ if [ $(is_wdtoe) -eq 1 ] ; then \
	        $(MAKE) -C $(specs) wdtoe_libs ; \
	  else  \
	        echo -e "INFO : \t\tWDTOE-libraries [ Not supported ]" ; \
	        echo -e "WDTOE-lib\t\tlibwdtoe\t\trpm\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY:libibverbs_rpm 
libibverbs_rpm:
	$(call prepdir) \
	  if [ $(is_iwarp) -eq 1 ] ; then \
	        $(MAKE) -C $(LibSrc) libibverbs &> /dev/null;\
	        $(MAKE) -C $(specs) libibverbs &> /dev/null;\
	        libibverbs_ver="1.1.8";\
	        iwarp_libs_deps_rpm=(libibverbs libibverbs-devel libibverbs-utils);\
	         $(call install_rpm_always, $$iwarp_libs_deps_rpm, $$libibverbs_ver)\
	  fi; 

.PHONY:librdmacm_rpm
librdmacm_rpm:
	$(call prepdir)
	@ if [ $(is_iwarp) -eq 1 ] ; then \
		$(MAKE) -C $(LibSrc) librdmacm &> /dev/null;\
		$(MAKE) -C $(specs) librdmacm &> /dev/null;\
	        libcm_ver="1.0.21";\
	        iwarp_libs_deps_rpm=(librdmacm librdmacm-devel librdmacm-utils);\
	        $(call install_rpm_always, $$iwarp_libs_deps_rpm, $$libcm_ver)\
	  fi; 

.PHONY: libcxgb4_rpm
libcxgb4_rpm : libs
	@ if [ $(is_iwarp) -ne 1 ] ; then \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "iwarp-Libraries\t\trpm\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(specs) libcxgb4 ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: lio_rpm
lio_rpm : $(strip $(call get_prerequisites,lio_rpm,${is_lio}))
	@ if [ $(is_lio) -ne 1 ] ; then \
		echo -e "INFO : \t\tLIO-Target [ Not supported ]" ; \
		echo -e "LIO-Target\t\trpm\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(specs) lio ;\
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: ovs_rpm
ovs_rpm: $(strip $(call get_prerequisites,ovs_rpm,${is_ovs}))
 ifeq ($(DEBUG),1)
        $(info TGT : $@)
        $(info PRE : $<)
 endif
	@ if [ $(is_ovs) -eq 1 ]; then \
	      if [ ! -f openvswitch-$(vers)-*.${arch}.rpm ]  ; then \
	          $(MAKE) -C $(specs) ovs ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "ovs rpm already present skipping the build"; \
	      else \
	          $(call logs,OVS,openvswitch,rpm)\
	      fi; \
	  else\
	      echo -e "INFO : \t\tOVS [ Not supported ]" ; \
	      echo -e "OVS\t\topenvswitch\t\trpm\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),rpm)

.PHONY: tools_rpm
tools_rpm : tools
	$(call prepdir)
	@ if [ ! -f chelsio-utils-$(vers)-*.${arch}.rpm ]  ; then \
	       $(MAKE) -C $(specs) chutils ;\
	       install -D -v -m 755 $(ToolSrc)/chelsio_adapter_config_v4/bin/chelsio_adapter_config.py  /sbin ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "Tools rpm already present skipping the build"; \
	  else \
	       $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),rpm) \
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY: iser_rpm
iser_rpm: $(strip $(call get_prerequisites,iser_rpm,${is_iser}))
	$(call prepdir) \
	  if [ ${IWARP_WPM} -eq 1 ] ; then \
	     $(MAKE) -C $(specs) libiwpm ; \
	  fi ; \
	  if [ $(installOISCSI) -ne 0 ] ; then \
	     $(MAKE) -C $(specs) oiscsiutils ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: nvme_rpm
nvme_rpm : iwarp_rpm nvme
	$(call prepdir)
	@ if [ ! -f chelsio-nvmeutils-$(vers)-*.${arch}.rpm ]  ; then \
	       $(MAKE) -C $(specs) nvmeutils ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "NVMEe utils rpm already present skipping the build"; \
	  else \
	       $(call logs,NVMe-Utils,nvme,rpm) \
	  fi; \
	  $(call displaysummary,$(@),rpm)


.PHONY: ba_tools_rpm
ba_tools_rpm:  ba_tools
	@ if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f chelsio-bypass-utils-$(vers)-*.${arch}.rpm ]  ; then \
	           $(MAKE) -C $(specs) bypassutils ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass Tools rpm already present skipping the build"; \
	      else \
	          $(call logs,Bypass_tools,ba_*,rpm) \
	      fi; \
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\trpm\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),rpm)

.PHONY: deb
deb:$(MAKECMDGOALS)

.PHONY: firmware_deb
firmware_deb: 
ifeq ($(firmware),1)
	@ if [ ! -f chelsio-series4-firmware-$(vers)-*.${arch}.deb ]  ; then \
	       $(MAKE) -C $(debrules) firmware ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "FW deb already present skipping the build"; \
	  else \
	       $(call logs,Firmware,t4fw-X.Y.Z.bin,deb) \
	  fi;\
	  $(call displaysummary,$(@),deb)
firmware = 2
endif

.PHONY: nic_deb
nic_deb:$(strip $(call get_prerequisites,nic_deb,${is_nic}))
ifeq ($(nic),7)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4nic-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) nic ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC deb already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,deb) \
	     fi;\
	 else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)
nic = 8
endif 

.PHONY: nic_offload_deb
nic_offload_deb: $(strip $(call get_prerequisites,nic_offload_deb,${is_nic}))
ifeq ($(nic),8)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) nic_offload ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC-OFFLOAD deb already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,deb) \
	     fi; \
	else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)
nic = 9
endif

.PHONY: nic_ipv4_deb
nic_ipv4_deb: $(strip $(call get_prerequisites,nic_ipv4_deb,${is_nic}))
ifeq ($(nic),9)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_nic) -eq 1 ] ; then \
	     if [ ! -f cxgb4-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) nic_offload ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Cxgb4 NIC-IPV4 deb already present skipping the build"; \
	     else \
	        $(call logs,Network(NIC),cxgb4,deb) \
	     fi; \
	else \
	     echo -e "INFO : \t\tNIC [ Not supported ]" ; \
	     echo -e "Network(NIC)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)
nic = 10
endif

.PHONY: vnic_deb
vnic_deb: $(strip $(call get_prerequisites,vnic_deb,${is_vnic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_vnic) -eq 1 ]; then \
	      if [ ! -f cxgb4vf-$(vers)-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) vnic ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4vf deb already present skipping the build"; \
	     else \
	        $(call logs,SR-IOV_networking(vNIC),cxgb4vf,deb)\
	     fi; \
	  else\
	       echo -e "INFO : \t\tvNIC [ Not supported ]" ; \
	       echo -e "SR-IOV_networking(vNIC)\t\tcxgb4vf\t\tdeb\tNot-supported" >> temp.log ; \
	  fi;\
	  $(call displaysummary,$(@),deb)

.PHONY: toe_deb
toe_deb: $(strip $(call get_prerequisites,toe_deb,${is_toe}))
ifeq ($(toe),4)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	      if [ ! -f cxgb4toe-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) toe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE deb already present skipping the build"; \
	      else \
	        $(call logs,Network-Offload(TOE),t4_tom,deb) \
	      fi; \
	      if [ $(ipv6_enable) -eq 0 ] ; then \
		echo -e "IPv6-Offload\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	      fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-Offload(TOE)\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	$(call displaysummary,$(@),deb)
toe = 5
endif 

.PHONY: toe_ipv4_deb
toe_ipv4_deb: $(strip $(call get_prerequisites,toe_ipv4_deb,${is_toe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_toe) -eq 1 ]; then \
	     if [ ! -f cxgb4toe-ipv4-$(vers)-*.${arch}.deb ]  ; then \
	         $(MAKE) -C $(debrules) toe_ipv4 ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	         echo -e "Cxgb4 TOE-ipv4 deb already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(TOE),t4_tom,deb) \
	     fi; \
	 else \
	      echo -e "INFO : \t\tTOE [ Not supported ]" ; \
	      echo -e "Network-Offload(TOE)\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)


.PHONY: wdtoe_deb
wdtoe_deb: $(strip $(call get_prerequisites,wdtoe_deb,${is_wdtoe}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_wdtoe) -eq 1 ]; then \
	      if [ ! -f cxgb4wdtoe-${vers}-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) wdtoe ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "Cxgb4 TOE deb already present skipping the build"; \
	      else \
	          $(call logs,WD-TOE,t4_tom,deb) \
	      fi; \
	 else \
	      echo -e "INFO : \t\tWD-TOE [ Not supported ]" ; \
	      echo -e "WD-TOE\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)

.PHONY: wdtoe_wdudp_deb
wdtoe_wdudp_deb: wdtoe_deb iwarp_deb 
	@ $(call displaysummary,$(@),deb)

.PHONY: bypass_deb
bypass_deb: $(strip $(call get_prerequisites,bypass_deb,${is_bypass}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	 $(call prepdir)\
	  if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f bypass-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) --no-print-directory -C $(debrules) bypass ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass deb already present skipping the build"; \
	     else \
	        $(call logs,Network-Offload(Bypass),cxgb4,deb) \
	     fi; \
	  else \
	      echo -e "INFO : \t\tBypass [ Not supported ]" ; \
	      echo -e "Network-Offload(Bypass)\t\tcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iwarp_deb
iwarp_deb: $(strip $(call get_prerequisites,iwarp_deb,${is_iwarp}))
ifeq ($(iwarp),4)
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	       if [ ! -f chiwarp-$(vers)-*.${arch}.deb ]  ; then \
		   $(MAKE) -C $(debrules) chiwarp ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iWARP deb already present skipping the build"; \
	       else \
	           $(call logs,RDMA(iWARP),iw_cxgb4,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "RDMA(iWARP)\t\tiw_cxgb4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)
iwarp = 5
endif 

.PHONY: udp_offload_deb
udp_offload_deb:$(strip $(call get_prerequisites,udp_offload_deb,${is_udp_offload}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	$(call prepdir) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	       if [ ! -f cxgb4toe-$(vers)-*.${arch}.deb ]  ; then \
		   $(MAKE) --no-print-directory -C $(debrules) udp_offload ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "UDP-SO deb already present skipping the build"; \
	       else \
	           $(call logs,UDP-Offload,t4_tom,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tUDP-Offload [ Not supported ]" ; \
		echo -e "UDP-Offload\t\tt4_tom\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ;\
	  $(call displaysummary,$(@),deb) 

.PHONY: sniffer_deb
sniffer_deb: $(strip $(call get_prerequisites,sniffer_deb,${is_sniffer}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_sniffer) -eq 1 ] ; then \
	       if [ ! -f sniffer-$(vers)-*.${arch}.deb ]  ; then \
	          $(MAKE) -C $(debrules) sniffer ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	          echo -e "sniffer deb already present skipping the build"; \
	       else \
	           $(call logs,Sniffer,wd_tcpdump,deb)\
	       fi; \
	  else \
	       echo -e "INFO : \t\tSniffer [ Not supported ]" ; \
	       echo -e "Sniffer\t\twd_tcpdump\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: bonding_deb 
bonding_deb: $(strip $(call get_prerequisites,bonding_deb,${is_bonding}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_bonding) -eq 1 ] ; then \
	      if [ ! -f bonding-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) bonding ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bonding deb already present skipping the build"; \
	       else \
	           $(call logs,Bonding-Offload,bonding,deb)\
	       fi; \
	  else \
		echo -e "INFO : \t\tbonding [ Not supported ]" ; \
		echo -e "Bonding-Offload\t\tbonding\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: fcoe_full_offload_initiator_deb
fcoe_full_offload_initiator_deb: $(strip $(call get_prerequisites,fcoe_full_offload_initiator_deb,${is_fcoe_full_offload_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_full_offload_initiator) -eq 1 ] ; then \
	      if [ ! -f csiostor-initiator-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) fcoe ;\
	       elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "FCoE initiator deb already present skipping the build"; \
	       else \
	           $(call logs,FCoE(full-offload-initiator),csiostor,deb) \
	       fi; \
	  else \
		echo -e "INFO : \t\tfcoe_full_offload_initiator [ Not supported ]" ; \
		echo -e "INFO : \t\tiscsi_full_offload_initiator [ Not supported ]" ; \
		echo -e "FCoE(full-offload-initiator)\t\tcsiostor\t\tdeb\tNot-supported" >> temp.log ;\
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iscsi_full_offload_initiator_deb
iscsi_full_offload_initiator_deb:$(strip $(call get_prerequisites,iscsi_full_offload_initiator_deb,${is_iscsi_full_offload_initiator}))
	@ $(call displaysummary,$(@),deb)

.PHONY: fcoe_pdu_offload_target_deb
fcoe_pdu_offload_target_deb: $(strip $(call get_prerequisites,fcoe_pdu_offload_target_deb,${is_fcoe_pdu_offload_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_fcoe_pdu_offload_target) -eq 1 ] ; then \
		if [ ! -f chfcoe-$(vers)-*.${arch}.deb ]  ; then \
			$(MAKE) -C $(debrules) chfcoe ;\
		elif [ ${DEBUG} -eq 1 ] ; then\
			echo -e "fcoe_pdu_offload_target deb already present skipping the build"; \
		else \
			$(call logs,FCoE(PDU-Offload-Target),chfcoe,deb) \
		fi; \
	  else \
		echo -e "INFO : \t\tfcoe_pdu_offload_target [ Not supported ]" ; \
		echo -e "FCoE(PDU-Offload-Target)\t\tchfcoe\t\tdeb\tNot-supported" >> temp.log ;\
	  fi ; \
          $(call displaysummary,$(@),deb)

.PHONY: iscsi_pdu_target_deb
iscsi_pdu_target_deb: $(strip $(call get_prerequisites,iscsi_pdu_target_deb,${is_iscsi_pdu_target}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_target) -eq 1 ] ; then \
	      if [ ! -f chiscsi-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) chiscsi ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "iSCSI target deb already present skipping the build"; \
	      else \
	           $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,deb)\
	      fi; \
	  else \
		echo -e "INFO : \t\tiscsi-target [ Not supported ]" ; \
		echo -e "iSCSI(pdu-offload-target)\t\tchiscsi_t4\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: iscsi_pdu_initiator_deb
iscsi_pdu_initiator_deb: $(strip $(call get_prerequisites,iscsi_pdu_initiator_deb,${is_iscsi_pdu_initiator}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@ if [ $(is_iscsi_pdu_initiator) -ne 1 ] ; then \
		echo -e "INFO : \t\topen-iscsi Data path accelerator [ Not supported ]" ; \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\tdeb\tNot-supported" >> temp.log ; \
		echo -e "iSCSI(iscsi-pdu-initiator)\t\tcxgb4i\t\tdeb\tNot-supported" >> temp.log ; \
	  elif [ $(openssl) == "1" ] ; then \
	        if [ ! -f cxgb4i-$(vers)-*.${arch}.deb ]  ; then \
		    $(MAKE) -C $(debrules) cxgbi ;\
	        elif [ ${DEBUG} -eq 1 ] ; then\
	            echo -e "iSCSI initiator deb already present skipping the build"; \
	       else \
	           $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,deb)\
	       fi; \
	  else \
		echo -e "iSCSI(open-iscsi-utils)\t\tiscsi*\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: rdma_block_device_deb
rdma_block_device_deb: $(strip $(call get_prerequisites,rdma_block_device_deb,${is_rdma_block_device}))
	@ if [ $(is_rdma_block_device) -eq 1 ] ; then \
	      if [ ! -f rdma-block-device-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) rdma_block ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "RDMA Block Device deb already present skipping the build"; \
	      else \
	           $(call logs,RDMA-Block-dev,rbd,deb)\
	      fi; \
	  else \
		echo -e "INFO : \t\tRDMA-Block-Device [ Not supported ]" ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: libs_deb
libs_deb: libs
ifeq ($(iwarp_libs),4)
	@ if [ $(is_iwarp) -eq 1 ] ; then \
	        $(MAKE) -C $(debrules) libs ; \
	  else  \
		echo -e "INFO : \t\tiwarp-libraries [ Not supported ]" ; \
		echo -e "iWARP-lib\t\tlibcxgb4\t\tdeb\tNot-supported" >> temp.log ; \
		echo -e "WD-UDP\t\tlibcxgb4_sock\t\tdeb\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),deb)
iwarp_libs = 4
endif

.PHONY: wdtoe_libs_deb
wdtoe_libs_deb: wdtoe_libs
	@ if [ $(is_wdtoe) -eq 1 ] ; then \
	        $(MAKE) -C $(debrules) wdtoe_libs ; \
	  else  \
	        echo -e "INFO : \t\tWDTOE-libraries [ Not supported ]" ; \
	        echo -e "WDTOE-lib\t\tlibwdtoe\t\tdeb\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),deb)

.PHONY: libcxgb4_deb
libcxgb4_deb : libs
	@ if [ $(is_iwarp) -ne 1 ] ; then \
		echo -e "INFO : \t\tiwarp [ Not supported ]" ; \
		echo -e "iwarp-Libraries\t\tdeb\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(debrules) libcxgb4_devel ;\
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: tools_deb
tools_deb : tools
	$(call prepdir)
	@ if [ ! -f chelsio-utils-$(vers)-*.${arch}.deb ]  ; then \
	       $(MAKE) -C $(debrules) chutils ;\
	       install -D -v -m 755 $(ToolSrc)/chelsio_adapter_config_v4/bin/chelsio_adapter_config.py  /sbin ;\
	  elif [ ${DEBUG} -eq 1 ] ; then\
	       echo -e "Tools deb already present skipping the build"; \
	  else \
	       $(call logs,Chelsio-utils(tools),$(cxgbtool_msg),deb) \
	  fi; \
	  $(call displaysummary,$(@),deb)

.PHONY: ba_tools_deb
ba_tools_deb:  ba_tools
	@ if [ $(is_bypass) -eq 1 ] ; then \
	      if [ ! -f chelsio-bypass-utils-$(vers)-*.${arch}.deb ]  ; then \
	           $(MAKE) -C $(debrules) bypassutils ;\
	      elif [ ${DEBUG} -eq 1 ] ; then\
	           echo -e "Bypass Tools deb already present skipping the build"; \
	      else \
	          $(call logs,Bypass_tools,ba_*,deb) \
	      fi; \
	  else \
	      echo -e "Bypass_tools\t\tba_*\t\tdeb\tNot-supported" >> temp.log ; \
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: crypto_deb
crypto_deb: $(strip $(call get_prerequisites,crypto_deb,${is_nic}))
 ifeq ($(DEBUG),1)
	$(info TGT : $@)
	$(info PRE : $<)
 endif
	@if [ $(is_crypto) -eq 1 ] ; then \
	     if [ ! -f chcr-$(vers)-*.${arch}.deb ]  ; then \
	        $(MAKE) -C $(debrules) crypto ;\
	     elif [ ${DEBUG} -eq 1 ] ; then\
	        echo -e "Crypto deb already present skipping the build"; \
	     else \
	        $(call logs,Chelsio-Crypto,${chcr_sum},deb) \
	     fi; \
	else \
	     echo -e "INFO : \t\tChelsio-Crypto [ Not supported ]" ; \
	     echo -e "Chelsio-Crypto\t\tchcr/TLS\t\tdeb\tNot-supported" >> temp.log ; \
	 fi;\
	 $(call displaysummary,$(@),deb)

.PHONY: iser_deb
iser_deb: $(strip $(call get_prerequisites,iser_deb,${is_iser}))
	$(call prepdir) \
	  if [ ${IWARP_WPM} -eq 1 ] ; then \
	     $(MAKE) -C $(debrules) libiwpm ; \
	  fi ;\
	  if [ $(installOISCSI) -ne 0 ] ; then \
	     $(MAKE) -C $(debrules) oiscsiutils ; \
	  fi ;\
	  $(call displaysummary,$(@),deb)

.PHONY: lio_deb
lio_deb : $(strip $(call get_prerequisites,lio_deb,${is_lio}))
	@ if [ $(is_lio) -ne 1 ] ; then \
		echo -e "INFO : \t\tLIO-Target [ Not supported ]" ; \
		echo -e "LIO-Target\t\tcxgbit\t\tdeb\tNot-supported" >> temp.log ; \
	  else \
		$(MAKE) -C $(debrules) cxgbit ;\
	  fi ; \
	  $(call displaysummary,$(@),deb)

.PHONY: nvme_deb
nvme_deb: iwarp_deb
	$(call prepdir) \
	  if [ $(is_nvme) -eq 1 ] ; then \
	     if [ ${NORPMKERNELFLAG} == 1 ] || [ ${DEBIAN} -eq 1 ] ; then \
		$(MAKE) --no-print-directory -C $(ToolSrc)/nvme_utils install ; \
	     else \
	        ( $(call installdrvrpm,nvme) ) && ( $(call logs,NVMe-Utils,nvme,deb) ) || \
	        ( $(call logtemp,NVMe-Utils,nvme,deb) )\
	     fi;\
	  else \
		echo -e "INFO : \t\tnvme [ Not supported ]" ; \
		echo -e "nvme\t\tnvme\t\tdeb\tNot-supported" >> temp.log ; \
	  fi; \
	  $(call displaysummary,$(@),deb)
	
.PHONY: clean
clean:
	@ echo "################################################## " ;\
	  echo "#          Cleaning Source/Build                 # " ;\
	  echo "################################################## " ;
	@ rm -rf build;

.PHONY: distclean
distclean:
	@ echo "################################################## " ;\
	  echo "#          Cleaning Source/Build/RPMDir          # " ;\
	  echo "################################################## " ;
	@ rm -rf build;
	@ rm -rf rpmbuild;
	@ rm -f scripts/deps.log;
	@ $(MAKE) --no-print-directory -C ${debrules} distclean

.PHONY: rpmclean
rpmclean: distclean
	@ echo "################################################## " ;\
          echo "#          Cleaning RPM Cluster Dir              # " ;\
          echo "################################################## " ;
	@ rm -rf RPM-Manager/DRIVER-RPMS/inbox/* ;
	@ rm -rf RPM-Manager/DRIVER-RPMS/ofed/* ;
	@ rm -rf RPM-Manager/OFED-RPMS/* ;
	@ rm -rf ChelsioUwire-3.14.0.3-RPM-Installer ;
	@ rm -rf ChelsioUwire-3.14.0.3-RPM-Installer.tar.gz ;

.PHONY: uninstall_all
uninstall_all:nic_uninstall toe_uninstall ipv6_uninstall iwarp_uninstall bonding_uninstall vnic_uninstall sniffer_uninstall fcoe_full_offload_initiator_uninstall iscsi_pdu_target_uninstall iscsi_pdu_initiator_uninstall libs_uninstall crypto_uninstall lio_uninstall iser_uninstall nvme_toe_spdk_uninstall dpdk_uninstall ovs_uninstall tools_uninstall
	@ [[ $(CONF) == "T4_UN" ]] && ${pwd}/scripts/inbox_bk_rt.sh 1 || echo "" ; \
	  depmod -a ;
	@ $(call displaysummary,$(@),Uninstall)

.PHONY: help
help: DEFAULT

.PHONY: prep
prep :
	$(call prepare)

.PHONY: removeallPrevious
removeallPrevious: distclean
	$(call prepdir) \
	 if [ -f ${pwd}/uninstall.log ] ; then \
	     rm -f ${pwd}/uninstall.log ;\
	 fi;\
	${pwd}/scripts/inbox_bk_rt.sh 0 ; \
	echo "Uninstalling all previously installed drivers/libs. This step may take some time." ;\
	if [ -f ${pwd}/scripts/uninstall.py ]; then \
	    if [ ${DEBIAN} -eq 1 ] ; then \
	       python scripts/uninstall_deb.py inbox ; \
	    else \
	      if [ ${kdist} == "RHEL8.0" ] ; then \
	        python scripts/uninstall.py inbox ; \
	      else \
	        python scripts/uninstall.py inbox ; \
	      fi ;\
	    fi ; \
	else \
	    echo -e "uninstall script missing";\
	    exit -1;\
	fi; \
	$(MAKE) uninstall_all UM_UNINST=${UM_UNINST} UNAME_R=${UNAME_R} >> ${pwd}/uninstall.log 2>&1 ; \
	if [ ${dracut} -eq 1 ] ; then \
	    if [ ${DEBIAN} -eq 1 ] ; then \
	      if [ ${kdist} != "ubuntu-20.04" ] && [ ${kdist} != "ubuntu-20.04.1" ] && [ ${kdist} != "ubuntu-20.04.2" ]; then \
		lsinitramfs $(initimg) | grep ko | grep -i "csio\|cxgb" &> /dev/null; \
	        if [ $$? -eq 0 ]; then  \
	            export logfile=${pwd}/install.log ; export initimg=${initimg} ; ${pwd}/scripts/fix_init.sh -r cxgb4,csiostor,cxgb4vf,csiostor,iw_cxgb4,chcr,libcxgbi,cxgb4i,libcxgb,cxgbit,cxgb,cxgb3,cxgb3i -y || echo "" ; \
	        fi;\
	      else \
		lsinitramfs $(initimg) | grep ko | grep -i "csio\|cxgb" &> /dev/null; \
	        if [ $$? -eq 0 ]; then  \
	            export logfile=${pwd}/install.log ; export initimg=${initimg} ; ${pwd}/scripts/fix_init_ubuntu-20.sh || echo "" ; \
	        fi;\
	      fi;\
	    else \
		lsinitrd $(initimg) | grep ko | grep -i "csio\|cxgb" &> /dev/null; \
	        if [ $$? -eq 0 ]; then  \
	            export logfile=${pwd}/install.log ; ${pwd}/scripts/fix_init.sh -r cxgb4,csiostor,cxgb4vf,csiostor,iw_cxgb4,chcr,libcxgbi,cxgb4i,libcxgb,cxgbit,cxgb,cxgb3,cxgb3i -y || echo "" ; \
	        fi;\
	    fi;\
        fi ;

.PHONY: removeall
removeall:
	$(call prepdir) \
	  if [ -f ${pwd}/uninstall.log ] ; then \
	       rm -f ${pwd}/uninstall.log ;\
	  fi;\
	  if [ -f ${pwd}/scripts/uninstall.py ]; then \
	      if [ ${DEBIAN} -eq 1 ] ; then \
	         python scripts/uninstall_deb.py inbox ; \
	      else \
	        if [ ${kdist} == "RHEL8.0" ] ; then \
	          python scripts/uninstall.py inbox ; \
	        else \
	          python scripts/uninstall.py inbox ; \
	        fi ;\
	      fi ; \
	  else \
	       echo -e "uninstall script missing";\
	       exit -1;\
	  fi; \
	  $(call displaysummary,$(@),rpm)

.PHONY: removetools
removetools:
	@ if [ ${TOOLS_UNINST} -eq 1 ] ; then \
	      $(MAKE) --no-print-directory tools_uninstall TOOLS_UNINST=${TOOLS_UNINST} > ${pwd}/uninstall.log 2>&1 ; \
	  fi ;


define prepdir
	@ if [ ! -d "build" ] ; then\
	       $(MAKE) --no-print-directory prep || exit 1;\
	  fi ; 
endef

define ptpinstall
	if [ $(SETPTP) -eq 1  ] ; then\
		$(MAKE) --no-print-directory -C $(NwSrc) ptp_install ;\
	fi ;
endef

define getpatch
$(shell f=0; for kl in $(1)  ; do if [ $$(echo $(UNAME_R) | grep -c $$kl) -eq 1 ] ; then f=1 ; break ; fi ; done ;echo $$f ;)
endef

define printpatchKver
	if [ ${debug_patch} -eq 1 ] ; then \
		echo "Patching with $1 patch" ; \
	fi ;
endef

define prepare
	 @ rm -rf temp.log deps.log ; \
	 if [ ! -d "build" ] ; then \
		mkdir build ;\
	 else \
	        rm -rf build ; \
	        mkdir build ;\
	  fi ; \
	 cp -rp src tools libs build; \
	 set -e ; if [ $(patchSrc) -ne 0 ]; then \
	 if [ $(kerFlag) -eq 0 ] ; then \
	    cd build ; \
	    if [ `echo ${UNAME_R} | grep -c el6` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 279 ]; then \
	        $(call printpatchKver,RHEL6.X) \
	        patch -p1 -f < src/patches/RHEL6.X* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 123 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -lt 514 ]; then \
	        $(call printpatchKver,RHEL7.X) \
	        if [ `ofed_info 2>/dev/null | head -1 | grep -c 4.8` -eq 1 ] ; then \
	            $(call printpatchKver,RHEL7.3) \
	            patch -p1 -f < src/patches/RHEL7.3* > $(NULL_OUT) ; \
	        else \
	            patch -p1 -f < src/patches/RHEL7.X* > $(NULL_OUT) ; \
	        fi ; \
	    elif [ `echo ${UNAME_R} | grep -c el7` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 514 ]; then \
	        $(call printpatchKver,RHEL7.3) \
	        patch -p1 -f < src/patches/RHEL7.3* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c el8` -eq 1 ] && [ `echo ${UNAME_R} | cut -d- -f2 | cut -d. -f1` -ge 80 ]; then \
	        $(call printpatchKver,RHEL8.0) \
	        patch -p1 -f < src/patches/RHEL8.XGA.patch > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 3.0 ] && [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 13 ]; then \
	        $(call printpatchKver,SLES11X) \
	        patch -p1 -f < src/patches/SLES11X* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 3.12 ] && [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 28 ]; then \
	        $(call printpatchKver,SLES12) \
	        patch -p1 -f < src/patches/SLES12GA* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.4 ] && [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 21 ]; then \
	        $(call printpatchKver,SLES12SP2) \
	        patch -p1 -f < src/patches/SLES12SP2* > $(NULL_OUT) ; \
            elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2` == 4.12 ] && [ `echo ${UNAME_R} | cut -d- -f1 | cut -d. -f3` -ge 14 ]; then \
                $(call printpatchKver,SLES15) \
                patch -p1 -f < src/patches/SLES15* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 3.19.0 ] && [ `echo ${UNAME_R} | cut -d- -f2` -ge 25 ]; then \
	        $(call printpatchKver,ubuntu-14.04.3) \
	        patch -p1 -f < src/patches/ubuntu-14.04.3* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.2.0 ] && [ `echo ${UNAME_R} | cut -d- -f2` -ge 27 ]; then \
	        $(call printpatchKver,ubuntu-14.04.4) \
	        patch -p1 -f < src/patches/ubuntu-14.04.4* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.4.0 ] && [ `echo ${UNAME_R} | cut -d- -f2` -ge 21 ]; then \
	        $(call printpatchKver,ubuntu-16.04) \
	        patch -p1 -f < src/patches/ubuntu-16.04* > $(NULL_OUT) ; \
            elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 4.15.0 ] && [ `echo ${UNAME_R} | cut -d- -f2` -ge 29 ]; then \
                $(call printpatchKver,ubuntu-18.04) \
                patch -p1 -f < src/patches/ubuntu-18.04* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c -` -eq 1 ] && [ `echo ${UNAME_R} | cut -d. -f1,2,3 | cut -d- -f1` == 5.4.0 ] && [ `echo ${UNAME_R} | cut -d- -f2` -ge 26 ]; then \
	        $(call printpatchKver,ubuntu-20.04) \
	        patch -p1 -f < src/patches/ubuntu-20.04* > $(NULL_OUT) ; \
	    fi ; \
	 else \
	    cd build ; \
	    if [ `echo ${UNAME_R} | grep -c ^3"\."[6789]` -eq 1 ] || [ `echo ${UNAME_R} | grep -c ^3"\.1"\[012345678\]` -eq 1 ]; then \
	        $(call printpatchKver,3.X) \
	        patch -p1 -f < src/patches/3.X* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "4\.[1][9]"` -eq 1 ]; then \
	        $(call printpatchKver,4.19) \
	        patch -p1 -f < src/patches/4.19* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "5\.[0]"` -eq 1 ]; then \
	        $(call printpatchKver,4.19) \
	        patch -p1 -f < src/patches/4.19* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "5\.[6]"` -eq 1 ]; then \
	        $(call printpatchKver,5.4) \
	        patch -p1 -f < src/patches/5.4* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "5\.[4]"` -eq 1 ]; then \
	        $(call printpatchKver,5.4) \
	        patch -p1 -f < src/patches/5.4* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "5\.[1][0]"` -eq 1 ]; then \
	        echo  ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "4\.[1][4]"` -eq 1 ]; then \
	        $(call printpatchKver,4.14) \
	        patch -p1 -f < src/patches/4.14* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "^4"\."[1-2][.|-]"` -eq 1 ]; then \
	        $(call printpatchKver,4.1) \
	        patch -p1 -f < src/patches/4.1* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | egrep  -c "4\.[8-9]"` -eq 1 ]; then \
	        $(call printpatchKver,4.9) \
	        patch -p1 -f < src/patches/4.9* > $(NULL_OUT) ; \
	    elif [ `echo ${UNAME_R} | grep -c ^4"\."[4-5]` -eq 1 ]; then \
	        $(call printpatchKver,4.4) \
	        patch -p1 -f < src/patches/4.4* > $(NULL_OUT) ; \
	    fi;\
	 fi;\
	  if [ $$? -ne 0 ]; then \
	        echo "Failed to apply ${UNAME_R} patch." ; \
	  else \
	        echo ; \
	  fi; \
	  fi; \
	 cd $(pwd) ; \
	 if [ $(shell uname -r | grep 2.6.32.36 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.36-0.5/bonding.h . ; \
		cp ../../../../bonding/2.6.32.36-0.5/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.36-0.5/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.54 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.54-0.3/bonding.h . ; \
		cp ../../../../bonding/2.6.32.54-0.3/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.54-0.3/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.46-0.3 ) ]; then \
		cd build/src/network/include/drivers/net/bonding/ ; \
		rm -f bond_3ad.h bond_alb.h bonding.h ; \
		cp ../../../../bonding/2.6.32.46-0.3/bonding.h . ; \
		cp ../../../../bonding/2.6.32.46-0.3/bond_3ad.h . ; \
		cp ../../../../bonding/2.6.32.46-0.3/bond_alb.h . ; \
		echo ; \
	  elif [ $(shell uname -r | grep 2.6.32.59 ) ]; then \
                cd build/src/network/include/drivers/net/bonding/ ; \
                rm -f bond_3ad.h bond_alb.h bonding.h ; \
                cp ../../../../bonding/2.6.32.59-0.7/bonding.h . ; \
                cp ../../../../bonding/2.6.32.59-0.7/bond_3ad.h . ; \
                cp ../../../../bonding/2.6.32.59-0.7/bond_alb.h . ; \
                echo ; \
	  fi; \
	 if [ ${CHFCOE_TARGET} -eq 1 ]; then \
                ( cd build/src/network/cxgb4 && patch -p1 -f < ../../../src/chfcoe/linux/cxgb4_pofcoe.patch > /dev/null ) ; \
                echo ; \
          fi;                \
	 cd $(pwd) ; \
	 if [ -f $(OFA_DIR)/Module.symvers ] ; then \
		echo "copying Module.symvers" ;\
		cp -f $(OFA_DIR)/Module.symvers $(NwSrc)/network/. ;\
	  fi ;
endef

define checklibibverbs
	echo "################################################## " ;\
	echo "#          $(2)ing $4 Libraries         # " ;\
	echo "################################################## " ;\
	$(MAKE) --no-print-directory -C $(LibSrc) $(1) ; 
endef

define installwdudpdebug
        $(MAKE) --no-print-directory -C $(LibSrc) $(1); 
endef

define checksnifferlibibverbs
        if [[ $(shell echo $(ARCH64) | grep $(arch)) ]] && [ $(DEBIAN) -ne 1 ] ; then \
                if [ -f /usr/lib64/libibverbs.so ] || [ ${2} == "Uninstall"  ] ; then \
                        $(MAKE) --no-print-directory -C $(SnifferSrc) $(3); \
                else \
                        if [ $(3) ] ; then \
                                echo -e "$(1)\t\t$(4)\t\t$(2)\tNot-supported" >> temp.log ;\
                        fi ;\
                fi ; \
        else \
                if [ -f /usr/lib/libibverbs.so ] || [ ${2} == "Uninstall"  ] ; then \
                        $(MAKE) --no-print-directory -C $(SnifferSrc) $(3) ; \
                else \
                        if [ $(3) ] ; then \
                                echo -e "$(1)\t\t$(4)\t\t$(2)\tNot-supported" >> temp.log ;\
                        fi ;\
                fi ; \
        fi ;
endef
# install_rpm_always function installs the proivded RPM.
# It takes care of already installed RPM by either upgrading
# or downgrading.
define install_rpm_always
	iwarp_libs_deps_rpm="$(1)";\
	version="$(2)";\
	read  -rd '' version <<< "$$version";\
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
            echo -e "RPM LOC : $$rpm_location" ;\
	    echo -e "|$$version|";\
	    echo -e "RPM Install Sequence : $${iwarp_libs_deps_rpm[*]}" ; \
        fi;\
	for rpm in $${iwarp_libs_deps_rpm[*]}; do \
	    if [ ${DEBUG} -eq 1 ]; then\
	         echo -e "RPM : $$rpm" ;\
	    fi;\
            rpm -q $$rpm &> /dev/null; \
            if [ $$? -ne 0 ]; then  \
                if [ ${DEBUG} -eq 1 ] ; then \
                    echo "Installing RPM : $$rpm";\
                    echo -e "rpm -ivh $$rpm_location/$$rpm-$$version*"; \
                fi;\
                rpm -ivh $$rpm_location/$$rpm-$$version* &> /dev/null ;\
            else\
       	        if [ ${DEBUG} -eq 1 ] ; then \
                     echo "RPM : $$rpm already installed, trying to update.";\
       	             echo -e "rpm -Uvh $$rpm_location/$$rpm-$$version*"; \
                fi;\
       	        rpm -Uvh $$rpm_location/$$rpm-$$version* &> /dev/null;\
                if [ $$? -ne 0 ]; then  \
                    if [ ${DEBUG} -eq 1 ] ; then \
                        echo "Upgrade failed, probably newer version is installed, attempting a downgrade.";\
                        echo -e "rpm -Uvh --oldpackage $$rpm_location/$$rpm-$$version*"; \
                    fi;\
                    rpm -Uvh --oldpackage $$rpm_location/$$rpm-$$version* &> /dev/null ;\
                    if [ $$? -ne 0 ]; then  \
                        if [ ${DEBUG} -eq 1 ] ; then \
                            echo "Downgrade failed, attempting a force install.";\
                            echo -e "rpm -ivh --force $$rpm_location/$$rpm-$$version*"; \
                        fi;\
                        rpm -ivh --force $$rpm_location/$$rpm-$$version* &> /dev/null;\
       	            fi;\
       	        fi;\
            fi;\
       done;
endef

#installdrvrpm function installs driver RPM's and dependecies.
define installdrvrpm
	rpm_deps_chart="nic|chelsio-series4-firmware:cxgb4nic \
	               nic_offload|chelsio-series4-firmware:cxgb4 \
		       vnic|chelsio-series4-firmware:cxgb4vf \
		       toe|chelsio-series4-firmware:cxgb4:cxgb4toe \
		       wdtoe|chelsio-series4-firmware:cxgb4wdtoe:libwdtoe:libwdtoe_dbg \
		       udp_offload|chelsio-series4-firmware:cxgb4:cxgb4toe \
		       toe_ipv4|chelsio-series4-firmware:cxgb4:cxgb4toe-ipv4 \
		       bypass|chelsio-series4-firmware:bypass:chelsio-bypass-utils \
		       ipv6|chelsio-series4-firmware:cxgb4:cxgb4ipv6 \
		       iwarp|chelsio-series4-firmware:cxgb4:chiwarp \
		       libcxgb4|libcxgb4:libcxgb4-devel \
		       libcxgb4_udp|libcxgb4_udp:libcxgb4_udp_debug \
		       libcxgb4_sock|libcxgb4_sock:libcxgb4_sock_debug \
		       libiwpm|iwpmd \
		       sniffer|sniffer \
		       bonding|chelsio-series4-firmware:cxgb4:cxgb4toe:bonding \
		       fcoe_full_offload_initiator|chelsio-series4-firmware:csiostor-initiator \
		       fcoe_full_offload_target|chelsio-series4-firmware:csiostor-target \
		       iscsi_pdu_target|chelsio-series4-firmware:cxgb4:cxgb4toe:chiscsi \
		       iscsi_pdu_initiator|chelsio-series4-firmware:cxgb4:cxgb4i \
		       scst_chfcoe|scst \
		       chfcoe|chelsio-series4-firmware:cxgb4:chfcoe \
		       rdma_block_device|rdma-block-device \
		       crypto|${chcr}${chsslbin} \
		       lio|chelsio-series4-firmware:cxgb4:cxgbit \
		       iser|chelsio-series4-firmware:cxgb4:chiwarp:${iser_libcxgb4}${iser_libs}${oiscsi_iser} \
	               nvme|chelsio-nvmeutils \
	               nvme_toe_spdk|chtcp \
		       ovs|openvswitch:kmod-openvswitch:kmod-openvswitch-debug:kmod-openvswitch-kdump\
		       tools|chelsio-utils \
		       libs|libcxgb4:libcxgb4-devel:${udp_libs}" ;\
	if [ ${DEBIAN} -eq 1 ]; then \
	    deb_location=$(shell pwd)/debrules/debinaries;\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "DEB LOC : $$deb_location" ;\
	        echo -e "Installing RPM : $(1)";\
	    fi;\
	    for entry in $${rpm_deps_chart[*]}; do \
	         proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
	             echo -e "ENTRY : $$entry" ;\
	             echo -e "PROTO : $$proto";\
	         fi;\
	         if [ $$proto  == "$(1)" ] && [ $$proto  != "nvme_toe_spdk" ]; then  \
	             deb_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	             if [ ${DEBUG} -eq 1 ] ; then \
	                  echo -e "got match for $(1) : $$entry" ;\
		     fi;\
		     break;\
	         fi; \
	    done ;\
	    deb_install_seq=$$(echo $$deb_install_seq | tr ":" " ");\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "DEB Install Sequence : $${deb_install_seq[*]}" ; \
	    fi;\
	    for deb in $${deb_install_seq[*]}; do \
	        dpkg -s $$deb &> /dev/null; \
	        if [ $$? -ne 0 ]; then  \
	            if [ ${DEBUG} -eq 1 ] ; then \
	                echo "Installing  : $$deb-$(vers)";\
		        echo -e "dpkg -i $$deb_location/$$deb-$(vers)*"; \
	            fi;\
	            if [[ $$deb == "chelsio-series4-firmware" ]] ; then \
	                dpkg --force overwrite -i $$deb_location/$$deb-$(vers)* ;\
	                if [ $$? -ne 0 ] ; then exit 1 ; fi ; \
	            else \
	                if [ $$deb == "cxgb4wdtoe" ] || [ $$deb == "libcxgb4" ] ; then \
	                    dpkg --force overwrite -i $$deb_location/$$deb-$(vers)* 2> /dev/null ;\
	                    if [ $$? -ne 0 ] ; then exit 1 ; fi ; \
	                else \
	                    dpkg -i $$deb_location/$$deb-$(vers)* ;\
	                    if [ $$? -ne 0 ] ; then exit 1 ; fi ; \
	                fi;\
	            fi ; \
	        elif [ ${DEBUG} -eq 1 ] ; then \
	            echo "DEB : $$deb already installed";\
	        fi;\
	    done;\
	else \
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM LOC : $$rpm_location" ;\
	    echo -e "Installing RPM : $(1)";\
	fi;\
	for entry in $${rpm_deps_chart[*]}; do \
	    proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "ENTRY : $$entry" ;\
	        echo -e "PROTO : $$proto";\
	    fi;\
	    if [ $$proto  == "$(1)" ]; then  \
	         rpm_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
		     echo -e "got match for $(1) : $$entry" ;\
		 fi;\
		 break;\
            fi; \
        done ;\
	rpm_install_seq=$$(echo $$rpm_install_seq | tr ":" " ");\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM Install Sequence : $${rpm_install_seq[*]}" ; \
	fi;\
	for rpm in $${rpm_install_seq[*]}; do \
	    rpm -q $$rpm &> /dev/null; \
            if [ $$? -ne 0 ]; then  \
	         if [ ${DEBUG} -eq 1 ] ; then \
		    echo "Installing RPM : $$rpm-$(vers)";\
	            echo -e "rpm -ivh $$rpm_location/$$rpm-$(vers)*"; \
	         fi;\
		 if [ $$rpm == "scst" ] ; then \
			for rpmbin in scst-${UNAME_R} scst-${UNAME_R}-devel scst-${UNAME_R}-debuginfo scstadmin scstadmin-debuginfo ; do \
				rpm -q $$rpmbin &> /dev/null; \
				if [ $$? -ne 0 ]; then  \
				 	rpm -ivh $$rpm_location/$$rpmbin* ;\
				fi ; \
			done; \
		 else \
		        if [ $$rpm == "chopenssl" ] || [ $$rpm == "iwpmd" ] ; then \
	         	  rpm -ivh $$rpm_location/$$rpm* --nodeps;\
		        elif [[ $$rpm =~ "libcxgb4" ]] || [[ $$rpm =~ "chelsio-nvmeutils" ]] ; then \
	         	  rpm -ivh $$rpm_location/$$rpm-$(vers)* --force --nodeps || exit 1 ;\
		        elif [[ $$rpm == "openvswitch-kmod" ]] ; then \
	         	  rpm -ivh $$rpm_location/$$rpm* --force --nodeps || exit 1 ;\
		        elif [[ $$rpm == "chelsio-utils" ]] ; then \
	         	  rpm -ivh $$rpm_location/$$rpm* --force --nodeps || exit 1 ;\
		        elif [[ $$rpm == "chelsio-series4-firmware" ]] ; then \
	         	       rpm -ivh $$rpm_location/$$rpm* --force   ;\
		        else \
	         	  rpm -ivh $$rpm_location/$$rpm-$(vers)* ;\
		        fi ;\
		 fi ; \
	    elif [ ${DEBUG} -eq 1 ] ; then \
		 echo "RPM : $$rpm already installed";\
	    fi;\
	done; \
	fi
endef

#uninstalldrvrpm function uninstalls driver RPM's and dependecies.
define uninstalldrvrpm
	rpm_deps_chart="nic|cxgb4nic:cxgb4:chelsio-series4-firmware \
	               nic_offload|cxgb4:chelsio-series4-firmware \
		       vnic|cxgb4vf \
		       toe|cxgb4toe \
		       wdtoe|cxgb4wdtoe:cxgb4:chelsio-series4-firmware:libwdtoe:libwdtoe_dbg \
		       udp_offload|bonding:cxgb4toe \
		       toe_ipv4|cxgb4toe-ipv4 \
		       bypass|chelsio-bypass-utils:bypass:chelsio-series4-firmware \
		       ipv6|cxgb4ipv6 \
		       iwarp|libcxgb4_sock_debug:libcxgb4_udp_debug:libcxgb4_sock:libcxgb4_udp:libcxgb4-devel:libcxgb4:chiwarp \
		       sniffer|sniffer \
		       bonding|bonding \
		       fcoe_full_offload_initiator|csiostor-initiator \
		       fcoe_full_offload_target|csiostor-target \
		       chfcoe|chfcoe \
		       scst_chfcoe|scst \
		       iscsi_pdu_target|chiscsi \
		       iscsi_pdu_initiator|cxgb4i \
		       crypto|chcr:chopenssl-devel:chopenssl-doc:chopenssl-debuginfo:chopenssl:af_alg:af_alg-debuginfo \
		       lio|cxgbit \
		       iser| \
	               nvme|chelsio-nvmeutils \
	               nvme_toe_spdk|chtcp \
		       tools|chelsio-utils \
		       rdma_block_device|rdma-block-device \
		       ovs|openvswitch:kmod-openvswitch:kmod-openvswitch-debug:kmod-openvswitch-kdump \
		       libs|libcxgb4_sock_debug:libcxgb4_udp_debug:libcxgb4_sock:libcxgb4_udp:libcxgb4-devel:libcxgb4" ; \
	if [ ${DEBIAN} -eq 1 ] ; then \
	    deb_deps_chart="nic|cxgb4nic:cxgb4:chelsio-series4-firmware \
                       nic_offload|cxgb4:chelsio-series4-firmware \
                       vnic|cxgb4vf \
                       toe|cxgb4toe \
                       wdtoe|cxgb4wdtoe:cxgb4:chelsio-series4-firmware:libwdtoe:libwdtoe-dbg \
                       udp_offload|bonding:cxgb4toe \
                       toe_ipv4|cxgb4toe-ipv4 \
                       bypass|chelsio-bypass-utils:bypass:chelsio-series4-firmware \
                       ipv6|cxgb4ipv6 \
                       iwarp|libcxgb4-sock-dbg:libcxgb4-udp-dbg:libcxgb4-sock:libcxgb4-udp:libcxgb4-devel:libcxgb4:chiwarp \
                       sniffer|sniffer \
                       bonding|bonding \
                       fcoe_full_offload_initiator|csiostor-initiator \
                       fcoe_full_offload_target|csiostor-target \
                       chfcoe|chfcoe \
                       scst_chfcoe|scst \
                       iscsi_pdu_target|chiscsi \
                       iscsi_pdu_initiator|cxgb4i \
		       crypto|chcr:chopenssl \
		       lio|cxgbit \
		       iser| \
	               nvme|chelsio-nvmeutils \
                       tools|chelsio-utils \
		       rdma_block_device|rdma-block-device \
                       libs|libcxgb4-sock-dbg:libcxgb4-udp-dbg:libcxgb4-sock:libcxgb4-udp:libcxgb4-devel:libcxgb4" ; \
	    deb_location=$(shell pwd)/debrules/debinaries;\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "Removing package : $(1)";\
	    fi;\
	    for entry in $${deb_deps_chart[*]}; do \
	       proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	       if [ ${DEBUG} -eq 1 ] ; then \
	          echo -e "ENTRY : $$entry" ;\
	          echo -e "PROTO : $$proto";\
	       fi;\
	       if [ $$proto  == "$(1)" ] && [ $$proto  != "nvme_toe_spdk" ]; then  \
	          deb_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	          if [ ${DEBUG} -eq 1 ] ; then \
	             echo -e "got match for $(1) : $$entry" ;\
	          fi;\
	          break;\
	       fi; \
	    done ;\
	    deb_install_seq=$$(echo $$deb_install_seq | tr ":" " ");\
	    if [ ${DEBUG} -eq 1 ] ; then \
	       echo -e "DEB Uninstall Sequence : $${deb_install_seq[*]}" ; \
	    fi;\
	    for deb in $${deb_install_seq[*]}; do \
	       dpkg -s $$deb &> /dev/null; \
	       if [ $$? -eq 0 ]; then  \
	          if [ ${DEBUG} -eq 1 ] ; then \
	             echo "Uninstalling DEB : $$deb";\
	             echo -e "dpkg -r $$deb"; \
	             echo -e "dpkg -P $$deb"; \
	          fi;\
	          dpkg -r $$deb ; \
	          dpkg -P $$deb ; \
	       elif [ ${DEBUG} -eq 1 ] ; then \
	          echo "DEB : $$deb not uninstalled";\
	       fi;\
	    done; \
	else \
	rpm_location=$(shell pwd)/rpmbuild/RPMS/$(arch);\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "Removing package : $(1)";\
	fi;\
	for entry in $${rpm_deps_chart[*]}; do \
	    proto=$$(echo $$entry | awk -F"|" '{print $$1}');\
	    if [ ${DEBUG} -eq 1 ] ; then \
	        echo -e "ENTRY : $$entry" ;\
	        echo -e "PROTO : $$proto";\
	    fi;\
	    if [ $$proto  == "$(1)" ]; then  \
	         rpm_install_seq=$$(echo $$entry | awk -F"|" '{print $$2}');\
	         if [ ${DEBUG} -eq 1 ] ; then \
		     echo -e "got match for $(1) : $$entry" ;\
		 fi;\
		 break;\
            fi; \
        done ;\
	rpm_install_seq=$$(echo $$rpm_install_seq | tr ":" " ");\
	if [ ${DEBUG} -eq 1 ] ; then \
	    echo -e "RPM Uninstall Sequence : $${rpm_install_seq[*]}" ; \
	fi;\
	for rpm in $${rpm_install_seq[*]}; do \
	    if [ $$rpm == "scst" ] ; then \
                for rpmbin in scst-${UNAME_R} scst-${UNAME_R}-devel scst-${UNAME_R}-debuginfo scstadmin scstadmin-debuginfo ; do \
			rpm -q $$rpmbin &> /dev/null; \
                        if [ $$? -eq 0 ]; then  \
				if [ ${DEBUG} -eq 1 ] ; then \
		                    echo "Uninstalling RPM : $$rpmbin";\
				    echo -e "rpm -e $$rpmbin"; \
		                fi;\
				rpm -e $$rpmbin ;\
                        fi ; \
                done; \
		depmod -a ; \
	    fi;\
	    rpm -q $$rpm &> /dev/null; \
            if [ $$? -eq 0 ]; then  \
	         if [ ${DEBUG} -eq 1 ] ; then \
		    echo "Uninstalling RPM : $$rpm";\
	            echo -e "rpm -e $$rpm"; \
	         fi;\
	         rpm -e $$rpm ;\
	    elif [ ${DEBUG} -eq 1 ] ; then \
		 echo "RPM : $$rpm not uninstalled";\
	    fi;\
	done; \
	fi  ; 
endef

define delwdbins
	if [[ $(shell echo $(dist)|grep -c kernel5u0 ) -eq 1  ]] ; then\
		rm -rf /sbin/wdload ;\
		rm -rf /sbin/wdunload ;\
	fi;\
	if [[ $(shell echo $(dist)|grep -c kernel5u6 ) -eq 1  ]] ; then\
		rm -rf /sbin/wdload ;\
		rm -rf /sbin/wdunload ;\
	fi;
endef

define installrdmatools
        if [[ $(shell echo $(arch) | grep -c aarch) -eq 0 ]] ; then \
	if [ ! -f /usr/bin/rdma_lat ] && [ ! -f /sbin/rdma_lat ]; then \
		$(MAKE) --no-print-directory -C ${ToolSrc}/rdma_tools lat_install ;\
	fi ; \
	if [ ! -f /usr/bin/rdma_bw ] && [ ! -f /sbin/rdma_bw ]; then \
		$(MAKE) --no-print-directory -C ${ToolSrc}/rdma_tools bw_install ;\
	fi ; \
	fi ;
endef

define uninstallrdmatools
	if [ -f /sbin/rdma_lat ]; then \
		rm -f /sbin/rdma_lat ; \
	fi ; \
	if [  -f /sbin/rdma_bw ]; then \
		rm -f /sbin/rdma_bw ;\
	fi ;
endef

define copyiscsiconffile
	if [ ${DEBIAN} -eq 1 ] ; then \
		if [ -f /etc/iscsi/iscsid.conf.1 ] ; then \
			mv /etc/iscsi/iscsid.conf.1 /etc/iscsi/iscsid.conf ; \
		fi;\
	fi;
endef

define libcxgb4_cleanup
	find /usr/lib -name libcxgb4* -exec rm {} \+; \
	find /usr/lib64 -name libcxgb4* -exec rm {} \+; \
	find /usr/local/lib -name libcxgb4* -exec rm {} \+; \
	find /usr/local/lib64 -name libcxgb4* -exec rm {} \+; \
	ldconfig ;
endef

define copyconfigfile
if [ ${CONF} == "UNIFIED_WIRE" ] ; then \
    install -m 644 $(FwSrc)/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_TOE" ]; then \
    install -m 644 $(FwSrc)/high_capacity_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_RDMA" ] ; then \
    install -m 644 $(FwSrc)/high_capacity_rdma/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_rdma/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_rdma/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "LOW_LATENCY" ]; then \
    install -m 644 $(FwSrc)/low_latency_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/low_latency_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/low_latency_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "UDP_OFFLOAD" ]; then \
    install -m 644 $(FwSrc)/udp_so_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/udp_so_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/udp_so_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "WIRE_DIRECT_LATENCY" ]; then \
    install -m 644 $(FwSrc)/edc_only_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/edc_only_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/edc_only_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_WD" ]; then \
    install -m 644 $(FwSrc)/high_capacity_wd/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_wd/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_wd/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_HASH_FILTER" ]; then \
    install -m 644 $(FwSrc)/high_capacity_hash_filter_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_hash_filter_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_hash_filter_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "RDMA_PERFORMANCE" ]; then \
    install -m 644 $(FwSrc)/rdma_perf_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/rdma_perf_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/rdma_perf_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "NVME_PERFORMANCE" ]; then \
    install -m 644 $(FwSrc)/nvme_perf_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/nvme_perf_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/nvme_perf_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "ISCSI_PERFORMANCE" ]; then \
    install -m 644 $(FwSrc)/iscsi_perf_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/iscsi_perf_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/iscsi_perf_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "MEMORY_FREE" ]; then \
    install -m 644 $(FwSrc)/memfree_config/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/memfree_config/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/memfree_config/t6-config.txt $(FwTar) ; \
elif [ ${CONF} == "HIGH_CAPACITY_VF" ]; then \
    install -m 644 $(FwSrc)/high_capacity_vf/t4-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_vf/t5-config.txt $(FwTar) ; \
    install -m 644 $(FwSrc)/high_capacity_vf/t6-config.txt $(FwTar) ; \
fi ;
endef
    

define displaysummary
$(if $(filter $1,$(MAKECMDGOALS)),$(if $(filter 0,$(inst)),$(call display,$(2)),),)
endef

define display
$(eval j := $(shell expr $j + 1 ) ) \
if [ $(j) == $(k) ] ; then \
 $(call summary,$(1)) \
fi
endef

define summary
echo ; \
echo ; \
echo "***********************" ; \
echo "*      Summary        *" ; \
echo "***********************" ; \
echo "CONFIG = $(firm_config)" ; \
echo "Protocol   Modules\Libraries\Tools Action Status" | awk '{printf "%-30s%-30s%-15s%-10s\n", $$1,$$2,$$3,$$4}' ; \
echo "------------------------------------------------------------------------------------------" ;\
sort -u temp.log | grep $(1) | awk '{printf "%-30s%-30s%-15s%-10s\n", $$1,$$2,$$3,$$4}' | uniq -i ;\
if [ -f deps.log ] ; then \
echo -e "***********************" ; \
echo -e "*      Warnings       *" ; \
echo -e "***********************" ; \
cat deps.log ; \
mv -f deps.log scripts/. ;\
fi ;\
if [ $(inst) != 1 ] ; then \
 rm -rf temp.log; \
fi ; \
if [ $(installprecheck) == 1 ] ; then \
 ldconfig ; \
fi ;
endef

define logtemp
echo -e "$1\t\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logtempc
echo -e "$1\t\t\t$2\t\t$3\tFailed*" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log ;
endef
