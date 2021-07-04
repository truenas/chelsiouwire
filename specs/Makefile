SHELL = /bin/bash

# The top-level makefile defines required variables and flags.
ifneq ($(shell [[ $(MAKELEVEL) -ge 1 ]] && echo 1),1)
  $(info Please use the top-level Makefile to build this driver)
endif

topdir=$(shell pwd)/..
srcdirNw = $(topdir)/build/src/network
srcdirchfcoe = $(topdir)/build/src
FwSrc = $(topdir)/build/src/network/firmware
srcdirTg = $(topdir)/build/src/csiostor_target
srcdirSt = $(topdir)/build/src/scst
srcdir = $(topdir)/build/src/cxgbi
srcdird = $(topdir)/build/src/oiscsi
srcdirs = $(topdir)/build/src/chiscsi
cxgbitsrc = $(topdir)/build/src/cxgbit/src
libdirs = $(topdir)/build/libs
toolsdir = $(topdir)/build/tools
srcrdma = $(topdir)/build/src/rdma_block_dev
ptpsrcdir = $(topdir)/build/src/linuxptp
ovsver =$(OVS_VERSION)
ovsdir = $(topdir)/build/src/openvswitch-$(ovsver)
rpmdir = $(topdir)/rpmbuild
target = $(shell uname -m)
#kversion = $(shell uname -r)
kversion = $(UNAME_RPM)
asrcdir = $(topdir)/build/src

udp_libs := libcxgb4_udp libcxgb4_sock libs_dbg
ifneq ($(filter aarch64 ppc64 ppc64le ,$(target)),)
  udp_libs :=
endif
ifeq ($(NVME),1)
  udp_libs :=
endif

ifeq (${CONF},UNIFIED_WIRE)
    f=$(FwSrc)/*-config.txt
endif
ifeq (${CONF},RING)
    f=$(FwSrc)/ring_config/*-config.txt
endif
ifeq (${CONF},HIGH_CAPACITY_TOE)
    f=$(FwSrc)/high_capacity_config/*-config.txt
endif
ifeq (${CONF},HIGH_CAPACITY_RDMA)
    f=$(FwSrc)/high_capacity_rdma/*-config.txt
endif
ifeq (${CONF},LOW_LATENCY)
    f=$(FwSrc)/low_latency_config/*-config.txt 
endif
ifeq (${CONF},UDP_OFFLOAD)
    f=$(FwSrc)/udp_so_config/*-config.txt 
endif
ifeq ($(CONF),WIRE_DIRECT_LATENCY)
    f=$(FwSrc)/edc_only_config/*-config.txt
endif
ifeq ($(CONF),HIGH_CAPACITY_WD)
    f=$(FwSrc)/high_capacity_wd/*-config.txt
endif
ifeq ($(CONF),HIGH_CAPACITY_HASH_FILTER)
    f=$(FwSrc)/high_capacity_hash_filter_config/*-config.txt
endif
ifeq ($(CONF),RDMA_PERFORMANCE)
    f=$(FwSrc)/rdma_perf_config/*-config.txt
endif
ifeq ($(CONF),NVME_PERFORMANCE)
    f=$(FwSrc)/nvme_perf_config/*-config.txt
endif
ifeq ($(CONF),ISCSI_PERFORMANCE)
    f=$(FwSrc)/iscsi_perf_config/*-config.txt
endif
ifeq ($(CONF),MEMORY_FREE)
    f=$(FwSrc)/memfree_config/*-config.txt
endif
ifeq ($(CONF),HIGH_CAPACITY_VF)
    f=$(FwSrc)/high_capacity_vf/*-config.txt
endif

ifneq ($(filter $(kdist),RHEL7.0 RHEL7.1 RHEL7.2 RHEL7.3 RHEL7.4 RHEL7.5 RHEL7.6 RHEL7.7 RHEL7.8 RHEL7.9 RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 RHEL6.8 RHEL6.9 RHEL6.10 SLES12sp2 SLES12sp3 SLES12sp4 SLES15 SLES15sp1 SLES11sp4 ubuntu-14.04.4 ubuntu-16.04 ubuntu-16.04.1 ubuntu-16.04.4 ubuntu-16.04.5 ubuntu-18.04.1 ubuntu-18.04.2 ubuntu-18.04.3 ubuntu-18.04.4 ubuntu-18.04.5 ubuntu-20.04 ubuntu-20.04.1 ubuntu-20.04.2), )
  enable_oiscsi=0
else
  enable_oiscsi=1
endif

ifneq ($(filter $(kdist),RHEL8.0 RHEL8.1 RHEL8.2 RHEL8.3 ), )
  debug_enable=0
  udp_enable=1
  rhel_flag=1
  sles_flag=0
else
  debug_enable=1
  udp_enable=0
  rhel_flag=0
  sles_flag=1
endif
ifeq ($(dist),kernel5u10)
  debug_enable=0
endif
ifeq ($(kdist),SLES15sp1)
  debug_enable_sles=0
else
  debug_enable_sles=1
endif

.PHONY: all
all: prep nic toe firmware vnic chiwarp bonding cxgbi oiscsi oiscsiutils \
	chiscsi chutils chiutils

.PHONY: nic_offload
nic_offload: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "setptp $(SETPTP)" \
	  --define "ptpsrcdir $(ptpsrcdir)" \
	  --define "name cxgb4" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  cxgb4.spec && $(call logs,Network-Offload(NIC),cxgb4,rpm) ) || $(call logtemp,Network-Offload(NIC),cxgb4,rpm) 

.PHONY: nic_ipv4
nic_ipv4: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
	  --define "setptp $(SETPTP)" \
	  --define "ptpsrcdir $(ptpsrcdir)" \
          --define "name cxgb4" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
          --target $(target) \
          cxgb4.spec && $(call logs,Network(NIC_IPV4),cxgb4,rpm) ) || $(call logtemp,Network(NIC_IPV4),cxgb4,rpm)

.PHONY: nic
nic: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
	  --define "setptp $(SETPTP)" \
	  --define "ptpsrcdir $(ptpsrcdir)" \
          --define "name cxgb4nic" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
          --target $(target) \
          cxgb4nic.spec && $(call logs,Network(NIC),cxgb4,rpm) ) || $(call logtemp,Network(NIC),cxgb4,rpm) 

.PHONY: crypto
crypto: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name chcr" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --define "debug_enable_sles $(debug_enable_sles)"  \
          --target $(target) \
          crypto.spec && $(call logs,Chelsio-Crypto,${chcr_sum},rpm) ) || $(call logtemp,Chelsio-Crypto,${chcr_sum},rpm) 

.PHONY: chspdk
chspdk: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name chtcp" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --define "debug_enable_sles $(debug_enable_sles)"  \
          --target $(target) \
          chspdk.spec && $(call logs,SPDK_NVMe/TOE,chtcp,rpm) ) || $(call logtemp,SPDK_NVMe/TOE,chtcp,rpm) 

.PHONY: toe
toe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4toe" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  cxgb4toe.spec && $(call logs,Network-Offload(TOE),t4_tom,rpm) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
	    $(call logs,Udp_offload,t4_tom,rpm) \
	  fi ; \
	  if [ $(ipv6_enable) -eq 1 ] ; then \
	   $(call logs,Ipv6_offload,t4_tom,rpm) \
	  fi;\
	  ) || $(call logtemp,Network-Offload(TOE),t4_tom,rpm) 

.PHONY: wdtoe
wdtoe: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4wdtoe" \
          --define "release 0" \
          --target $(target) \
          cxgb4wdtoe.spec && $(call logs,WD-TOE,t4_tom,rpm) ) || $(call logtemp,WD-TOE,t4_tom,rpm) 

.PHONY: udp_offload
udp_offload: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4toe" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
          --target $(target) \
          cxgb4toe.spec && $(call logs,Network(UDP-Offload),t4_tom,rpm) ) || $(call logtemp,Network(UDP-Offload),t4_tom,rpm) 


.PHONY: toe_ipv4
toe_ipv4: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4toe-ipv4" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  cxgb4toe.spec && $(call logs,Network-Offload(TOE_IPV4),t4_tom,rpm) \
	  if [ $(is_udp_offload) -eq 1 ] ; then \
             $(call logs,Udp_offload,t4_tom,rpm) \
	  fi ; \
	  ) || $(call logtemp,Network-Offload(TOE),t4_tom,rpm) 

.PHONY: bypass
bypass: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name bypass" \
	  --define "release 0" \
	  --target $(target) \
	  bypass.spec && $(call logs,Network-Offload(Bypass),cxgb4,rpm) ) || $(call logtemp,Network-Offload(Bypass),cxgb4,rpm) 

.PHONY: ipv6
ipv6: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4ipv6" \
          --define "release 0" \
          --target $(target) \
          cxgb4ipv6.spec && $(call logs,IPv6-Offload,ipv6,rpm) ) || $(call logtemp,IPv6-Offload,ipv6,rpm) 

.PHONY: toe_ipv6
toe_ipv6: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(srcdirNw)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name cxgb4ipv6" \
          --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
          --target $(target) \
          cxgb4toe.spec && $(call logs,IPv6-Offload,ipv6,rpm) ) || $(call logtemp,IPv6-Offload,ipv6,rpm) 

.PHONY: firmware
firmware: prep
	 @ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "conffile $(f)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-series4-firmware" \
	  --define "release 0" \
	  --target $(target) \
	  firmware.spec && $(call logs,Firmware,t4fw-X.Y.Z.bin,rpm) ) || $(call logtemp,Firmware,t4fw-X.Y.Z.bin,rpm) 

.PHONY: chiwarp
chiwarp: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiwarp" \
	  --define "release 0" \
	  --target $(target) \
	  chiwarp.spec && $(call logs,RDMA(iWARP),iw_cxgb4,rpm) ) || $(call logtemp,RDMA(iWARP),iw_cxgb4,rpm) 

.PHONY: sniffer
sniffer: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(toolsdir)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name sniffer" \
          --define "release 0" \
          --target $(target) \
          sniffer.spec && $(call logs,Sniffer,wd_tcpdump,rpm) ) || $(call logtemp,Sniffer,wd_tcpdump,rpm) 

.PHONY: bonding
bonding: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name bonding" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  bonding.spec && $(call logs,Bonding-Offload,bonding,rpm) ) || $(call logtemp,Bonding-Offload,bonding,rpm) 

.PHONY: fcoe
fcoe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name csiostor-initiator" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  csiostor.spec && $(call logs,FCoE(full-offload-initiator),csiostor,rpm) ) || ( $(call logtemp,FCoE(full-offload-initiator),csiostor,rpm))

.PHONY: chfcoe
chfcoe: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirchfcoe)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chfcoe" \
	  --define "release 0" \
	  --target $(target) \
	  chfcoe.spec && $(call logs,chfcoe(PDU-Offload-Target),chfcoe,rpm) ) || ( $(call logtemp,chfcoe(PDU-Offload-Target),chfcoe,rpm))

.PHONY: fcoe_target
fcoe_target: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirTg)" \
	  --define "srcdirSt $(srcdirSt)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name csiostor-target" \
	  --define "release 0" \
	  --target $(target) \
	  csiostor-scst.spec && $(call logs,FCoE(full-offload-target),csioscst,rpm) ) || $(call logtemp,FCoE(full-offload-target),csioscst,rpm) 

.PHONY: cxgbi
cxgbi: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdir)"  \
	  --define "osrcdir $(srcdird)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "enable_oiscsi $(enable_oiscsi)" \
	  --define "name cxgb4i" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --define "debug_enable_sles $(debug_enable_sles)"  \
	  --target $(target) \
	  cxgbi.spec && $(call logs,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm) \
	  ) || $(call logtemp,iSCSI(iscsi-pdu-initiator),cxgb4i,rpm) 

.PHONY: vnic
vnic: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirNw)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgb4vf" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --define "debug_enable_sles $(debug_enable_sles)"  \
	  --target $(target) \
	  cxgb4vf.spec && $(call logs,SR-IOV_networking(vNIC),cxgb4vf,rpm) ) || $(call logtemp,SR-IOV_networking(vNIC),cxgb4vf,rpm) 

.PHONY: oiscsiutils
oiscsiutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdird)" \
	  --define "osrcdir $(srcdird)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name oiscsi-utils" \
	  --define "release 0" \
	  --define "debug_enable $(debug_enable)"  \
	  --target $(target) \
	  oiscsi.spec && $(call logs,iSCSI(user_utilities),iscsi*,rpm) \
	  ) || $(call logtemp,iSCSI(user_utilities),iscsi*,rpm) 

.PHONY: chiscsi
chiscsi: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiscsi" \
	  --define "release 0" \
	  --target $(target) \
	  chiscsi.spec && $(call logs,iSCSI(pdu-offload-target),chiscsi_t4,rpm) \
	  ) || ( $(call logtemp,iSCSI(pdu-offload-target),chiscsi_t4,rpm) \
	   $(call logtemp,iSCSI(target_user_util),iscsictl,rpm))

.PHONY: lio
lio: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(cxgbitsrc)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name cxgbit" \
	  --define "release 0" \
	  --target $(target) \
	  cxgbit.spec && $(call logs,LIO-Target,cxgbit,rpm) \
	  ) || ( $(call logtemp,LIO-Target,cxgbit,rpm) )

.PHONY: chutils
chutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(toolsdir)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-utils" \
	  --define "release 0" \
	  --target $(target) \
	  chelsio-utils.spec && $(call logs,Chelsio-utils(tools),cxgbtool,rpm) \
	  ) || $(call logtemp,Chelsio-utils(tools),cxgbtool,rpm) 

.PHONY: bypassutils
bypassutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(toolsdir)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-bypass-utils" \
	  --define "release 0" \
	  --target $(target) \
	  bypass-utils.spec && $(call logs,Bypass_tools,ba_*,rpm) \
	  ) || $(call logtemp,Bypass_tools,ba_*,rpm) 

.PHONY: chiutils
chiutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chiscsi-utils" \
	  --define "release 0" \
	  --define "arch $(target)" \
	  --target $(target) \
	  chiscsi-data.spec && $(call logs,iSCSI(target_user_util),iscsictl,rpm) \
	  ) || $(call logtemp,iSCSI(target_user_util),iscsictl,rpm) 

.PHONY: nvmeutils
nvmeutils: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "toolsdir $(toolsdir)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name chelsio-nvmeutils" \
	  --define "release 0" \
	  --define "arch $(target)" \
	  --target $(target) \
	  nvme.spec && $(call logs,NVMe-Utils,nvme,rpm) \
	  ) || $(call logtemp,NVMe-Utils,nvme,rpm) 


.PHONY: rdma_block
rdma_block: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(srcrdma)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name rdma-block-device" \
	  --define "release 0" \
	  --define "arch $(target)" \
	  --target $(target) \
	  rdma_block.spec && $(call logs,RDMA-Block-Device,rbd,rpm) \
	  ) || $(call logtemp,RDMA-Block-Device,rbd,rpm) 

.PHONY: ovs
ovs: prep
	@ ( cd $(ovsdir) ; make dist ; \
	cp -f openvswitch-$(ovsver).tar.gz $(rpmdir)/SOURCES/ ; \
	( rpmbuild -bb \
	--without check \
	--define "_topdir $(rpmdir)" \
	rhel/openvswitch.spec && \
	rpmbuild -bb \
	--without check \
	--define "_topdir $(rpmdir)" \
	--define "kversion $(kversion)" \
	--define "kflavors default debug kdump " \
	rhel/openvswitch-kmod-rhel6.spec ) && $(call logs,OVS,openvswitch,rpm) ) || $(call logtemp,OVS,openvswitch,rpm)

.PHONY: libs
libs: libcxgb4 $(udp_libs)

.PHONY: libs_dbg
libs_dbg: libcxgb4_udp_dbg libcxgb4_sock_dbg

.PHONY: libcxgb4
libcxgb4: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(libdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name libcxgb4" \
	  --define "release 0" \
	  --target $(target) \
	  libcxgb4.spec && $(call logs,iWarp-Libraries,libcxgb4,rpm) \
          ) || $(call logtemp,iWarp-Libraries,libcxgb4,rpm)
	@ echo ' --define "_topdir $(rpmdir)" --define "srcdir $(libdirs)" --define "kversion $(kversion)" --define "version $(vers)" --define "name libcxgb4" --define "release 0"  --target $(target) '


.PHONY: libiwpm
libiwpm: prep
	@  $(call checklibibverbs,,rpm,iSER-Library,iwpmd,1.0.6)
	@  rm -rf libiwpm-$(vers) libiwpm-1.0.6* iwpmd-$(vers) iwpmd-1.0.6*

.PHONY: libibverbs
libibverbs: prep
	@  $(call checklibibverbs,,rpm,RDMA(iWARP-Lib),libibverbs,1.1.8)
	@  rm -rf libibverbs-$(vers) libibverbs-1.1.8*

.PHONY: librdmacm
librdmacm: prep
	@  $(call checklibibverbs,,rpm,RDMA(iWARP-Lib),librdmacm,1.0.21)
	@  rm -rf librdmacm-$(vers) librdmacm-1.0.21*

.PHONY: libcxgb4_udp
libcxgb4_udp: prep
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(libdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name libcxgb4_udp" \
	  --define "release 0" \
	  --define "udp_enable $(udp_enable)"  \
	  --target $(target) \
	  libcxgb4_udp.spec && $(call logs,WD-UDP-Libraries,libcxgb4_udp,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_udp,rpm)

.PHONY:wdtoe_libs
wdtoe_libs:prep wdtoe_libs_debug
	rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libwdtoe" \
          --define "release 0" \
          --target $(target) \
          libwdtoe.spec

.PHONY:wdtoe_libs_debug
wdtoe_libs_debug:prep
	rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libwdtoe_dbg" \
          --define "release 0" \
          --target $(target) \
          libwdtoe_dbg.spec

.PHONY: libcxgb4_sock
libcxgb4_sock: prep libcxgb4_udp
	@ ( rpmbuild -bb \
	  --define "_topdir $(rpmdir)" \
	  --define "srcdir $(libdirs)" \
	  --define "kversion $(kversion)" \
	  --define "version $(vers)" \
	  --define "name libcxgb4_sock" \
	  --define "release 0" \
	  --define "udp_enable $(udp_enable)"  \
	  --target $(target) \
	  libcxgb4_sock.spec && $(call logs,WD-UDP-Libraries,libcxgb4_sock,rpm) \
	  ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_sock,rpm) 

.PHONY: libcxgb4_udp_dbg
libcxgb4_udp_dbg: prep
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libcxgb4_udp_debug" \
          --define "release 0" \
	  --define "udp_enable $(udp_enable)"  \
          --target $(target) \
          libcxgb4_udp_dbg.spec && $(call logs,WD-UDP-Libraries,libcxgb4_udp_dbg,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_udp_dbg,rpm)

.PHONY: libcxgb4_sock_dbg
libcxgb4_sock_dbg: prep libcxgb4_udp_dbg
	@ ( rpmbuild -bb \
          --define "_topdir $(rpmdir)" \
          --define "srcdir $(libdirs)" \
          --define "kversion $(kversion)" \
          --define "version $(vers)" \
          --define "name libcxgb4_sock_debug" \
          --define "release 0" \
	  --define "udp_enable $(udp_enable)"  \
          --target $(target) \
          libcxgb4_sock_dbg.spec && $(call logs,WD-UDP-Libraries,libcxgb4_sock_dbg,rpm) \
          ) || $(call logtemp,WD-UDP-Libraries,libcxgb4_sock_dbg,rpm)

.PHONY: prep
prep:
	@ package=$(pkgname)-$(pkgvers);\
	  /bin/mkdir -p $(rpmdir)/BUILD/$$package;\
	  /bin/mkdir -p $(rpmdir)/SOURCES ;\
	  /bin/mkdir -p $(rpmdir)/RPMS/$(target);

.PHONY: chssl
chssl:
	@ cp -rpf $(asrcdir)/chopenssl-1.0.2d . ; \
               tar cfz chopenssl-1.0.2d.tar.gz chopenssl-1.0.2d ; \
               mv -f chopenssl-1.0.2d.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(asrcdir)/chopenssl-1.0.2d" \
               --define "kversion $(kversion)" \
               --target $(target) \
               $(asrcdir)/chopenssl-1.0.2d/chopenssl.spec && $(call logs,Chelsio-Crypto(libs),chopenssl,rpm) \
               ) || $(call logtemp,Chelsio-Crypto(libs),chopenssl,rpm)

.PHONY: chssl_sles15
chssl_sles15:
	@ cp -rpf $(asrcdir)/chopenssl-1.1.1 . ; \
               tar cfz chopenssl-1.1.1.tar.gz chopenssl-1.1.1 ; \
               mv -f chopenssl-1.1.1.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(asrcdir)/chopenssl-1.1.1" \
               --define "kversion $(kversion)" \
               --target $(target) \
	       --define "rhel_flag $(rhel_flag)"  \
	       --define "sles_flag $(sles_flag)"  \
               $(asrcdir)/chopenssl-1.1.1/chopenssl.spec && $(call logs,Chelsio-Crypto(libs),chopenssl,rpm) \
               ) || $(call logtemp,Chelsio-Crypto(libs),chopenssl,rpm)

define logtemp
echo -e "$1\t\t$2\t\t$3\tFailed" >> $(logpath)/temp.log ;
endef

define logs
echo -e "$1\t\t$2\t\t$3\tSuccessful" >> $(logpath)/temp.log  ;
endef

define checklibibverbs
        if [ $(shell uname -m) == "x86_64" ] ; then \
               cp -rpf $(libdirs)/$4 $(libdirs)/$4-$5 ; \
               cp -rpf $(libdirs)/$4-$5 . ; \
               tar cfz $4-$5.tar.gz $4-$5 ; \
               cp $4-$5.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(libdirs)/$4" \
               --define "kversion $(kversion)" \
               --define "version $5" \
               --define "name $4" \
               --define "release 0" \
               --target $(target) \
               $(libdirs)/$4/$4.spec && $(call logs,iWARP-lib,$4,rpm) \
               ) || $(call logtemp,iWARP-lib,$4,rpm) \
        else \
               cp -rvf $(libdirs)/$4 $(libdirs)/$4-$5; \
               cp -rvf $(libdirs)/$4-$5 . ; \
               tar cvfz $4-$5.tar.gz $4-$5 ; \
               cp $4-$5.tar.gz $(rpmdir)/SOURCES ; \
               ( rpmbuild -bb \
               --define "_topdir $(rpmdir)" \
               --define "srcdir $(libdirs)/$4" \
               --define "kversion $(kversion)" \
               --define "version $5" \
               --define "name $4" \
               --define "release 0" \
               --target $(target) \
               $(libdirs)/$4/$4.spec && $(call logs,iWARP-lib,$4,rpm) \
               ) || $(call logtemp,iWARP-lib,$4,rpm) \
        fi ;
endef
