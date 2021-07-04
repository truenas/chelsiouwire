                    ****************************************
                                   README

                    ****************************************

                         Chelsio Unified Wire for Linux


                             Version : 3.14.0.3
                             Date    : 05/21/2021



Overview
================================================================================

Chelsio Unified Wire software for Linux is an easy to use utility developed to 
provide installation of 64-bit Linux based drivers and tools for Chelsio's 
Unified Wire adapters. The Chelsio Unified Wire package provides an interactive 
installer to install various drivers and utilities.  
It consists of the following components:

- Network (NIC/TOE)
- Virtual Function Network (vNIC) 
- iWARP RDMA Offload
- iSER (Target & Initiator)
- WD-UDP
- NVMe-oF iWARP (Target & Initiator)
- SPDK NVMe-oF iWARP (Target & Initiator)
- NVMe-oF TOE (Target & Initiator)
- SPDK NVMe-oF TOE Target
- SoftiWARP Initiator
- LIO iSCSI Target Offload
- iSCSI PDU Offload Target  
- iSCSI PDU Offload Initiator 
- Crypto Offload
- Data Center Bridging (DCB)
- FCoE Full Offload Initiator 
- Offload Bonding
- Offload Multi-Adapter Failover (MAFO) 
- UDP Segmentation Offload and Pacing
- Offload IPv6
- WD Sniffing & Tracing
- Classification and Filtering 
- OVS Kernel Datapath Offload
- Mesh Topology
- Traffic Management feature (TM)
- Unified Boot Software
- Utility Tools (cop,cxgbtool,t4_perftune,benchmark tools)



================================================================================
  CONTENTS
================================================================================

- 1. Supported Operating Systems
- 2. Supported Hardware
- 3. How To Use
- 4. Support Documentation
- 5. Customer Support


   
1. Supported Operating Systems
================================================================================

The Chelsio Unified Wire software has been developed to run on 64-bit Linux 
based platforms. Following is the list of Drivers/Software and supported Linux
distributions.

x86_64 Architecture
===================

|##########################|#####################################################|
|   Linux Distribution     |                Driver/Software                      |
|##########################|#####################################################|
|RHEL 8.3,                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|4.18.0-240.el8.x86_64     |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                          |SoftiWARP,LIO iSCSI Target,iSCSI Initiator,Crypto,   |
|                          |DCB,FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,         |
|                          |Sniffer & Tracer,Filtering,Mesh,TM,uBoot*            |
|--------------------------|-----------------------------------------------------|
|RHEL 8.2,                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|4.18.0-193.el8.x86_64     |SPDK NVMe-oF iWARP,SPDK NVMe-oF TOE,SoftiWARP,       |
|                          |LIO iSCSI Target,iSCSI Initiator,Crypto,DCB,         |
|                          |FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,Sniffer &    |
|                          |Tracer,Filtering,Mesh,TM,uBoot*                      |
|--------------------------|-----------------------------------------------------|
|RHEL 7.9,                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|3.10.0-1160.el7.x86_64    |SPDK NVMe-oF iWARP,SPDK NVMe-oF TOE,LIO iSCSI Target,|
|                          |iSCSI Initiator,Crypto,DCB,FCoE Initiator,Bonding,   |
|                          |MAFO,UDP-SO,IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,|
|                          |TM,uBoot*                                            |
|--------------------------|-----------------------------------------------------|
|RHEL 7.8,                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|3.10.0-1127.el7.x86_64    |SPDK NVMe-oF iWARP,SPDK NVMe-oF TOE,LIO iSCSI Target,|
|                          |iSCSI Initiator,Crypto,DCB,FCoE Initiator,Bonding,   |
|                          |MAFO,UDP-SO,IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,|
|                          |TM,uBoot*                                            |
|--------------------------|-----------------------------------------------------|
|RHEL 6.10,                |NIC/TOE,vNIC,iWARP,iSCSI Target,iSCSI Initiator,DCB, | 
|2.6.32-754.el6            |Bonding,MAFO,UDP-SO,IPv6,Sniffer & Tracer,Filtering, |
|                          |TM,WD-UDP                                            |              
|--------------------------|-----------------------------------------------------|
|Ubuntu 20.04.2,           |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|5.4.0-65-generic          |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                          |SoftiWARP,LIO iSCSI Target,iSCSI Initiator,Crypto,   |
|                          |DCB,FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,         |
|                          |Sniffer & Tracer,Filtering,Mesh,TM                   |
|--------------------------|-----------------------------------------------------|
|Ubuntu 18.04.5,           |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|4.15.0-135-generic        |LIO iSCSI Target,iSCSI Initiator,Crypto,DCB,         |
|                          |FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,Sniffer &    |
|                          |Tracer,Filtering,TM                                  |
|--------------------------|-----------------------------------------------------|
|Kernel.org linux-5.10.23  |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                          |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                          |SoftiWARP,LIO iSCSI Target,iSCSI Initiator,Crypto,   |
|                          |DCB,FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,         |
|                          |Sniffer & Tracer,Filtering,Mesh,TM                   |
|--------------------------|-----------------------------------------------------|
|Kernel.org linux-5.4.105  |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                          |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                          |SoftiWARP,LIO iSCSI Target,iSCSI Initiator,Crypto,   |
|                          |DCB,FCoE Initiator,Bonding,MAFO,UDP-SO,IPv6,         |
|                          |Sniffer & Tracer,Filtering,Mesh,TM                   |
|--------------------------------------------------------------------------------|

* PXE,FCoE,iSCSI

NOTE: Other kernel versions have not been tested and are not guaranteed to work.


POWERPC64 Architecture
======================

|#########################|#####################################################|
|   Linux Distribution    |                Driver/Software                      |
|#########################|#####################################################|
|RHEL 7.6 (POWER8),       |NIC/TOE,iWARP,LIO iSCSI Target,iSCSI Initiator,      |
|3.10.0-957.el7.ppc64le   |Bonding,MAFO,IPv6,Filtering,TM                       |
|-------------------------|-----------------------------------------------------|
|RHEL 7.5 (POWER8),       |NIC/TOE,iWARP,LIO iSCSI Target,iSCSI Initiator,      |
|3.10.0-862.el7.ppc64le   |Bonding,MAFO,IPv6,Filtering,TM                       |
|-------------------------------------------------------------------------------|

NOTE: Other kernel versions have not been tested and are not guaranteed to work.


ARM64 Architecture
==================

|#########################|#####################################################|
|   Linux Distribution    |                Driver/Software                      |
|#########################|#####################################################|
|RHEL 7.6 (ARM64),        |NIC/TOE,iSER,NVMe-oF iWARP,LIO iSCSI Target,Bonding, |
|4.14.0-115.el7a.aarch64  |MAFO,iSCSI Initiator,Crypto,IPv6,Filtering,TM        |
|-------------------------|-----------------------------------------------------|
|RHEL 7.5 (ARM64),        |NIC/TOE,iWARP,iSER,NVMe-oF iWARP,LIO iSCSI Target,   |
|4.14.0-49.el7a.aarch64   |iSCSI Initiator,Crypto,Bonding,MAFO,IPv6,Filtering,TM|
|-------------------------|-----------------------------------------------------|

NOTE: Other kernel versions have not been tested and are not guaranteed to work.



2. Supported Hardware
================================================================================

Chelsio Drivers/Software and supported adapters
===============================================

|########################|#####################################################|
|    Chelsio Adapter     |                 Driver/Software                     |
|########################|#####################################################|
|T61100-OCP              |NIC,vNIC,SoftiWARP,Crypto(Co-processor),DCB,         |
|                        |Filtering^,OVS^,Mesh(NIC),TM(NIC)                    |
|------------------------|-----------------------------------------------------|
|T62100-CR               |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,Crypto,DCB,  |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T62100-LP-CR            |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,Crypto,DCB,  |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T62100-SO-CR            |NIC,vNIC,SoftiWARP,Crypto(Co-processor),DCB,         |
|                        |Filtering^,OVS^,Mesh(NIC),TM(NIC),uBoot(PXE)         |
|------------------------|-----------------------------------------------------|
|T6425-CR**              |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,Crypto,DCB,  |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T6225-CR                |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,Crypto,DCB,  |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T6225-LL-CR             |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,Crypto,DCB,  |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T580-CR                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF,NVMe-TOE,     |
|                        |SPDK NVMe-TOE,SoftiWARP,LIO iSCSI Target,iSCSI Target|
|                        |iSCSI Initiator,DCB,FCoE Initiator,Bonding,MAFO,IPv6,|
|                        |UDP-SO,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*,|
|                        |SPDK NVMe-oF                                         |
|------------------------|-----------------------------------------------------|
|T580-LP-CR              |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T580-SO-CR              |NIC,vNIC,SoftiWARP,DCB,Filtering^,OVS^,Mesh(NIC),    |
|                        |TM(NIC),uBoot(PXE)                                   |
|------------------------|-----------------------------------------------------|
|T580-OCP-SO             |NIC,vNIC,SoftiWARP,DCB,Filtering^,OVS^,Mesh(NIC),    |
|                        |TM(NIC),uBoot(PXE)                                   |
|------------------------|-----------------------------------------------------|
|T540-CR                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T540-LP-CR              |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T540-SO-CR              |NIC,vNIC,SoftiWARP,DCB,Filtering^,OVS^,Mesh(NIC),    |
|                        |TM(NIC)                                              |
|------------------------|-----------------------------------------------------|
|T540-BT                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T520-CR                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T520-LL-CR              |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------|-----------------------------------------------------|
|T520-SO-CR              |NIC,vNIC,SoftiWARP,DCB,Filtering^,OVS^,Mesh(NIC),    |
|                        |TM(NIC),uBoot(PXE)                                   |
|------------------------|-----------------------------------------------------|
|T520-OCP-SO             |NIC,vNIC,SoftiWARP,DCB,Filtering^,OVS^,Mesh(NIC),    |
|                        |TM(NIC),uBoot(PXE)                                   |
|------------------------|-----------------------------------------------------|
|T520-BT                 |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,        |
|                        |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,     |
|                        |SoftiWARP,LIO iSCSI Target,iSCSI Target,DCB,         |
|                        |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,UDP-SO,  |
|                        |IPv6,Sniffer & Tracer,Filtering,OVS,Mesh,TM,uBoot*   | 
|------------------------------------------------------------------------------|


* PXE,FCoE,iSCSI

** All 4-ports of T6425-CR adapter will be functional only if 
   PCIe x8 -> 2x PCIe x4 slot bifurcation is supported by the system and enabled 
   in BIOS. Otherwise, only 2-ports will be functional.

^ Hash filter not supported.


Memory-free Adapters
====================

|########################|#####################################################|
|    Chelsio Adapter     |                 Driver/Software                     |
|########################|#####################################################|
|T6225-OCP               |NIC/TOE,vNIC,iWARP*,iSER Initiator*,iSCSI Initiator*,|
|                        |NVMe-oF iWARP Initiator*,SoftiWARP Initiator,DCB,    |
|                        |NVMe-oF TOE Initiator*,Crypto(Co-processor),Mesh*,   | 
|                        |Filtering^,OVS^,TM(NIC)                              |
|------------------------|-----------------------------------------------------|
|T6225-SO-CR             |NIC/TOE,vNIC,iWARP*,iSER Initiator*,iSCSI Initiator*,|
|                        |NVMe-oF iWARP Initiator*,SoftiWARP Initiator,DCB,    |
|                        |NVMe-oF TOE Initiator*,Crypto(Co-processor),Mesh*,   | 
|                        |Filtering^,OVS^,TM(NIC),uBoot(PXE)                   |     
|------------------------------------------------------------------------------|

* 256 IPv4/128 IPv6 offload connections supported.

^ Hash filter not supported.


Unified Boot Software
=====================

Supported hardware platforms 
----------------------------

- Dell T5600
- DELL PowerEdge 2950
- DELL PowerEdge T110
- DELL PowerEdge T710
- DELL PowerEdge R220
- DELL PowerEdge R720  
- IBM X3650 M2
- IBM X3650 M4*
- HP Proliant DL180 gen9       
- HP ProLiant DL385G2
- Supermicro X7DWE
- Supermicro X8DTE-F
- Supermicro X8STE
- Supermicro X8DT6
- Supermicro X9SRL-F
- Supermicro X9SRE-3F 
- Supermicro-X10DRi
- ASUS P5KPL
- ASUS P8Z68
- Lenovo X3650 M5
- Intel DQ57TM

* If system BIOS version is lower than 1.5 and both Legacy and uEFI are enabled,
  please upgrade to 1.5 or higher. Otherwise the system will hang during POST.


Supported Switches
-------------------

- Cisco Nexus 5010 with 5.1(3)N1(1a) firmware
- Arista DCS-7124S-F
- Mellanox SX_PPC_M460EX 

NOTE: Other platforms/switches have not been tested and are not guaranteed to 
      work.



3. How to Use
================================================================================

++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Chelsio Unified Wire
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

- RHEL 8.X distributions ship with Python v3.6 by default. Configure Python v2.7 
  using the below commands to run the installer. 

  [root@host~]# tar zxvf ChelsioUwire-x.x.x.x.tar.gz
  [root@host~]# cd ChelsioUwire-x.x.x.x
  [root@host~]# sh install-python.sh

- To install Unifided Wire using GUI mode (with Dialog utility), ncurses-devel 
  package must be installed.


Installing Chelsio Unified Wire 
===============================

There are two main methods to install the Chelsio Unified Wire package: from 
source and from RPM. If you decide to use source, you can install the package 
using CLI or GUI mode. If you decide to use RPM, you can install the package 
using Menu or CLI mode. 

RPM packages support only distro base kernels. In case of updated/custom 
kernels, use source package. 

The following table describes the various "configuration tuning options" 
available during installation and drivers/software installed with each option by
default:

|#############################|################################################|
|Configuration Tuning Option  |           Driver/Software installed            |
|#############################|################################################|
|Unified Wire (Default)       |NIC/TOE,vNIC,iWARP,iSER,WD-UDP,NVMe-oF iWARP,   |
|                             |SPDK NVMe-oF iWARP,NVMe-oF TOE,SPDK NVMe-oF TOE,| 
|                             |SoftiWARP,LIO iSCSI Target,iSCSI Target,        |
|                             |iSCSI Initiator,FCoE Initiator,Bonding,MAFO,    |
|                             |UDP-SO,IPv6,Sniffer & Tracer,Filtering,Mesh,TM  |
|-----------------------------|------------------------------------------------|
|Low latency Networking       |TOE,iWARP,WD-UDP,IPv6,Bonding,MAFO              |                                   
|-----------------------------|------------------------------------------------|
|High capacity RDMA           |iWARP                                           |
|-----------------------------|------------------------------------------------|
|RDMA Performance             |iWARP,iSER,NVMe-oF iWARP                        |
|-----------------------------|------------------------------------------------|
|High capacity TOE            |TOE,Bonding,MAFO,IPv6                           |
|-----------------------------|------------------------------------------------|
|iSCSI Performance (T5)       |LIO iSCSI Target,iSCSI Target,iSCSI Initiator,  |
|                             |Bonding,DCB                                     |
|-----------------------------|------------------------------------------------|
|UDP Seg.Offload & Pacing (T5)|UDP-SO,Bonding                                  |
|-----------------------------|------------------------------------------------|
|Wire Direct Latency          |TOE,iWARP,WD-UDP                                |
|-----------------------------|------------------------------------------------|
|High Capacity WD             |WD-UDP                                          |
|-----------------------------|------------------------------------------------|
|High Capacity Hash Filter    |Filtering                                       |
|-----------------------------|------------------------------------------------|
|NVMe Performance (T6)        |iWARP,NVMe-oF iWARP,SPDK NVMe-oF iWARP          |
|-----------------------------|------------------------------------------------|
|High Capacity VF             |NIC,vNIC                                        |
|------------------------------------------------------------------------------|

IMPORTANT: Crypto, DCB and OVS drivers will not be installed by default. Please
           refer to the respective sections for instructions on installing them.


Mounting debugfs
----------------

All driver debug data is stored in debugfs, which will be mounted in most
cases. If not, mount it manually.

   [root@host~]# mount -t debugfs none /sys/kernel/debug


Configuring IPv6
----------------

The interfaces should come up with a link-local IPv6 address for complete and 
fully functional IPv6 configuration. Update the Interface network-script with 
ONBOOT="yes".


Installation
------------

Follow the steps mentioned below for installation using CLI. For GUI or Menu 
based installation, refer the User's Guide.

1.1. From source
----------------

a) Download Chelsio Unified Wire driver package.

b) Untar the tarball
    
  [root@host~]# tar zxvf ChelsioUwire-x.x.x.x.tar.gz
  
c) Change your current working directory to Chelsio Unified Wire package 
   directory and build the source.

  [root@host~]# cd ChelsioUwire-x.x.x.x
  [root@host~]# make
  
d) Install the drivers, tools and libraries.
    
  [root@host~]# make install
  
e) The default configuration tuning option is Unified Wire.
   The configuration tuning can be selected using the following commands:

  [root@host~]# make CONF=<configuration_tuning>
  [root@host~]# make CONF=<configuration_tuning> install

NOTE: To view the different configuration tuning options, view help by 
      typing [root@host~]# make help

f) Reboot your machine for changes to take effect.

IMPORTANT: Steps (c) and (d) mentioned above will NOT install Crypto, DCB,  
           OVS drivers and benchmark tools. They will have to be installed 
           manually. Please refer to their respective sections for instructions 
           on installing them.


Installation using additional flags
-----------------------------------

Provided here are steps to build and install drivers using additional flags. For 
the complete list,  view help by running "make help".

Change your current working directory to Chelsio Unified Wire package directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

- To build and install all drivers without IPv6 support.

   [root@host~]# make ipv6_disable=1
   [root@host~]# make ipv6_disable=1 install

- The default configuration tuning option is Unified Wire. 
  The configuration tuning can be selected using the following commands:

   [root@host~]# make CONF=<configuration_tuning> <Build Target>
   [root@host~]# make CONF=<configuration_tuning> <Install Target>

- To build and install drivers along with benchmarks. 

   [root@host~]# make BENCHMARKS=1
   [root@host~]# make BENCHMARKS=1 install

- The drivers will be installed as RPMs or Debian packages (for ubuntu). To 
  skip this and install drivers,
   
   [root@host~]# make SKIP_RPM=1 install

- The installer will remove the Chelsio specific drivers (inbox/outbox) from 
  initramfs. To skip this and install drivers, 

   [root@host~]# make SKIP_INIT=1 install

- The installer will check for the required dependency packages and will install
  them if they are missing from the machine. To skip this and install drivers,

   [root@host~]# make SKIP_DEPS=1 install

NOTE:
     - To view the different configuration tuning options, view the help by 
       typing [root@host~]# make help

     - If IPv6 is disabled in the machine, the drivers will be built and installed 
       without IPv6 Offload support by default.
     
		  
iWARP Driver Installation on Cluster Nodes
------------------------------------------

IMPORTANT: Ensure that you have enabled password less authentication with ssh on
           the peer nodes for this feature to work.

Chelsio's Unified Wire package allows installing iWARP drivers on multiple 
Cluster nodes with a single command. Follow the procedure mentioned below:

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

  [root@host~]# cd ChelsioUwire-x.x.x.x

b) Create a file (machinefilename) containing the IP addresses or hostnames of 
   the nodes in the cluster. You can view the sample file, sample_machinefile, 
   provided in the package to view the format in which the nodes have to be 
   listed.

c) Now, execute the following command:

   [root@host~]# ./install.py -C  -m <machinefilename>
   
d) Select the required configuration tuning option. The tuning options 
   may vary depending on the Linux distribution.

e) Select the required Cluster Configuration.
   
f) The selected components will now be installed.

The above command will install iWARP (iw_cxgb4) and TOE (t4_tom) drivers on all 
the nodes listed in the <machinefilename> file.


1.2. From RPM (tarball) 
-----------------------

NOTE: 
- IPv6 should be enabled in the machine to use the RPM Packages.
- Drivers installed from RPM Packages do not have DCB support.

a) Download the tarball specific to your operating system and architecture.

b) Untar the tarball
    
E.g. For RHEL 6.10, untar using the following command:
    
   [root@host~]# tar zxvf ChelsioUwire-x.x.x.x-RHEL6.10_x86_64.tar.gz

c) Change your current working directory to Chelsio Unified Wire package 
   directory and install the driver.
    
   [root@host~]# cd ChelsioUwire-x.x.x.x-<OS>-<arch>
   [root@host~]# ./install.py -i <nic_toe/all/udpso/wd/crypto/ovs>

nic_toe  : NIC and TOE drivers only.
all      : all Chelsio drivers.
udpso    : UDP segmentation offload capable NIC and TOE drivers only.
wd       : Wire Direct drivers and libraries only.
crypto   : Crypto drivers and Chelsio Openssl modules.
ovs      : OVS modules and NIC driver.

NOTE: The Installation options may vary depending on the Linux distribution.
   
d) The default configuration tuning option is Unified Wire.
   The configuration tuning can be selected using the following command:

   [root@host~]# ./install.py -i <Installation mode> -c <configuration_tuning>

NOTE: To view the different configuration tuning options, view the help by 
      typing 

  [root@host~]# ./install.py -h
 
e) Reboot your machine for changes to take effect.

NOTE: If the installation aborts with the message "Resolve the errors/dependencies
      manually and restart the installation", please go through the install.log 
      to resolve errors/dependencies and then start the installation again.
	 
	 	 
iWARP Driver Installation on Cluster Nodes
-------------------------------------------

IMPORTANT: Please make sure that you have enabled password less authentication 
           with ssh on the peer nodes for this feature to work.

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x-<OS>-<arch>

b) Create a file (machinefilename) containing the IP addresses or hostnames of 
   the nodes in the cluster. You can view the sample file, sample_machinefile, 
   provided in the package to view the format in which the nodes have to be 
   listed.

c) Install iWARP and TOE drivers.
    
   [root@host~]# ./install.py -C -m <machinefilename> -i <nic_toe/all/udpso/wd> 
                 -c <configuration_tuning>

The above command will install iWARP (iw_cxgb4) and TOE (t4_tom) drivers on all 
the nodes listed in the <machinefilename> file

d) Reboot your machine for changes to take effect.

  
Firmware Update
===============

The firmware (v1.25.6.0) is installed on the system, typically in 
/lib/firmware/cxgb4, and the driver will auto-load the firmware if an update 
is required. The kernel must be configured to enable userspace firmware loading 
support.

Device Drivers -> Generic Driver Options -> Userspace firmware loading support

The firmware version can be verified using ethtool.

   [root@host~]# ethtool -i <iface>

 
Uninstalling Chelsio Unified Wire
=================================

There are two methods to uninstall the Chelsio Unified Wire package: from source 
and from RPM. If you decide to use source, you can uninstall the package using 
CLI or GUI mode. 

Follow the steps mentioned below for uninstallation using CLI. For GUI based 
uninstallation, refer the User's Guide. 

From source
-----------

a) Change your current working directory to Chelsio Unified Wire package 
   directory. 

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Uninstall the source.

   [root@host~]# make uninstall
  

Uninstalling Individual Drivers/Software 
----------------------------------------

You can also choose to uninstall drivers/software individually. Provided here 
are steps to uninstall few of them. For the complete list, view help by running 
"make help".

Change your current working directory to Chelsio Unified Wire package directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

- To uninstall NIC driver,

   [root@host~]# make nic_uninstall

- To uninstall drivers with offload support,

   [root@host~]# make toe_uninstall

- To uninstall iWARP driver,

   [root@host~]# make iwarp_uninstall

- To uninstall UDP Segmentation Offload driver,

   [root@host~]# make udp_offload_uninstall

 	 
iWARP Driver Uninstallation on Cluster Nodes
--------------------------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory. 

    [root@host~]# cd ChelsioUwire-x.x.x.x

b) Uninstall iWARP drivers on multiple Cluster nodes.

    [root@host~]# ./install.py -C -m <machinefilename> -u all

The above command will remove Chelsio iWARP (iw_cxgb4) and TOE (t4_tom) drivers 
from all the nodes listed in the machinefilename file.
  
  
From RPM (tar-ball)
-------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x-<OS>-<arch>

b) Run the following command:

   [root@host~]# ./uninstall.py
   
	 
iWARP Driver Uninstallation on Cluster Nodes
--------------------------------------------

To uninstall iWARP drivers on multiple Cluster nodes,

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x-<OS>-<arch>

b) Run the following command:

   [root@host~]# ./install.py -C -m <machinefilename> -u

The above command will remove Chelsio iWARP (iw_cxgb4) and TOE (t4_tom) drivers 
from all the nodes listed in the machinefilename file.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Network (NIC/TOE)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

Change your current working directory to Chelsio Unified Wire package directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

- To build and install NIC only driver (without offload support),

   [root@host~]# make nic_install

- To build and install drivers with offload support,

   [root@host~]# make toe_install

NOTE: For more installation options, please run "make help" or "install.py -h".

Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT: Please ensure that all inbox drivers are unloaded before proceeding 
           with unified wire drivers.

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.
   
- To load the driver in NIC mode (without offload support),
   
   [root@host~]# modprobe cxgb4

- To load driver in TOE mode (with offload support),

   [root@host~]# modprobe t4_tom
   
NOTE: Offload support needs to be enabled upon each reboot of the system. This 
      can be done manually as shown above.

In VMDirect Path environment, it is recommended to load the offload driver using
the following command:

   [root@host~]# modprobe t4_tom vmdirectio=1


Enabling TCP Offload
====================

Load the offload drivers and bring up the Chelsio interface.

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig ethX <IP> up
  
All TCP traffic will be offloaded over the Chelsio interface now. To see the 
number of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids


Enabling Busy Waiting
=====================

Busy waiting/polling is a technique where a process repeatedly checks to see if 
an event has occurred, by spinning in a tight loop. By making use of similar 
technique, Linux kernel provides the ability for the socket layer code to poll 
directly on an Ethernet device's Rx queue. This eliminates the cost of  
interrupts and context switching, and with proper tuning allows to achieve 
latency performance similar to that of hardware.

Chelsio's NIC and TOE drivers support this feature and can be enabled on Chelsio
supported devices to attain improved latency.

To make use of BUSY_POLL feature, follow the steps mentioned below: 

a) Enable BUSY_POLL support in kernel config file by setting 
   "CONFIG_NET_RX_BUSY_POLL=y".
  
b) Enable BUSY_POLL globally in the system by setting the values of following 
   sysctl parameters depending on the number of connections:

   sysctl -w net.core.busy_read=<value>
   sysctl -w net.core.busy_poll=<value> 
   
Set the values of the above parameters to 50 for 100 or less connections; and 
100 for more than 100 connections.

NOTE: BUSY_POLL can also be enabled on a per-connection basis by making use of
      SO_BUSY_POLL socket option in the socket application code.Refer socket 
      man-page for further details.


Precision Time Protocol (PTP)
=============================

IMPORTANT: This feature is not supported on RHEL 6.X platforms.

ptp4l tool (installed during Unified Wire installation) is used to synchronise 
clocks:

a) Load the network driver on all master and slave nodes.

   [root@host~]# modprobe cxgb4 

b) Assign IP addresses and ensure that master and slave nodes are connected.

c) Start the ptp4l tool on master using the Chelsio interface.

   [root@host~]# ptp4l -i <interface> -H -m
 
d) Start the tool on slave nodes.

   [root@host~]# ptp4l -i <interface> -H -m -s

NOTE: To view the complete list of available options, refer ptp4l help manual.

e) Synchronize the system clock to a PTP hardware clock (PHC) on slave nodes.

   [root@host~]# phc2sys -s <interface> -c CLOCK_REALTIME -w -m


VXLAN Offload
=============

Chelsio adapters are uniquely capable of offloading the processing of VXLAN 
encapsulated frames such that all stateless offloads (checksums and TSO) are 
preserved, resulting in significant performance benefits. This is enabled by
default on loading the driver. 

For information regarding the configuration, please refer User's Guide.


HMA
===

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire (Default)" configuration tuning option. Currently 256 IPv4/128 IPv6 
TOE Offload connections are supported on T6 25G SO adapters. To see the number of 
connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids 


Performance Tuning
==================

To tune your system for better network performance, refer the 
"Performance Tuning" section of the Network (NIC/TOE) chapter in the User's Guide.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.

  
Driver Unloading
================

- To unload the driver in NIC mode (without offload support),

   [root@host~]# rmmod cxgb4

- A reboot is required to unload the driver in TOE (with Offload support). 
  To avoid rebooting, follow the steps mentioned below:

a) Load t4_tom driver with unsupported_allow_unload parameter. 

   [root@host~]# modprobe t4_tom unsupported_allow_unload=1

b) Stop all the offloaded traffic, servers and connections. Check for the 
   reference count.

   [root@host~]# cat /sys/module/t4_tom/refcnt 

If the reference count is 0, the driver can be directly unloaded. Skip to step 
(c). 

If the count is non-zero, load a COP policy which disables offload using the 
following procedure:

i. Create a policy file which will disable offload.

   [root@host~]# cat policy_file
   all => !offload

ii. Compile and apply the output policy file.

   [root@host~]# cop –o no-offload.cop policy_file
   [root@host~]# cxgbtool ethX policy no-offload.cop

c) Unload the driver. 

   [root@host~]# rmmod t4_tom
   [root@host~]# rmmod toecore
   [root@host~]# rmmod cxgb4


NOTE: For more information on additional configuration options, please refer 
      User's Guide.

	  
	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Virtual Function Network (vNIC) 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The Virtual Function implementation for Chelsio adapters comprises of two 
modules: 

- Standard NIC driver module, cxgb4, which runs on base Hypervisor and is 
  responsible for instantiation and management of the PCIe Virtual Functions 
  (VFs) on the adapter.

- VF NIC driver module, cxgb4vf, which runs on Virtual Machine (VM) guest OS 
  using VFs "attached" via Hypervisor VM initiation commands.


Pre-requisites 
==============

Please make sure that the following requirements are met before installation:

- PCI Express Slot should be ARI capable.

- SR-IOV should be enabled in the machine.

- Intel Virtualization Technology for Directed I/O (VT-d) should be enabled in 
  the BIOS.

- Add intel_iommu=on to the kernel command line in grub/grub2 menu, to use VFs 
  in VMs.



Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) On the host, install network driver.

   [root@host~]# make nic_install

c) On the guest (VM), install vNIC driver.

   [root@host~]# make vnic_install

NOTE: For more installation options, please run "make help" or "install.py -h".

d) Reboot your machine for changes to take effect.



Instantiate Virtual Functions
=============================

To instantiate Virtual Functions (VFs) on the host, run the following commands: 

   [root@host~]# modprobe cxgb4
   [root@host~]# echo n > /sys/class/net/ethX/device/driver/<bus_id>/sriov_numvfs

Here, "ethX" is the interface and "n" specifies the number of VFs to be 
instantiated per physical function (bus_id). VFs can be instantiated only from 
PFs 0 - 3 of the Chelsio adapter. A maximum of 64 virtual functions can be 
instantiated with 16 virtual functions per physical function.

NOTE: To get familiar with physical and virtual function terminologies, please 
      refer the PCI Express specification.

Unload the vNIC driver on the host (if loaded).

   [root@host~]# rmmod cxgb4vf

The virtual functions can now be assigned to virtual machines (guests). 


Driver Loading
==============

IMPORTANT: Please ensure that all inbox drivers are unloaded before proceeding 
           with unified wire drivers.

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The vNIC (cxgb4vf) driver must be loaded on the Guest OS by the root user. Any 
attempt to load the driver as a regular user will fail.

To load the driver execute the following command:

   [root@host~]# modprobe cxgb4vf 


Configuration
=============

VF Communication
----------------

Once the VF driver (cxgb4vf) is loaded in the VM and the VF interface is up with 
an IP address, it will be able to communicate (send/receive network traffic).

 [root@host~]# modprobe cxgb4vf
 [root@host~]# ifconfig ethX <IP Address> up

2-port card:
VFs of PF0 and PF2 can communicate with each other and with hosts connected to Port 0.
VFs of PF1 and PF3 can communicate with each other and with hosts connected to Port 1.

4-port card:
VFs of PF0 can communicate with each other and with hosts connected to Port 0.
VFs of PF1 can communicate with each other and with hosts connected to Port 1.
VFs of PF2 can communicate with each other and with hosts connected to Port 2.
VFs of PF3 can communicate with each other and with hosts connected to Port 3.

By default, the VFs (in VM) can not communicate with PFs (on Host). To enable 
this communication, set ethtool private flag port_tx_vm_wr for PF interface (on Host).

 [root@host~]# ethtool --set-priv-flags ethX port_tx_vm_wr on


VF Link State
-------------

VF link state depends on the physical port link status to which the VF is mapped to.
Please refer the above section for VF to physical port mappings. To override this 
and always enable the VF link, follow the below procedure. This will enable VF to VF 
communication irrespective of the physical port link status.

a) After instantiating the VFs, check the current VF link state using the below 
   command on Host (hypervisor). By default, it will be auto.
   
   [root@host~]# ip link show mgmtpfX,Y

b) Enable the VF link state for the required VFs.
   
   [root@host~]# ip link set dev mgmtpfX,Y vf Z state enable

c) The VFs can then be assigned to Virtual Machines. On loading cxgb4vf driver in 
   the VM and bringing up the VF interface, the VF will be enabled. It can then 
   communicate with other VFs (which are enabled) irrespective of physical link. 

   To revert to default behavior, set the VF link state to auto.
   
   [root@host~]# ip link set dev mgmtpfX,Y vf Z state auto


VF Rate Limiting
----------------

This section describes the method to rate-limit traffic passing through virtual 
functions (VFs).

a) The VF rate limit needs to be set on the Host (hypervisor). Apply 
   rate-limiting.

   [root@host~]# ip link set dev mgmtpfXX vf <vf_number> rate <rate_in_mbps>

Here, 

- mgmtpfXX is the management interface to be used. For each PF on which VFs are 
  instantiated, 1 management interface will be created (in "ifconfig -a").

- vf_number is VF on which rate-limiting is applied. Value 0-15.

b) Run traffic over the VF and the throughput should be rate-limited as per the 
   values set in the previous step.


Bonding
-------

The VF network interfaces (assigned to a VM) can be aggregated into a single 
logical bond interface effectively combining the bandwidth into a single 
connection. It also provides redundancy in case one of the link fails. Execute the 
following steps in the VM (attached with more than 1 VF interface):

a) Load the Virtual Function network driver. 

   [root@host~]# modprobe cxgb4vf

b) Create a bond interface.

   [root@host~]# modprobe bonding mode=<bonding mode> <optional paramters>

c) Bring up the bond interface and enslave the VF interfaces to the bond.

   [root@host~]# ifconfig bond0 up
   [root@host~]# ifenslave bond0 ethX ethY

NOTE: ethX and ethY are the VF interfaces attached to the same VM. It is 
      recommended to use VFs of different Ports to achieve redundancy in case 
      of link failures. 

d) Assign IPv4/IPv6 address to the bond interface. 

   [root@host~]# ifconfig bond0 X.X.X.X/Y
   [root@host~]# ifconfig bond0 inet6 add <128-bit IPv6 Address> up


High Capacity VF Configuration 
------------------------------

Chelsio adapters by default support 16 VFs per PF. In order to use more VFs per 
PF, please refer User's Guide.

IMPORTANT: Currently supported on T6225-SO-CR and T6225-OCP adapters. 


Driver Unloading
================

To unload the driver execute the following command:

   [root@host~]# rmmod cxgb4vf

NOTE: For more information on additional configuration options, please refer 
      User's Guide.

        
   
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
iWARP RDMA Offload 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that the following requirements are met before installation:

- Uninstall any OFED present in the machine.

- rdma-core-devel package should be installed on RHEL 8.X/7.X systems.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install iWARP drivers and libraries.

   [root@host~]# make iwarp_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============
  
IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.

To load the iWARP driver we need to load the NIC driver & core RDMA drivers first:
  
   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm

Optionally, you can start iWARP Port Mapper daemon to enable port mapping: 

   [root@host~]# iwpmd


HMA
====

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire (Default)" configuration tuning option. Currently 256 IPv4/128 IPv6 
iWARP Offload connections are supported on T6 25G SO adapters. To see the number 
of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids 


Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the iWARP (RDMA) chapter in the User's Guide.


Driver Unloading
================

To unload the iWARP driver, run the following command:

   [root@host~]# rmmod iw_cxgb4
 
NOTE: For more information on additional configuration options, please refer 
      User's Guide.  



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
iSER
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that the following requirements are met before installation:

- Python v2.7 or above is required for targetcli installation. If Python v2.7 is
  not already present in the system, or if an older version exists, v2.7.10 
  provided in the package will be installed.

- Uninstall any OFED present in the machine.

- rdma-core-devel package should be installed on RHEL 8.X/7.X systems.


Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) To install 5.4.105 kernel with iSER components enabled, use the following 
   command: 

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following iSER 
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_ISCSI_TARGET=m
      CONFIG_INFINIBAND_ISER=m
      CONFIG_INFINIBAND_ISERT=m

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X/7.X, Ubuntu 20.04.X/18.04.X
------------------------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install Chelsio iSER driver, libraries and targetcli utilities.

   [root@host~]# make iser_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below on both target and initiator machines:

a) Unload Chelsio iWARP driver if previously loaded.

   [root@host~]# rmmod iw_cxgb4
   
b) Load the following modules.

   [root@host~]# modprobe iw_cxgb4 mpa_rev=2
   [root@host~]# modprobe rdma_ucm 
   
c) Start the iWARP Port Mapper Daemon.

   [root@host~]# iwpmd
 
d) Bring up the Chelsio interface(s).

   [root@host~]# ifconfig ethX x.x.x.x up

e) On target, run the following command:

   [root@host~]# modprobe ib_isert

   On initiator, run the following command:
   
   [root@host~]# modprobe ib_iser
   

Configuration
=============

a) Configure LIO target with iSER support, using ramdisk as LUN.

   [root@host~]# targetcli /backstores/ramdisk create name=ram0 size=1GB
   [root@host~]# targetcli /iscsi create wwn=iqn.2003-01.org.lun0.target
   [root@host~]# targetcli /iscsi/iqn.2003-01.org.lun0.target/tpg1/luns create /backstores/ramdisk/ram0
   [root@host~]# targetcli /iscsi/iqn.2003-01.org.lun0.target/tpg1 set attribute 
                 authentication=0 demo_mode_write_protect=0 generate_node_acls=1 cache_dynamic_acls=1
   [root@host~]# targetcli saveconfig      

b) Discover the LIO target using OpeniSCSI initiator. 

   [root@host~]# iscsiadm -m discovery -t st -p 102.10.10.4

c) Enable iSER support in LIO target. 

   [root@host~]# targetcli /iscsi/iqn.2003-01.org.lun0.target/tpg1/portals/0.0.0.0:3260 enable_iser boolean=True

d) Login from the initiator with iSER as transport.

   [root@host~]# iscsiadm -m node -p 102.10.10.4 -T iqn.2003-01.org.lun0.target --op update -n node.transport_name -v iser
   [root@host~]# iscsiadm -m node -p 102.10.10.4 -T iqn.2003-01.org.lun0.target --login


HMA
====

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire (Default)" configuration tuning option. Currently 256 IPv4/128 IPv6 
iSER Offload connections are supported on T6 25G SO adapters. To see the number 
of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids 


Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the iSER chapter in the User's Guide.


Driver Unloading 
================

- On target, run the following commands:

   [root@host~]# rmmod ib_isert
   [root@host~]# rmmod iw_cxgb4

- On initiator, run the following commands:
   
   [root@host~]# rmmod ib_iser
   [root@host~]# rmmod iw_cxgb4   
 


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
WD-UDP
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Instalallation
=====================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install iWARP drivers and WD-UDP Libraries:

   [root@host~]# make iwarp_install  

NOTE: For more installation options, please run "make help" or "install.py -h".


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Load the cxgb4, iw_cxgb4 and rdma_ucm drivers:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm  

  
Configuring WD-UDP 
==================

Preload "libcxgb4_sock" using one of the methods mentioned below when starting 
your application:

Preloading using wdload script
------------------------------

   [root@host~]# PROT=UDP wdload <pathto>/your_application

The above command will generate an end point file, libcxgb4_sock.conf  at /etc/.
Parameters like interface name and port number can be changed in this file.

The following example shows how to run Netperf with WD-UDP:

server:

   [root@host~]# PROT=UDP wdload netserver -f -p <port_num> -D -L <server_ip>

client:
 
   [root@host~]# PROT=UDP wdload netperf -H <hostIp> -p <port_num> -t UDP_RR 


Preloading manually
-------------------

Create a configuration file that defines which UDP endpoints should be 
accelerated, their vlan and priority if any, as well as which interface/port 
should be used. The file /etc/libcxgb4_sock.conf contains these 
endpoint entries. Create this file on all systems using libcxgb4_sock. Here is 
the syntax:

   Syntax:
   endpoint { attributes } ...
   where attributes include:
           interface = interface-name
           port = udp-port-number

E.g:
To accelerate all applications that preload libcxgb4_sock using eth2, you only 
need one entry in /etc/libcxgb4_sock.conf:

endpoint {interface=eth2 port=0}

For VLAN support, create your VLANs using the normal OS service (like vconfig, for
example), then add entries to define the VLAN and priority for each endpoint to be 
accelerated: 

endpoint {interface = eth2.5 port=10000} 
endpoint {interface = eth2.7 priority=3 port=9000}


Now, preload libcxgb4_sock using the following command:

    [root@host~]# CXGB4_SOCK_CFG=<path to config file> LD_PRELOAD=libcxgb4_sock.so <pathto>/your_application

NOTE: i. In WD-UDP only one application can be run per Terminator device per UDP 
         port number. For running 2 concurrent netperf UDP_RR tests, each must use a 
         unique UDP port number.
 
         E.g.:
         endpoint {interface=eth2 port=8888}
         endpoint {interface=eth2 port=9000}
   
     ii. In order to offload IPv6 UDP sockets, please select "low latency 
         networking" as configuration tuning option during installation.


Multiple interfaces
-------------------

To run on multiple interfaces, it is recommended to create a configuration file for each 
interface with the corresponding ports to offload. The applications can be started as below: 

[root@host~]# CXGB4_SOCK_CFG=<config_file1> PROT=UDP wdload <application>
[root@host~]# CXGB4_SOCK_CFG=<config_file2> PROT=UDP wdload <application>


Driver Unloading
================

To unload the iWARP driver, run the following command:

   [root@host~]# rmmod iw_cxgb4


NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
NVMe-oF iWARP
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that the following requirements are met before installation:

- Uninstall any OFED present in the machine.

- rdma-core-devel package should be installed on RHEL 8.X/7.X systems.


Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) To install 5.4.105 kernel with NVMe-oF components enabled, use the following 
   command: 

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following  
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_BLK_DEV_NVME=m
      CONFIG_NVME_RDMA=m
      CONFIG_NVME_TARGET=m
      CONFIG_NVME_TARGET_RDMA=m
      CONFIG_BLK_DEV_NULL_BLK=m
      CONFIG_CONFIGFS_FS=y

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X/7.X, Ubuntu 20.04.X/18.04.X
------------------------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install iWARP RDMA Offload driver and NVMe utilities.

   [root@host~]# make nvme_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below on both target and initiator machines:
 
a) Load the following drivers:

   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm    

b) Bring up the Chelsio interface(s).

   [root@host~]# ifconfig ethX x.x.x.x up

c) Mount configfs by running the below command:

   [root@host~]# mount -t configfs none /sys/kernel/config
  
d) On target, load the following drivers:

   [root@host~]# modprobe null_blk
   [root@host~]# modprobe nvmet
   [root@host~]# modprobe nvmet-rdma 

   On initiator, load the following drivers:
   
   [root@host~]# modprobe nvme
   [root@host~]# modprobe nvme-rdma


Configuration
=============

Target
------

a) The following commands will configure target using nvmetcli with a LUN:

   [root@host~]# nvmetcli
   /> cd subsystems
   /subsystems> create nvme-ram0
   /subsystems> cd nvme-ram0/namespaces
   /subsystems/n...m0/namespaces> create nsid=1
   /subsystems/n...m0/namespaces> cd 1
   /subsystems/n.../namespaces/1> set device path=/dev/ram1
   /subsystems/n.../namespaces/1> cd ../..
   /subsystems/nvme-ram0> set attr allow_any_host=1
   /subsystems/nvme-ram0> cd namespaces/1
   /subsystems/n.../namespaces/1> enable
   /subsystems/n.../namespaces/1> cd ../../../..
   /> cd ports
   /ports> create 1
   /ports> cd 1/
   /ports/1> set addr adrfam=ipv4.
   /ports/1> set addr trtype=rdma
   /ports/1> set addr trsvcid=4420
   /ports/1> set addr traddr=102.1.1.102
   /ports/1> cd subsystems
   /ports/1/subsystems> create nvme-ram0
     
b) Save the target configuration to a file. 

   /ports/1/subsystems> saveconfig /root/nvme-target_setup
   /ports/1/subsystems> exit

c) To clear the targets, 

   [root@host~]# nvmetcli clear


Initiator
---------

a) Discover the target.
   
   [root@host~]# nvme discover -t rdma -a <target_ip> -s 4420 

b) Connect to target.

Connecting to a specific target.
   
   [root@host~]# nvme connect -t rdma -a <target_ip> -s 4420 -n <target_name>

Connecting to all targets configured on a portal.  

   [root@host~]# nvme connect-all -t rdma -a <target_ip> -s 4420 

c) List the connected targets.

   [root@host~]# nvme list

d) Format and mount the NVMe disks shown with the above command.

e) Disconnect from the target and unmount the disk.
   
   [root@host~]# nvme disconnect -d <nvme_disk_name>

   NOTE: nvme_disk_name is the name of the device (Ex:nvme0n1) and not the device 
         path. 


HMA
----

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire (Default)" configuration tuning option. Currently 256 IPv4/128 IPv6 
NVMe-oF iWARP connections are supported on T6 25G SO adapters. To see the number 
of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids 

The total number of connections depends on the devices used and I/O queues. 
For example, if the Initiator connects to 2 target devices with 4 I/O queues 
per device (-i 4), a total of 10 NVMe-oF iWARP connections will be used. 


Performance Tuning
------------------

To tune your system for better performance, refer the "Performance Tuning" 
section of the NVMe-oF chapter in the User's Guide.


Driver Unloading 
================

Follow the steps mentioned below to unload the drivers:

On target, run the following commands:

   [root@host~]# rmmod nvmet-rdma 
   [root@host~]# rmmod nvmet
   [root@host~]# rmmod iw_cxgb4 

On initiator, run the following commands:
   
   [root@host~]# rmmod nvme-rdma
   [root@host~]# rmmod nvme
   [root@host~]# rmmod iw_cxgb4


NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
SPDK NVMe-oF iWARP
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that the following requirements are met before installation:

- Uninstall any OFED present in the machine.

- rdma-core-devel package should be installed on RHEL 8.X/7.X systems.


Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) To install 5.4.105 kernel with NVMe-oF components enabled, use the following 
   command: 

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following  
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_BLK_DEV_NVME=m
      CONFIG_NVME_RDMA=m
      CONFIG_NVME_TARGET=m
      CONFIG_NVME_TARGET_RDMA=m
      CONFIG_BLK_DEV_NULL_BLK=m
      CONFIG_CONFIGFS_FS=y

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X/7.X, Ubuntu 20.04.X
----------------------------

No extra kernel configuration required.


Driver Installation
===================

a) rdma-core version > 23 is recommended for SPDK NVMe-oF iWARP. Below are the 
   steps to install v27.

   [root@host ~]# wget "https://github.com/linux-rdma/rdma-core/releases/download/v27.0/rdma-core-27.0.tar.gz"
   [root@host ~]# tar zxfv rdma-core-27.0.tar.gz
   [root@host ~]# tar cjf /root/rpmbuild/SOURCES/rdma-core-27.0.tgz rdma-core-27.0/
   [root@host rdma-core-27.0]# rpmbuild -ba redhat/rdma-core.spec      
   [root@host ~]# cd /root/rpmbuild/RPMS/x86_64/
   [root@host x86_64]# rpm -ivh *27*.rpm

b) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

c) Install iWARP RDMA Offload driver and NVMe utilities.

   [root@host~]# make nvme_install

NOTE: For more installation options, please run "make help" or "install.py -h".

d) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below on both target and initiator machines: 
 
a) Load the following modules:

   [root@host~]# modprobe iw_cxgb4
   [root@host~]# modprobe rdma_ucm    

b) Bring up the Chelsio interface(s).

   [root@host~]# ifconfig ethX x.x.x.x up


Configuration
=============

Target
------

a) Download SPDK v21.01.

   [root@host~]# git clone https://github.com/spdk/spdk 
   [root@host~]# git checkout v21.01
   [root@host~]# cd spdk
   [root@host~]# git submodule update –init
   Change the below in CONFIG file.
            CONFIG_FIO_PLUGIN=y
            FIO_SOURCE_DIR=<path_to_FIO_source>	
            CONFIG_RDMA=y
            CONFIG_RDMA_SEND_WITH_INVAL=y

b) Run the below script to check that minimum SPDK dependencies are installed. 

   [root@host~]# cd spdk
   [root@host~]# sh scripts/pkgdep.sh

c) Compile SPDK with RDMA and install it. 

   [root@host~]# make clean ; ./configure --with-rdma; make; make install

d) Configure Huge Pages.

   [root@host~]# mkdir -p /mnt/huge
   [root@host~]# echo 8192 > /proc/sys/vm/nr_hugepages
   [root@host~]# echo 0 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
   [root@host~]# echo 8192 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   [root@host~]# vim /etc/fstab
   nodev      /dev/hugepages          hugetlbfs pagesize=2MB  0 0
   nodev      /mnt/huge               hugetlbfs pagesize=1GB  0 0
   [root@host~]# mount -a
   [root@host~]# cd spdk
   [root@host~]# NRHUGE=8192 scripts/setup.sh 

e) Start the SPDK NVMe-oF iWARP target. 

   [root@host~]# spdk/build/bin/nvmf_tgt -m 0xFFF &

f) Below are the sample configuration steps to create a malloc LUN.

   [root@host~]# spdk/scripts/rpc.py nvmf_create_transport -t RDMA -c 8192 -u 131072 -n 8192 -b 256
   [root@host~]# spdk/scripts/rpc.py bdev_malloc_create -b Malloc$i 256 512
   [root@host~]# spdk/scripts/rpc.py nvmf_create_subsystem  nqn.2016-06.io.spdk:cnode0 -a -s SPDK00000000000000 -d SPDK_Controller0
   [root@host~]# spdk/scripts/rpc.py nvmf_subsystem_add_ns  nqn.2016-06.io.spdk:cnode0 Malloc0
   [root@host~]# spdk/scripts/rpc.py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t rdma -a 10.1.1.163 -s 4420 


Initiator
---------

SPDK NVMe-oF iWARP target works seamlessly with SPDK NVMe-oF iWARP initiator or any 
standard Linux kernel initiators. Please see NVMe-oF iWARP Initiator section for steps 
to connect with Linux kernel initiator. To use the SPDK NVMe-oF iWARP Initiator, 

a) Follow steps a) to d) of the SPDK Target section above to configure and install SPDK.
b) Connect to the target using fio plugin. 

[root@host~]# LD_PRELOAD=/root/spdk/build/fio/spdk_nvme fio --rw=randread/randwrite 
 --name=random --norandommap=1 --ioengine=/root/spdk/build/fio/spdk_nvme --thread=1 
--size=400m --group_reporting --exitall --invalidate=1 --direct=1 --filename='trtype=RDMA 
adrfam=IPv4 traddr=10.1.1.163 trsvcid=4420 subnqn=nqn.2016-06.io.spdk\:cnode0 ns=1' 
--time_based --runtime=20 --iodepth=64 --numjobs=4 --unit_base=1 --bs=<value> 
--kb_base=1000 --ramp_time=3


Performance Tuning
------------------

To tune your system for better performance, refer the "Performance Tuning" 
section of the SPDK NVMe-oF chapter in the User's Guide.


Driver Unloading 
================

Follow the steps mentioned below to unload the drivers:

   [root@host~]# rmmod iw_cxgb4 

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
NVMe-oF TOE
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) To install the 5.4.105 kernel with NVMe-TCP components enabled, use the 
   following command. 

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following 
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_NVME_CORE=m
      CONFIG_NVME_FABRICS=m
      CONFIG_NVME_TCP=m
      CONFIG_NVME_TARGET=m
      CONFIG_NVME_TARGET_TCP=m
      CONFIG_BLK_DEV_NVME=m
      CONFIG_BLK_DEV_NULL_BLK=m
      CONFIG_CONFIGFS_FS=y

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X, Ubuntu 20.04.X
------------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install TOE driver and NVMe utilities.

   [root@host~]# make nvme_toe_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below on both target and initiator machines:
 
a) Load the TOE driver.

   [root@host~]# modprobe t4_tom  

b) Bring up the Chelsio interface(s).

   [root@host~]# ifconfig ethX x.x.x.x up

c) Mount configfs by running the below command:

   [root@host~]# mount -t configfs none /sys/kernel/config
  
d) Apply cop policy to disable DDP and Rx Coalesce. 

   [root@host~]# cat <policy_file>
   all => offload !ddp !coalesce  
   [root@host~]# cop -d -o <policy_out> <policy_file>
   [root@host~]# cxgbtool ethX policy <policy_out>

   NOTE: The policy applied using cxgbtool is not persistent and should be 
         applied everytime drivers are reloaded or the machine is rebooted.
    
   The applied cop policies can be read using, 

   [root@host~]# cat /proc/net/offload/toeX/read-cop

e) Load the nvme drivers. On target, run the following commands:

   [root@host~]# modprobe null_blk
   [root@host~]# modprobe nvmet
   [root@host~]# modprobe nvmet-tcp 

   On initiator, run the following commands:
   
   [root@host~]# modprobe nvme
   [root@host~]# modprobe nvme-tcp


Configuration
=============

Target
------

a) The following commands will configure target using nvmetcli with a LUN.

   [root@host~]# nvmetcli
   /> cd subsystems
   /subsystems> create nvme-ram0
   /subsystems> cd nvme-ram0/namespaces
   /subsystems/n...m0/namespaces> create nsid=1
   /subsystems/n...m0/namespaces> cd 1
   /subsystems/n.../namespaces/1> set device path=/dev/ram1
   /subsystems/n.../namespaces/1> cd ../..
   /subsystems/nvme-ram0> set attr allow_any_host=1
   /subsystems/nvme-ram0> cd namespaces/1
   /subsystems/n.../namespaces/1> enable
   /subsystems/n.../namespaces/1> cd ../../../..
   /> cd ports
   /ports> create 1
   /ports> cd 1/
   /ports/1> set addr adrfam=ipv4
   /ports/1> set addr trtype=tcp
   /ports/1> set addr trsvcid=4420
   /ports/1> set addr traddr=102.1.1.102
   /ports/1> cd subsystems
   /ports/1/subsystems> create nvme-ram0
     
b) Save the target configuration to a file. 

   /ports/1/subsystems> saveconfig /root/nvme-target_setup
   /ports/1/subsystems> exit

c) Clear the targets. 

   [root@host~]# nvmetcli clear


Initiator
---------

a) Discover the target.
   
   [root@host~]# nvme discover -t tcp -a <target_ip> -s 4420 

b) Connect to target.

Connecting to a specific target.
   
   [root@host~]# nvme connect -t tcp -a <target_ip> -s 4420 -n <target_name>

Connecting to all targets configured on a portal.  

   [root@host~]# nvme connect-all -t tcp -a <target_ip> -s 4420 

c) List the connected targets.

   [root@host~]# nvme list

d) Format and mount the NVMe disks shown with the above command.

e) Disconnect from the target and unmount the disk.
   
   [root@host~]# nvme disconnect -d <nvme_disk_name>

   NOTE: nvme_disk_name is the name of the device (Ex:nvme0n1) and not the device 
         path. 


HMA
---

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire (Default)" configuration tuning option. Currently 256 IPv4/128 IPv6 
NVMe-oF TOE connections are supported on T6 25G SO adapters. To see the number 
of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids 

The total number of connections depends on the devices used and I/O queues. 
For example, if the Initiator connects to 2 target devices with 4 I/O queues 
per device (-i 4), a total of 10 NVMe-oF TOE connections will be used. 


Performance Tuning
------------------s

To tune your system for better performance, refer the "Performance Tuning" 
section of the NVMe-TOE chapter in the User's Guide.


Driver Unloading 
================

Follow the steps mentioned below to unload the drivers:

On target, run the following commands:

   [root@host~]# rmmod nvmet-rdma 
   [root@host~]# rmmod nvmet

On initiator, run the following commands:
   
   [root@host~]# rmmod nvme-rdma
   [root@host~]# rmmod nvme

To unload TOE driver, see Software/Driver Unloading section in Network (NIC/TOE) 
section.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
SPDK NVMe-oF TOE
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install the 5.4.105 kernel with NVMe-TCP components enabled by default.

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following 
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_NVME_CORE=m
      CONFIG_NVME_FABRICS=m
      CONFIG_NVME_TCP=m
      CONFIG_NVME_TARGET=m
      CONFIG_NVME_TARGET_TCP=m
      CONFIG_BLK_DEV_NVME=m
      CONFIG_BLK_DEV_NULL_BLK=m
      CONFIG_CONFIGFS_FS=y

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X/7.X, Ubuntu 20.04.X
----------------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install SPDK NVMe-oF TOE driver and NVMe utilities.

   [root@host~]# make nvme_toe_spdk_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below on the target machine:
 
a) Load the SPDK NVMe-oF TOE driver.

   [root@host~]# modprobe chtcp

b) Bring up the Chelsio interface(s).

   [root@host~]# ifconfig ethX x.x.x.x up


Configuration
=============

Target
------

a) SPDK v20.10, customized to support TCP/IP offload and kernel bypass for 
   SPDK NVMe-oF TCP Target is part of Chelsio Unified Wire package. Change your 
   current working directory to Chelsio SPDK directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x/build/src/chspdk/user/spdk/

b) Configure Huge Pages.

   [root@host~]# mkdir -p /mnt/huge
   [root@host~]# echo 8192 > /proc/sys/vm/nr_hugepages
   [root@host~]# echo 0 > /sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages
   [root@host~]# echo 8192 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
   [root@host~]# vim /etc/fstab
   nodev      /dev/hugepages          hugetlbfs pagesize=2MB  0 0
   nodev      /mnt/huge               hugetlbfs pagesize=1GB  0 0
   [root@host~]# mount -a
   [root@host~]# NRHUGE=8192 scripts/setup.sh 

c) Start the target. 

   [root@host spdk]# ./build/bin/nvmf_tgt -m <cpu_mask>

d) Below are the sample configuration steps to create a LUN with null device.

   SPDK_PATH=$'ChelsioUwire-x.x.x.x/build/src/chspdk/user/spdk/' 
   $SPDK_PATH/scripts/rpc.py nvmf_create_transport -t TCP
   $SPDK_PATH/scripts/rpc.py bdev_null_create Null0 1024 4096
   $SPDK_PATH/scripts/rpc.py nvmf_create_subsystem nqn.2016-06.io.spdk:cnode0 -a -s SPDK00000000000000 -d SPDK_Controller0
   $SPDK_PATH/scripts/rpc.py nvmf_subsystem_add_ns nqn.2016-06.io.spdk:cnode0 Null0
   $SPDK_PATH/scripts/rpc.py nvmf_subsystem_add_listener nqn.2016-06.io.spdk:cnode0 -t tcp -a 10.1.1.163 -s 4420
 

Initiator
---------

SPDK NVMe-oF TOE target works seamlessly with SPDK NVMe-oF  TCP initiator or 
any kernel mode initiators. Please see NVMe-oF TOE Initiator section for steps 
to connect to the target.


Driver Unloading 
================

Follow the below steps on the target machine to unload the drivers:

   [root@host~]# rmmod chtcp 
   [root@host~]# rmmod cxgb4



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
SoftiWARP
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) To install the 5.4.105 kernel with SoftiWARP components enabled by default,

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, enable the following 
      parameters in the kernel configuration file and then proceed with kernel 
      installation:

      CONFIG_RDMA_SIW=m

c) Boot into the new kernel and install Chelsio Unified Wire.


RHEL 8.X/Ubuntu 20.04.X
-----------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install network driver and NVMe, iSER utilities.

   [root@host~]# make install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading 
==============

IMPORTANT: Please ensure that all inbox drivers are unloaded before proceeding 
           with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Follow the steps mentioned below the Initiator/Client machine:
 
a) Load the network driver (cxgb4).

   [root@host~]# modprobe cxgb4

b) Load the SoftiWARP driver (siw). 

   [root@host~]# modprobe siw

c) Unload the iWARP RDMA offload driver (iw_cxgb4).

   [root@host~]# rmmod iw_cxgb4


Configuration
=============

Initiator/Client
----------------

IMPORTANT: Disable iWARP Port Mapper (iwpmd) service on Traget and Initiator. 
   
           [root@host~]# systemctl stop iwpmd


a) RDMA tool (rdma) is used to configure the siw device. It is installed by default 
   in RHEL 8.2, 8.3 and Ubuntu 20.04 distibutions. If not present in the machine, 
   install it from latest iproute2 package (https://git.kernel.org/pub/scm/network/iproute2/iproute2.git).

b) Configure the siw device.

   [root@host~]# rdma link add <siw_device> type siw netdev <ethX>
   [root@host~]# ifconfig ethX <IP address> up

c) Verify the configuration using ibv_devices.

d) The initiator/client can now connect to the target/server machines. 
   Please refer NVMe-oF iWARP initiator and iSER initiator sections for steps
   to connect to the respective targets.


Driver Unloading 
================

Follow the below steps to unload the the SoftiWARP and network drivers:

   [root@host~]# rmmod siw 
   [root@host~]# rmmod cxgb4



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
LIO iSCSI Target Offload
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Kernel Configuration
====================

RHEL 8.X/7.X
------------

a) Download the kernel source RPM kernel-3.10.0-xxx.el7.src.rpm for your  
   distribution.
b) Install the kernel source

   [root@host~]# rpm -ivh kernel-3.10.0-xxx.el7.src.rpm

c) Prepare the kernel source:

   [root@host~]# cd /root/rpmbuild/SPECS/
   [root@host~]# rpmbuild -bp kernel.spec --nodeps
   [root@host~]# cd /root/rpmbuild/BUILD/kernel-3.10.0-xxx.el7/linux-3.10.0-xxx.el7.x86_64/
   [root@host~]# make prepare

d) Copy the source to /usr/src directory.

   [root@host~]# cp -r linux-3.10.0-xxx.el7 /usr/src	

e) Proceed with driver installation as directed in the "Driver Installation" 
   section.


Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install 5.4.105 kernel with LIO iSCSI Target Offload enabled. 

   [root@host~]# make kernel_install

c) Boot into the new kernel and proceed with driver installation as directed in the 
   "Driver Installation" section.

   Alternately, to use a different 5.10.X/5.4.X kernel version, 

   i.   Download the kernel from kernel.org
   ii.  Untar the tar-ball. 
   iii. Change your working directory to kernel directory and invoke the installation 
        menu:

        [root@host~]# make menuconfig

   iv.  Select Device Drivers -> Generic Target Core Mod (TCM) and ConfigFS 
        Infrastructure.
   v.   Enable Linux-iSCSI.org iSCSI Target Mode Stack as a Module (if not already 
        enabled).
   vi.  Select Save. 
   vii. Exit from the installation menu.
   viii. Continue with kernel installation as usual.
   ix.  Boot into the new kernel and proceed with driver installation as directed 
        in the "Driver Installation" section.


Kernel.org linux-4.9.X
----------------------

a) Download the stable version of 4.9 from kernel.org.
b) Untar the tar-ball. 
c) Change your working directory to kernel package directory and run the 
   following command to invoke the installation menu.

   [root@host~]# make menuconfig

d) Select "Device Drivers" > "Generic Target Core Mod (TCM) and ConfigFS 
   Infrastructure".
e) Enable "Linux-iSCSI.org iSCSI Target Mode Stack".
f) Select Save. 
g) Exit from the installation menu.
h) Apply the patch provided in the Unified Wire package:

   [root@host~]# patch -p1 < /root/<driver_package>/src/cxgbit/patch/iscsi_target.patch

i) Continue with kernel installation as usual.
j) Boot into the new kernel and proceed with driver installation as directed in the 
   "Driver Installation" section.


Ubuntu 20.04.X/18.04.X
----------------------

a) Clone Ubuntu Linux kernel source repository.

   Ubuntu 18.04.X:
   [root@host~]# git clone git://kernel.ubuntu.com/ubuntu/ubuntu-bionic.git

   Ubuntu 20.04.X:
   [root@host~]# git clone git://kernel.ubuntu.com/ubuntu/ubuntu-focal.git

b) Check the booted kernel version using "uname -r"
c) Find the git tag which matches the kernel version.

   [root@host~]# cd ubuntu-bionic/
   [root@host~]# git tag -l Ubuntu-* | grep -i 4.15.0-29
   Ubuntu-4.15.0-29.31

d) Check out to the changeset.

   [root@host~]# git checkout Ubuntu-4.15.0-29.31

e) Proceed with driver installation as directed in the "Driver Installation" section.


3.14.57
-------

a) Download the kernel from kernel.org
b) Untar the tar-ball. 
c) Change your working directory to kernel directory and invoke the installation 
   menu:

   [root@host~]# make menuconfig

d) Select Device Drivers -> Generic Target Core Mod (TCM) and ConfigFS 
   Infrastructure.
e) Enable Linux-iSCSI.org iSCSI Target Mode Stack as a Module (if not already
   enabled).
f) Select Save. 
g) Exit from the installation menu.
h) Untar the patch file.

   [root@host~]# cp /root/<driver_package>/src/cxgbit/patch/linux_3-14.a .
   [root@host~]# ar xvf linux_3-14.a

i) Apply all the patches to kernel source one by one.

   [root@host~]# patch -p1 < <file_name>.patch

j) Continue with kernel installation as usual.
k) Reboot to the newly installed kernel. Verify by running uname -a  command. 
l) Install LIO iSCSI target offload driver as mentioned in the next section. 


Driver Installation
===================

Pre-requisites
--------------

Please make sure that the following components are installed in the system. If 
not already present, the components provided in the package will be installed.

- Python v2.7 or above (v2.7.10 provided in the package)
- TargetCLI (v2.1 provided in the package)
- OpenSSL (Download from https://www.openssl.org/source/)

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install LIO Target driver and targetcli utils.

   [root@host~]# make lio_install

In case of RHEL 8.X/7.X and Ubuntu 20.04.X/18.04.X you can use one 
of the following options to install the driver by specifying kernel source (KSRC) 
and kernel object (KOBJ):


CLI mode
--------

   [root@host~]# make lio_install KSRC="<kernel_source_dir>" KOBJ="<kernel_object_dir>"

Example: For Ubuntu 18.04.4, 

   [root@host~]# make lio_install KSRC=/root/ubuntu-bionic/ KOBJ=/lib/modules/4.15.0-76-generic/build


CLI mode (without Dialog utility)
---------------------------------

   [root@host~]# ./install.py --ksrc=<kernel_source_dir> --kobj=<kernel_object_dir>

Example: For RHEL 7.8, 

   [root@host~]# ./install.py --ksrc=/usr/src/linux-3.10.0-1127.el7 --kobj=/lib/modules/3.10.0-1127.el7.x86_64/build/


GUI mode
--------

   [root@host~]# ./install.py --set-kpath	

Provide the paths for kernel source and kernel object on the last screen of the 
installer. Select "OK".
 
NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT: Please ensure that all inbox drivers are unloaded before proceeding 
           with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.
   
a) Load network driver (cxgb4).
   
   [root@host~]# modprobe cxgb4

b) Bring up the interface.

   [root@host~]# ifconfig ethX <IP address> up

c) Load the LIO iSCSI Target Offload driver (cxgbit).

   [root@host~]# modprobe cxgbit 


Driver Configuration
====================

Configuring LIO iSCSI Target
-----------------------------

The LIO iSCSI Target needs to be configured before it can become useful. Please 
refer the user manual at http://www.linux-iscsi.org/Doc/LIO Admin Manual.pdf to do so.


Offloading LIO iSCSI Connection
--------------------------------

To offload the LIO iSCSI Target, use the following command:

[root@host~]# echo 1 > /sys/kernel/config/target/iscsi/<target_iqn>/tpgt_1/np/<target_ip>\:3260/cxgbit
   
Execute the above command for every portal address listening on Chelsio interface.


Running LIO iSCSI and Network Traffic Concurrently
--------------------------------------------------

If you wish to run network traffic with offload support (TOE) and LIO iSCSI 
traffic together, follow the steps mentioned below:

a) If not done already, load network driver with offload support (TOE).

  [root@host~]# modprobe t4_tom
  
b) Create a new policy file.

  [root@host~]# cat <new_policy_file>
  
c)  Add the following lines to offload all traffic except LIO iSCSI.

   listen && src port <target_listening_port> && src host <target_listening_ip> => !offload
   all => offload
  
d) Compile the policy.

   [root@host~]# cop -d -o <output_policy_file> <new_policy_file>
  
e) Apply the policy.

  [root@host~]# cxgbtool ethX policy <output_policy_file>
  
   NOTE: The policy applied using cxgbtool is not persistent and should be 
         applied everytime drivers are reloaded or the machine is rebooted.
 
  The applied cop policies can be read using, 

  [root@host~]# cat /proc/net/offload/toeX/read-cop

 
Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the LIO iSCSI Target Offload chapter in the User's Guide.


Driver Unloading
================

Unloading LIO iSCSI Target Offload driver
-----------------------------------------

To unload the LIO iSCSI Target Offload driver, follow the steps mentioned below:

a) Log out from the initiator
b) Run the following command: 

   [root@host~]# echo 0 > /sys/kernel/config/target/iscsi/<target_iqn>/tpgt_1/np/<target_ip>\:3260/cxgbit

Execute the above command for every portal address listening on Chelsio interface.   

c) Unload the driver:

   [root@host~]# rmmod cxgbit


Unloading Network driver
------------------------

- To unload the driver in NIC mode (without offload support):

   [root@host~]# rmmod cxgb4

     
     
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
iSCSI PDU Offload Target
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x


b) Install iSCSI-target driver,firmware and utilities:

   [root@host~]# make iscsi_pdu_target_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

   [root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

To load the module, run modprobe as follows:

   [root@host~]# modprobe chiscsi_t4


Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the iSCSI PDU Offload Target chapter in the User's Guide.

   
Driver Unloading
================

Use the following command to unload the module:

   [root@host~]# rmmod chiscsi_t4

NOTE:i. While using rpm-tar-ball for installation
        a. Uninstallation will result into chiscsi.conf file renamed into
        chiscsi.conf.rpmsave.
        b. It is advised to take a backup of chiscsi.conf file before you do an
        uninstallation and installation of new/same unified wire package.
        As re-installing/upgrading unified-wire package may lead to loss of
        chiscsi.conf file.

    ii. Installation/uninstallation using source-tar-ball will neither remove 
        the conf file nor rename it. It will always be intact.
        However it is recommended to always take a backup of your configuration 
        file for both methods of installation. 


NOTE: For more information on additional configuration options, please refer 
      User's Guide.   
      
	  
	  
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
iSCSI PDU Offload Initiator 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites  
==============

Please make sure that the following requirements are met before installation:

- The iSCSI PDU Offload Initiator driver (cxgb4i) runs on top of 
  NIC module (cxgb4) and open-iscsi-2.0-872/873/874 only, on a Chelsio card.
 
- openssl-devel package should be installed.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install open-iSCSI,iSCSI-initiator,firmware and utilities:

   [root@host~]# make iscsi_pdu_initiator_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.

   
Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to loading the driver as
a regular user will fail.

Load cxgb4i driver using the following command:

   [root@host~]# modprobe cxgb4i
  
The cxgb4i module registers a new transport class "cxgb4i".  

If loading of cxgb4i displays "unkown symbols found" error in dmesg, follow the 
steps mentioned below: 

a) Kill iSCSI daemon "iscsid"
b) View all the loaded iSCSI modules

   [root@host~]# lsmod | grep iscsi

c) Now, unload them using the following command:

   [root@host~]# rmmod <modulename>

d) Finally reload the cxgb4i driver


Accelerating open-iSCSI Initiator
=================================

The following steps need to be taken to accelerate the open-iSCSI initiator:


I. Configuring interface (iface) file
-------------------------------------

Create the file automatically by loading cxgb4i driver and then executing the 
following command:

   [root@host~]# iscsiadm -m iface

Alternatively, you can create an interface file located under iface directory 
for the new transport class cxgb4i in the following format:

iface.iscsi_ifacename = <iface file name>
iface.hwaddress = <MAC address>
iface.transport_name = cxgb4i
iface.net_ifacename = <ethX>
iface.ipaddress = <iscsi ip address>

Here,

iface.iscsi_ifacename : Interface file in /etc/iscsi/ifaces/
iface.hwaddress       : MAC address of the Chelsio interface via which iSCSI 
                        traffic will be running.
iface.transport_name  : Transport name, which is cxgb4i.
iface.net_ifacename   : Chelsio interface via which iSCSI traffic will be running.
iface.ipaddress       : IP address which is assigned to the interface.


II. Discovery and Login
-----------------------

a) Start Daemon from /sbin:

   [root@host~]# iscsid

NOTE: If iscsid is already running, then kill the service and start it as shown 
      above after installing the Chelsio Unified Wire package.

b) Discover iSCSI target:

   [root@host~]# iscsiadm -m discovery -t st -p <target ip address>:<target port no> -I <cxgb4i iface file name>

c) Log into an iSCSI target:

   [root@host~]# iscsiadm -m node -T <iqn name of target> -p <target ip address>:<target port no> -I <cxgb4i iface file name> -l

If the login fails with an error message in the format of 
ERR! MaxRecvSegmentLength <X> too big. Need to be <= <Y>. in dmesg, edit the 
iscsi/iscsid.conf file and change the setting for MaxRecvDataSegmentLength:

node.conn[0].iscsi.MaxRecvDataSegmentLength = 8192

IMPORTANT: Always take a backup of iscsid.conf file before installing Chelsio 
           Unified Wire package. Although the file is saved to iscsid.rpmsave 
           after uninstalling the package using RPM, you are still advised to 
           take a backup.

d) Log out from an iSCSI Target: 

   [root@host~]# iscsiadm -m node -T <iqn name of target> -p <target ip address>:<target port no> -I <cxgb4i iface file name> -u

NOTE: Other options can be found by typing iscsiadm --help


HMA
====

To use HMA, please ensure that Unified Wire is installed using the 
"Unified Wire(Default)" configuration tuning option.

a) Use LIO iSCSI Traget in offload mode.

b) Configure MTU 9000 for Chelsio Interfaces.

c) Load the driver using the following parameters.

 [root@host~]# modprobe cxgb4i cxgb4i_snd_win=131072 cxgb4i_rcv_win=262144

Currently 256 IPv4/128 IPv6 iSCSI PDU Offload Initiator connections 
are supported on T6225-SO-CR adapter. 

The following command shows the number of offloaded connections.
 
 [root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids


Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the iSCSI PDU Offload Initiator chapter in the User's Guide.


Driver Unloading
================

   [root@host~]# rmmod cxgb4i
   [root@host~]# rmmod libcxgbi

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Crypto Offload
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that SELinux and firewall are disabled.


Kernel Configuration
====================

Kernel.org linux-5.10.X/5.4.X
-----------------------------

a) Change your current working directory to Chelsio Unified Wire package directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install the 5.4.105 kernel with Crypto components enabled by default. 

   [root@host~]# make kernel_install

NOTE: If you wish to use custom 5.10.X/5.4.X kernel, multiple options need 
      to be enabled in the kernel configuration file. Please refer the User Guide 
      for the complet list of options and then proceed with kernel installation.

c) Boot into the new kernel and proceed with driver installation as directed in 
   the "Driver Installation" section.


RHEL 8.X/7.X x86_64, Ubuntu 20.04.X/18.04.X, RHEL 7.5/7.6 ARM
-------------------------------------------------------------

No extra kernel configuration required.


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install Crypto driver and Chelsio openSSL modules.

   [root@host~]# make crypto_install

NOTE: For more installation options, please run "make help" or "install.py -h"

c) Reboot the machine for changes to take effect.

   [root@host~]# reboot
 

Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Inline
------

a) To load Crypto Offload driver in Inline mode, load the network driver in TOE mode.

   [root@host~]# modprobe t4_tom

b) Bring up the Chelsio network interface.

   [root@host~]# ifconfig ethX up

Where ethX is the Chelsio interface.


Co-processor
------------

a) To load Crypto Offload driver in Co-processor mode (chcr), run the following 
   command:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe chcr

b) Bring up the Chelsio network interface.

   [root@host~]# ifconfig ethX up

Where ethX is the Chelsio interface.


Configuration
=============

Limitations
-----------

- AEAD is not supported on RHEL 7.x x86_64 (Kernel limitation). Due to this, 
  GCM cipher is not supported for co-processor.
- Applications using AF_ALG are not supported on RHEL 7.4 (due to a kernel bug 
  in AF_ALG framework).


Inline TLS Offload
------------------

Configure TLS Offload and TOE Ports
-----------------------------------

To configure Inline TLS Offload, connection offload policy should be used with 
the required TCP port numbers. Follow the steps mentioned below:

a) Create a new policy file and add the following line for each TCP port (to be 
   TLS offloaded):

   src or dst port <tcp_port> => offload tls mss 32 bind random 
   .
   .
   all => offload

  The all => offload is added to ensure that rest of the TCP ports will be 
  regular TOE offloaded. 

  Alternatively, portrange can be used to define a range of TCP ports (to be 
  TLS offloaded).

  src or dst portrange <M-N> => offload tls mss 32 bind random
  all => offload

b) Compile the policy.

   [root@host~]# cop -d -o <policy_out> <new_policy_file>

c) Apply the policy.

   [root@host~]# cxgbtool <iface> policy <policy_out>

   Upon applying the above policy, traffic on all the mentioned TCP ports will
   be TLS offloaded, while traffic on other TCP ports will be TOE offloaded.

   NOTE: The policy applied using cxgbtool is not persistent and should be 
         applied everytime drivers are reloaded or the machine is rebooted.

   The applied cop policies can be read using, 

   [root@host~]# cat /proc/net/offload/toeX/read-cop


Configuring Chelsio OpenSSL and Applications
--------------------------------------------

OpenSSL which supports Inline offload is installed as part of Unified
Wire package. It is installed in /usr/chssl/bin. It is recommended to use TLSv1.2 
for the connections to be TLS offloaded. Connections will be TOE Offloaded if any 
TLS version > 1.2 is used. 

OpenSSL tool:

a) Start TLS offload Server:

   [root@host~]# cd /usr/chssl/bin
   [root@host~]# ./openssl s_server -key <key_file> -cert <cert_file> -accept 443 -cipher AES128-GCM-SHA256 -WWW -tls1_2

   On RHEL 8.X and Ubuntu distributions with openssl version 1.1.1, additionally -4 
   or -6 should be given to start IPv4 or IPv6 server respectively. 

b) Start TLS offload Client: 

   [root@host~]# cd /usr/chssl/bin
   [root@host~]# ./openssl s_time -connect <tls_server_ip>:<tls_server_port>  -www /<file>

   On RHEL 8.X and Ubuntu distributions with openssl version 1.1.1, the IPv6 address 
   should be specified within [].


Custom Applications: 

To compile applications using Chelsio OpenSSL library: 

   [root@host~]# export LD_LIBRARY_PATH=/usr/chssl/lib/
   [root@host~]# gcc -g -o <server/client output file> <server/client file> -lcrypto -lssl -L/usr/chssl/lib/

Please refer User's Guide for configuring nginx and apache server.


Inline TLS Counters
-------------------

To verify if Chelsio Inline is used, run the following command:

   [root@host~]# cat /sys/kernel/debug/cxgb4/<PF4_id>/tls
   Chelsio Inline TLS Stats
   TLS PDU Tx: 32661534
   TLS PDU Rx: 231039210
   TLS Keys (DDR) Count: 48


Co-processor
------------

To view the complete list of supported cryptographic algorithms, use the following 
command:

[root@host~]# cat /proc/crypto|grep -i chcr

The following applications can be offloaded by Chelsio Co-processor: 

Data at Rest
- Dmcrypt
- VeraCrypt
TLS/SSL
- Apache
- nginx
- OpenVPN
IPsec
- Strongswan

Please refer User's Guide for configuring nginx and apache servers.

To verify if Chelsio Co-processor is used by the applications, run the following 
command:

   [root@host~]# cat /sys/kernel/debug/cxgb4/<PF4_id>/crypto
   Chelsio Crypto Co-processor Stats
   aes_ops: 1016
   digest_ops: 323
   aead_ops: 2739611
   comp: 2740950
   error: 0
   Fallback: 9


Performance Tuning
==================

To tune your system for better performance, refer the "Performance Tuning" 
section of the Crypto Offload chapter in the User's Guide.


Driver Unloading
================

To unload Crypto Offload driver in Co-processor mode, run the following command:

   [root@host~]# rmmod chcr

To unload Crypto Offload driver in Inline mode, unload the network driver in TOE
mode, as mentioned under "Driver Unloading" in "Network (NIC/TOE)" section.   

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
DCB 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Build and install all drivers with DCB support:

   [root@host~]# make dcbx=1 install

NOTE: For more installation options, please run "make help".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

   [root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

Before proceeding, please ensure that Unified Wire is installed with 
DCB support as mentioned in the previous section. The switch ports need to be 
enabled with DCBX configuration s(Class mapping, ETS and PFC).

Upon loading the network/storage driver and interface bringup, firmware 
completes DCBX negotiation with the switch.

[root@host~]# modprobe cxgb4
[root@host~]# modprobe t4_tom
[root@host~]# ifconfig ethX up
[root@host~]# modprobe csiostor

The negotiated DCBX parameters can be reviewed at 
/sys/kernel/debug/cxgb4/<PF4_id>/dcb_info

The storage driver(FCoE Full Offload Initiator) uses the DCBX negotiated 
parameters (ETS, PFC etc.) Without any further configuration. The network 
drivers (cxgb4, t4_tom) and iSCSI drivers (cxgb4i, chiscsi) need further VLAN 
configuration to be setup, which is explained in the next section 
"Running NIC & iSCSI Traffic together with DCBx".
	  
	  
Running NIC & iSCSI Traffic together with DCBx
==============================================

NOTE: Please refer to "iSCSI PDU Offload Initiator" section to configure iSCSI 
Initiator.

Use the following procedure to run NIC and iSCSI traffic together with DCBx 
enabled.

a) Identify the VLAN priority configured for NIC and iSCSI class of traffic on 
   the switch.
b) Create VLAN interfaces for running NIC and iSCSI traffic, and configure 
   corresponding VLAN priority.
	
Example:

Switch is configured with a VLAN priority of 2 and 5 for NIC and iSCSI class of 
traffic respectively. NIC traffic is run on VLAN10 and iSCSI traffic is run on 
VLAN20.

Assign proper VLAN priorities on the interface (here eth5), using the following 
commands on the host machine:

   [root@host~]# vconfig set_egress_map eth5.10 0 2 
   [root@host~]# vconfig set_egress_map eth5.20 5 5


NOTE: For more information on additional configuration options, please refer 
      User's Guide.
	

	
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
FCoE Full Offload Initiator 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install FCoE full offload initiator driver:

   [root@host~]# make fcoe_full_offload_initiator_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as a
regular user will fail.
   
To load the driver, execute the following command:

   [root@host~]# modprobe csiostor   


Configuring the switch and Troubleshooting
==========================================

Please refer "Software Configuration and Fine-tuning" section in User's Guide


Driver Unloading
================

To unload the driver, execute the following command:

   [root@host~]# modprobe -r  csiostor

NOTE:If multipath services are running, unload of FCoE driver is not possible. 
     Stop the multipath service and then unload the driver.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Offload Bonding driver
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install Chelsio Offload Bonding driver.
   
   [root@host~]# make bonding_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb
   
The driver must be loaded by the root user. Any attempt to loading the driver as
a regular user will fail.

   To load the Bonding driver (with offload support), run the following command:
   
   [root@host~]# modprobe bonding


Offloading TCP Traffic over a Bonded Interface
==============================================

The Chelsio Offload Bonding driver supports all the bonding modes in NIC Mode. 
In offload mode (t4_tom loaded) however, only the balance-rr (mode=0),
active-backup (mode=1),balance-xor (mode=2) and 802.3ad (mode=4) modes are 
supported.   

To offload TCP traffic over a bonded interface, use the following method:

a) Load the network driver with TOE support.
   
   [root@host~]# modprobe t4_tom

b) Create a bond interface. 

   [root@host~]# modprobe bonding mode=1 miimon=100

NOTE: On RHEL8.X distributions, max_bonds=1 should be provided additionally.

c) Bring up the bond interface and enslave the interfaces to the bond.

   [root@host~]# ifconfig bond0 up
   [root@host~]# ifenslave bond0 ethX ethY
   
NOTE: "ethX" and "ethY" are interfaces of the same adapter.

d) Assign IPv4/IPv6 address to the bond interface.

   [root@host~]# ifconfig bond0 X.X.X.X/Y
   [root@host~]# ifconfig bond0 inet6 add <128-bit IPv6 Address> up   
      
e) Disable FRTO on the PEER. 

   [root@host~]# sysctl -w net.ipv4.tcp_frto=0

f) Ping the PEER interface and verify the successful connectivity over the 
   bond interface. 

All TCP traffic will be offloaded over the bond interface now.


Driver Unloading
================

To unload the bonding driver.

   [root@host~]# rmmod bonding

NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Offload Multi-Adapter Failover (MAFO)
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Multi-Adapter fail-over feature will work for link down events caused by:
- Cable unplug on bonded interface
- Bringing corresponding switch port down

NOTE: The feature will not work if the bonded interfaces are administratively 
      taken down. 
	  
IMPORTANT:
- Portions of this software are covered under US Patent "Failover and migration 
  for full-offload network interface devices : US 8346919 B1"
- Use of the covered technology is strictly limited to Chelsio ASIC-based 
  solutions.


Installation
============

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install the MAFO feature: 
   
   [root@host~]# make bonding_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as a 
regular user will fail.

To load the driver (with offload support), run the following command:

   [root@host~]# modprobe bonding 

   
Offloading TCP Traffic over a Bond Interface
============================================

The Chelsio MAFO driver supports only the active-backup (mode=1) mode. To offload
TCP traffic over a bond interface, use the following method:

a) Load the network driver with TOE support.
   
   [root@host~]# modprobe t4_tom

b) Create a bond interface. 

   [root@host~]# modprobe bonding mode=1 miimon=100

NOTE: On RHEL8.X distributions, max_bonds=1 should be provided additionally.

c) Bring up the bond interface and enslave the interfaces to the bond.

   [root@host~]# ifconfig bond0 up
   [root@host~]# ifenslave bond0 ethX ethY
   
NOTE: "ethX" and "ethY" are interfaces of different adapters.

d) Assign IPv4/IPv6 address to the bond interface.

   [root@host~]# ifconfig bond0 X.X.X.X/Y
   [root@host~]# ifconfig bond0 inet6 add <128-bit IPv6 Address> up  

e) Disable TCP timestamps.

   [root@host~]# sysctl -w net.ipv4.tcp_timestamps=0     

f) Disable FRTO on the PEER. 

   [root@host~]# sysctl -w net.ipv4.tcp_frto=0 

g) Ping the PEER interface and verify the successful connectivity over the 
   bond interface. 

All TCP traffic will be offloaded over the bond interface now and fail-over
will happen in case of link-down event.

   
Driver Unloading
================

To unload the driver, run the following command:

   [root@host~]# rmmod bonding 
	 
NOTE: For more information on additional configuration options, please refer 
      User's Guide.


	 
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
UDP Segmentation Offload and Pacing
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Installation
===================

The offload drivers support UDP Segmentation Offload with limited number 
of connections (1024 connections). To build and install UDP Offload drivers 
which support large number of offload connections (approx 10K):

NOTE: 10K UDP Segmentation offload connections currently not supported on T6. 

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Run the following command:

   [root@host~]# make udp_offload_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

[root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

The driver must be loaded by the root user. Any attempt to load the driver as
a regular user will fail.

Run the following commands to load the driver:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom

Though normally associated with the Chelsio TCP Offload engine, the t4_tom 
module is required in order to allow for the proper redirection of UDP socket 
calls.


Modifying the Application
=========================

To use the UDP offload functionality, the application needs to be modified. 
Please refer User's Guide for detailed steps.


Configuring UDP Pacing
======================

Once the application is modified, traffic pacing can be set using cxgbtool.

a) Bring up the network interface.

[root@host~]# ifconfig <ethX> up

b) Run the following command.

[root@host~]# cxgbtool <ethX> sched-class params type packet level cl-rl mode flow 
              rate-unit bits rate-mode absolute channel <Channel No.> class <scheduler-class-index> 
              max-rate <maximum-rate> pkt-size <Packet size>

Here,
ethX                  : Chelsio interface
Channel No.           : is the port on which data is flowing (0-3)
scheduler-class-index : UDP traffic class (0-14 for T4/T5 adapters and 0-30 for 
                        T6 adapters) set in the SOL_SCHEDCLASS socket option in 
                        the application.
maximum-rate          : Bit rate (Kbps) for this UDP stream. This value should 
                        be in the range of 50 Kbps to 50 Mbps for T4 adapters. 
                        For T5/T6 adapters, it should should be 100 kbps to 1 Gbps.
Packet size           : UDP packet payload size in bytes; it should be equal 
                        to the value set in the SO_FRAMESIZE socket option in the 
                        application.

NOTE: To get an accurate bit rate per class, data sent by the application to the 
      sockets should be a multiple of the value set for the “pkt-size” parameter. 


Enabling Offload
================

Load the offload drivers and bring up the Chelsio interface.

[root@host~]# modprobe t4_tom
[root@host~]# ifconfig ethX <IP> up
	
The traffic will be offloaded over the Chelsio interface now. To see the number 
of connections offloaded, run the following command:

[root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids

UOTID shows the number of UDP offload connections.

IMPORTANT: While running IPv6 UDP-SO conenctions, please bind the application to 
           a single CPU using taskset.  For example, 
           
           [root@host~]# taskset -c 3 netperf -6 -H <PEER> <options>


Driver Unloading
================

Reboot the system to unload the driver. To unload without rebooting, refer 
"Unloading the driver" in Network (NIC/TOE) section.


NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Offload IPv6 Driver
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

Please make sure that the following requirements are met before installation:

- IPv6 must be enabled in your system (enabled by default).

- Unified Wire must be installed with IPv6 support as explained in the 
  "Unified Wire" chapter in the User Guide.


Installation
============

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) IPv6 must be enabled in your system (enabled by default) to use the Offload 
   IPv6 feature. Also, Unified Wire package must be installed with IPv6 support: 

   [root@host~]# make install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


NIC & TOE Driver Loading
========================

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

   [root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

		  
After installing Unified Wire package and rebooting the host, load the NIC 
(cxgb4) and TOE (t4_tom) drivers. The drivers must be loaded by root user. Any 
attempt to load the drivers as a regular user will fail.

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom


Configuration
=============

a) Load the Offload capable drivers.

   [root@host~]# modprobe t4_tom 

b) Bring up the interface and ensure that IPv6 Link Local address is present. 

   [root@host~]# ifconfig ethX up

c) Configure the required IPv6 address.

   [root@host~]# ifconfig ethX inet6 add <IPv6 address>

   On some distributions, ONBOOT="yes" should be added to interface network script 
   for the interface to come up automatically with IPv6 Link Local address.

d) All the IPv6 traffic over the Chelsio interface will be offloaded now. To see
   the number of connections offloaded, run the following command:

   [root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/tids
 
 
NIC & TOE Driver Unloading
==========================

- To unload the NIC driver:

   [root@host~]# rmmod cxgb4

- To unload the TOE driver:

Please reboot the system to unload the TOE driver. To unload without rebooting, 
refer "Unloading the driver" in Network (NIC/TOE) section.


NOTE: For more information on additional configuration options, please refer 
      User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
WD Sniffing and Tracing
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

The objective of these utilities (wd_sniffer and wd_tcpdump_trace) is to provide
sniffing and tracing capabilities by making use of Terminator's hardware features. 

Sniffer- Involves targeting specific multicast traffic and sending it directly 
         to user space. 
Tracer - All tapped traffic is forwarded to user space and also pushed back on 
         the wire via the internal loop back mechanism 

In either mode the targeted traffic bypasses the kernel TCP/IP stack and is 
delivered directly to user space by means of a RX queue which is defined by the 
register MPS_TRC_RSS_CONTROL.


Installation
============

a) Change your current working directory to Chelsio Unified Wire package 
   directory.

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install Sniffer & Tracer utilities and iWARP driver.

   [root@host~]# make sniffer_install

NOTE: For more information on additional configuration options, please refer 
      User's Guide.

c) Reboot your machine for changes to take effect.


NOTE: For more information on usage, please refer User's Guide.


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Classification and Filtering
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

1. LE-TCAM Filters
=================

Creating Filter Rules
---------------------

Network driver (cxgb4) must be installed before setting the filter rule. 

a) If you haven't done already, run the Unified Wire Installer with the 
   appropriate configuration tuning option to install the Network Driver.

b) Load the network driver and bring up the Chelsio interface:

   [root@host~]# modprobe cxgb4
   [root@host~]# ifconfig ethX up

c) Now, create filter rules using cxgbtool:

   [root@host~]# cxgbtool ethx filter <index> action [pass/drop/switch] <prio 1> <hitcnts 1>

Where, 
ethX   : Chelsio interface.
index  : positive integer set as filter id. 0-495 for T5 adapters; 0-559 for T6 
         adapters. 
action : Ingress packet disposition.
pass   : Ingress packets will be passed through set ingress queues.
switch : Ingress packets will be routed to an output port with optional header 
         rewrite. 
drop   : Ingress packets will be dropped.
prio 1 : Optional for T5. 
         Mandatory for T6 indices 0-63; Should not be added for T6 indices 64-559.
hitcnts 1 : To enable hit counts in cxgbtool filter show output.  

NOTE: In case of multiple filter rules, the rule with the lowest filter index 
      takes higher priority.
	  
	  
Listing Filter Rules
--------------------

To list previously set filters, run the following command:

   [root@host~]# cxgbtool ethX filter show

   OR

   [root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/filters        
	
	
Removing Filter Rules
---------------------

To remove a filter, run the following command with the corresponding filter rule
index

   [root@host~]# cxgbtool ethX filter <index> <delete|clear>

NOTE:For more information on additional parameters, refer to cxgbtool manual by 
     running the "man cxgbtool" command. 	 
	 
	 
2. Hash/DDR Filters
===================

If you wish to create large number of filters, select one of the below configuration 
tuning options during Unified Wire installation:

- High Capacity Hash Filter:  Allows you to create ~0.5 million filter rules. 
  Can run non-offload NIC traffic.
- Unified Wire (Default): Allows you to create ~18k filter rules. Can run all offload 
  traffic.

You can create both LE-TCAM and Hash/DDR filters in the above configurations. 

NOTE: Please refer User Guide for chosing the appropriate filterMode and 
      filterMask.


Creating Filter Rules
---------------------

Network driver (cxgb4) must be installed and loaded before setting the filter 
rule. 

a) If you haven’t done already, run the Unified Wire Installer with the 
   "High Capacity Hash Filter" or "Unified Wire" (Default) configuration tuning 
    option to install the drivers.
   
b) Load the network driver with DDR filters support and bring up the Chelsio
   interface:

   [root@host~]# modprobe cxgb4 use_ddr_filters=1
   [root@host~]# ifconfig ethX up

c) Now, create filter rules using cxgbtool:

   [root@host~]# cxgbtool ethX filter <index> action [pass/drop/switch] fip <source_ip> 
                 lip <destination_ip> fport <source_port> lport <destination_port> 
                 proto <protocol> <hitcnts 1> <cap maskless>

Where, 
ethX                 : Chelsio interface.
index                : Filter index. For LE-TCAM filters, filter index should be
                       0-495 for T5 adapters and 0-559 for T6 adapters. In case 
                       of Hash/DDR filter, the index will be ignored and 
                       replaced by an automatically computed value, based on the
                       hash (4-tuple). The index will be displayed after the 
                       filter rule is created successfully.
action               : Ingress packet disposition.
pass                 : Ingress packets will be passed through set ingress queues.
switch               : Ingress packets will be routed to an output port with. 
                       optional header rewrite. 
drop                 : Ingress packets will be dropped.
source_ip/port       : Source IP/port of incoming packet.
destination_ip/port  : Destination IP/port of incoming packet.
protocol             : TCP by default. To change, specify the corresponding 
                       internet protcol number. E.g. for UDP, use 17.
hitcnts 1             : To enable hit counts in cxgbtool filter show output.  
cap maskless         : This is mandatory for hash filter. If not provided, LE-TCAM 
                       filter will be created at the specified index. 
                       
NOTE: In case of Hash/DDR filters, source_ip, destination_ip, source_port and 
      destination_port are mandatory, since the filters don't support masks and 
      hence, 4-tuple must always be supplied. "Proto" is also a mandatory parameter. 

	 
Listing Filter Rules
--------------------

- To list the Hash/DDR filters set, run the following command:

   [root@host~]# cat /sys/kernel/debug/cxgb4/<bus-id>/hash_filters     

- To list both LE-TCAM and Hash/DDR filters set, run the following command:

   [root@host~]# cxgbtool ethX filter show

   
Removing Filter Rules
----------------------

To remove a filter, run the following command with cap maskless parameter and 
corresponding filter rule index:

   [root@host~]# cxgbtool ethX filter <index> <delete|clear> cap maskless

NOTE: Filter rule index can be determined by referring the "hash_filters" 
      file located in /sys/kernel/debug/cxgb4/<bus-id>/

NOTE: For more information on additional parameters, refer cxgbtool manual by
      running the man cxgbtool command.


Filter Priority
---------------

By default, Hash/DDR filter has priority over LE-TCAM filter. To override this, 
the LE-TCAM filter should be created with prio option. For example:

[root@host~]# cxgbtool ethx filter <index> action <pass/drop/switch> prio 1

Where index is a positive integer set as filter id. 0-495 for T5 adapters and 
0-63 for T6 adapters.


Swap MAC Feature
-----------------

Chelsio’s T6/T5 Swap MAC feature swaps packet source MAC and destination MAC 
addresses. This is applicable only for switch filter rules. Here’s an example:

   [root@host~]# cxgbtool eth2 filter 100 action switch lip 102.2.2.1 fip 102.2.2.2 
                 lport 5001 fport 14000 hitcnts 1 iport 1 eport 0 swapmac 1 proto 17 cap maskless
   Hash-Filter Index = 21936

The above example will swap source and destination MAC addresses of UDP packets 
(matching above 4 tuple) received on adapter port 1 and then switch them to 
port 0.


Traffic Mirroring
-----------------

Enabling Mirroring
------------------

To enable traffic mirroring, follow the steps mentioned below:

a) If not done already, install Unified Wire with the 
   "High Capacity Hash Filter" or "Unified Wire" (Default) configuration tuning 
    option as mentioned in the Unfied Wire section.

b) Enable vnic_id match for filterMode in Hash filter config file, 
   t5-config.txt, located in /lib/firmware/cxgb4/

   filterMode = fragmentation, mpshittype, protocol, vnic_id, port, fcoe 
   filterMask = port, protocol, vnic_id

c) Unload network driver (cxgb4) and reload it with mirroring enabled.

   [root@host~]# rmmod cxgb4
   [root@host~]# modprobe cxgb4 enable_mirror=1 use_ddr_filters=1

d) The traffic will now be mirrored and received via mirror PF/VF corresponding 
   to each port.    

 
Switch Filter with Mirroring
----------------------------

The following example explains the method to switch and mirror traffic 
simultaneously:  

a) Obtain the PF and VF values of the incoming port from 
   /sys/kernel/debug/cxgb4/<bus-id>/mps_tcam 

b) Create the desired switch filter rule:

   [root@host~]# cxgbtool ethX filter 0 fip 102.8.8.2 lip 102.8.8.1 fport 20000 lport 12865 
                 proto 6 pf 4 vf 64 action switch iport 0 eport 1 cap maskless

The hash filter rule switches TCP traffic matching the above 4-tuple received on 
port 0 to port 1. The traffic will be switched and simultaneously received on 
mirror queues and network stack of host as mirroring is enabled.


Filtered Traffic Mirroring
--------------------------

Once mirroring is enabled, all the traffic received on a physical port will be 
duplicated. The following example explains the method to filter out the 
redundant traffic and receive only specific traffic on mirror queues:

a) Obtain the mirror PF and VF values from dmesg

   [root@host~]# dmesg
   ....
   ...
   cxgb4 0000:02:00.4: Port 0 Traffic Mirror PF = 4; VF = 66
   cxgb4 0000:02:00.4: Port 1 Traffic Mirror PF = 4; VF = 67

b) Create a DROP-ALL rule as below:

   [root@host~]# cxgbtool ethX filter 255 pf 4 vf 66 action drop

Where, 255 is the last index of available TCAM filters. This will create a 
catch-all DROP filter for Mirror PF/VF of port 0. Similarly, create DROP filters
for rest of Mirror PF/VF.

c) Create specific filter rules to allow specific traffic to be received on 
   mirror queues as below:

   [root@host~]# cxgbtool ethX filter 1 lip 102.8.8.1 fip 102.8.8.2 lport 12865 fport 20000 pf 4 vf 66 action pass

Now, the above specific traffic (from 102.8.8.2,20000 to 102.8.8.1,12865) will 
be received in Mirror receive queues and network stack of host.


Packet Tracing and Hit Counters
-------------------------------

For T5/T6 LE-TCAM and T6 Hash/DDR filters, hit counters will work simply by 
adding hitcnts 1 parameter to the filter rule. However, for T5 Hash/DDR filters,
you will have to make use of tracing feature and RSS queues. Here’s a 
step-by-step guide to enable packet tracing and hit counters for Hash/DDR filter rules:

a) Load nerwork driver with the following parameters:

   [root@host~]# modprobe cxgb4 use_ddr_filters=1 enable_traceq=1

b) Configure the required filter rules.

c) Enable tracing on adapter.

   [root@host~]# cxgbtool ethX reg 0x09800=0x13

d) Setup a trace filter

   [root@host~]# echo tx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus_id>/trace0

Here, "snaplen" is the length in bytes to be captured.

NOTE: Use "snaplen=60" in case of IPv6.

The above step will trace all the packets transmitting from port1(tx1) to trace 
filter 0.
             
e) Configure the RSS Queue to receive traced packets. Determine the "RspQ ID" of 
   the queue by looking at "Trace" QType in 
   /sys/kernel/debug/cxgb4/<bus-id>/sge_qinfo file

   [root@host~]# cxgbtool ethX reg 0x0a00c=<Trace Queue0-RspQ ID>

Now the traced packets can be seen in tcpdump and the hit counters will also 
increment.


Multi-tracing
---------------

To enable packet capture or hit counters for multiple Chelsio ports in Tx/Rx 
direction enable Multi-tracing. Using this we can configure 4 different RSS 
Queues separately corresponding to 4 trace-filters.

a) Enable Tracing as well as MultiRSSFilter

   [root@host~]# cxgbtool ethX reg 0x09800=0x33

b) Setup a trace filter

   [root@host~]# echo tx0 snaplen=40 > /sys/kernel/debug/cxgb4/<bus_id>/trace0
   
c) Configure the RSS Queue corresponding to trace0 filter configured above.
   Determine the "RspQ ID" of the queues by looking at "Trace" QType in 
   /sys/kernel/debug/cxgb4/<bus-id>/sge_qinfo file.

   [root@host~]# cxgbtool ethX reg 0x09808=<Trace-Queue0-RspQ ID>

d) Similarly for other direction and for multiple ports run the follow commands:

   [root@host~]# echo rx0 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace1
   [root@host~]# echo tx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace2
   [root@host~]# echo rx1 snaplen=40 > /sys/kernel/debug/cxgb4/<bus-id>/trace3
   [root@host~]# cxgbtool ethX reg 0x09ff4=<Trace-Queue1-RspQ ID>
   [root@host~]# cxgbtool ethX reg 0x09ffc=<Trace-Queue2-RspQ ID>
   [root@host~]# cxgbtool ethX reg 0x0a004=<Trace-Queue3-RspQ ID>

NOTE: Use "snaplen=60" in case of IPv6.

NOTE: For more information on additional configuration options, please refer 
      User's Guide.


3. NAT Filtering
================

T5/T6 adapters support offloading of stateless/static NAT functionality i.e. 
translating source/destination L3 IP addresses, and  source/destination L4 port
numbers. This feature is supported with both LE-TCAM and Hash filters.

NOTE: This feature is only supported with filter action switch.

Syntax:

   [root@host~]# cxgbtool ethX filter <index> action switch fip <source_ip> lip <destination_ip> 
                 fport <source_port> lport <destination_port> nat <mode> nat_fip <new_source_ip> 
                 nat_lip <new_destination_ip> nat_fport <new_source_port> nat_lport <new_destination_port>

Where, 
ethX                   : Chelsio interface.
source_ip/port         : Source IP/port of incoming packet.
destination_ip/port    : Destination IP/port of incoming packet.
new_source_ip/port     : Source IP/port to be translated to. 
new_destination_ip/port: Destination IP/port to be translated to.
mode                   :Combination of IP/port to be translated. "all" will
                        translate all 4-tuple fields. To see other modes, refer
                        cxgbtool manual page.
                       
For more information and examples, refer User's Guide.



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
OVS Kernel Datapath Offload
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

The following dependencies must be installed: 
  
- GCC 4.6+
- Python 2.7+
- Python-six 
- Autoconf 2.63+
- Automake 1.10+
- libtool 2.4+

For the complete list please visit 
http://docs.openvswitch.org/en/latest/intro/install/general/


Driver Installation
===================

a) Change your current working directory to Chelsio Unified Wire package 
   directory:

   [root@host~]# cd ChelsioUwire-x.x.x.x

b) Install OVS modules and NIC driver:

   [root@host~]# make ovs_install

NOTE: For more installation options, please run "make help" or "install.py -h".

c) Reboot your machine for changes to take effect.


Configuration
=============

Configuring OVS Machine
-----------------------

The following example explains the method to configure an OVS machine:

                    ------------       
 --------          | OVS Switch |          --------
| HOST A | ------->| eth2  eth3 |<------- | HOST B |
 --------           ------------           --------

"eth2" and "eth3" are Chelsio interfaces.

a) Ensure that Unified Wire in installed with "High Capacity Hash Filter" 
   configuration tuning option.  

b) Update the "filterMode" and "filterMask" in the the hash config file in 
   /lib/firmware/cxgb4/. Select a Filter Mode combination with fragmentation, 
   ethertype, protocol and port from the supported list. Use "t6-config.txt" 
   for T6 adapters and "t5-config.txt" for T5 adapters:

filterMode = fragmentation, mpshittype, ethertype, protocol, tos, port, fcoe
filterMask = fragmentation, ethertype, protocol, port

NOTE: filterMask tuples can be subset of or equal to filterMode tuples. 

c) Load NIC (cxgb4) driver with hash-filter support:

   [root@host~]# modprobe cxgb4 use_ddr_filters=1

d) Bring up the Chelsio interfaces in promiscous mode:

   [root@host~]# ifconfig eth2 promisc up
   [root@host~]# ifconfig eth3 promisc up

e) Load Open vSwitch module:

   [root@host~]# modprobe openvswitch

f) Configure OVS

   [root@host~]# ovs-appctl exit
   [root@host~]# pkill -9 ovs
   [root@host~]# rm -rf /usr/local/etc/ovs-vswitchd.conf
   [root@host~]# rm -rf /usr/local/var/run/openvswitch/db.sock
   [root@host~]# rm -rf /usr/local/etc/openvswitch/conf.db
   [root@host~]# touch /usr/local/etc/ovs-vswitchd.conf
   [root@host~]# ovsdb-tool create /usr/local/etc/openvswitch/conf.db <uwire_package>/src/openvswitch-x.x.x/vswitchd/vswitch.ovsschema
   [root@host~]# ovsdb-server /usr/local/etc/openvswitch/conf.db --remote=punix:/usr/local/var/run/openvswitch/db.sock \ 
   --remote=db:Open_vSwitch,Open_vSwitch,manager_options --bootstrap-ca-cert=db:Open_vSwitch,SSL,ca_cert --pidfile --detach --log-file
   [root@host~]# ovs-vsctl --no-wait init
   [root@host~]# export DB_SOCK=/usr/local/var/run/openvswitch/db.sock
   [root@host~]# ovs-vswitchd --pidfile --detach

g) Create an OVS brige and add Chelsio interfaces to it:

   [root@host~]# ovs-vsctl add-br br0
   [root@host~]# sleep 2
   [root@host~]# ifconfig br0 up
   [root@host~]# ovs-vsctl add-port br0 eth2
   [root@host~]# sleep 5
   [root@host~]# ovs-vsctl add-port br0 eth3
   [root@host~]# sleep 5
   [root@host~]# ovs-vsctl show

 NOTE: Ports on OVS bridge must be added in the same order as the adapter, since
       there's no mapping between OVS and physical ports.

h) Now ping from Host A to Host B to verify that OVS is configured successfully.

i) Stop the ping traffic and delete all the flows on switch:

   [root@host~]# ovs-ofctl del-flows br0


Creating OVS flows
------------------

It is mandatory to specify L2 Ethernet Type (dl_type) to offload OVS flows. 
There are two types of flows:

- exact-match: Protocol and 4-tuple are mandatory to create an exact-match flow.
               ~0.5 million exact-match flows can be offloaded. 
- wild-card: If any of 4-tuple and protocol are absent, wild-card flow is 
             created. 496 wild-card flows can be offloaded. 

NOTE: 

- T5/T6 SO adapters do not support exact-match flows. You can create 494 
  wild-card flows on these adapters.

- To view OVS flow (and VXLAN flow) examples, refer User Guide.


Verifying OVS Flow Dump
----------------------

OVS flow dump can be verified using:

   [root@host~]# ovs-ofctl dump-flows br0

Run traffic between hosts which matches the flow and verify if the 'n_packet' 
counter is incrementing.

To check if the OVF Flows were offloaded, run the below command:

[root@host~]# cxgbtool ethX filter show

Wild-card flows will be shown as LE-TCAM Filters and Exact-match flows will be shown 
as Hash Filters. Hits and Hit-Bytes will increment for the corresponding filters. 


Setting up ODL with OVS
-----------------------

The following example explains the method to set up OpenDaylight(ODL) using OVS:

                  ------------
                  |     ODL    |
                  | Controller |
                   ------------
                         ^
                         |
                         |(private network)
                    ------------       
 --------          | OVS_Switch |          --------
| HOST A | ------->| eth2  eth3 |<------- | HOST B |
 --------           ------------           --------

On the ODL controller setup,

a) Download latest Java Development Kit.

b) Untar the tar file. 

c) Create an entry in .bashrc which points to the extracted folder:

   export JAVA_HOME=<path>/jdk1.8.0_92
   export PATH=$PATH:$JAVA_HOME

d) Logout & log back in.

e) Download ODL controller pre-built zip package. 
  
f) Unzip the package and change your working directory to "opendaylight"

g) Run the script "run.sh" and wait for ~3 minutes for the controller to be setup.

h) Open a web browser and enter the address http://localhost:8080
   
i)  Login with admin keyword for both username and password.
  
j) On the OVS machine, add the bridge to the controller and disable in-band:

   [root@host ~]# ovs-vsctl set-controller br0 tcp:<ODL Controller IP>:6633
   [root@host ~]# ovs-vsctl set bridge br0 other-config:disable-in-band=true

k) Refresh the webpage on the ODL controller and you should see the OVS details.

l) Goto "Flows" tab, add and install a flow.

m) Verify the flow dump on the OVS machine:

   [root@host ~]# ovs-ofctl dump-flows br0

Run traffic between hosts which matches the flow and verify if the "n_packet" 
counter is incrementing.


Driver Uninstallation
=====================

   [root@host~]# make ovs_uninstall



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Mesh Topology
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Mesh Connectivity
=================

Each node should be connected to other node. Supported configs using this 
approach: N ports per node, N+1 node cluster. 

NOTE: Please refer User Guide for further details.


Installation
============

Install Unified Wire on all the machines in the mesh topology: 

a) Change your current working directory to Chelsio Unified Wire package directory. 

   [root@host~]# cd ChelsioUwire-x.x.x.x	

b) Install the drivers, tools and libraries using the following command:

   [root@host~]# make install 

NOTE: For more installation options, please run make help or install.py -h

c) Reboot your machine for changes to take effect.


Configuration
=============

Configure all the machines in the mesh topology using the below steps.

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

   [root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb

a) Load network driver.

   [root@host~]# modprobe cxgb4

b) Configure interfaces with required IPs and networking as mentioned in 
   https://access.redhat.com/solutions/30564 article. 

You should be able to run traffic between the nodes. To run different protocol traffic, 
please refer their respective sections for protocol configuration.

NOTE: Please refer User Guide for detailed example. 



++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Traffic Management
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Driver Loading
==============

IMPORTANT:Please ensure that all inbox drivers are unloaded before proceeding 
          with unified wire drivers:

   [root@host~]# rmmod csiostor cxgb4i cxgbit iw_cxgb4 chcr cxgb4vf cxgb4 libcxgbi libcxgb
		  
Traffic Management can be performed on non-offloaded connections as well as on 
offloaded connections.

The drivers must be loaded by the root user. Any attempt to load the drivers as 
a regular user will fail.Run the following commands to load the TOE driver:

   [root@host~]# modprobe cxgb4
   [root@host~]# modprobe t4_tom
   
   
Usage
=====

Traffic Management Rules
------------------------

Traffic Management supports the following types of scheduler hierarchy levels 
which can be configured using the cxgbtool utility:

- Class Rate Limiting
- Class Weighted Round Robin
- Channel Rate Limiting

For more information, refer "Traffic Management" chapter in User Guide.


Traffic Management of Non-Offloaded Connections 
-----------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for Non-offload connections:

a) Load the network driver and bring up the interface

   [root@host~]# modprobe cxgb4
   [root@host~]# ifconfig eth0 up
  
b) Bind connections with destination IP address 192.168.5.3 to NIC TX queue 3 

   [root@host~]# tc qdisc add dev eth0 root handle 1: multiq
   [root@host~]# tc filter add dev eth0 parent 1: protocol ip prio 1 u32 
                 match ip dst 192.168.5.3 action skbedit queue_mapping 3

c) Bind the NIC TX queue to class 0 

   [root@host~]# cxgbtool eth0 sched-queue 3 0 

d) Set the appropriate rule for class 0 

   [root@host~]# cxgbtool eth0 sched-class params type packet level cl-rl 
                 mode class rate-unit bits rate-mode absolute channel 0 class 0 
                 max-rate 300000 pkt-size 1460

IMPORTANT: Flow mode is not supported for Non-Offloaded Connections.


Traffic Management of Offloaded Connections 
-------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for offloaded connections:

a) Load the TOE driver and bring up the interface:

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig eth0 up

b) Create a new policy file (say new_policy_file) and add the following line to 
   associate connections with the given scheduling class:

   src host 102.1.1.1 => offload class 0

NOTE: If no specified rule matches a connection, a default setting will be used 
      which disables offload for that connection.  That is, there will always be
      a final implicit rule following all the rules in the input rule set of:

     all => !offload

c) Compile the policy file using COP. 

   [root@host~]# cop -d -o <output_policy_file> <new_policy_file> 

d) Apply the COP policy. 

   [root@host~]# cxgbtool eth0 policy <output_policy_file>

   NOTE: The policy applied using cxgbtool is not persistent and should be applied 
         everytime drivers are reloaded or the machine is rebooted.

   The applied cop policies can be read using, 

   [root@host~]# cat /proc/net/offload/toeX/read-cop
   
e) Set the appropriate rule for class 0 

   [root@host~]# cxgbtool ethX sched-class params type packet level cl-rl mode class 
                 rate-unit bits rate-mode absolute channel 0 class 0 max-rate 300000 pkt-size 1460

   
Traffic Management of Offloaded Connections with Modified Application
---------------------------------------------------------------------

The following example demonstrates the method to rate limit all TCP connections 
on class 0 to a rate of 300 Mbps for for offloaded connections with modified 
application.

a) Load the TOE driver and bring up the interface

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig eth0 up

b) Modify the application as mentioned in the Configuring Traffic Management 
   section in the User's Guide.
   
c) Set the appropriate rule for class 0 

   [root@host~]# cxgbtool ethX sched-class params type packet level cl-rl mode class 
                 rate-unit bits rate-mode absolute channel 0 class 0 max-rate 300000 pkt-size 1460 

NOTE: For more information on additional parameters, refer cxgbtool manual by 
      running the "man cxgbtool" command. 

NOTE: For more information on additional configuration options, please refer 
      User's Guide.


Traffic Management of Inline TLS Offload Connections 
----------------------------------------------------

Please refer Inline TLS Offload chapter to go through configuration steps. To 
rate limit Inline TLS Offload connections, follow the steps mentioned below:

a) Load the TOE driver and bring up the interface

   [root@host~]# modprobe t4_tom
   [root@host~]# ifconfig eth0 up

b) Create a new policy file and add the following line for TCP port (to be TLS 
   offloaded), 443 in this case. Bind the connections to class 0.

   src or dst port 443 => offload tls mss 32 bind random class 0  
   all => offload

   The all  => offload is added to ensure that rest of the TCP ports will be 
   regular TOE offloaded.
 
c) Compile the policy file using COP. 

   [root@host~]# cop -d –o <output_policy_file> <new_policy_file> 

d) Apply the COP policy. 
 
   [root@host~]# cxgbtool ethX policy <output_policy_file>

   NOTE: The policy applied using cxgbtool is not persistent and should be applied 
         everytime drivers are reloaded or the machine is rebooted.

   The applied cop policies can be read using, 

   [root@host~]# cat /proc/net/offload/toeX/read-cop
   
e) Set the appropriate rule for class 0 with the required rate and burst size 16384. 

   [root@host~]# cxgbtool ethX sched-class params type packet level cl-rl mode flow 
                 rate-unit bits rate-mode absolute channel 0 class 0 max-rate 5000 
                 pkt-size 1460 burst-size 16384

   This rule will rate limit all Inline TLS connections on class 0 to 5 Mbps per 
   connection. 


Driver Unloading
================

Reboot the system to unload the driver. To unload without rebooting, refer 
"Unloading the driver" in Network (NIC/TOE) section.
	  


++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Unified Boot Software
++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Pre-requisites
==============

A DOS bootable USB flash drive or Floppy Disk is required for updating firmware,
option ROM etc.


Secure Boot
===========

The following example describes the method to enable Secure Boot on HP ProLiant 
servers. Steps may differ slightly on other platforms:  

a) During system boot, press F9 to run the System Utilities. 
b) Select System Configuration. 
c) Select BIOS/Platform Configuration (RBSU). 
d) Select Server Security. 
e) Select Secure Boot Settings. 
f) Select Advanced Secure Boot Options.
g) Provide the Platform Key (PK), Key Exchange Key (KEK) and Allowed Signature 
   Database (DB) to the respective uEFI NVRAM variables.

- Windows: 

 - PK: Will be generated at the discretion of the platform owner (OEM). For more
       information, visit https://docs.microsoft.com/en-us/windows-hardware/manufacture/desktop/windows-secure-boot-key-creation-and-management-guidance
 - KEK: http://www.microsoft.com/pkiops/certs/MicCorKEKCA2011_2011-06-24.crt  
 - Windows DB: http://www.microsoft.com/pkiops/certs/MicWinProPCA2011_2011-10-19.crt  
 - uEFI DB: http://www.microsoft.com/pkiops/certs/MicCorUEFCA2011_2011-06-27.crt 
 - Signature GUID for all the above keys: 77fa9abd-0359-4d32-bd60-28f4e78f784b

- Linux:

 - Use the same values for PK, KEK, Windows DB, uEFI DB and Signature ID as mentioned above. 
 - In addition, provide the following values:
   - chcert.cer: Provided in ChelsioUwire-x.x.x.x/Uboot/chelsio_key/
   - Signature GUID for chcert.cer: 0b74ace7-6136-a493-19a9-6104d6d1e432

h) Reboot the system, run System Utilities and go to Secure Boot Settings.
i) Select and enable Secure Boot Enforcement.
j) Reboot the system.


Flashing Firmware & Option ROM
==============================

Depending on the boot mode selected, Chelsio Unified Boot provides the
following methods to flash Firmware and Option ROM onto Chelsio adapters:

Legacy mode: 
- cfut4 

uEFI mode: 
- HII
- drvcfg
- Firmware Manager Protocol (FMP) 

OS Level: 
- cxgbtool  

These methods also provide the functionality to update/erase Hardware 
configuration and Phy Firmware files. 

IMPORTANT: It is highly recommended to use the same Option ROM (type and 
           version) on all the Chelsio adapters present in the system. 


Preparing USB flash drive
-------------------------

This document assumes that you are using an USB flash drive as a storage 
media for the necessary files. Follow the steps below to prepare the drive:

a) Create a DOS bootable USB flash drive.
b) Create a directory "CHELSIO" on USB flash drive.
c) If you haven't done already, download Chelsio Unified Wire driver package 
   from Chelsio Download Center, service.chelsio.com
d) Untar the downloaded package and change your working directory to "OptionROM"
   directory. 
	  
   [root@host~]# tar zxvf ChelsioUwire-x.x.x.x.tar.gz 	  
   [root@host~]# cd ChelsioUwire-x.x.x.x/Uboot/OptionROM
   
e) Copy all the files and place them in the CHELSIO directory created on the 
   USB flash drive.
f) Plug-in the USB flash drive in the system on which the Chelsio CNA is 
    installed.
g) Reboot the system.

   
Legacy 
------

a) Configure the system having Chelsio adapter to boot in Legacy mode. 

b) Once the system boots from the USB flash drive, change your working directory
   to CHELSIO directory.

   C:\>cd CHELSIO

c) Run the following command to list all Chelsio adapters present in the 
   system. The list displays a unique index for each adapter found.

   C:\CHELSIO>cfut4 -l

d) Delete any previous version of Option ROM flashed onto the adapter.

   C:\CHELSIO>cfut4 -d <idx> -xb 
   
Here, idx is the adapter index found in step (c) 

e) Delete any previous firmware using the following command.

   C:\CHELSIO>cfut4 -d <idx> -xh -xf 
  
f) Delete any previous Option ROM settings.

   C:\CHELSIO>cfut4 -d <idx> -xc

g) Run the following command to flash the appropriate firmware. 

   C:\CHELSIO>cfut4 -d <idx> -uf <firmware_file>.bin
   
h) Flash the Option ROM onto the Chelsio adapter using the following command.

   C:\CHELSIO>cfut4 -d <idx> -ub cubt4.bin  

Here, "cubt4.bin" is the Unified option ROM image file present in the CHELSIO 
directory.   

i) In case of multiple adapters, please repeat steps d) to h) to update/flash 
   the firmware and Option ROM on all of them.
 
j) Reboot the system for changes to take effect.

k) To configure the base MAC address (optional), use the below command:

   C:\CHELSIO>cfut4 -d <idx> -um <Hex MAC Address>

For example, 

   C:\CHELSIO>cfut4 -d 0 -um 000743000123


uEFI
-----

To configure Chelsio adapter using HII in uEFI mode, please refer User's Guide.


cxgbtool (OS Level)
-------------------

Follow the steps mentioned below to flash the Option ROM onto Chelsio adapters 
using cxgbtool utility: 

a) If not done already, install the Network driver and cxgbtool.

   [root@host~]# cd ChelsioUwire-x.x.x.x
   [root@host~]# make install

b) Load the Network driver.

   [root@host~]# modprobe cxgb4

c) Delete any previous version of Option ROM flashed onto the adapter.

   [root@host~]# cxgbtool ethX loadboot clear

d) Flash the Option ROM onto the Chelsio adapter.

   [root@host~]# cd ChelsioUwire-x.x.x.x/Uboot/OptionROM/
   [root@host~]# cxgbtool ethX loadboot cubt4.bin

e) Flash the default boot configuration onto the adapter.
 
   [root@host~]# cd ChelsioUwire-x.x.x.x/Uboot/OptionROM/
   [root@host~]# cxgbtool ethX loadboot-cfg bootcfg

f) In case of multiple adapters in the system, please repeat the steps from 
   c) to e) to update/flash the Option ROM on all the adapters.

g) Reboot the system for changes to take effect.


Update Option ROM Settings
==========================

Default Settings
----------------

If you wish to restore Option ROM settings to their default values, i.e., 
PXE enabled, iSCSI and FCoE disabled, use any of the methods mentioned below:

- Using Option ROM (boot level)

For Legacy PXE, boot system into Chelsio’s Unified Boot Setup utility and press F8.

For uEFI PXE, boot system into uEFI mode and press F3.
 
- Using cxgbtool (OS level)

Change your working directory to OptionROM directory and use cxgbtool to flash 
the default boot configuration onto the adapter:

   [root@host~]# cd ChelsioUwire-x.x.x.x/Uboot/OptionROM/
   [root@host~]# cxgbtool <ethX> loadboot-cfg bootcfg

The below command can be used to read the current settings. 

   [root@host~]# cxgbtool <ethX> readboot-cfg


Custom Settings (using cxgbtool)
--------------------------------

Use the below command to enable/disable PXE/FCoE/iSCSI boot for all the ports of 
the adapter.

  [root@host~]# cxgbtool <ethX> modifyboot-cfg bios <value>

Where, 
ethX   : Chelsio interface.
value  : Bitwise OR of boot types that need to be enabled. Ranging from 0x0 – 0x7.  
         PXE (NIC) = 0x1
         FCoE = 0x2
         iSCSI = 0x4

Use the below command to enable/disable PXE (NIC) boot per port.

  [root@host~]# cxgbtool <ethX> modifyboot-cfg port <port no.> <param>

Where, 
ethX     : Chelsio interface.
port no. : Port number ranging from 0 – 3.
param  	 : en_nicboot to enable and dis_nicboot to disable NIC boot for the port. 

Use the below command to set the VLAN id for the port. 

  [root@host~]# cxgbtool <ethX> modifyboot-cfg port <port no.> vlan <id>

Where, 
ethX     : Chelsio interface.
port no. : Port number ranging from 0 – 3.
id  	 : VLAN id ranging from 0 – 4095. 



4. Support Documentation
================================================================================

The documentation for this release can be found inside the 
ChelsioUwire-x.x.x.x/docs folder. 
It contains:

- README
- Release Notes
- User's Guide



6. Customer Support
================================================================================

Installer issues
----------------

In case of any failures while running the Chelsio Unified Wire Installer, please 
collect the below:
- install.log fille, if installed using install.py
- Entire make command output, if installed using the makefile

Logs collection
---------------

In case of any other issues, please run the below command to collect all the 
necessary log files:

[root@host~]# chdebug

A compressed tar ball, chelsio_debug_logs_with_cudbg.tar.bz2 will be created 
with all the logs. 

In case of kernel panics, following files need to be provided for analysis.

vmcore, vmcore-dmesg.txt, vmlinux, System.map-$(uname  -r), Chelsio modules .ko files
 

Please contact Chelsio support at support@chelsio.com with relevant logs for any 
issues.








********************************************************************************
Copyright (C) 2021 Chelsio Communications. All Rights Reserved.

The information in this document is furnished for informational use only, is
subject to change without notice, and should not be construed as a commitment by
Chelsio Communications. Chelsio Communications assumes no responsibility or
liability for any errors or inaccuracies that may appear in this document or any
software that may be provided in association with this document. Except as
permitted by such license, no part of this document may be reproduced, stored in
a retrieval system, or transmitted in any form or by any means without the
express written consent of Chelsio Communications.