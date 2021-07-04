/*
 * This file is part of the Chelsio OptionROM management interface.
 *
 * Copyright (C) 2003-2013 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 */
#ifndef __CONFIG_HDR_H__
#define __CONFIG_HDR_H__

#include <stdint.h>

#define MAXIMUM_T4PORTS               4
#define MAXIMUM_NIC_FUNCTIONS         4
#define MAXIMUM_PXE_BOOT_ENTRIES      8
#define MAXIMUM_FCOE_BOOT_ENTRIES     4
#define MAXIMUM_ISCSI_BOOT_ENTRIES    1
#define BIOS_DISABLED                 0
#define BIOS_ENABLED                  1
#define MAX_TARGET_PORTAL                 2
#define MAX_ISCSI_BOOT_TARGETS            1

#define ISCSI_INITIATOR_NAME_LENGTH   224
#define ISCSI_CHAP_USER_NAME_LENGTH   224
#define ISCSI_CHAP_SECRET_NAME_LENGTH 128   /* between 12 and 32 */

#define PLATFORM_BOTH                 0
#define PLATFORM_LEGACY               1
#define PLATFORM_UEFI                 2

typedef uint8_t       UINT8;
typedef uint16_t      UINT16;

typedef union
{
    uint8_t  Addr8[4];
    uint32_t Addr32;
}bIPv4_ADDRESS;


typedef union
{
        uint8_t      Addr8[16];
        uint16_t     Addr16[8];
}bIPv6_ADDRESS;

typedef struct
{
        uint8_t      UserName[ISCSI_CHAP_USER_NAME_LENGTH];
        uint8_t      Secret[ISCSI_CHAP_SECRET_NAME_LENGTH];
}bsChapInfo;


#pragma pack(1)
typedef struct s_ConfigiSCSIHeader {
        uint8_t      Port[MAXIMUM_T4PORTS];

        uint16_t     DefaultTime2Wait;
        uint16_t     DefaultTime2Retain;

        uint16_t     FirstBurstLength;
        uint16_t     MaxBurstLength;

        uint16_t     MaxOutstandingR2T;
        uint16_t     MaxRecvSegmentLen;

        uint16_t     tgtPortNo;
        uint8_t      Bios;
        uint8_t      PciFunction;                    /* 0x02 - default function */

        uint8_t      ChapMethod;
        uint8_t      DiscoverTimeout;
        uint8_t      InitialR2T;
        uint8_t      ImmediateData;

        uint8_t      OSInitiator;      /* 1 = Chelsio 0 = Others */
        uint8_t      HeaderDigest;
        uint8_t      DataDigest;
        uint8_t      ChapType;
        uint8_t      tgtdhcp;
        uint8_t      tgtv6;
        uint8_t      rsvd0;
        uint8_t      rsvd1;

        bIPv4_ADDRESS   IPv4[MAXIMUM_T4PORTS];
        bIPv4_ADDRESS   NetMaskv4[MAXIMUM_T4PORTS];     /* sub net mask */
        bIPv4_ADDRESS   Gatewayv4[MAXIMUM_T4PORTS];     /* GateWay Addr */

        uint16_t       vLan[MAXIMUM_T4PORTS];
        uint8_t        dhcp[MAXIMUM_T4PORTS];
        uint8_t        v6[MAXIMUM_T4PORTS];
        bIPv4_ADDRESS  tgtIPv4;
        uint8_t        rsvd2[MAXIMUM_T4PORTS];

        uint8_t      BootLun[8];
        uint8_t      InitiatorName[ISCSI_INITIATOR_NAME_LENGTH];
        uint8_t      TargetName[ISCSI_INITIATOR_NAME_LENGTH];

        bsChapInfo      ChapInfo[2];
        bIPv6_ADDRESS   tgtIPv6;
        bIPv6_ADDRESS   IPv6[MAXIMUM_T4PORTS];
        bIPv6_ADDRESS   LLv6[MAXIMUM_T4PORTS];
        bIPv6_ADDRESS   Gatewayv6[MAXIMUM_T4PORTS];
		UINT8	PrefixLen[MAXIMUM_T4PORTS];
} t_ConfigiSCSIHeader;
#pragma pack()

typedef struct s_ConfigFCoEHeader {
        uint8_t        DiscoverTimeout;
        uint8_t        Bios;
        uint8_t        PciFunction;        // 0x01 - default function
        uint8_t        BootEntryValidFlag;
        uint8_t        Port[MAXIMUM_T4PORTS];

        uint8_t        wwpn[8][8];
        uint8_t        lun[8][8];
} t_ConfigFCoEHeader;

typedef struct s_ConfigNICHeader {
        uint8_t      Bios[MAXIMUM_NIC_FUNCTIONS];
        uint8_t      rsvdPort[MAXIMUM_NIC_FUNCTIONS][MAXIMUM_T4PORTS];
        uint8_t      rsvdIpv6[MAXIMUM_NIC_FUNCTIONS];
        uint8_t      rsvdVlan[MAXIMUM_NIC_FUNCTIONS];
        uint8_t      rsvdVlanPriority[MAXIMUM_NIC_FUNCTIONS];
        uint16_t     VlanId[MAXIMUM_NIC_FUNCTIONS];
} t_ConfigNICHeader;


typedef struct s_ConfigHeader {
        uint8_t      Signature[4];           /* signature = "CBIO" */
        uint16_t     StructSize;             /* size of this struct */
        uint8_t      Rsvd;
        uint8_t      EDD;

        uint8_t      Mode;
        uint8_t      EBDA;
        uint8_t      Bios;
        uint8_t      InitPlatform;
        uint8_t      VerMaj;             /* Unified config version Major */
        uint8_t      VerMin;             /* Unified config version Minor */
        uint8_t      VerMic;             /* Unified config version Micro */
        uint8_t      VerBld;             /* Unified config version Build */

        t_ConfigNICHeader     NIC;     /* 40 Bytes in size */
        t_ConfigFCoEHeader    FCoE;    /* 136 Bytes in size */
        t_ConfigiSCSIHeader   iSCSI;   /* 1472 Bytes in size */
} t_ConfigHeader;

struct ch_oprom {
        uint32_t cmd;
	uint32_t len;
        t_ConfigHeader cfg_data;
};

#define CONFIG_HEADER_SIG               "CBIO"

#endif /* __CONFIG_HDR_H__ */
