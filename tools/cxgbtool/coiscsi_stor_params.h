/*
 *  Copyright (C) 2019-2021 Chelsio Communications.  All rights reserved.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the LICENSE file included in this
 * release for licensing terms and conditions.
 *
 * Description: Data structures to define default, min and max COiSCSI target
 * configs
 *
 */
#ifndef _COISCSI_STOR_PARAMS_H_
#define _COISCSI_STOR_PARAMS_H_

enum v_pars {
	V_TDSIO,	/* DataSequenceInOrder  */
	V_TDPIO,	/* DataPDUInOrder       */
	V_TMAXCONN,	/* MaxConnections       */
	V_TINITR2T,	/* InitialR2T           */
	V_TMAXR2T,	/* MaxOutstandingR2T    */
	V_TFSTBL,	/* FirstBurstLength     */
	V_TMAXBL,	/* MaxBurstLength       */
	V_TMAXRDSL,	/* MaxRecvDataSegmentLength             */
	V_TIDATA,	/* ImmediateData        */
	V_TT2W,		/* DefaultTime2Wait     */
	V_TT2R,		/* DefaultTime2Retain   */
	V_TPINGTMO,	/* PingTimeout          */
	V_THDGST,	/* HeaderDigest         */
	V_TDGGST,	/* DataDigest           */
	V_TAUTHPOL,	/* AuthPolicy           */
	V_TAUTHM,	/* AuthMethod           */
	V_TD_AUTHPOL,	/* DiscAuthPolicy	*/
	V_TD_AUTHM,	/* DiscAuthMethod	*/
	V_TUSER,	/* UserName		*/
	V_TSEC,		/* Password		*/
	V_TIUSER,	/* UserNameIN		*/
	V_TISEC,	/* PasswordIN		*/
	V_TD_USER,	/* DiscUserName		*/
	V_TD_SEC,	/* DiscPassword		*/
	V_TD_IUSER,	/* DiscUserNameIN	*/
	V_TD_ISEC,	/* DiscPasswordIN	*/
	V_TTDISK,	/* TargetDisk		*/
	V_TTNAME,	/* TargetName		*/
	V_TTALIAS,	/* TargetAlias		*/
	V_TTADDR,	/* ListenAddr		*/
	V_ACLEN,	/* ACL_Enable		*/
	V_ACL,		/* ACL			*/
	V_SHADOW,	/* ShadowMode		*/
	V_TSNSADDR,     /* SnsAddr              */
	V_TSNSLSTN,	/* SnsLstn		*/

	V_TPARAM_MAX,
};

enum {
        cval_def,
        cval_min,
        cval_max,
        cval_type,
	cval_name,
};

enum {
	t_bool,
	t_val,
	t_str,
};

struct params {
	int	dflt;
	int	min;
	int	max;
	int	type;
	char	*name;
};

#ifndef FW_FOISCSI_NAME_MAX_LEN
#define FW_FOISCSI_NAME_MAX_LEN 224
#endif

#define N_MAXLEN	FW_FOISCSI_NAME_MAX_LEN
#define N_MINSEC	12
#define N_MAXSEC	16
#define N_ADDLEN	64

enum { NO, YES };

static struct params coiscsi_param_set[V_TPARAM_MAX] = {
/*        default,      min,    	max,            type 	name*/
	{ YES,          NO,     	YES,            t_bool,	"DataSequenceInOrder" },
	{ YES,          NO,     	YES,            t_bool,	"DataPDUInOrder" },
	{ 1,            1,      	65535,          t_val,	"MaxConnections" },
	{ YES,          NO,     	YES,            t_bool,	"InitialR2T" },
	{ 1,            1,      	65535,          t_val,	"MaxOutstandingR2T" },
	{ 65536,	512,    	16777215,       t_val,	"FirstBurstLength" },
	{ 262144,	512,    	262144,      	t_val,	"MaxBurstLength" },
	{ 8192,		512,    	16777215,    	t_val,	"MaxRecvDataSegmentLength" },
	{ YES,          NO,     	YES,            t_bool,	"ImmediateData" },
	{ 20,           0,      	3600,           t_val,	"DefaultTime2Wait" },
	{ 20,           0,      	3600,           t_val,	"DefaultTime2Retain" },
	{ 10,           0,      	300,            t_val,	"PingTimeout" },
	{ 0,            0,      	0,              t_str,	"HeaderDigest" },
	{ 0,            0,      	0,              t_str,	"DataDigest" },
	{ 0,            0,      	0,              t_str,	"AuthPolicy" },
	{ 0,            0,      	0,              t_str,	"AuthMethod" },
	{ 0,		0,		0,		t_str,	"DiscAuthPolicy" },
	{ 0,		0,		0,		t_str,	"DiscAuthMethod" },
	{ 0,		1,		N_MAXLEN,	t_str,	"UserName" },
	{ 0,		N_MINSEC,	N_MAXSEC,	t_str,	"Password" },
	{ 0,		1,		N_MAXLEN,	t_str,	"UserNameIN" },
	{ 0,		N_MINSEC,	N_MAXSEC,	t_str,	"PasswordIN" },
	{ 0,           	1,      	N_MAXLEN,      	t_str, 	"DiscUserName" },
	{ 0,           	N_MINSEC,      	N_MAXSEC,      	t_str, 	"DiscPassword" },
	{ 0,           	1,      	N_MAXLEN,     	t_str, 	"DiscUserNameIN" },
	{ 0,           	N_MINSEC,      	N_MAXSEC,      	t_str, 	"DiscPasswordIN" },
	{ 0,         	0,   		N_MAXLEN,	t_str,	"TargetDisk" },
	{ 0,		0,		N_MAXLEN,	t_str,	"TargetName:" },
	{ 0,		0,		N_MAXLEN,	t_str,	"TargetAlias" },
	{ 0,		0,		N_ADDLEN,	t_str,	"ListenAddr" },
	{ 0,		0,		0,		t_bool,	"ACL_Enable" },
	{ 0,		0,		0,		t_str,	"ACL" },
	{ NO,		NO,		YES,		t_bool, "ShadowMode" },
	{ 0,		0,		N_ADDLEN,	t_str,	"SnsAddr" },
	{ 0,		0,		N_ADDLEN,	t_str,	"SnsLstn" },
};

#endif
