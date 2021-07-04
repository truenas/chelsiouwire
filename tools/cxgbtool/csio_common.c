#include <csio_hw.h>
#include <csio_common_ioctl.h>
#include <csio_common.h>

void convert_decimal_ip(char ip[], uint32_t ipaddr)
{
	sprintf(ip,"%d.%d.%d.%d", 
	(ipaddr>>24)&0xFF, 
	(ipaddr>>16)&0xFF, 
	(ipaddr>>8)&0xFF, 
	ipaddr&0xFF);
}

adap_handle_t open_adapter_handle(char *dev)
{
	if (!dev)
		return -1;

	return open_adapter_str(dev);
}

void shift_argv(int *argc, char *argv[], int pos)
{
	int i;

	for (i = 1 ; i <= *argc; i++)
		argv[i - 1] = argv[i];

	(*argc)--;
}


char*           
str_to_ipport(char *str, int *port, int *tpgt)
{                       
	char *stpgt, *sport = str, *ip = str;

	if (!strchr(ip, '.')) {
		if (*ip == '[') {
			if (!(sport = strchr(ip, ']')))
				return NULL;
			*sport++ = '\0';
			ip++;
			str = sport;
		} else
			sport = NULL;
	}               

	if (sport && (sport = strchr(str, ':'))) {
		*sport++ = '\0';        
		*port = strtoul(sport, NULL, 10);
		str = sport;
	}                       

	if ((stpgt = strchr(str, ','))) {
		*stpgt++ = '\0';
		*tpgt = strtoul(stpgt, NULL, 10);
	} else          
		*tpgt = -1;

	csio_app_log_devel_debug("ip %s, port %d, tgpt %d\n", ip, *port, *tpgt);
	return ip;      
}

int str_to_mode(const char *str)
{
	int mode;

	if (!strcmp("iface", str))
		mode = CSIO_APP_MOD_CHNET_IFACE;
	else if (!strcmp("ifconf", str))
		mode = CSIO_APP_MOD_CHNET_IFCONF;
	
	else if (!strcmp("init-instance", str))
		mode = CSIO_APP_MOD_FOISCSI_INIT_INST;
	else if (!strcmp("session", str))
		mode = CSIO_APP_MOD_FOISCSI_SSN;
	else if (!strcmp("discovery", str))
		mode = CSIO_APP_MOD_FOISCSI_DSC;
	else if (!strcmp("persistent", str))
		mode = CSIO_APP_MOD_FOISCSI_PRST;

	else if (!strcmp("tgt-instance", str))
		mode = CSIO_APP_MOD_COISCSI_TGT_INST;
	else if (!strcmp("target", str))
		mode = CSIO_APP_MOD_COISCSI_TGT;
	else if (!strcmp("server", str))
		mode = CSIO_APP_MOD_ISNS_SERVER;
	else if (!strcmp("client", str))
		mode = CSIO_APP_MOD_ISNS_CLIENT;
	
	else if (!strcmp("hw", str))
		mode = CSIO_APP_MOD_HW;
	else
		mode = CSIO_APP_MOD_NON;

	return mode;
}

int str_to_op(const char *str)
{
	int op;

	if (!strcmp("assign", str))
		op = CSIO_APP_OP_ASSIGN;
	else if (!strcmp("clear", str))
		op = CSIO_APP_OP_CLEAR;
	else if (!strcmp("show", str))
		op = CSIO_APP_OP_SHOW;
	else if (!strcmp("login", str))
		op = CSIO_APP_OP_LOGIN;
	else if (!strcmp("logout", str))
		op = CSIO_APP_OP_LOGOUT;
	else if (!strcmp("up", str))
		op = CSIO_APP_OP_UP;
	else if (!strcmp("down", str))
		op = CSIO_APP_OP_DOWN;
	else if (!strcmp("vlan", str))
		op = CSIO_APP_OP_VLAN;
	else if (!strcmp("mtu", str))
		op = CSIO_APP_OP_MTU;
	else if (!strcmp("dcbx", str))
		op = CSIO_APP_OP_DCBX;
	else if (!strcmp("update", str))
		op = CSIO_APP_OP_MOD;
	else if (!strcmp("stats", str))
		op = CSIO_APP_OP_STATS;
	else if (!strcmp("statsclr", str))
		op = CSIO_APP_OP_STATS_CLR;
	else if (!strcmp("ping", str))
		op = CSIO_APP_OP_PING;
	else if (!strcmp("pmtu_clear", str))
		op = CSIO_APP_OP_PMTU6_CLEAR;
	else
		op = CSIO_APP_OP_NOOP;

	return op;
}

static const char *const csio_err_msgs[CSIO_ELAST + 1] = {
	"Invalid index",
	"Instance already exists",
	"Exceeded Max Instances supported",
	"Insufficient resources",
	"Invalid instance name",
	"Invalid operation",
	"Instance not found",
	"Cannot continue: one or more active sessions exist",
	"Zero objects to display",
	"Inteface not provisioned",
	"No memory",
	"Session already exists",
	"Parameters mismatch",
	"Invalid Request",
	"Login Timedout",
	"Invalid port",
	"Interface busy",
	"No such device",
	"Interface LINK down",
	"Invalid parameter",
	"Function not implemented",
	"Port listen failed",
	"Storage driver init failed",
	"Address conflict detected, resetting existing IP Address",
	"Address cannot be assigned",
	"Cannot read config file",
	"ISNS command failed",
	"Please try again",
	"Invalid initiator instance",
	"Initiator instance not initialized",
	"No error message found",
};


const char *csio_err_to_msg(enum csio_app_err err)
{
	return ((err > CSIO_ELAST) ? csio_err_msgs[CSIO_ELAST] :
		csio_err_msgs[err]);
}
