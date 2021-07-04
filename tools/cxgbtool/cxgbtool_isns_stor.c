#include <csio_hw.h>
#include <csio_common.h>
#include <csio_foiscsi.h>
#include <cxgbtool_foiscsi_stor.h>
#include <csio_services.h>
#include <csio_isns_ioctl.h>
#include <csio_coiscsi_ioctl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <cxgbtool_isns_stor.h>
#include <coiscsi_stor_params.h>

static const char *isns_name = "cxgbtool stor --isns ";
static const char *isns_base_opt = "--isns";

static struct option const long_options[] = 
{
	{"mode", required_argument, NULL, 'm'},
	{"dev", required_argument, NULL, 'd'},
	{"op", required_argument, NULL, 'o'},
	{"addr", required_argument, NULL, 'a'},
	{"port", required_argument, NULL, 'p'},
	{"type", required_argument, NULL, 't'},
	{"ifid", required_argument, NULL, 'i'},
	{"vlanid", required_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "hm:d:o:a:p:t:i:v:";

static int str_to_isns_type(char *str)
{
	int type;

	if (!strcasecmp("ipv4", str))
		type = CSIO_ISNS_L3CFG_TYPE_IPV4;
	else if (!strcasecmp("ipv6", str))
		type = CSIO_ISNS_L3CFG_TYPE_IPV6;
	else
		type = CSIO_ISNS_L3CFG_TYPE_NONE;

	return type;
}

static void usage(int status)
{

	if (status)
		fprintf(stderr, "Try cxgbtool stor --isns --help for more information\n");
	else {
		printf("Usage: cxgbtool stor --isns [OPTION]\n");
		printf("\
\n\
CLIENT MODE COMMANDS\n\
--------------------\n\
\n\
cxgbtool stor --isns --mode client --dev device --op assign [--addr xxx.xxx.xxx.xxx] [--port 0..65535] --type IPV4 --ifid 0...n [--vlanid 0..n]\n\
cxgbtool stor --isns --mode client --dev device --op assign [--addr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx] [--port 0..65535] --type IPV6 --ifid 0...n [--vlanid 0..n]\n\
cxgbtool stor --isns --mode client --dev device --op clear [--addr xxx.xxx.xxx.xxx] [--port 0..65535] --type IPV4 --ifid 0...n [--vlanid 0..n]\n\
cxgbtool stor --isns --mode client --dev device --op clear [--addr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx] [--port 0..65535] --type IPV6 --ifid 0...n [--vlanid 0..n]\n\
cxgbtool stor --isns --mode client --dev device --op show [--type IPV4] [--ifid 0..n]\n\
cxgbtool stor --isns --mode client --dev device --op show [--type IPV6] [--ifid 0..n]\n\
\n\
Note:\n\
If 'addr' and 'port' are not provided in CLI, it can be provided in config file /etc/csio_iscsi_tgt_param.conf as below\n\
SnsAddr         <IPV4/IPV6 address>:[port num]\n\
\n\
If port number specified, enclose IPV6 address in []\n\
\n\
\n\
LISTENING SERVER MODE COMMANDS\n\
------------------------------\n\
\n\
cxgbtool stor --isns --mode server --dev device --op assign [--addr xxx.xxx.xxx.xxx] [--port 0..65535] --type IPV4 --ifid 0...n\n\
cxgbtool stor --isns --mode server --dev device --op assign [--addr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx] [--port 0..65535] --type IPV6 --ifid 0...n\n\
cxgbtool stor --isns --mode server --dev device --op clear [--addr xxx.xxx.xxx.xxx] [--port 0..65535] --type IPV4 --ifid 0...n\n\
cxgbtool stor --isns --mode server --dev device --op clear [--addr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx] [--port 0..65535] --type IPV6 --ifid 0...n\n\
cxgbtool stor --isns --mode server --dev device --op show [--type IPV4] [--ifid 0..n]\n\
cxgbtool stor --isns --mode server --dev device --op show [--type IPV6] [--ifid 0..n]\n\
\n\
Note:\n\
If 'addr' and 'port' are not provided in CLI, it can be provided in config file /etc/csio_iscsi_tgt_param.conf as below\n\
SnsLstn         <IPV4/IPV6 address>:[port num]\n\
\n\
If port number specified, enclose IPV6 address in []\n\
\n\
\n");
	}

	exit(status == 0 ? 0 : CSIO_EINVAL);
}

static int
verify_short_mode_params(int argc, char **argv, char *short_allowed, int skip_m)
{
	int ch, longindex;
	int ret = 0;

	optind = 2;

	while ((ch = getopt_long(argc, argv, short_options,
					long_options, &longindex)) >= 0) {
		if (!strchr(short_allowed, ch)) {
			if (ch == 'm' && skip_m)
				continue;
			ret = ch;
			break;
		}
	}

	return ret;
}

int make_isns_ioctl(struct isns_ioctl_list **i_list, struct ip_addr *addr, uint16_t port, 
			uint16_t type,  uint8_t ifid, uint16_t vlanid, uint32_t cmd_type, uint8_t mode, char *eid)
{
	int rc = 0;
	void *buffer = NULL;
	struct csio_isns_ioctl *req = NULL;
	struct isns_ioctl_list *l_node = NULL, *trav;
	size_t len;
	uint32_t cmd = CSIO_ISNS_OPCODE(cmd_type);

	/* Find end of the list */
	trav = *i_list;
	while(trav && trav->next)
		trav = trav->next;

	len = os_agnostic_buffer_len(sizeof(*req));

	l_node = malloc(sizeof(struct isns_ioctl_list));
	if (!l_node) {
		csio_app_log_devel_debug("%s: isns_ioctl_list alloc failed\n", isns_name);
		rc = CSIO_ENOMEM;
		goto out;
	}
			
	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		csio_app_log_devel_debug("%s: ioctl buffer alloc failed\n", isns_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	l_node->next = NULL;
	l_node->len = len;
	l_node->i_buf = buffer;

	if (trav) {
		trav->next = l_node;
		trav = trav->next;
	} else {
		*i_list = l_node;
		trav = *i_list;
	}

	req = (struct csio_isns_ioctl *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	csio_app_log_devel_debug("%s: port %u type %d\n",__func__,
			port, type);
	if(type == CSIO_ISNS_L3CFG_TYPE_IPV6) {
		memcpy((char *)req->addr.ip6, (char *)addr->ip6, 16);
		csio_app_log_devel_debug("addr %2x%2x%2x%2x%2x%2x%2x%2x--%2x%2x%2x%2x%2x%2x%2x%2x\n",
			req->addr.ip6[0], req->addr.ip6[1], req->addr.ip6[2],
			req->addr.ip6[3], req->addr.ip6[4], req->addr.ip6[5],
			req->addr.ip6[6], req->addr.ip6[7], req->addr.ip6[8],
			req->addr.ip6[9], req->addr.ip6[10], req->addr.ip6[11],
			req->addr.ip6[12], req->addr.ip6[13], req->addr.ip6[14],
			req->addr.ip6[15]);
	} else if(type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
		req->addr.ip4 = addr->ip4;
		csio_app_log_devel_debug("IPV4 addr 0x%x\n", req->addr.ip4);
	}
	req->port = port;
	req->type = type;
	req->mode = mode;
	req->ifid = ifid;
	req->vlanid = vlanid;
	strcpy(req->eid, eid);

	return 0;
out:
	if(l_node)
		free(l_node);

	return rc;
}

uint8_t parse_isns_value(char **val, char **val_i, uint8_t type)
{
	uint8_t ip_type = CSIO_ISNS_L3CFG_TYPE_NONE;
	char *tmp = NULL;

	/* Find port */
	tmp = strrchr(*val, ':');
	if (tmp) {
		/* ipv4 with port */
		if (strchr(*val, ':') == tmp) {
			*tmp = '\0';
			*val_i = tmp + 1;
			ip_type = CSIO_ISNS_L3CFG_TYPE_IPV4;
			csio_app_log_devel_debug("%s: IPV4\n",__func__);
		/* ipv6 with port */
		} else if (*(tmp - 1) == ']') {
			*(tmp - 1) = '\0';
			*tmp = '\0';
			*val_i = tmp + 1;
			ip_type = CSIO_ISNS_L3CFG_TYPE_IPV6;
			csio_app_log_devel_debug("%p IPV6 %s %d\n",*val, *val, atoi(tmp+1));
		/* part of ipv6 address, ignore */
		} else {
			ip_type = CSIO_ISNS_L3CFG_TYPE_IPV6;
		}
	} else {
		ip_type = type;
	}

	/* Remove [ at beginning */
	if (**val == '[') {
		**val = '\0';
		*val += 1;
		ip_type = CSIO_ISNS_L3CFG_TYPE_IPV6;
		csio_app_log_devel_debug(" %p %s IPV61\n",*val, *val);
	}

	/* Remove ] at end */
	tmp = *val;
	tmp += strlen(*val)-1;
	if (*tmp == ']') {
		*tmp = '\0';
		ip_type = CSIO_ISNS_L3CFG_TYPE_IPV6;
		csio_app_log_devel_debug(" %p %s IPV61\n",*val, *val);
	}

	return ip_type;
}

uint8_t
check_num_valid(char *num_str, uint32_t min, uint32_t max)
{
	char *test_str = NULL;
	char *ptr_str = NULL;
	uint8_t valid = 1;

	test_str = (char *)malloc((int)strlen(num_str)+1);
	if(!test_str)
		return 0;

	ptr_str = test_str;
	strcpy(test_str, num_str);
	csio_app_log_devel_debug("num_str %s(%d) test_str %s(%d)\n",
			num_str, (int)strlen(num_str), test_str, (int)strlen(test_str));

	/* find any non-digit number */
	csio_app_log_devel_debug("%s: check for non-digit value\n", isns_name);
	while(*test_str) {
		if (!isdigit(*test_str++)) {
			valid = 0;
			break;
		}
	}

	if(!valid)
		goto out;

	csio_app_log_devel_debug("%s: check for range\n", isns_name);
	test_str = ptr_str;

	/* Check whether the specified number is in range */
	if(atoi(test_str) >= min && atoi(test_str) <= max)
		csio_app_log_devel_debug("%s: Value %u\n", isns_name, atoi(test_str));
	else
		valid = 0;

out: 
	free(ptr_str);
	return valid;
}

uint8_t
check_ip_valid(char *ip_str, uint8_t type)
{
	struct ip_addr test_addr;

	if(type == CSIO_ISNS_L3CFG_TYPE_IPV4)
		return inet_pton(AF_INET, ip_str, &test_addr.ip4);
	else if(type == CSIO_ISNS_L3CFG_TYPE_IPV6)
		return inet_pton(AF_INET6, ip_str, &test_addr.ip6);
	else
		return 0;
}

void get_ip_addr(struct ip_addr *addr, char *ip_str, uint8_t type)
{
	if(type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
		addr->ip4 = inet_network(ip_str);
		csio_app_log_devel_debug("IPV4 addr 0x%x\n", addr->ip4);
	} else if(type == CSIO_ISNS_L3CFG_TYPE_IPV6) {
		inet_pton(AF_INET6, ip_str, &addr->ip6);
		csio_app_log_devel_debug("IPV6 addr %2x%2x%2x%2x%2x%2x%2x%2x-\
					 %2x%2x%2x%2x%2x%2x%2x%2x\n",
		addr->ip6[0], addr->ip6[1], addr->ip6[2], addr->ip6[3],
		addr->ip6[4], addr->ip6[5], addr->ip6[6], addr->ip6[7],
		addr->ip6[8], addr->ip6[9], addr->ip6[10], addr->ip6[11],
		addr->ip6[12], addr->ip6[13], addr->ip6[14], addr->ip6[15]);
	}
}

int parse_isns(struct isns_ioctl_list **rp, uint8_t ifid, uint16_t vlanid, uint32_t cmd, uint8_t mode, 
		uint8_t type, char *eid)
{
	int rc = 0;
	size_t len;
	ssize_t read;
	char *line=NULL;
	FILE *fp = NULL;
	char *token = NULL;
	char *val = NULL, *val_i = NULL;
	struct ip_addr addr;
	uint16_t port;
	uint8_t ip_type;

	if(!(fp = fopen(ISCSI_TGT_PARAM_FILE, "r"))) {
                csio_app_log_devel_debug("Unable to open Config file\n");
                return CSIO_ECFG_RD_FAIL;
        }

	/* Read line by line */
	while ((read = getline(&line, &len, fp)) != -1) {
	
		/* Skip anything following a #, that is for comments */
		token = strchr(line, '#');
		if (token) {
			/* Truncate string to only readable portions */
			read -= strlen((char *)token);
			*token = '\0';
		}

		/* A config string less than 12 characters long cannot be valid */
		if (read < 12)
			continue;

		/* Split string into token and value */
		token = strtok(line, " \t\r\n");
		val = strtok(NULL, " \t\r\n");

		/* Skip any line that does not have a token:value pair */
		if (!token || !val)
			continue;

		/* Init everything */
		port = 0;
		memset(&addr, 0, sizeof(struct ip_addr));

		/* SnsAddr or SnsLstn */
		if ((!strncmp(coiscsi_param_set[V_TSNSADDR].name, token, strlen(token)) && 
				mode == CSIO_APP_MOD_ISNS_CLIENT) ||
			(!strncmp(coiscsi_param_set[V_TSNSLSTN].name, token, strlen(token)) &&
			                                 mode == CSIO_APP_MOD_ISNS_SERVER)) {

			ip_type = parse_isns_value(&val, &val_i, type);

			if(ip_type == type) {
				/* Get port */
				if(val_i && strlen(val_i)) {
					if(check_num_valid(val_i, CSIO_MIN_PORT_NUM, CSIO_MAX_PORT_NUM)) {
						port = atoi(val_i);
						csio_app_log_devel_debug("%s: Port num %u\n", isns_name, port);
					} else {
						csio_printf("Config file: Invalid port num %s(valid: 0-65535)\n", val_i);
						continue;
					}
				} else {
					port = CSIO_ISNS_PORT;
					csio_app_log_devel_debug("%s: Port num %u\n", isns_name, port);
				}

				/* Get IP */
				if(val) {
					if(check_ip_valid(val, type)) {
						get_ip_addr(&addr, val, type);
						csio_app_log_devel_debug("%s: IP address %s\n", isns_name, val);
					} else  {
						csio_printf("Config file: Invalid IPV%d address %s\n", 
								(type==CSIO_ISNS_L3CFG_TYPE_IPV4?4:6), val);
						continue;
					}
				} else {
					csio_printf("Config file: IP address not provided\n");
					continue;
				}

				csio_printf("Config file: Valid IPV%d address %s Port %u\n", 
						(type==CSIO_ISNS_L3CFG_TYPE_IPV4?4:6), val, port);
				rc = make_isns_ioctl(rp, &addr, port, type, ifid, vlanid, cmd, mode, eid);
				if(rc) {
					csio_app_log_devel_debug("%s: make_isns_ioctl rc %d\n",
		                                                __func__, rc);
					goto err_out;
				}
			} else {
				csio_printf("Config file: Invalid IPV%d address %s\n", 
					(type==CSIO_ISNS_L3CFG_TYPE_IPV4?4:6), val);
			}
		}	
	}


err_out:
	if (line)
		free(line);

	if (fp)
		fclose(fp);

	return rc;
}	

int
csio_isns_op(adap_handle_t hw, int32_t op, char *sip, uint16_t port, uint8_t ifid, 
		uint16_t vlanid, uint8_t mode, uint8_t type, char *eid)
{
        int rc = 0;
	int cmd = (op == CSIO_APP_OP_ASSIGN?CSIO_START_ISNS_IOCTL:CSIO_STOP_ISNS_IOCTL);
        struct csio_isns_ioctl *req = NULL;
	struct isns_ioctl_list *ioctl_buf_list = NULL, *tmp = NULL;
	struct ip_addr addr;

	csio_app_log_devel_debug("%s: op %d cmd 0x%x\n",__func__, op, cmd);

	/* Create ioctl for CLI info */
	if((sip) && (port >= 0)) {
		get_ip_addr(&addr, sip, type);
		rc = make_isns_ioctl(&ioctl_buf_list, &addr, port, type, ifid, vlanid, cmd, mode, eid);
		if(rc) {
			csio_app_log_devel_debug("%s: make_isns_ioctl rc %d\n", 
						__func__, rc);
			goto out;
		}
	} else {
		/* Create ioctl for config file info */
		rc = parse_isns(&ioctl_buf_list, ifid, vlanid, cmd, mode, type, eid);
		if(rc) {
			csio_app_log_devel_debug("%s: parse_isns rc %d\n", 
						__func__, rc);
			goto out;
		}
	}

	if(!ioctl_buf_list) {
		csio_printf("iSNS %s op: No valid details in CLI or Config file\n", 
			(mode == CSIO_APP_MOD_ISNS_SERVER? "LISTENING SERVER":"CLIENT"));
		goto out;
	}

	while(ioctl_buf_list) {
		rc = issue_ioctl(hw, ioctl_buf_list->i_buf, ioctl_buf_list->len);

		req = get_payload(ioctl_buf_list->i_buf);

		rc = req->retval;

		if(req->type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
			uint8_t ip[4];
			ip[0] = (req->addr.ip4 >> 24) & 0xFF;
			ip[1] = (req->addr.ip4 >> 16) & 0xFF;
			ip[2] = (req->addr.ip4 >> 8) & 0xFF;
			ip[3] = (req->addr.ip4) & 0xFF;
			csio_printf("%s iSNS %s " FORMAT_IPV4_PORT " %s\n",
				(op == CSIO_APP_OP_ASSIGN? "Starting": "Stopping"), 
				(mode == CSIO_APP_MOD_ISNS_SERVER? "LISTENING SERVER at":"CLIENT for"), 
				ip[0], ip[1], ip[2], ip[3], req->port, (rc == 0? "Success": "Failed"));
		} else if(req->type == CSIO_ISNS_L3CFG_TYPE_IPV6) {
			csio_printf("%s iSNS %s " FORMAT_IPV6_PORT " %s\n",
				(op == CSIO_APP_OP_ASSIGN? "Starting": "Stopping"), 
				(mode == CSIO_APP_MOD_ISNS_SERVER? "LISTENING SERVER at":"CLIENT for"), 
				req->addr.ip6[0], req->addr.ip6[1], req->addr.ip6[2], req->addr.ip6[3],
				req->addr.ip6[4], req->addr.ip6[5], req->addr.ip6[6], req->addr.ip6[7],
				req->addr.ip6[8], req->addr.ip6[9], req->addr.ip6[10], req->addr.ip6[11],
				req->addr.ip6[12], req->addr.ip6[13], req->addr.ip6[14], req->addr.ip6[15],	
				req->port, (rc == 0? "Success": "Failed"));
		}
		
		ioctl_buffer_free(ioctl_buf_list->i_buf);

		tmp = ioctl_buf_list;

		ioctl_buf_list = ioctl_buf_list->next;

		free(tmp);
		rc = 0;
	}

	if (ioctl_buf_list) {
		ioctl_buffer_free(ioctl_buf_list->i_buf);
		free(ioctl_buf_list);
	}

out:
        return rc;
}

void print_isns_details(uint8_t type, uint8_t *ip_addr, 
		uint32_t port, uint8_t idx, char *mode)
{
	uint8_t ip[16];
	memcpy(ip, ip_addr, 16);

	if(!idx) 
		csio_printf("\n\n ***** ISNS %s INFO ***** \n\n", mode);

	if(type == CSIO_ISNS_L3CFG_TYPE_IPV4) {
		csio_printf("ISNS %s %u: " FORMAT_IPV4_PORT " \n", 
		mode, idx, ip[12], ip[13], ip[14], ip[15], port);
	} else if(type == CSIO_ISNS_L3CFG_TYPE_IPV6) {
		csio_printf("ISNS %s %u: " FORMAT_IPV6_PORT " \n", 
		mode, idx, ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7], 
		ip[8], ip[9], ip[10], ip[11], ip[12], ip[13], ip[14], ip[15], 
		port);
	}
}

uint8_t print_isns(uint16_t type, uint16_t ip_type, uint8_t iface_id, uint8_t ifid)
{

	if(type != CSIO_ISNS_L3CFG_TYPE_NONE && iface_id != CSIO_INV_IFID_NUM) {
		if(type == ip_type && iface_id == ifid)
			return 1;
	} else if(type !=  CSIO_ISNS_L3CFG_TYPE_NONE) {
		if(type == ip_type)
			return 1;
	} else if(iface_id != CSIO_INV_IFID_NUM) {
		if(iface_id == ifid)
			return 1;
	} else {
		return 1;
	}

	return 0;
}

uint16_t csio_isns_show_ioctl(adap_handle_t hw, uint8_t mode, uint8_t op, 
			uint16_t rlen, uint16_t plen, uint16_t *cnt, 
			uint16_t type, uint16_t *tgt_cnt, uint8_t iface_id)
{
	struct csio_isns_ioctl *req = NULL;
	uint8_t *payload;
	uint8_t *buf;
	uint8_t *pl, *tmp;
	size_t buf_len = 0;
	uint8_t ip[16];
	uint8_t idx = 0;
	uint16_t ifid;
	uint16_t port;
	uint16_t ip_type;
	uint16_t num_entry = *cnt;
	uint16_t num_tgt = *tgt_cnt;
	char tgt_name[256];
	int cmd = CSIO_SHOW_ISNS_IOCTL;
	int i, j;
	int rc = 0;

	buf_len = os_agnostic_buffer_len(plen + sizeof(*req));
	csio_app_log_devel_debug("%s: ISNS GET len %d buf len %d\n",
				__func__, plen, (uint16_t)buf_len);

	/* Allocate IOCTL buffer */
	buf = ioctl_buffer_alloc(buf_len, CSIO_IOCTL_SIGNATURE);
	if (!buf) {
		csio_app_log_devel_debug("%s: isns ioctl buffer alloc failed\n", isns_name);
		return CSIO_ENOMEM;
	}

	req = (struct csio_isns_ioctl *)get_payload(buf);
        memset(req, 0, sizeof(*req));
        req->mode = mode;

	payload = (uint8_t *)req + sizeof(*req);
	memset(payload, 0, plen);

	csio_init_header(buf, CSIO_ISNS_OPCODE(cmd), CSIO_IOCTL_SIGNATURE, buf_len, CSIO_IOCD_RW);

	if(op == 0x1)
		memset(payload + sizeof(int), 0x01, 1);

	rc = issue_ioctl(hw, buf, buf_len);

	req = (struct csio_isns_ioctl *)get_payload(buf);
	payload = (uint8_t *)req + sizeof(*req);

	memcpy((uint8_t *)&rc, payload, sizeof(int));

	if(rc) {
		csio_app_log_devel_debug("iSNS SHOW cmd Failed\n");
		ioctl_buffer_free(buf);
		return rc;
	} else {
		if(op == 0x1) {
			memcpy((uint8_t *)cnt, payload+sizeof(int), 2);
			memcpy((uint8_t *)tgt_cnt, payload+sizeof(int)+2, 2);
		} else {
			pl = payload + sizeof(int);
			if(mode == CSIO_APP_MOD_ISNS_SERVER) {
				for(i=0 ; i < num_entry ; i++) {

					memcpy((uint8_t *)&ip, pl, 16);
					memcpy((uint8_t *)&port, pl+16, 2);
					memcpy((uint8_t *)&ifid, pl+18, 2);
					memcpy((uint8_t *)&ip_type, pl+20, 2);
					if(print_isns(type, ip_type, iface_id, ifid)) {
						print_isns_details(ip_type, ip, port, idx, "LIST SERV");
						idx++;
					}
					pl += rlen; 
				}
			} else  {
				pl = payload + sizeof(int);
				for(i=0 ; i < num_entry ; i++) {
					memcpy((uint8_t *)&ip, pl, 16);
					memcpy((uint8_t *)&port, pl+16, 2);
					memcpy((uint8_t *)&ifid, pl+18, 2);
					memcpy((uint8_t *)&ip_type, pl+20, 2);
					if(print_isns(type, ip_type, iface_id, ifid)) {
						print_isns_details(ip_type, ip, port, idx, "CLIENT");
						tmp = pl + 22;
						idx++;
						for(j=0; j < num_tgt; j++) {
							memcpy(tgt_name, tmp, 256);
							if(strlen(tgt_name))
								csio_printf("	Tgt registered %d: %s\n",j, tgt_name);
							tmp += 256;
						}
					}
					pl += rlen; 
				}
			}

			if(!idx) csio_printf("\n\n%s: No iSNS details to show\n\n", isns_name);
			else csio_printf("\n **************************** \n\n");
		}
	}

	ioctl_buffer_free(buf);
	return 0;
}

int csio_isns_show(adap_handle_t hw, uint8_t mode, uint16_t type, int8_t ifid)
{
	uint16_t cnt = 0;
	uint16_t tgt_cnt = 0;
	uint16_t rlen = 0;
	uint16_t plen = 0;
	int rc = 0;

	/* Get number of entries to be listed */
	rlen = 0;
	plen = 16;
	rc = csio_isns_show_ioctl(hw, mode, 0x1, rlen, plen, &cnt, type, &tgt_cnt, ifid);
	if(rc)
		goto out;

	if(!cnt) {
		csio_printf("\n\n%s: No ISNS details to show\n\n", isns_name);
		return 0;
	}

	if(mode == CSIO_APP_MOD_ISNS_SERVER) {
		rlen = 22;
	        plen = sizeof(int) + (cnt * rlen);
	} else if(mode == CSIO_APP_MOD_ISNS_CLIENT) {
		rlen = 22 + (tgt_cnt * 256);
	        plen = sizeof(int) + (cnt * rlen);
	}
	rc = csio_isns_show_ioctl(hw, mode, 0x0, rlen, plen, &cnt, type, &tgt_cnt, ifid);
out:
	return rc;
}

int
csio_isns_do_op(adap_handle_t hw, int32_t op, char *sip, uint16_t port, 
		uint16_t type, uint8_t ifid, uint16_t vlanid, uint8_t mode, char *eid)
{	
	int rc = 0;

	switch (op) {
	case CSIO_APP_OP_ASSIGN:
	case CSIO_APP_OP_CLEAR:
		rc = csio_isns_op(hw, op, sip, port, ifid, vlanid, mode, type, eid);
		break;
	case CSIO_APP_OP_SHOW:
		rc = csio_isns_show(hw, mode, type, ifid);
		break;
	default:
		csio_app_log_devel_debug("Invalid opcode %d\n", op);
		rc = CSIO_EINVAL;
		break;
	}
	
	return rc;
}

int run_isns_cmd(int argc, char *argv[])
{
	int ch, longindex, mode = CSIO_APP_MOD_NON;
	int rc=0, op=CSIO_APP_OP_NOOP;
	char *device = NULL;
	char *sip = NULL;
	char *port_num = NULL;
	char *iface_id = NULL;
	char *vlan_id = NULL;
	adap_handle_t hw = -1;
	int oassign_cnt = 0;
	int oclear_cnt = 0;
	int oshow_cnt = 0;
	uint8_t ifid = CSIO_INV_IFID_NUM;
	uint16_t vlanid = 0;
	uint16_t sport = CSIO_ISNS_PORT;
	uint16_t type = CSIO_ISNS_L3CFG_TYPE_NONE;
	char eid[256];

	csio_app_log_devel_debug("%s: entering\n", isns_name);
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	optopt = 0;
	optind = 3;

	if (!strncmp(argv[2], isns_base_opt, strlen(isns_base_opt))) {
		memset(argv[2], 0, strlen(isns_base_opt));
		strncpy(argv[2], "isns", strlen(isns_base_opt));
	}
	csio_app_log_devel_debug("%s: argv[0] %s, argv[1] %s\n",
					isns_name, argv[0], argv[1]);


	while ((ch = getopt_long(argc, argv, short_options, long_options, &longindex)) >= 0) {
		csio_app_log_devel_debug("%s: ch : %c, longindex %d\n",
						isns_name, ch, longindex);

		switch (ch) {
		case 'd':
			device = optarg;
			csio_app_log_devel_debug("%s: device %s\n",
							isns_name, device);
			break;
		case 'o':
			op = str_to_op(optarg);
			if (op == CSIO_APP_OP_ASSIGN)
				oassign_cnt++;
			else if (op == CSIO_APP_OP_CLEAR)
				oclear_cnt++;
			else if (op == CSIO_APP_OP_SHOW)
				oshow_cnt++;
			
			csio_app_log_devel_debug("%s: opcode %d\n", isns_name, op);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			csio_app_log_devel_debug("%s: mode %d\n", isns_name, mode);
			break;
		case 'i':
			iface_id = optarg;
			csio_app_log_devel_debug("%s: iface id %s\n", isns_name, iface_id);
			break;
		case 'v':
			vlan_id = optarg;
			csio_app_log_devel_debug("%s: vlan id: %s\n", isns_name, optarg);
			break;
		case 'a':
			sip = optarg;
			csio_app_log_devel_debug("%s: isns ip %s\n", isns_name, sip);
			break;
		case 'p':
			port_num = optarg;
			csio_app_log_devel_debug("%s: isns port %s\n", isns_name, port_num);
			break;
		case 't':
			type = str_to_isns_type(optarg);
			csio_app_log_devel_debug("%s: type %d : %s\n", isns_name, type, optarg);
			break;
		case 'h':
			usage(0);
			break;
		case '?':
		default:
			usage(1);
			csio_app_log_devel_debug("in default\n");
			csio_app_log_devel_debug("%s: Invalid character %c\n", isns_name, optopt);
			rc = CSIO_EINVAL;
			goto out;

			break;
		}
	}

	if (argc == 2)
		usage(0);
	
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	if (optind < argc) {
		fprintf(stderr, "%s: unrecognised option %s\n",
				isns_name, argv[optind]);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (optopt) {
		fprintf(stderr, "%s: Invalid character %c\n",
				isns_name, optopt);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (mode == CSIO_APP_MOD_NON) {
		fprintf(stderr, "%s:  Please specify mode(-m server/client)\n",
				isns_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (!device) {
		fprintf(stderr, "%s: Please specify Chelsio device(Eg: -d /dev/csiostor0)\n",
				isns_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(op == CSIO_APP_OP_NOOP) {
		fprintf(stderr, "%s: Please specify opcode(-o assign/clear/show)\n", isns_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(type == CSIO_ISNS_L3CFG_TYPE_NONE && op != CSIO_APP_OP_SHOW) {
		fprintf(stderr, "%s: Please specify IP type(-t IPV4/IPV6)\n", isns_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(iface_id) {
		if (check_num_valid(iface_id, CSIO_MIN_IFID_NUM, CSIO_MAX_IFID_NUM)) {
			ifid = atoi(iface_id); 
			csio_app_log_devel_debug("%s: ifid %d\n", isns_name, ifid);
		} else {
			fprintf(stderr, "%s: Invalid ifid %s(valid: 0-3)\n", isns_name, iface_id);
			rc = CSIO_EINVAL;
			goto out;
		}
	} else {
		if (op != CSIO_APP_OP_SHOW) {
			fprintf(stderr, "%s: Please specify ifid(-i 0/1/2/3)\n", isns_name);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	if(vlan_id) {	
		if (check_num_valid(vlan_id, CSIO_MIN_VLAN_NUM, CSIO_MAX_VLAN_NUM)) {
			vlanid = atoi(vlan_id); 
			csio_app_log_devel_debug("%s: vlanid %d\n", isns_name, vlanid);
		} else {
			fprintf(stderr, "%s: Invalid vlanid %s(valid: 2-4094)\n", isns_name, vlan_id);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	if(port_num) {
		if (check_num_valid(port_num, CSIO_MIN_PORT_NUM, CSIO_MAX_PORT_NUM)) {
			sport = atoi(port_num); 
			csio_app_log_devel_debug("%s: sport %u\n", isns_name, sport);
		} else {
			fprintf(stderr, "CLI: Invalid port num %s(valid: 0-65535)\n", port_num);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	if(sip) {
		if (check_ip_valid(sip, type)) {
			csio_app_log_devel_debug("%s: sip %s\n", isns_name, sip);	
		} else {
			fprintf(stderr, "CLI: Invalid IPV%d address %s\n", 
					(type==CSIO_ISNS_L3CFG_TYPE_IPV4?4:6), sip);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	if(mode == CSIO_APP_MOD_ISNS_CLIENT) {
		gethostname(eid, 256);
		strcat(eid, ".target");
		csio_app_log_devel_debug("%s: EID %s\n", isns_name, eid);
	}

	if (device) {
		hw = open_adapter_handle(device);

		if (hw == -1 || (csio_probe_adapter(hw) != 0)) {
			fprintf(stderr, "%s: error opening device %s, %s\n", 
					isns_name, device, strerror(errno));
			rc = errno;
			goto out;
		}
	}

	switch (mode) {
	case CSIO_APP_MOD_ISNS_SERVER:
	case CSIO_APP_MOD_ISNS_CLIENT:
		if ((rc = verify_short_mode_params(argc, argv, "mdoatpiv", 0))) {
			fprintf(stderr, "%s: target option '-%c' is not "
					"supported\n", isns_name, rc);
			rc = CSIO_EINVAL;
			goto out;
		}
		csio_app_log_devel_debug("op %d, sip %s, port %u, " 
					"type %d, ifid %d, vlanid %d, mode %d\n",
					op, sip, sport, type, ifid, vlanid, mode);
		rc = csio_isns_do_op(hw, op, sip, sport, type, ifid, vlanid, mode, eid);
		break;

	default:
		fprintf(stderr, "%s: Unsupported Mode %d\n", isns_name, mode);
		rc = CSIO_EINVAL;
		usage(1);
	}

out:
	if (rc > 0 && rc <= CSIO_ELAST)
		fprintf(stderr, "%s\n", csio_err_to_msg(rc));
	else if (rc > CSIO_ELAST)
		fprintf(stderr, "Invalid parameter, retval %d\n", rc);
	
	if (hw != -1)
		close_adapter(hw);
	
	csio_app_log_devel_debug("%s: %d: \n", isns_name, rc);
	
	return 0;
}
