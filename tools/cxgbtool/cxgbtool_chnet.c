#include <csio_hw.h>
#include <csio_chnet_ioctl.h>
#include <csio_common.h>
#include <cxgbtool_chnet.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <limits.h>

static const char * const chnet_name = "cxgbtool stor --chnet";
static const char * const chnet_base_opt = "--chnet";

/* move these to related headers */

/* ======================================= */

static struct option const long_options[] = 
{
	{"mode", required_argument, NULL, 'm'},
	{"dev", required_argument, NULL, 'd'},
	{"saddr", required_argument, NULL, 'r'},
	{"addr", required_argument, NULL, 'a'},
	{"mask", required_argument, NULL, 'k'},
#if 1
	{"bcaddr", required_argument, NULL, 'b'},
#endif
	{"gw", required_argument, NULL, 'g'},
	{"type", required_argument, NULL, 't'},
	{"loopback", required_argument, NULL, 'O'},
	{"op", required_argument, NULL, 'o'},
	{"ifid", required_argument, NULL, 'i'},
	{"vlanid", required_argument, NULL, 'l'},
	{"vlanprio", required_argument, NULL, 'y'},
	{"mtu", required_argument, NULL, 'u'},
	{"help", no_argument, NULL, 'h'},
	{"prefix", required_argument, NULL, 'f'},
	{"pingtimeout", required_argument, NULL, 'p'},
	{"pingcnt", required_argument, NULL, 'c'},
	{"pingpldsize", required_argument, NULL, 's'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "hm:P:T:o:i:n:a:p:s:d:t:I:r:u:I:S:R:C:A:L:p:c:";

static int str_to_ifconf_type(char *str)
{
	int type;

	if (!strcasecmp("ipv4", str))
		type = CSIO_CHNET_L3CFG_TYPE_IPV4;
	else if (!strcasecmp("vlan_ipv4", str))
		type = CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4;
	else if (!strcasecmp("ipv6", str))
		type = CSIO_CHNET_L3CFG_TYPE_IPV6;
	else if (!strcasecmp("dhcp", str))
		type = CSIO_CHNET_L3CFG_TYPE_DHCP;
	else if (!strcasecmp("dhcpv6", str))
		type = CSIO_CHNET_L3CFG_TYPE_DHCPV6;
	else
		type = CSIO_CHNET_L3CFG_TYPE_NONE;

	return type;
}

static void usage(int status)
{

	if (status)
		fprintf(stderr, "Try cxgbtool stor --chnet --help for more information\n");
	else {
		printf("Usage: cxgbtool stor --chnet [OPTION]\n");
		printf("\
\n\
cxgbtool stor --chnet --mode iface --dev device --op up --ifid 0...n --loopback\n\
cxgbtool stor --chnet --mode iface --dev device --op down --ifid 0...n --loopback\n\
cxgbtool stor --chnet --mode iface --dev device --op vlan --ifid 0...n --vlanid 2...4094 --vlanprio 0...7 --loopback\n\
cxgbtool stor --chnet --mode iface --dev device --op mtu --ifid 0...n --mtu 1500...9000 --loopback\n\
cxgbtool stor --chnet --mode iface --dev device --op show --ifid 0...n --loopback\n\
\n\
cxgbtool stor --chnet --mode ifconf --dev device --op assign --type IPV4 --saddr xxx.xxx.xxx.xxx --mask xxx.xxx.xxx.xxx --gw xxx.xxx.xxx.xxx --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op assign --type IPV6 --saddr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx --prefix n --gw xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
\n\
cxgbtool stor --chnet --mode ifconf --dev device --op assign --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op assign --type DHCPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op show --type IPV4 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op show --type IPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op show --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op show --type DHCPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op clear --type IPV4 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op clear --type IPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op clear --type DHCP --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op clear --type DHCPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n\
cxgbtool stor --chnet --mode ifconf --dev device --op ping --type IPV4 --ifid 0...n --addr xxx.xxx.xxx.xxx --vlanid 2...4094 --vlanprio 0...7 --pingtimeout n --pingcnt n --pingpldsize n\n\
cxgbtool stor --chnet --mode ifconf --dev device --op ping --type IPV6 --ifid 0...n --addr xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx:xxxx --vlanid 2...4094 --vlanprio 0...7 --pingtimeout n --pingcnt n --pingpldsize n\n\
cxgbtool stor --chnet --mode ifconf --dev device --op pmtu_clear --type IPV6 --ifid 0...n --vlanid 2...4094 --vlanprio 0...7\n");
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

static int csio_chnet_iface_do_link_op(adap_handle_t hw, int op, int8_t port, uint8_t flags)
{
	void *buffer = NULL;
	struct csio_chnet_iface_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EIFACE_INVALID_PORT;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	cmd = CSIO_CHNET_OPCODE(op == CSIO_APP_OP_UP ?
			CSIO_CHNET_IFACE_LINK_UP_IOCTL:
			CSIO_CHNET_IFACE_LINK_DOWN_IOCTL);
	
	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_iface_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	req->ifid = port;
	req->flags = flags;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_chnet_iface_ioctl*)get_payload(buffer);
	rc = req->retval;

	if(rc == 0)
		csio_printf("Interface LINK %s Success\n", (op == CSIO_APP_OP_UP?"UP":"DOWN"));

	ioctl_buffer_free(buffer);
out:
	return rc;
}

static int32_t
csio_chnet_iface_do_vlan(adap_handle_t hw, uint16_t vlanid, int8_t port)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_VLAN_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	
	req->ifid = port;
	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	
	csio_app_log_devel_debug("%s: status %d, req->retval %d\n",
						chnet_name, rc, req->retval);

	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);

	rc = req->retval;

	if (rc == 0) {
		fprintf(stderr, "ifid[%d]: vlan-id %u, vlan-prio %u provisioned successfully\n",
				port, vlanid & 0x0fff, (vlanid >> 13) & 0x7);
	} else if (rc == 2) {
		fprintf(stderr, "ifid[%d]: vlan in use\n", port);
	} else {
		fprintf(stderr, "ifid[%d]: error provisioning vlan-id %u, vlan-prio %u\n",
				port, vlanid & 0x0fff, (vlanid >> 13) & 0x7);
	}

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int csio_chnet_iface_do_mtu(adap_handle_t hw, int16_t mtu, int8_t port)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_MTU_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	
	req->ifid = port;
	req->mtu = mtu;
	
	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	rc = req->retval;

	if (rc == 0) {
		fprintf(stderr, "\nifid : %d\n", port);
		fprintf(stderr, "----------------------------------\n");
		fprintf(stderr, "mtu changed to  : %u\n", req->mtu);
		fprintf(stderr, "----------------------------------\n");
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);
	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_chnet_iface_do_show(adap_handle_t hw, uint8_t ifid, struct csio_chnet_ifconf_ioctl *um_iface)
{

	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFACE_GET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);

	if (rc == 0) { 
		if(!um_iface) {
			fprintf(stderr, "\nifid : %d\n", ifid);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "link state : %s\n", !(req->if_state) ? "down" :
				(req->if_state == CHNET_IFACE_STATE_LINK_UP ? "up" : "enabled"));
			fprintf(stderr, "mtu   : %u\n", req->mtu);
			fprintf(stderr, "vlan-id: %u\n",
				csio_chnet_is_valid_vlan(req->vlanid) ? (req->vlanid & 0x0fff) : 0);
			fprintf(stderr, "vlan-prio: %u\n",
				csio_chnet_is_valid_vlan(req->vlanid) ? ((req->vlanid >> 13) & 0xf) : 0);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "Address Type Mask : 0x%x\n", req->address_state);
		} else {
			memcpy(um_iface, req, sizeof(struct csio_chnet_ifconf_ioctl));
		}
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}


void csio_chnet_ifconf_do_dhcp_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid)
{
	return;
}

int32_t csio_chnet_ifconf_do_ipv6_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd =
		CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_GET_IOCTL);
	int rc = 0;
	char ipv6_addr[64];

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n",
			chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->vlanid = vlanid;
	req->type = type;
	
	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0) {
		fprintf(stderr, "\nifid : %d\n", ifid);
		fprintf(stderr, "----------------------------------\n");
		if (inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64)){
			fprintf(stderr, "ip:\t %s/%u\n",
				ipv6_addr, req->v6.prefix_len);
			
		}
		inet_ntop(AF_INET6, req->v6.ipv6_gw, ipv6_addr, 64);
		fprintf(stderr, "gw:\t %s\n", ipv6_addr);
		fprintf(stderr, "----------------------------------\n");
	} else
		fprintf(stderr, "\nInvalid parameter\n");

	req->subop = CSIO_APP_OP_LLOCAL;
	rc = issue_ioctl(hw, buffer, len);
        if (rc == 0) {
                fprintf(stderr, "\nLink-local\n");
                fprintf(stderr, "----------------------------------\n");
                if (inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64)){
                        fprintf(stderr, "ip:\t %s/%u\n",
                                ipv6_addr, req->v6.prefix_len);

                }
                fprintf(stderr, "----------------------------------\n");
        } else
                fprintf(stderr, "\nInvalid parameter\n");

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

int32_t csio_chnet_ifconf_do_ipv4_show(adap_handle_t hw, uint16_t type,
				uint16_t vlanid, uint8_t ifid, struct csio_chnet_ifconf_ioctl *um_req)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV4_GET_IOCTL);
	struct in_addr iaddr;
	struct in_addr mask;
	struct in_addr gw;
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->vlanid = vlanid;
	req->type = type;
	
	rc = issue_ioctl(hw, buffer, len);

	/*req = get_payload(buffer);*/
	iaddr.s_addr = ntohl(req->v4.ipv4_addr);
	mask.s_addr = ntohl(req->v4.ipv4_mask);
	gw.s_addr = ntohl(req->v4.ipv4_gw);


	if (rc == 0) {
		if(!um_req) {
			fprintf(stderr, "\nifid : %d\n", ifid);
			fprintf(stderr, "----------------------------------\n");
			fprintf(stderr, "ip:\t %s\n", inet_ntoa(iaddr));
			fprintf(stderr, "mask:\t %s\n", inet_ntoa(mask));
			fprintf(stderr, "gw:\t %s\n", inet_ntoa(gw));
			fprintf(stderr, "----------------------------------\n");
		} else {
			memcpy(um_req, req, sizeof(struct csio_chnet_ifconf_ioctl));
		}
	} else 
		fprintf(stderr, "\nInvalid parameter\n");

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_chnet_ifconf_do_dhcp_assign(adap_handle_t hw, uint16_t type,
					uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;
	struct in_addr iaddr, mask, gw;
	char ipv6_addr[64];
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	if (type == CSIO_CHNET_L3CFG_TYPE_DHCP)
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV4_DHCP_SET_IOCTL);
	else /* (type == CSIO_CHNET_L3CFG_TYPE_DHCPV6) */
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_DHCP_SET_IOCTL);

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = CSIO_APP_OP_ASSIGN;
	
	if (csio_chnet_is_valid_vlan(vlanid))
		req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	rc = req->retval;

	csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	if (type == CSIO_CHNET_L3CFG_TYPE_DHCP) {
		iaddr.s_addr = ntohl(req->v4.ipv4_addr);
		mask.s_addr = ntohl(req->v4.ipv4_mask);
		gw.s_addr = ntohl(req->v4.ipv4_gw);
	
		if (rc == 0) {
			csio_printf("\nip\t%s\n\n",
 			req->v4.ipv4_addr == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(iaddr));
			csio_printf("mask\t%s\n\n",
			req->v4.ipv4_mask == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(mask));
			csio_printf("gw\t%s\n\n",
			req->v4.ipv4_gw == 0 ?\
				 "xxx.xxx.xxx.xxx" : inet_ntoa(gw));
			csio_printf("[%s on iface %d successfully]\n",
 			"provisioned", ifid);
		}
	} else {
		if ((rc == 0) &&
		     inet_ntop(AF_INET6, req->v6.ipv6_addr, ipv6_addr, 64))
			fprintf(stderr, "\nip\t%s\n\n"
				"[provisioned on iface %d successfully\n",
				ipv6_addr, ifid);

	}

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_chnet_ifconf_do_ipv6_assign(adap_handle_t hw, uint16_t type, char *saddr,
				unsigned int prefix_len, char *gw,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_SET_IOCTL);
	uint8_t addr6[16], gw6[16];

	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n",
			chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (saddr && (inet_pton(AF_INET6, saddr, addr6) != 1)) {
		fprintf(stderr, "%s: Invalid saddr\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}
	if (gw && (inet_pton(AF_INET6, gw, gw6) !=  1)) {
		fprintf(stderr, "%s: Invalid router address\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = CSIO_APP_OP_ASSIGN;
	
	if (saddr)
		memcpy(req->v6.ipv6_addr, addr6, 16);
	if (gw)
		memcpy(req->v6.ipv6_gw, gw6, 16);

	req->v6.prefix_len = prefix_len;

	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);
	rc = req->retval;

	csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (!rc) {
		fprintf(stderr, "\nip\t%s/%d\n\ngw\t%s \n\n"
				"[%s on iface %d successfully]\n\n",
				saddr == NULL ? "xxx.xxx.xxx.xxx" : saddr,
				prefix_len,
				gw == NULL ? "xxx.xxx.xxx.xxx" : gw,
				"provisioned", ifid);

	} else if (rc == EADDRNOTAVAIL) {
		rc = CSIO_EADDRNOTAVAIL;
	} else if (rc == EADDRINUSE) {
		rc = CSIO_EADDRINUSE;
	} else if (rc == EAGAIN) {
		rc = CSIO_EAGAIN;
	}

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

static int32_t
csio_chnet_ifconf_do_ipv4_assign(adap_handle_t hw, uint16_t type, char *saddr,
				char *mask, char *bcaddr, char *gw,
				uint16_t vlanid, uint8_t ifid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV4_SET_IOCTL);
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = CSIO_APP_OP_ASSIGN;
	
	if(saddr)
		req->v4.ipv4_addr = inet_network(saddr);
	
	if (mask)
		req->v4.ipv4_mask = inet_network(mask);
	
	if(gw)
		req->v4.ipv4_gw = inet_network(gw);

	req->vlanid = vlanid;

	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	rc = req->retval;

	csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (!rc) {
		fprintf(stderr, "\nip\t%s\nmask\t%s\ngw\t%s \n\n"
			"[%s on iface %d successfully]\n\n",
			saddr == NULL ? "xxx.xxx.xxx.xxx" : saddr,
			mask == NULL ? "xxx.xxx.xxx.xxx" : mask,
			gw == NULL ? "xxx.xxx.xxx.xxx" : gw,
			"provisioned", ifid);
	} else if (rc == EADDRNOTAVAIL) {
		rc = CSIO_EADDRNOTAVAIL;
	} else if (rc == EADDRINUSE) {
		rc = CSIO_EADDRINUSE;
	}


	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);

out:
	return rc;
}

int32_t
csio_chnet_ifconf_do_pmtu6_clear(adap_handle_t hw, uint16_t type,
                                uint8_t ifid, uint16_t vlanid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;
	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	if ((type != CSIO_CHNET_L3CFG_TYPE_IPV6) &&
		(type != CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6)) {
		rc = CSIO_EINVAL;
		goto out;
	}
	cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_PMTU_CLEAR_IOCTL);

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = CSIO_APP_OP_PMTU6_CLEAR;

	if (csio_chnet_is_valid_vlan(vlanid))
		req->vlanid = vlanid;
	else
		req->vlanid = CSIO_CHNET_VLAN_NONE;

	rc = issue_ioctl(hw, buffer, len);

	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);

	rc = req->retval;

	csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);

	if (!rc)
		fprintf(stderr, "ifid[%d]: PMTU cleared\n", ifid);

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);

	ioctl_buffer_free(buffer);
out:
	return rc;

}

int32_t
csio_chnet_ifconf_do_ip_clear(adap_handle_t hw, uint16_t type,
				uint8_t ifid, uint16_t vlanid)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd;

	int rc = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", chnet_name);
		rc = CSIO_ENOMEM;
		goto out;
	}
	if (type == CSIO_CHNET_L3CFG_TYPE_IPV6 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6 || type == CSIO_CHNET_L3CFG_TYPE_DHCPV6) {
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_SET_IOCTL);
		if (type == CSIO_CHNET_L3CFG_TYPE_DHCPV6)
			type = CSIO_CHNET_L3CFG_TYPE_IPV6;
	} else {
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV4_SET_IOCTL);
		if (type == CSIO_CHNET_L3CFG_TYPE_DHCP)
			type = CSIO_CHNET_L3CFG_TYPE_IPV4;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	req->ifid = ifid;
	req->type = type;
	req->subop = CSIO_APP_OP_CLEAR;
	
	if (csio_chnet_is_valid_vlan(vlanid))
		req->vlanid = vlanid;
	else
		req->vlanid = CSIO_CHNET_VLAN_NONE;
	
	rc = issue_ioctl(hw, buffer, len);

	req = get_payload(buffer);

	rc = req->retval;

	csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, rc);
	
	if (!rc) 
		fprintf(stderr, "ifid[%d]: IP deleted\n", ifid);

	csio_app_log_devel_debug("%s: status %d\n", chnet_name, rc);


	ioctl_buffer_free(buffer);

out:
	return rc;

}

static int32_t
csio_chnet_ifconf_do_ping(adap_handle_t hw, uint16_t type, char *saddr,
			uint16_t vlanid, uint8_t ifid, int8_t ping_timeout, 
			int32_t ping_cnt, uint16_t pld_size)
{
	void *buffer = NULL;
	struct csio_chnet_ifconf_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = 0, rsp_time = 0;
	int32_t i;
	uint16_t seq_num = 0;
	int rc = 0, ping_fails = 0, ping_pass = 0, ipv4 = 0;
	uint8_t addr6[16];

	if(type == CSIO_CHNET_L3CFG_TYPE_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4) {
		ipv4 = 1;
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV4_PING_IOCTL);
	} else {
		cmd = CSIO_CHNET_OPCODE(CSIO_CHNET_IFCONF_IPV6_PING_IOCTL);
	}

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(!ipv4 && (inet_pton(AF_INET6, saddr, addr6) != 1)) {
		fprintf(stderr, "%s: Invalid IPV6 addr\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	csio_printf("\n\n");

	seq_num = 1;
	for(i = 1; i <= ping_cnt; i++, seq_num++) {

		buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
		if (!buffer) {
			fprintf(stderr, "%s: Out of memory\n", chnet_name);
			rc = CSIO_ENOMEM;
			goto out;
		}

		csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
		req = (struct csio_chnet_ifconf_ioctl*)get_payload(buffer);
		memset(req, 0, sizeof(*req));

		req->ifid = ifid;
		req->type = type;
		req->subop = CSIO_APP_OP_PING;
		req->ping_time = ping_timeout;
		req->ping_seq = seq_num;
		req->ping_pldsize = pld_size;
		if(i == ping_cnt) {
			req->ping_param_rspcode = V_FW_CHNET_IFCONF_WR_FIN_BIT(1);
		}

		if(seq_num == 65535)
			seq_num = 0;

		if(ipv4)
			req->v4.ipv4_addr = inet_network(saddr);
		else
			memcpy(req->v6.ipv6_addr, addr6, 16);

		req->vlanid = vlanid;

		rc = issue_ioctl(hw, buffer, len);

		req = get_payload(buffer);

		rc = req->retval;

		if(!rc) {
			csio_printf("Ping Passed, icmp_seq=%d, ttl=%d, pldsize=%d bytes,",
				    seq_num, req->ping_ttl, req->ping_pldsize);
			ping_pass++;
		} else {
			csio_printf("Ping Failed, icmp_seq=%d, status=%d, type=%d, code=%d,", 
				seq_num, rc, req->ping_rsptype, req->ping_param_rspcode);
			ping_fails++;
		}
		if(!req->ping_time)
			csio_printf(" time <1 ms\n");
		else 
			csio_printf(" time=%d ms\n", req->ping_time);
		rsp_time += req->ping_time;
		ioctl_buffer_free(buffer);
	}

	csio_printf("\n--- PING STATISTICS ---\n");
	csio_printf("%d packets transmitted, %d recevied, %d dropped,", 
			ping_cnt, ping_pass, ping_fails);

	if(!(rsp_time/ping_cnt))
		csio_printf(" avg time <1 ms\n\n");
	else 
		csio_printf(" avg time=%d ms\n\n", (rsp_time/ping_cnt));
out: 
	return rc;
}

int32_t
csio_chnet_ifconf_do_op(adap_handle_t hw, int32_t op, uint16_t type,
			char *sip, char *mask, char *bcaddr, char *gw,
			uint16_t vlanid, uint8_t ifid, unsigned int prefix_len,
			int8_t ping_timeout, int32_t ping_cnt,
			uint16_t pld_size)
{
	int32_t rc = 0;

	switch (op) {
	case CSIO_APP_OP_ASSIGN:
		if (type == CSIO_CHNET_L3CFG_TYPE_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4)
			rc = csio_chnet_ifconf_do_ipv4_assign(hw, type, sip,
					mask, bcaddr, gw, vlanid, ifid);
		else if ((type == CSIO_CHNET_L3CFG_TYPE_IPV6) || (type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6))
			rc = csio_chnet_ifconf_do_ipv6_assign(hw, type, sip,
					prefix_len, gw, vlanid, ifid);
		else if ((type == CSIO_CHNET_L3CFG_TYPE_DHCP) || (type == CSIO_CHNET_L3CFG_TYPE_DHCPV6))
			rc = csio_chnet_ifconf_do_dhcp_assign(hw, type,
								vlanid, ifid);
		break;

	case CSIO_APP_OP_SHOW:
		if (type == CSIO_CHNET_L3CFG_TYPE_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_DHCP)
			csio_chnet_ifconf_do_ipv4_show(hw, CSIO_CHNET_L3CFG_TYPE_IPV4,
							vlanid, ifid, NULL);
		else if ((type == CSIO_CHNET_L3CFG_TYPE_IPV6) || (type == CSIO_CHNET_L3CFG_TYPE_DHCPV6))
			csio_chnet_ifconf_do_ipv6_show(hw, CSIO_CHNET_L3CFG_TYPE_IPV6,
							vlanid, ifid);
		break;
	
	case CSIO_APP_OP_CLEAR:
		rc = csio_chnet_ifconf_do_ip_clear(hw, type, ifid,
							vlanid);
		break;
	case CSIO_APP_OP_PING:
		rc = csio_chnet_ifconf_do_ping(hw, type, sip, vlanid, ifid,
					       ping_timeout, ping_cnt,
					       pld_size);
		break;
	case CSIO_APP_OP_PMTU6_CLEAR:
		rc = csio_chnet_ifconf_do_pmtu6_clear(hw, type, ifid,
						      vlanid);
		break;
	default:
		break;
	}

	return rc;
}

int32_t
csio_chnet_iface_do_op(adap_handle_t hw, int32_t op, int16_t mtu, uint16_t vlanid, uint8_t ifid, uint8_t flags)
{
	int32_t rc = 0;

	switch(op) {
	case CSIO_APP_OP_UP:
	case CSIO_APP_OP_DOWN:
		rc = csio_chnet_iface_do_link_op(hw, op, ifid, flags);
		break;

	case CSIO_APP_OP_MTU:
		if (mtu < 1500 || mtu > 9000) {
			fprintf(stderr, "invalid mtu %d specified\n", mtu);
			rc = CSIO_EINVAL;
			goto out;
		}
		rc = csio_chnet_iface_do_mtu(hw, mtu, ifid);
		break;
	
	case CSIO_APP_OP_VLAN:
		if (!csio_chnet_is_valid_vlan(vlanid)) {
			fprintf(stderr, "invalid vlanid %u specified\n", vlanid);
			rc = CSIO_EINVAL;
			goto out;
		}
		rc = csio_chnet_iface_do_vlan(hw, vlanid, ifid);
		break;
		
	case CSIO_APP_OP_SHOW:
		rc = csio_chnet_iface_do_show(hw, ifid, NULL);
		break;
		
	default:
		break;
	}

out:
	return rc;
}

int32_t
um_csio_chnet_ifconf_do_op(adap_handle_t hw, int32_t op, struct csio_chnet_ifconf_ioctl *um_req)
{                       
        int32_t rc = 0;
        
        switch (op) {
        case CSIO_APP_OP_ASSIGN: {
                if (um_req->type == CSIO_CHNET_L3CFG_TYPE_IPV4 ||
		    um_req->type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4) {
			char ip[16], gw[16], nm[16];

			convert_decimal_ip(ip, um_req->v4.ipv4_addr);
        		convert_decimal_ip(gw, um_req->v4.ipv4_gw);
			convert_decimal_ip(nm, um_req->v4.ipv4_mask);

                        rc = csio_chnet_ifconf_do_ipv4_assign(hw,
					um_req->type, ip, nm, NULL, gw,
					um_req->vlanid, um_req->ifid);
		} else if (um_req->type == CSIO_CHNET_L3CFG_TYPE_IPV6)
                        rc = csio_chnet_ifconf_do_ipv6_assign(hw,
				um_req->type, (char *) um_req->v6.ipv6_addr,
				um_req->v6.prefix_len,
				(char *)um_req->v6.ipv6_gw,
				um_req->vlanid, um_req->ifid);

                else if ((um_req->type == CSIO_CHNET_L3CFG_TYPE_DHCP) ||
			 (um_req->type == CSIO_CHNET_L3CFG_TYPE_DHCPV6))
                        rc = csio_chnet_ifconf_do_dhcp_assign(hw,
				um_req->type, um_req->vlanid, um_req->ifid);
                break;
	}

        case CSIO_APP_OP_SHOW:
                if ((um_req->type == CSIO_CHNET_L3CFG_TYPE_IPV4) ||
		    (um_req->type == CSIO_CHNET_L3CFG_TYPE_DHCP))
                        csio_chnet_ifconf_do_ipv4_show(hw, CSIO_CHNET_L3CFG_TYPE_IPV4,
                                                        um_req->vlanid, um_req->ifid, um_req);
                else if ((um_req->type == CSIO_CHNET_L3CFG_TYPE_IPV6) ||
			 (um_req->type == CSIO_CHNET_L3CFG_TYPE_DHCPV6))
                        csio_chnet_ifconf_do_ipv6_show(hw, CSIO_CHNET_L3CFG_TYPE_IPV6,
                                                        um_req->vlanid, um_req->ifid);
                break;

        case CSIO_APP_OP_CLEAR:
		csio_chnet_ifconf_do_ip_clear(hw, um_req->type,
					um_req->ifid, um_req->vlanid);
                break;

        default:
                break;
        }

        return rc;
}

int32_t
um_csio_chnet_iface_do_op(adap_handle_t hw, struct csio_chnet_iface_ioctl *um_ioc, struct csio_chnet_ifconf_ioctl *um_req)
{
        int32_t rc = 0;

        switch(um_ioc->op) {
        case CSIO_APP_OP_UP:
        case CSIO_APP_OP_DOWN:
                rc = csio_chnet_iface_do_link_op(hw, um_ioc->op, um_ioc->ifid, um_ioc->flags);
                break;

        case CSIO_APP_OP_MTU:
                if (um_req->mtu < 1500 || um_req->mtu > 9000) {
                        rc = CSIO_EINVAL;
                        goto out;
                }
                rc = csio_chnet_iface_do_mtu(hw, um_req->mtu, um_ioc->ifid);
                break;

        case CSIO_APP_OP_VLAN:
                if (!csio_chnet_is_valid_vlan(um_req->vlanid)) {
                        rc = CSIO_EINVAL;
                        goto out;
                }
                rc = csio_chnet_iface_do_vlan(hw, um_req->vlanid, um_ioc->ifid);
                break;

        case CSIO_APP_OP_SHOW:
                rc = csio_chnet_iface_do_show(hw, um_ioc->ifid, um_req);
                break;

        default:
                break;
        }

out:
        return rc;
}

int run_chnet_cmd(int argc, char *argv[])
{
	int ch, longindex, mode=-1;
	int rc=0, op=CSIO_APP_OP_NOOP;
	char *sip = NULL;
	char *mask = NULL, *bcaddr = NULL, *gw = NULL;
	char *device = NULL;
	adap_handle_t hw = -1;
	short mtu = -1;
	uint16_t type = CSIO_CHNET_L3CFG_TYPE_NONE;
	int oport_cnt = 0;
	int oup_cnt = 0;
	int odown_cnt = 0;
	int oping_cnt = 0;
	int oassign_cnt = 0;
	int oshow_cnt = 0;
	int ip_valid = 0;
	unsigned int prefix_len = 64;
	uint8_t ifid = -1;
	uint16_t vlanid = CSIO_CHNET_VLAN_NONE;
	uint8_t vlanprio = 0;
	uint8_t flags = 0;
	int8_t ping_timeout = -1;
	int32_t ping_cnt = -1;
	uint16_t pld_size = 56;
	struct ip_addr addr;

	csio_app_log_devel_debug("%s: entering\n", chnet_name);
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	optopt = 0;
	optind = 3;

	if (!strncmp(argv[2], chnet_base_opt, strlen(chnet_base_opt))) {
		memset(argv[2], 0, strlen(chnet_base_opt));
		strncpy(argv[2], "chnet", strlen(chnet_base_opt));
	}

	csio_app_log_devel_debug("%s: argv[0] %s, argv[1] %s\n",
					chnet_name, argv[0], argv[1]);


	while ((ch = getopt_long(argc, argv, short_options, long_options, &longindex)) >= 0) {

		csio_app_log_devel_debug("%s: ch : %c, longindex %d\n",
						chnet_name, ch, longindex);

		switch (ch) {
		case 'd':
			device = optarg;
			csio_app_log_devel_debug("%s: device %s\n",
							chnet_name, device);
			break;
		case 'o':
			op = str_to_op(optarg);
			if (op == CSIO_APP_OP_UP)
				oup_cnt++;
			else if (op == CSIO_APP_OP_DOWN)
				odown_cnt++;
			else if (op == CSIO_APP_OP_ASSIGN)
				oassign_cnt++;
			else if (op == CSIO_APP_OP_SHOW)
				oshow_cnt++;
			else if (op == CSIO_APP_OP_PING)
				oping_cnt++;

			csio_app_log_devel_debug("%s: opcode %d\n", chnet_name, op);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			csio_app_log_devel_debug("%s: mode %d\n", chnet_name, mode);
			break;
		case 'i':
			ifid = atoi(optarg);
			csio_app_log_devel_debug("%s: index %d\n", chnet_name, ifid);
			break;
		case 'r':
			sip = optarg;
			csio_app_log_devel_debug("%s: saddr %s\n", chnet_name, optarg);
			break;
		case 'a':
			sip = optarg;
			csio_app_log_devel_debug("%s: addr %s\n", chnet_name, optarg);
			break;
		case 'k':
			mask = optarg;
			csio_app_log_devel_debug("%s: mask %s\n", chnet_name, optarg);
			break;
		case 'g':
			gw = optarg;
			csio_app_log_devel_debug("%s: gw %s\n", chnet_name, optarg);
			break;
		case 'l':
			vlanid = atoi(optarg);
			csio_app_log_devel_debug("%s: vlanid %u\n", chnet_name, vlanid);
			break;
		case 'y':
			vlanprio = atoi(optarg);
			csio_app_log_devel_debug("%s: vlanprio %u\n", chnet_name, vlanprio);
			break;
		case 't':
			type = str_to_ifconf_type(optarg);
			csio_app_log_devel_debug("%s: type %d : %s\n", chnet_name, type, optarg);
			break;
		case 'u':
			mtu = atoi(optarg);
			csio_app_log_devel_debug("%s: mtu %d\n", chnet_name, mtu);
			break;
		case 'O':
			flags = atoi(optarg);
			break;
		case 'h':
			usage(0);
			break;
		case 'f':
			prefix_len = atoi(optarg);
			csio_app_log_devel_debug("%s: ipv6 prefix len %d\n",
					chnet_name, prefix_len);
			break;
		case 'p':
			if(!atoi(optarg) || (atoi(optarg) < 0) || atoi(optarg) > 120) {
				fprintf(stderr, "%s: Invalid timeout %d (valid: 1..120)\n",
							chnet_name, atoi(optarg));
				rc = CSIO_EINVAL;
				goto out;
			}
			ping_timeout = atoi(optarg);
			csio_app_log_devel_debug("%s: ping timeout %d\n", chnet_name, ping_timeout);
			break;
		case 'c':
			if(!atol(optarg) || (atol(optarg) < 0) || atol(optarg) > INT_MAX) {
				fprintf(stderr, "%s: Invalid count %ld(valid: 1..%d)\n",
							chnet_name, atol(optarg), INT_MAX);
				rc = CSIO_EINVAL;
				goto out;
			}
			ping_cnt = atoi(optarg);
			csio_app_log_devel_debug("%s: ping cnt %d\n", chnet_name, ping_cnt);
			break;
		case 's':
			if (!atol(optarg) || (atol(optarg) < 0) ||
			    atol(optarg) > INT_MAX) {
				fprintf(stderr,
					"%s: Invalid count %ld(valid: 1..%d)\n",
					chnet_name, atol(optarg), INT_MAX);
				rc = CSIO_EINVAL;
				goto out;
			}
			pld_size = atoi(optarg);
			csio_app_log_devel_debug("%s: ping payload size %d\n",
						 chnet_name, pld_size);
			break;
		case '?':
		default:
			usage(1);
			csio_app_log_devel_debug("in default\n");
			csio_app_log_devel_debug("%s: Invalid character %c\n", chnet_name, optopt);
			rc = CSIO_EINVAL;
			goto out;

			break;
		}
	}

	if (argc == 2)
		usage(0);
	
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	if (optind < argc) {
		fprintf(stderr, "%s: unrecognised option %s\n", chnet_name, argv[optind]);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (optopt) {
		fprintf(stderr, "%s: Invalid character %c\n", chnet_name, optopt);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (!device) {
		fprintf(stderr, "%s: Please specify Chelsio device node\n", chnet_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (mode < 0) {
		fprintf(stderr, "Mode is a required parameter\n");
		usage(1);
	}

	if(vlanid > CSIO_CHNET_VLAN_NONE) {
		fprintf(stderr, "%s: Vlan ID %d invalid\n", chnet_name, vlanid);
		rc = CSIO_EINVAL;
		goto out;
	}

	if(vlanprio > 7) {
		fprintf(stderr, "%s: Vlan Priority %d invalid\n", chnet_name, vlanprio);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (device) {
		hw = open_adapter_handle(device);

		if (hw == -1 || (csio_probe_adapter(hw) != 0)) {
			fprintf(stderr, "%s: error opening device %s, %s\n", chnet_name, device, strerror(errno));
			rc = errno;
			goto out;
		}
	}

	if(op == CSIO_APP_OP_PING && ping_timeout < 0) {
		 csio_app_log_devel_debug("%s: Ping timeout not specified, using default 30\n", chnet_name);
		ping_timeout = 30;
	}

	if(op == CSIO_APP_OP_PING && ping_cnt < 0) {
		 csio_app_log_devel_debug("%s: Ping count not specified, using default 1\n", chnet_name);
		ping_cnt = 1;
	}

	switch (mode) {
	case CSIO_APP_MOD_CHNET_IFACE:

		if (op == CSIO_APP_OP_NOOP) {
			fprintf(stderr, "please specify an operation you want to perform.\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (ifid == (uint8_t)-1) {
			fprintf(stderr, "please specify a valid --ifid\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (mtu != -1 && vlanid != CSIO_CHNET_VLAN_NONE) {
			fprintf(stderr, "invalid option combination\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (op == CSIO_APP_OP_UP || op == CSIO_APP_OP_DOWN) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = CSIO_EINVAL;
				goto out;
			}

			if (oport_cnt > 1) {
				fprintf(stderr, "iface, multiple --ifid option is invalid\n");
				rc = CSIO_EINVAL;
				goto out;
			}
		} else if (op == CSIO_APP_OP_MTU) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiuO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = CSIO_EINVAL;
				goto out;
			}
		} else if (op == CSIO_APP_OP_VLAN) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoilyO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = CSIO_EINVAL;
				goto out;
			}
		} else if (op == CSIO_APP_OP_ASSIGN || op == CSIO_APP_OP_SHOW) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoiO", 0))) {
				fprintf(stderr, "iface, option '-%c' is not "
						"supported\n",rc);
				rc = CSIO_EINVAL;
				goto out;
			}
		}

		vlanid = (vlanid & 0x0fff) | (vlanprio << 13);
		csio_app_log_devel_debug("flags %u\n", flags);
		rc = csio_chnet_iface_do_op(hw, op, mtu, vlanid, ifid, flags);
		break;

	case CSIO_APP_MOD_CHNET_IFCONF:
		
		if (op == CSIO_APP_OP_NOOP) {
			fprintf(stderr, "ifconf, please specify an operation you want to perform.\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (type == CSIO_CHNET_L3CFG_TYPE_NONE) {
			fprintf(stderr, "ifconf, required option --type is missing\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (ifid == (uint8_t)-1) {
			fprintf(stderr, "ifconf, required option --ifid is missing\n");
			rc = CSIO_EINVAL;
			goto out;
		}

		if (op == CSIO_APP_OP_ASSIGN) {
			
			if (type == CSIO_CHNET_L3CFG_TYPE_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitrkglyf", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = CSIO_EINVAL;
					goto out;
				}
				
				if (!sip) {
					fprintf(stderr, "ifconf: please specify --saddr\n");
					rc = CSIO_EINVAL;
					goto out;
				}

				if(type == CSIO_CHNET_L3CFG_TYPE_IPV4)
					ip_valid = inet_pton(AF_INET, sip, &addr.ip4);
				else if(type == CSIO_CHNET_L3CFG_TYPE_IPV6)
					ip_valid = inet_pton(AF_INET6, sip, &addr.ip6); 

				if(ip_valid != 1) {
					fprintf(stderr, "ifconf: IPV%d address %s invalid\n",
						(type == CSIO_CHNET_L3CFG_TYPE_IPV4?4:6), sip);
					rc = CSIO_EINVAL;
					goto out;
				}
			/*} else if (type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitrkgl", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = CSIO_EINVAL;
					goto out;
				}
				
				if (!sip) {
					fprintf(stderr, "ifconf: please specify --saddr\n");
					rc = CSIO_EINVAL;
					goto out;
				}*/

			} else if (type == CSIO_CHNET_L3CFG_TYPE_DHCP) {
				if ((rc = verify_short_mode_params(argc, argv, "mdoitly", 0))) {
					fprintf(stderr, "ifconf, option '-%c' is not "
							"supported\n", rc);
					rc = CSIO_EINVAL;
					goto out;

				}
			}
		} else if (op == CSIO_APP_OP_SHOW || op == CSIO_APP_OP_CLEAR) {
			if ((rc = verify_short_mode_params(argc, argv, "mdoitly", 0))) {
				fprintf(stderr, "ifconf, option '-%c' is not "
						"supported\n", rc);
				rc = CSIO_EINVAL;
				goto out;
			}
		} else if (op == CSIO_APP_OP_PING) {
			if(type != CSIO_CHNET_L3CFG_TYPE_IPV4 &&
				type != CSIO_CHNET_L3CFG_TYPE_IPV6 &&
				type != CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4 &&
				type != CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6) { 
				fprintf(stderr, "ifconf: Invalid type %d(should be IPV4/IPV6)\n", type);
				rc = CSIO_EINVAL;
				goto out;
			}

			if ((rc = verify_short_mode_params(argc, argv, "mdoitalypcs", 0))) {
				fprintf(stderr, "ifconf, option '-%c' is not "
						"supported\n", rc);
				rc = CSIO_EINVAL;
				goto out;
			}

			if (!sip) {
				fprintf(stderr, "ifconf: please specify --addr\n");
				rc = CSIO_EINVAL;
				goto out;
			}

			if(type == CSIO_CHNET_L3CFG_TYPE_IPV4 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV4)
				ip_valid = inet_pton(AF_INET, sip, &addr.ip4);
			else if(type == CSIO_CHNET_L3CFG_TYPE_IPV6 || type == CSIO_CHNET_L3CFG_TYPE_VLAN_IPV6)
				ip_valid = inet_pton(AF_INET6, sip, &addr.ip6); 

			if(ip_valid != 1) {
				fprintf(stderr, "ifconf: IPV%d address %s invalid\n",
					((type & 0x1)?4:6), sip);
				rc = CSIO_EINVAL;
				goto out;
			}
		}
		vlanid = (vlanid & 0x0fff) | (vlanprio << 13);
		rc = csio_chnet_ifconf_do_op(hw, op, type, sip, mask,
					     bcaddr, gw, vlanid, ifid,
					     prefix_len, ping_timeout,
					     ping_cnt, pld_size);
		break;
	default:
		fprintf(stderr, "%s: Unsupported Mode\n", chnet_name);
		usage(0);
	}

out:
	if (rc > 0 && rc <= CSIO_ELAST)
		fprintf(stderr, "%s\n", csio_err_to_msg(rc));
	else if (rc > CSIO_ELAST)
		fprintf(stderr, "Invalid parameter, retval %d\n", rc);
	
	if (hw != -1)
		close_adapter(hw);
	
	/*csio_app_log_devel_debug("%s: %d: %s\n", chnet_name, rc, retval_to_str(rc));*/
	
	return 0;
}
