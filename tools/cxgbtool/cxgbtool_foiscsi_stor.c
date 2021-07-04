#include <csio_hw.h>
#include <csio_common.h>
#include <csio_foiscsi.h>
#include <cxgbtool_stor.h>
#include <cxgbtool_foiscsi_stor.h>
#include <csio_services.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>
#include <csio_chnet_ioctl.h>
#include <getopt.h>
#include <arpa/inet.h>

static const char *foiscsi_name = "cxgbtool stor --foiscsi ";
static const char *foiscsi_base_opt = "--foiscsi";
/* move these to related headers */

/* ======================================= */

static struct option const long_options[] = 
{
	{"mode", required_argument, NULL, 'm'},
	{"dev", required_argument, NULL, 'd'},
	{"portal", required_argument, NULL, 'P'},
	{"persistent", no_argument, NULL, 'B'},
	{"idx", required_argument, NULL, 'x'},
	{"targetname", required_argument, NULL, 'T'},
	{"sid", required_argument, NULL, 's'},
	{"nodeid", required_argument, NULL, 'e'},
	{"saddr", required_argument, NULL, 'r'},
	{"loopback", required_argument, NULL, 'O'},
	{"op", required_argument, NULL, 'o'},
	{"vlanid", required_argument, NULL, 'l'},
	{"name", required_argument, NULL, 'n' },
	{"alias", required_argument, NULL, 'a' },
	{"port", required_argument, NULL, 'p'},
	{"ini_user", required_argument, NULL, 'I'},
	{"ini_sec", required_argument, NULL, 'S'},
	{"tgt_user", required_argument, NULL, 'R'},
	{"tgt_sec", required_argument, NULL, 'C'},
	{"auth", required_argument, NULL, 'A'},
	{"policy", required_argument, NULL, 'L'},
	{"help", no_argument, NULL, 'h'},
	{"prefix", required_argument, NULL, 'f'},
	{"vend_key", required_argument, NULL, 'k'},
	{"vend_val", required_argument, NULL, 'v'},
	{"tcp_wscale", required_argument, NULL, 'w'},
	{"tcp_wsen", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "hm:P:T:o:i:n:a:p:s:d:t:I:r:u:I:S:R:C:A:L:k:v:w:c";

static void usage(int status)
{

	if (status)
		fprintf(stderr, "Try cxgbtool stor --foiscsi --help for more information\n");
	else {
		printf("Usage: cxgbtool stor --foiscsi [OPTION]\n");
		printf("\
cxgbtool stor --foiscsi --mode init-instance --dev device --op assign --nodeid 1...n --name node_name --alias alias --ini_user ini_username --ini_sec ini_chap_secret\n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op clear --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op show \n\
cxgbtool stor --foiscsi --mode init-instance --dev device --op show -nodeid 1...n \n\
\n\
cxgbtool stor --foiscsi --mode discovery --dev device --nodeid 1...n --saddr saddr --portal portal\n\
\n\
cxgbtool stor --foiscsi --mode session --dev device --op login --nodeid 1...n --saddr saddr --target target_name --portal portal --auth auth_method --policy auth_policy --tgt_user tgt_username --tgt_sec tgt_chap_secret --persistent --tcp_wsen --tcp_wscale <0-12>\n\
cxgbtool stor --foiscsi --mode session --dev device --op logout --nodeid 1...n --sid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op logout --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op show \n\
cxgbtool stor --foiscsi --mode session --dev device --op show --nodeid 1...n \n\
cxgbtool stor --foiscsi --mode session --dev device --op show --nodeid 1...n --sid 1...n\n\
\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op show\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op clear\n\
cxgbtool stor --foiscsi --mode persistent --dev device --op clear --idx 0...n\n\n\
cxgbtool stor --foiscsi --mode hw --dev device --op show\n\
cxgbtool stor --foiscsi --mode hw --dev device --op dcbx\n");
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

int32_t
csio_foiscsi_persistent_do_op_clear(adap_handle_t hw, int32_t op, uint8_t idx)
{
	void *buffer = NULL;
	struct iscsi_persistent_target_db  *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_PERSISTENT_CLEAR_IOCTL);
	uint32_t rc = 0;
	
	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
        }

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct iscsi_persistent_target_db *)get_payload(buffer);
	memset(req, 0, sizeof(*req));
	req->num_persistent_targets = idx;

	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0) {
		fprintf(stderr, "ioctl successful\n");
	} else
		fprintf(stderr, "invalid parameter\n");

	ioctl_buffer_free(buffer);

out:
        return rc;
}

int32_t
csio_foiscsi_persistent_do_op_show(adap_handle_t hw, int32_t op)
{
	void *buffer = NULL;
	struct iscsi_persistent_target_db  *req = NULL;
	struct in_addr saddr, taddr;
	char ip6[INET6_ADDRSTRLEN];
	size_t len = os_agnostic_buffer_len(sizeof(*req));
	uint32_t cmd = CSIO_STOR_FOISCSI_OPCODE(CSIO_FOISCSI_PERSISTENT_GET_IOCTL);
	int rc = 0, j = 0;

	if (hw < 0) {
		fprintf(stderr, "%s: No chelsio T4 CNA available\n", foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", foiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	req = (struct iscsi_persistent_target_db *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	rc = issue_ioctl(hw, buffer, len);
	if (rc == 0)
		fprintf(stderr, "ioctl successful\n");
	else
		fprintf(stderr, "\nInvalid parameter\n");

	for (j=0; j< req->num_persistent_targets; j++) {
		if (req->target[j].valid == VALID_REC) {
			printf("========Target Record idx %d ========\n",j);
			printf("target iqn = %s\n",req->target[j].targname);
			if (!req->target[j].flag) {
				taddr.s_addr = ntohl(
					req->target[j].portal.taddr.ipv4_address);
				printf("Target Portal  = %s:%u\n",
				       inet_ntoa(taddr),req->target[j].portal.tcpport);
				saddr.s_addr = ntohl(req->target[j].saddr);
                        	printf("Source Address = %s\n",inet_ntoa(saddr));
			} else {
				inet_ntop(AF_INET6, req->target[j].portal.taddr.ipv6_address, ip6, INET6_ADDRSTRLEN);
				printf("Target Portal  = [%s]:%u\n", ip6, req->target[j].portal.tcpport);
				inet_ntop(AF_INET6, req->target[j].saddr6, ip6, INET6_ADDRSTRLEN);
				printf("Source Address = %s\n", ip6);
			}
			printf("node Id = %u\n",req->target[j].node_id);
			printf("max conn = %u\n",req->target[j].attr.max_conn);
			printf("maxR2t = %u\n",req->target[j].attr.max_r2t);
			printf("time2wait = %u\n",req->target[j].attr.time2wait);
			printf("time2retain = %u\n",req->target[j].attr.time2retain);
			printf("max_burst = %u\n",req->target[j].attr.max_burst);
			printf("first_burst = %u\n",req->target[j].attr.first_burst);
			printf("max_rcv_dsl = %u\n",req->target[j].attr.max_rcv_dsl);
			printf("ping timeout = %u\n\n",req->target[j].attr.ping_tmo);
		}
	}	

	csio_app_log_devel_debug("%s: status %d\n", foiscsi_name, rc);
	ioctl_buffer_free(buffer);
out:
        return rc;
}

int32_t
csio_foiscsi_persistent_do_op(adap_handle_t hw, int32_t op, uint8_t idx)
{
	int32_t rc = 0;
        
	switch (op) {
	case CSIO_APP_OP_SHOW:
		rc = csio_foiscsi_persistent_do_op_show(hw, op);
		break;
	case CSIO_APP_OP_CLEAR:
		rc = csio_foiscsi_persistent_do_op_clear(hw, op, idx);
		break;
	default:
		fprintf(stderr, "Invalid options\n");
		break;
	}
	return rc;
}

int run_foiscsi_stor(int argc, char *argv[])
{
	int ch, longindex, mode=-1;
	int rc=0, op=CSIO_APP_OP_NOOP;
	unsigned long sid = -1;
	char *targetname = NULL, *ip = NULL, *sip = NULL;
	int tpgt, tcp_port = DEFAULT_ISCSI_TARGET_PORT;
	int nodeid = -1, persistent = 0;
	char *nodename = NULL, *alias = NULL;
	char *ini_user = NULL, *ini_sec = NULL;
        char *tgt_user = NULL, *tgt_sec = NULL;\
	char *auth_method = NULL, *policy = NULL;
        char *vend_key = NULL, *vend_val = NULL;
	char *device = NULL;
	adap_handle_t hw = -1;
	int oup_cnt = 0;
	int odown_cnt = 0;
	int oassign_cnt = 0;
	int oshow_cnt = 0;
	uint8_t idx = -1, tcp_wscale = 0, tcp_wsen = 0;
	uint16_t vlanid = CSIO_CHNET_VLAN_NONE;
	uint8_t maxnodenamelen = FW_FOISCSI_NAME_MAX_LEN - 1;
	uint8_t maxaliaslen = FW_FOISCSI_ALIAS_MAX_LEN - 1;

	csio_app_log_devel_debug("%s: entering\n", foiscsi_name);
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	optopt = 0;
	optind = 3;

	if (!strncmp(argv[2], foiscsi_base_opt, strlen(foiscsi_base_opt))) {
		memset(argv[2], 0, strlen(foiscsi_base_opt));
		strncpy(argv[2], "foiscsi", strlen(foiscsi_base_opt));
	}

	csio_app_log_devel_debug("%s: argv[0] %s, argv[1] %s\n",
					foiscsi_name, argv[0], argv[1]);


	while ((ch = getopt_long(argc, argv, short_options, long_options, &longindex)) >= 0) {

		csio_app_log_devel_debug("%s: ch : %c, longindex %d\n",
						foiscsi_name, ch, longindex);

		switch (ch) {
		case 'd':
			device = optarg;
			csio_app_log_devel_debug("%s: device %s\n",
							foiscsi_name, device);
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
			
			csio_app_log_devel_debug("%s: opcode %d\n", foiscsi_name, op);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			csio_app_log_devel_debug("%s: mode %d\n", foiscsi_name, mode);
			break;
		case 'a':
			alias = optarg;
			csio_app_log_devel_debug("%s: alias %s\n", foiscsi_name, alias);
			break;
		case 'n':
			nodename = optarg;
			csio_app_log_devel_debug("%s: nodename %s\n", foiscsi_name, nodename);
			break;
		case 'p':
			csio_app_log_devel_debug("%s: optarg %s\n", foiscsi_name, optarg);
			break;
		case 'T':
			targetname = optarg;
			csio_app_log_devel_debug("%s: targetname %s\n", foiscsi_name, targetname);
			break;
		case 'P':
			ip = str_to_ipport(optarg, &tcp_port, &tpgt);
			break;
		case 's':
			sid = strtoull(optarg, NULL, 10);
			break;
		case 'r':
			sip = optarg;
			csio_app_log_devel_debug("%s: saddr %s\n", foiscsi_name, optarg);
			break;
		case 'l':
			vlanid = atoi(optarg);
			csio_app_log_devel_debug("%s: vlanid %u\n", foiscsi_name, vlanid);
			break;
		case 'B':
			persistent = 1;
			break;
		case 'x':
			idx = atoi(optarg);
			csio_app_log_devel_debug("%s: index %d\n", foiscsi_name, idx);
			break;
		case 'e':
			nodeid = strtoull(optarg, NULL, 10);
			break;
		case 'I':
			ini_user = optarg;
			break;
		case 'S':
			ini_sec = optarg;
			break;
		case 'R':
			tgt_user = optarg;
			break;
		case 'C':
			tgt_sec = optarg;
			break;
		case 'A':
			auth_method = optarg;
			break;
		case 'L':
			policy = optarg;
			break;
		case 'h':
			usage(0);
			break;
		case 'k':
			vend_key = optarg;
			csio_app_log_devel_debug("%s: vend_key %s\n",
						foiscsi_name, vend_key);
			break;
		case 'v':
			vend_val = optarg;
			csio_app_log_devel_debug("%s: vend_val%s\n",
						foiscsi_name, vend_val);
			break;
		case 'w':
			tcp_wscale = atoi(optarg);
			csio_app_log_devel_debug("%s: tcp_window_scale [%d]\n",
						foiscsi_name, tcp_wscale);
			break;
		case 'c':
			tcp_wsen = 1;
			csio_app_log_devel_debug("%s: tcp_window_scale [%s]\n",
						foiscsi_name, tcp_wsen ?
						"ENABLED" : "DISABLED");
			break;
		case '?':
		default:
			usage(1);
			csio_app_log_devel_debug("in default\n");
			csio_app_log_devel_debug("%s: Invalid character %c\n", foiscsi_name, optopt);
			rc = CSIO_EINVAL;
			goto out;

			break;
		}
	}

	if (argc == 3)
		usage(0);
	
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	if (optind < argc) {
		fprintf(stderr, "%s: unrecognised option %s\n", foiscsi_name, argv[optind]);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (optopt) {
		fprintf(stderr, "%s: Invalid character %c\n", foiscsi_name, optopt);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (!device) {
		fprintf(stderr, "%s: Please specify Chelsio device node\n", foiscsi_name);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (mode < 0) {
		fprintf(stderr, "Mode is a required parameter\n");
		usage(1);
	}

	if (device) {
		hw = open_adapter_handle(device);

		if (hw == -1 || (csio_probe_adapter(hw) != 0)) {
			fprintf(stderr, "%s: error opening device %s, %s\n", foiscsi_name, device, strerror(errno));
			rc = errno;
			goto out;
		}
	}

	switch (mode) {
	case CSIO_APP_MOD_FOISCSI_INIT_INST:

		if ((rc = verify_short_mode_params(argc, argv, "moineadkvIS", 0))) {
			fprintf(stderr, "%s: init-instance option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = CSIO_EINVAL;
			goto out;
		}

		if (nodename && strlen(nodename) > maxnodenamelen) {
			fprintf(stderr, "Invalid nodename length %d\n", (int)strlen(nodename));
			rc = CSIO_EINVAL;
			goto out;
		}

		if (alias && strlen(alias) > maxaliaslen) {
			fprintf(stderr, "Invalid alias length %d\n", (int)strlen(alias));
			rc = CSIO_EINVAL;
			goto out;
		}

		rc = foiscsi_manage_instance(hw, op, nodeid, nodename, alias,
				ini_user, ini_sec, vend_key, vend_val);
		break;

	case CSIO_APP_MOD_FOISCSI_DSC:
		
		if ((rc = verify_short_mode_params(argc, argv, "mirePdl", 0))) {
			fprintf(stderr, "%s: discovery option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = CSIO_EINVAL;
			goto out;
		}

		rc = foiscsi_do_discovery(hw, op, nodeid, sip, ip, tcp_port,
					vlanid, NULL);
		break;

	case CSIO_APP_MOD_FOISCSI_SSN:
		
		if ((rc = verify_short_mode_params(argc, argv,
					"moiseSrTPdALRCBlwc", 0))) {
			fprintf(stderr, "%s: session option '-%c' is not "
					"supported\n", foiscsi_name, rc);
			rc = CSIO_EINVAL;
			goto out;
		}

		if (op == CSIO_APP_OP_LOGIN) {
			if (nodeid == -1 ||
				sip == NULL || targetname == NULL ||
				ip == NULL || !tcp_port) {
				fprintf(stderr,
					"required parameter missing\n\n");
				rc = CSIO_EINVAL;
				goto out;
			} else if (tcp_wscale && !tcp_wsen) {
				fprintf(stderr, "%s: Must enable '--tcp_wsen' "
					"to use '--tcp_wscale <0-3>'\n",
					foiscsi_name);
				rc = CSIO_EINVAL;
				goto out;
			} else if (tcp_wscale > 3) {
				fprintf(stderr, "%s: Using max possible window "
					"scale: 3\n", foiscsi_name);
				tcp_wscale = 3;
			}

			csio_app_log_devel_debug("\tnodeid: %d\n"
						"\tsource ip: %s\n"
						"\tTargetName: %s\n"
						"\tdestinatip ip: %s\n"
						"\tport: %d\n"
						"\tpersistent: %d\n",
						nodeid, sip, targetname, 
						ip, tcp_port, persistent);
		} else if (op == CSIO_APP_OP_LOGOUT) {
			if (nodeid == -1) {
				fprintf(stderr, "required parameter missing\n\n");
				rc = CSIO_EINVAL;
				goto out;
			}

			csio_app_log_devel_debug("\tnodeid %d\n"
							"\tsid %ld\n",
							nodeid, sid);
		}
		
		rc = foiscsi_manage_session(hw, op, nodeid, sip, targetname,
				ip, tcp_port, sid, auth_method, policy, 
				tgt_user, tgt_sec, persistent, vlanid,
				tcp_wscale, tcp_wsen);
		break;

	case CSIO_APP_MOD_FOISCSI_PRST:
		if (op == CSIO_APP_OP_CLEAR || op == CSIO_APP_OP_SHOW ) {
			rc = csio_foiscsi_persistent_do_op(hw, op, idx);
		}			
		break;

	case CSIO_APP_MOD_HW:
		if ((rc = verify_short_mode_params(argc, argv, "mdo", 0))) {
			fprintf(stderr, "ifconf, option '-%c' is not "
					"supported\n", rc);
			rc = CSIO_EINVAL;
			goto out;
		}
		if (op == CSIO_APP_OP_DCBX)
			rc = csio_print_all_dcbx_info(hw);
		else
			rc = csio_print_hw_info(hw);

		break;
	
	default:
		fprintf(stderr, "%s: Unsupported Mode\n", foiscsi_name);
		usage(0);
	}

out:
	if (rc > 0 && rc <= CSIO_ELAST)
		fprintf(stderr, "%s\n", csio_err_to_msg(rc));
	else if (rc > CSIO_ELAST)
		fprintf(stderr, "Invalid parameter, retval %d\n", rc);
	
	if (hw != -1)
		close_adapter(hw);
	
	/*csio_app_log_devel_debug("%s: %d: %s\n", foiscsi_name, rc, retval_to_str(rc));*/
	
	return 0;
}
