#include <csio_hw.h>
#include <csio_common.h>
#include <csio_foiscsi.h>
#include <cxgbtool_foiscsi_stor.h>
#include <csio_services.h>
#include <csio_coiscsi_ioctl.h>
#include <csio_chnet_ioctl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <coiscsi_helpers.h>
#include <coiscsi_stor_params.h>

#define min(a, b) (((a) < (b)) ? (a) : (b))

#define ISCSI_PDU_NONPAYLOAD_LEN        (56) /* bhs(48) + digest(8) */
#define ULP2_MAX_PKT_SIZE       (16224)
#define ULP2_MAX_PDU_PAYLOAD    (ULP2_MAX_PKT_SIZE - ISCSI_PDU_NONPAYLOAD_LEN)

static const char *coiscsi_name = "cxgbtool stor --coiscsi ";
static const char *coiscsi_base_opt = "--coiscsi";
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
	{"nodeid", required_argument, NULL, 'e'},
	{"laddr", required_argument, NULL, 'r'},
	{"loopback", required_argument, NULL, 'O'},
	{"op", required_argument, NULL, 'o'},
	{"ifid", required_argument, NULL, 'i'},
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
	{"tid", required_argument, NULL, 't'},
	{"tcp_wscale", required_argument, NULL, 'w'},
	{"tcp_wsen", no_argument, NULL, 'c'},
	{NULL, 0, NULL, 0},
};

static char *short_options = "hm:P:T:o:i:n:a:p:s:d:t:I:r:u:I:S:R:C:A:L:w:c";

static void usage(int status)
{

	if (status)
		fprintf(stderr, "Try cxgbtool stor --coiscsi --help for more information\n");
	else {
		printf("Usage: cxgbtool stor --coiscsi [OPTION]\n");
		printf("\
\n\
cxgbtool stor --coiscsi --mode target --dev device --op assign --name iqn/ALL "
"--tcp_wsen --tcp_wscale <0-12>\n\
cxgbtool stor --coiscsi --mode target --dev device --op clear --name iqn/ALL\n\
cxgbtool stor --coiscsi --mode target --dev device --op update --name iqn/ALL\n\
cxgbtool stor --coiscsi --mode target --dev device --op show --name iqn/ALL\n\
cxgbtool stor --coiscsi --mode target --dev device --op stats\n\
cxgbtool stor --coiscsi --mode target --dev device --op statsclr\n\
\n\
cxgbtool stor --coiscsi --mode hw --dev device --op show\n\
cxgbtool stor --coiscsi --mode hw --dev device --op dcbx\n");
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

static void enqueue_lun_port(struct coiscsi_parse_inst *inst, char *lun,
			     uint16_t port, char *ip_str, uint16_t tpgt,
			     enum vla_type type, uint16_t redir_p)
{
	struct coiscsi_lun_portal *lunp = NULL, *trav = NULL;

	lunp = malloc(sizeof(struct coiscsi_lun_portal));

	memset(lunp, 0, sizeof(struct coiscsi_lun_portal));

	switch (type) {
	case type_lun:
		lunp->l.disk = malloc(strlen(lun) + 1);
		memcpy(lunp->l.disk, lun, strlen(lun) + 1);
		lunp->l.disk[strlen(lun)] = '\0';
		lunp->l.lun_len = strlen(lun) + 1;
		inst->lun_count++;

                if (!inst->l_list)
                        inst->l_list = lunp;
                else
                        trav = inst->l_list;

		break;
	case type_port:
		lunp->p.t_port = port;
		lunp->p.tpgt = tpgt;
		lunp->p.redir = redir_p;

		if (strchr(ip_str, ':') != strrchr(ip_str, ':')) {
			inet_pton(AF_INET6, ip_str, &lunp->p.listen_addr.ip6);
			lunp->p.ip_type = CSIO_CHNET_L3CFG_TYPE_IPV6;
		} else {
			lunp->p.listen_addr.ip4 = inet_network(ip_str);
			lunp->p.ip_type = CSIO_CHNET_L3CFG_TYPE_IPV4;
		}
		inst->port_count++;

		if (!inst->p_list)
                        inst->p_list = lunp;
                else
                        trav = inst->p_list;

		break;
	/* Reuse disk pointer to store acl list */
	case type_acl:
		lunp->l.disk = malloc(strlen(lun) + 1);
		memcpy(lunp->l.disk, lun, strlen(lun) + 1);
		lunp->l.disk[strlen(lun)] = '\0';
		lunp->l.lun_len = strlen(lun) + 1;

                if (!inst->a_list)
                        inst->a_list = lunp;
                else
                        trav = inst->a_list;

		break;
	default:
		break;
	}

	lunp->next = NULL;

	if (trav) {
		while(trav->next)
			trav = trav->next;

		trav->next = lunp;
	}
}

static int param_verify(enum v_pars v_type, char *val, int i_val)
{
	switch (coiscsi_param_set[v_type].type) {
	case t_str:
		if (coiscsi_param_set[v_type].min)
			if (strlen(val) < coiscsi_param_set[v_type].min) {
				fprintf(stderr, "Length of %s must be atleast %u\n",
					coiscsi_param_set[v_type].name, coiscsi_param_set[v_type].min);
				return CSIO_EINVAL;
			}
                if (coiscsi_param_set[v_type].max)
                        if (strlen(val) > coiscsi_param_set[v_type].max) {
				fprintf(stderr, "Length of %s must not be more than %u\n",
					coiscsi_param_set[v_type].name, coiscsi_param_set[v_type].max);
                                return CSIO_EINVAL;
			}
		break;
	case t_val:
                if ((coiscsi_param_set[v_type].min &&
                        i_val < coiscsi_param_set[v_type].min) ||
                    (coiscsi_param_set[v_type].max &&
                        i_val > coiscsi_param_set[v_type].max)) {

			fprintf(stderr, "Value of %s must be in range [%u - %u]\n",
				coiscsi_param_set[v_type].name, coiscsi_param_set[v_type].min,
				coiscsi_param_set[v_type].max);
			return CSIO_EINVAL;
		}
                break;
	case t_bool:
		if (strncmp(val, "Yes", 3) && strncmp(val, "No", 2)) {
			fprintf(stderr, "Value of %s must be Yes or No\n",
			        coiscsi_param_set[v_type].name);
			return CSIO_EINVAL;
		}
		break;
	default:
		return -1;
	}

	return 0;
}

void csio_coiscsi_portal_close(adap_handle_t hw, struct coiscsi_ioctl_list **base_p, struct coiscsi_parse_inst *inst)
{
	void *buffer = NULL, *buf2 = NULL;
	struct coiscsi_target_info_ioctl *req = NULL;
	struct coiscsi_target_ioctl *treq = NULL;
	struct coiscsi_portal_info co_portal;
	struct coiscsi_ioctl_list *trav = *base_p, *l_node;
	struct coiscsi_lun_portal *port = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_info_ioctl));
	uint32_t cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_TARGET_INFO_IOCTL);
	uint32_t rc=0, p_count, i;
	uint16_t total_size = 0, match = 0;
	char *ltmp = NULL;

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	req = (struct coiscsi_target_info_ioctl *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	memcpy(req->tgt_name, inst->tgt_name, FW_FOISCSI_NAME_MAX_LEN);

	rc = issue_ioctl(hw, buffer, len);
	req = (struct coiscsi_target_info_ioctl *)get_payload(buffer);

	if (rc)
		goto out;

	csio_app_log_devel_debug(" Found %s lun_c %d p_c %d\n", req->tgt_name, req->lun_count, req->portal_count);

	p_count = req->portal_count;
	total_size = req->lun_buf_size;

	ioctl_buffer_free(buffer);

	/* Move from info to actual target params */
	cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_SHOW_TARGET_IOCTL);

	len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_ioctl) + (sizeof(char) * total_size) + sizeof(struct coiscsi_portal_info) * p_count);

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
	treq = (struct coiscsi_target_ioctl *)get_payload(buffer);
	memset(treq, 0, sizeof(*treq));

	memcpy(treq->tinst.tgt_name, inst->tgt_name, FW_FOISCSI_NAME_MAX_LEN);

	rc = issue_ioctl(hw, buffer, len);
	treq = get_payload(buffer);

	port = inst->p_list;

	ltmp = (char *)treq->tinst.tgt_disk + total_size;

	for (i = 0; i < p_count; i++) {
		memset(&co_portal, 0, sizeof(struct coiscsi_portal_info));
		memcpy(&co_portal, ltmp, sizeof(struct coiscsi_portal_info));

		match = 0;
		port = inst->p_list;
		while (port) {
			if (port->p.ip_type != co_portal.ip_type ||
			    port->p.t_port != co_portal.port ||
			    port->p.tpgt != co_portal.tpgt) {
				if (port->next) {
					port = port->next;
					continue;
				} else {
					break;
				}
			}

			if (port->p.ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
				if (!memcmp(&co_portal.ip, &port->p.listen_addr, sizeof(struct ip_addr)))
					match = 1;
			} else {
				if (co_portal.ip.ip4 == port->p.listen_addr.ip4)
					match = 1;
			}

			if (match)
				break;

			if (port->next)
				port = port->next;
			else
				break;
		}

		if (match) {
			l_node = malloc(sizeof(struct coiscsi_ioctl_list));

			if (!l_node) {
				fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
				rc = CSIO_ENOMEM;
				goto out;
			}

			cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_STOP_TARGET_IOCTL);
			len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_ioctl));

			buf2 = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
			if (!buf2) {
				fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
				rc = CSIO_ENOMEM;
				goto out;
			}

			csio_init_header(buf2, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);
			treq = (struct coiscsi_target_ioctl *)get_payload(buf2);
			memset(treq, 0, sizeof(struct coiscsi_target_ioctl));

			memcpy(treq->tinst.tgt_name, inst->tgt_name, FW_FOISCSI_NAME_MAX_LEN);
			treq->conn_attr.listen_port = co_portal.port;
			treq->conn_attr.tpgt = co_portal.tpgt;
			memcpy(&treq->conn_attr.listen_addr, &co_portal.ip, sizeof(struct ip_addr));

			l_node->next = NULL;
			l_node->len = len;
			l_node->i_buf = buf2;

			if (trav) {
				trav->next = l_node;
				trav = trav->next;
			} else {
				*base_p = l_node;
				trav = *base_p;
			}
		}

		ltmp += sizeof(struct coiscsi_portal_info);
	}

	ioctl_buffer_free(buffer);
	return;
out:
	return;
}

int make_ioctl(adap_handle_t hw, struct coiscsi_ioctl_list **i_list, struct coiscsi_parse_inst *inst,
	       struct coiscsi_target_disc *disc, uint32_t cmd_type, int op)
{
	void *buffer = NULL, *disk_buf = NULL;
	struct coiscsi_target_ioctl *req = NULL;
	struct coiscsi_ioctl_list *l_node = NULL, *trav;
	struct coiscsi_lun_portal *port = NULL, *lun = NULL;
	struct coiscsi_vla_block v_block;
	size_t len;
	uint32_t cmd = CSIO_STOR_COISCSI_OPCODE(cmd_type);
	uint32_t rc=0;
	uint16_t disk_buf_len = 0, acl_len = 0;
	int i, j;

	/* Find end of the list */
	trav = *i_list;
	while(trav && trav->next)
		trav = trav->next;

	port = inst->p_list;

	if (!inst->port_count) {
		fprintf(stderr, "No portal specified for target %s\n", inst->tgt_name);
		return CSIO_EINVAL;
	}

        /* If Discovery CHAP is enabled, make sure requisite parameters are provided. */
        if (disc->disc_auth_method == FW_FOISCSI_AUTH_METHOD_CHAP) {
		if (disc->disc_auth_policy == FW_FOISCSI_AUTH_POLICY_MUTUAL)
			if (!strlen((char *)disc->disc_chap_id) || !strlen((char *)disc->disc_chap_sec)) {
				csio_printf("Incomplete Discovery Mutual CHAP parameters provided for target %s\n", inst->tgt_name);
				rc = CSIO_EINVAL;
				goto out;
			}

		if (!strlen((char *)disc->disc_ini_chap_id) || !strlen((char *)disc->disc_ini_chap_sec)) {
			csio_printf("Incomplete Discovery CHAP parameters provided for target %s\n", inst->tgt_name);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	/* If CHAP is enabled, make sure requisite parameters are provided. */
	if (inst->auth_method == FW_FOISCSI_AUTH_METHOD_CHAP) {
		if (inst->auth_policy == FW_FOISCSI_AUTH_POLICY_MUTUAL)
			if (!strlen((char *)inst->chap_id) || !strlen((char *)inst->chap_sec)) {
				csio_printf("Incomplete Mutual CHAP parameters provided for target %s\n", inst->tgt_name);
				rc = CSIO_EINVAL;
				goto out;
			}

		if (!strlen((char *)inst->ini_chap_id) || !strlen((char *)inst->ini_chap_sec)) {
			csio_printf("Incomplete CHAP parameters provided for target %s\n", inst->tgt_name);
			rc = CSIO_EINVAL;
			goto out;
		}
	}

	/* uint16_t to store total size */
	disk_buf_len = sizeof(struct coiscsi_vla_block);
	for (j = 0, lun = inst->l_list; j < inst->lun_count; j++, lun = lun->next) {
		/* lun length of uint16_t */
		disk_buf_len += sizeof(uint16_t);
		disk_buf_len += lun->l.lun_len;
	}

	acl_len = sizeof(struct coiscsi_vla_block);
	for (j = 0, lun = inst->a_list; lun; j++, lun = lun->next) {
		/* acl length of uint16_t */
		acl_len += sizeof(uint16_t);
		acl_len += lun->l.lun_len;
	}

	/*
	if (op == CSIO_APP_OP_MOD) {
		csio_coiscsi_portal_close(hw, i_list, inst);
		if (!trav)
			trav = *i_list;

		while(trav && trav->next)
			trav = trav->next;
	}
	*/

	for (i = 0; i < inst->port_count; i++) {

		len = os_agnostic_buffer_len(sizeof(*req) + disk_buf_len + acl_len);

		l_node = malloc(sizeof(struct coiscsi_ioctl_list));

		if (!l_node) {
			fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
			rc = CSIO_ENOMEM;
			goto out;
		}
			
		buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
		if (!buffer) {
			fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
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

		req = (struct coiscsi_target_ioctl *)get_payload(buffer);
		memset(req, 0, sizeof(*req));

		csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

		memcpy((char *)req->tinst.tgt_name, (char *)inst->tgt_name, sizeof (req->tinst.tgt_name));
		memcpy((char *)req->tinst.tgt_alias, (char *)inst->tgt_alias, sizeof (req->tinst.tgt_alias));

                /* Default to 3260 */
                if (port) {
                        req->conn_attr.listen_port = port->p.t_port;
                        req->conn_attr.tpgt = port->p.tpgt;
                        memcpy(&req->conn_attr.listen_addr, &port->p.listen_addr, sizeof(struct ip_addr));
			req->conn_attr.ip_type = port->p.ip_type;
			req->conn_attr.redir = port->p.redir;
                        port = port->next;
                } else {
                        req->conn_attr.listen_port = 3260;
                }

		if (cmd_type == CSIO_COISCSI_STOP_TARGET_IOCTL)
			continue;

		memcpy((char *)req->tinst.chap_id, (char *)inst->chap_id, sizeof (req->tinst.chap_id));
		memcpy((char *)req->tinst.chap_sec, (char *)inst->chap_sec, sizeof (req->tinst.chap_sec));
		memcpy((char *)req->tinst.ini_chap_id, (char *)inst->ini_chap_id, sizeof (req->tinst.ini_chap_id));
		memcpy((char *)req->tinst.ini_chap_sec, (char *)inst->ini_chap_sec, sizeof (req->tinst.ini_chap_sec));

		req->tinst.max_con = inst->max_con ? inst->max_con : coiscsi_param_set[V_TMAXCONN].dflt;
		req->tinst.max_r2t = inst->max_r2t ? inst->max_r2t : coiscsi_param_set[V_TMAXR2T].dflt;
		req->tinst.time2wait = inst->time2wait;
		req->tinst.time2retain = inst->time2retain;
		req->tinst.max_burst = inst->max_burst ? inst->max_burst : coiscsi_param_set[V_TMAXBL].dflt;
		req->tinst.max_rcv_dsl = inst->max_rcv_dsl ? inst->max_rcv_dsl : coiscsi_param_set[V_TMAXRDSL].dflt;
		req->tinst.first_burst = inst->first_burst ? inst->first_burst : coiscsi_param_set[V_TFSTBL].dflt;
		req->tinst.ping_timeout = inst->ping_timeout;
		req->tinst.ping_interval = inst->ping_interval;

		req->tinst.hd_dd_dgst = inst->hd_dd_dgst;

		req->tinst.auth_method = inst->auth_method;
		req->tinst.auth_policy = inst->auth_policy;

		req->tinst.acl_enable = inst->acl_en;

		req->tinst.shadow_mode = inst->shadow;

		req->tinst.lun_count = inst->lun_count;
		req->tinst.num_portal = inst->port_count;
		req->tinst.tcp_wscale = inst->tcp_wscale;
		req->tinst.tcp_wsen = inst->tcp_wsen;

		/* Copy discovery auth information */
		memcpy(&req->disc_auth, disc, sizeof(struct coiscsi_target_disc));

		disk_buf = req->tinst.tgt_disk;

		if (inst->lun_count) {
			/* Write total size */
			memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
			v_block.total_len = disk_buf_len + acl_len;
			v_block.block_type = type_lun;
			v_block.block_len = disk_buf_len;

			memcpy(disk_buf, &v_block, sizeof(struct coiscsi_vla_block));
			disk_buf += sizeof(struct coiscsi_vla_block);

			for (j = 0, lun = inst->l_list; j < inst->lun_count; j++, lun = lun->next) {
				/* Write lun path length */
				memcpy(disk_buf, &lun->l.lun_len, sizeof(uint16_t));
				disk_buf += sizeof(uint16_t);

				/* Write lun path */
				memcpy(disk_buf, lun->l.disk, lun->l.lun_len);
				disk_buf += lun->l.lun_len;
			}
		}

		if (req->tinst.acl_enable) {
			memset(&v_block, 0, sizeof(struct coiscsi_vla_block));

			v_block.block_type = type_acl;
			v_block.block_len = acl_len;
			v_block.total_len = disk_buf_len + acl_len;

			memcpy(disk_buf, &v_block, sizeof(struct coiscsi_vla_block));
			disk_buf += sizeof(struct coiscsi_vla_block);
			for (j = 0, lun = inst->a_list; lun; j++, lun = lun->next) {
				/* Write ACL string length */
				memcpy(disk_buf, &lun->l.lun_len, sizeof(uint16_t));
				disk_buf += sizeof(uint16_t);

				/* Write ACL string*/
				memcpy(disk_buf, lun->l.disk, lun->l.lun_len);
				disk_buf += lun->l.lun_len;
			}
		}
	}

	/* Free up everything */
	port = inst->p_list;
	while (port) {
		lun = port->next;
		free(port);
		port = lun;
	}
	inst->p_list = NULL;

	lun = inst->l_list;
	while (lun) {
		port = lun->next;
		if (lun->l.disk)
			free(lun->l.disk);
		free(lun);
		lun = port;
	}

	inst->l_list = NULL;
out:
	return rc;
}

int parse(adap_handle_t hw, struct coiscsi_ioctl_list **rp, char *nodename,
		uint32_t cmd, int op, uint8_t tcp_wscale, uint8_t tcp_wsen)
{
	size_t len;
	ssize_t read;
	char *line=NULL;
	FILE *fp = NULL;
	char *token = NULL, *val = NULL, *tmp = NULL, *rdp = NULL;
	struct coiscsi_parse_inst *targ_block = NULL;
	struct coiscsi_target_disc d_auth;
	unsigned long val_i;
	uint16_t tpgt, redir_p = 0, ioctl_pending = 0;

	if(!(fp = fopen(ISCSI_TGT_PARAM_FILE, "r"))) {
                printf("Unable to open Config file\n");
                return -1;
        }

	memset(&d_auth, 0, sizeof(struct coiscsi_target_disc));

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
		//printf("Retrieved line of length %zu :\n", read);
		/* Skip any line that does not have a token:value pair */
		if (!token || !val)
			continue;

		if (nodename) {
			/* Match target name if looking for specific target */
			if (!strncmp(coiscsi_param_set[V_TTNAME].name, token, strlen(token))) {
				int len = min(FW_FOISCSI_NAME_MAX_LEN, strlen(nodename));

				if (!strncmp(val, nodename, len)) {
					if (targ_block) {
						fprintf(stderr, "%s: Duplicate target block detected\n", coiscsi_name);
						goto err_out;
					}

					targ_block = (struct coiscsi_parse_inst *)malloc(sizeof(struct coiscsi_parse_inst));
					if (!targ_block)
						goto err_out;

					memset(targ_block, 0, sizeof(struct coiscsi_parse_inst));

					targ_block->tcp_wscale = tcp_wscale;
					targ_block->tcp_wsen = tcp_wsen;
					memcpy((char *)targ_block->tgt_name, val, sizeof(targ_block->tgt_name));
					ioctl_pending = 1;
				} else {
					/* Target Block is over */
					if (targ_block) {
						ioctl_pending = 0;
						make_ioctl(hw, rp, targ_block, &d_auth, cmd, op);
						goto complete;
					}
				}
			}
		} else {
			/* Use target name token to update index for --ALL */
			if (!strncmp(coiscsi_param_set[V_TTNAME].name, token, strlen(token))) {
				if (targ_block) {
					/* New target block was found, so fill up an ioctl struct for previous block */
					ioctl_pending = 0;
					make_ioctl(hw, rp, targ_block, &d_auth, cmd, op);

					memset(targ_block, 0, sizeof(struct coiscsi_parse_inst));
					targ_block->tcp_wscale = tcp_wscale;
					targ_block->tcp_wsen = tcp_wsen;
					memcpy((char *)targ_block->tgt_name, val, sizeof (targ_block->tgt_name));
					ioctl_pending = 1;
				} else {
				
					targ_block = (struct coiscsi_parse_inst *)malloc(sizeof(struct coiscsi_parse_inst));
					if (!targ_block)
						goto err_out;

					memset(targ_block, 0, sizeof(struct coiscsi_parse_inst));
					targ_block->tcp_wscale = tcp_wscale;
					targ_block->tcp_wsen = tcp_wsen;
					memcpy((char *)targ_block->tgt_name, val, sizeof(targ_block->tgt_name));
					ioctl_pending = 1;
				}
			}

		}

		/* Copy global discovery CHAP settings */
                /* DiscUserName */
                if(!strncmp(coiscsi_param_set[V_TD_USER].name, token, strlen(token))) {
                        if (!param_verify(V_TD_USER, val, 0))
				memcpy((char *)d_auth.disc_chap_id, val, sizeof (d_auth.disc_chap_id));
                        else
                                goto err_out;
                        continue;

                /* DiscPassword */
                } else if(!strncmp(coiscsi_param_set[V_TD_SEC].name, token, strlen(token))) {
                        if (!param_verify(V_TD_SEC, val, 0))
				memcpy((char *)d_auth.disc_chap_sec, val, sizeof (d_auth.disc_chap_sec));
                        else
                                goto err_out;
                        continue;

                /* DiscUserNameIN */
                } else if(!strncmp(coiscsi_param_set[V_TD_IUSER].name, token, strlen(token))) {
                        if (!param_verify(V_TD_IUSER, val, 0))
				memcpy((char *)d_auth.disc_ini_chap_id, val, sizeof (d_auth.disc_ini_chap_id));
                        else
                                goto err_out;
                        continue;

                /* DiscPasswordIN */
                } else if(!strncmp(coiscsi_param_set[V_TD_ISEC].name, token, strlen(token))) {
                        if (!param_verify(V_TD_ISEC, val, 0))
				memcpy((char *)d_auth.disc_ini_chap_sec, val, sizeof(d_auth.disc_ini_chap_sec));
                        else
                                goto err_out;
                        continue;
		
                /* DiscAuthMethod */
                } else if(!strncmp(coiscsi_param_set[V_TD_AUTHM].name, token, strlen(token))) {

                        if (strcmp(val, "CHAP") && strcmp(val, "None")) {
                                csio_printf("\nDiscAuthMethod should be CHAP OR None\n");
                        }

                        if (!strcmp(val, "CHAP"))
                                d_auth.disc_auth_method = FW_FOISCSI_AUTH_METHOD_CHAP;
                        else
                                d_auth.disc_auth_method = FW_FOISCSI_AUTH_METHOD_NONE;

                        continue;

                /* DiscAuthPolicy */
                } else if(!strncmp(coiscsi_param_set[V_TD_AUTHPOL].name, token, strlen(token))) {
                        if ((cmd != CSIO_COISCSI_STOP_TARGET_IOCTL) && strcmp(val, "Oneway") && strcmp(val, "Mutual")) {
                                csio_printf("\nDiscAuthPolicy should be Oneway OR Mutual, Using Default Oneway\n");
                        }

                        if (!strcmp(val, "Mutual"))
                                d_auth.disc_auth_policy = FW_FOISCSI_AUTH_POLICY_MUTUAL;
                        else
                                d_auth.disc_auth_policy = FW_FOISCSI_AUTH_POLICY_ONEWAY;

                        continue;
		}

		/* Only copy in data when targ_block is valid or we're parsing the requested target block */
		if (!targ_block)
			continue;

		/* TargetAlias */
		if(!strncmp(coiscsi_param_set[V_TTALIAS].name, token, strlen(token))) {
			if (!param_verify(V_TTALIAS, val, 0))
				memcpy((char *)targ_block->tgt_alias, val, sizeof (targ_block->tgt_alias));
			else
				goto err_out;
			continue;

                /* UserName */
                } else if(!strncmp(coiscsi_param_set[V_TUSER].name, token, strlen(token))) {
                        if (!param_verify(V_TUSER, val, 0))
				memcpy((char *)targ_block->chap_id, val, sizeof (targ_block->chap_id));
                        else
                                goto err_out;
                        continue;

                /* Password */
                } else if(!strncmp(coiscsi_param_set[V_TSEC].name, token, strlen(token))) {
                        if (!param_verify(V_TSEC, val, 0))
				memcpy((char *)targ_block->chap_sec, val, sizeof (targ_block->chap_sec));
                        else
                                goto err_out;
                        continue;

                /* UserNameIN */
                } else if(!strncmp(coiscsi_param_set[V_TIUSER].name, token, strlen(token))) {
                        if (!param_verify(V_TIUSER, val, 0))
				memcpy((char *)targ_block->ini_chap_id, val, sizeof (targ_block->ini_chap_id));
                        else
                                goto err_out;
                        continue;

                /* PasswordIN */
                } else if(!strncmp(coiscsi_param_set[V_TISEC].name, token, strlen(token))) {
                        if (!param_verify(V_TISEC, val, 0))
				memcpy((char *)targ_block->ini_chap_sec, val, sizeof (targ_block->ini_chap_sec));
                        else
                                goto err_out;
                        continue;

		/* HeaderDigest */
		} else if(!strncmp(coiscsi_param_set[V_THDGST].name, token, strlen(token))) {
			if(!strncmp(val, "None", strlen(val)))
				targ_block->hd_dd_dgst |= FW_FOISCSI_DIGEST_TYPE_NONE;
			else if (!strncmp(val, "CRC32C", strlen(val)))
				targ_block->hd_dd_dgst |= FW_FOISCSI_DIGEST_TYPE_CRC32;
			else if (!strncmp(val, "CRC32C,None", strlen(val)))
				targ_block->hd_dd_dgst |= FW_FOISCSI_DIGEST_TYPE_CRC32_FST;
			else if (!strncmp(val, "None,CRC32C", strlen(val)))
				targ_block->hd_dd_dgst |= FW_FOISCSI_DIGEST_TYPE_CRC32_SEC;	

			continue;

		/* DataDigest */
                } else if(!strncmp(coiscsi_param_set[V_TDGGST].name, token, strlen(token))) {
                        if(!strncmp(val, "None", strlen(val)))
                                targ_block->hd_dd_dgst |= (FW_FOISCSI_DIGEST_TYPE_NONE << 4);
                        else if (!strncmp(val, "CRC32C", strlen(val)))
                                targ_block->hd_dd_dgst |= (FW_FOISCSI_DIGEST_TYPE_CRC32 << 4);
			else if (!strncmp(val, "CRC32C,None", strlen(val)))
				targ_block->hd_dd_dgst |= (FW_FOISCSI_DIGEST_TYPE_CRC32_FST << 4);
                        else if (!strncmp(val, "None,CRC32C", strlen(val)))
                                targ_block->hd_dd_dgst |= (FW_FOISCSI_DIGEST_TYPE_CRC32_SEC << 4);

			continue;

		/* AuthMethod */
		} else if(!strncmp(coiscsi_param_set[V_TAUTHM].name, token, strlen(token))) {

			if (strcmp(val, "CHAP") && strcmp(val, "None")) {
				csio_printf("\nAuthMethod should be CHAP OR None\n");
			}

			if (!strcmp(val, "CHAP"))
				targ_block->auth_method = FW_FOISCSI_AUTH_METHOD_CHAP;
			else
				targ_block->auth_method = FW_FOISCSI_AUTH_METHOD_NONE;

			continue;

		/* AuthPolicy */
		} else if(!strncmp(coiscsi_param_set[V_TAUTHPOL].name, token, strlen(token))) {
			if ((cmd != CSIO_COISCSI_STOP_TARGET_IOCTL) && strcmp(val, "Oneway") && strcmp(val, "Mutual")) {
				csio_printf("\nAuthPolicy should be Oneway or Mutual, Using Default Oneway\n");
			}

			if (!strcmp(val, "Mutual"))
				targ_block->auth_policy = FW_FOISCSI_AUTH_POLICY_MUTUAL;
			else
				targ_block->auth_policy = FW_FOISCSI_AUTH_POLICY_ONEWAY;

			continue;

		/* TargetDisk */
                } else if(!strncmp(coiscsi_param_set[V_TTDISK].name, token, strlen(token))) {
                        if (!param_verify(V_TTDISK, val, 0))
				enqueue_lun_port(targ_block, val, 0, NULL, 0, type_lun, 0);
                        else
                                goto err_out;
                        continue;

		/* ListenAddr */
		} else if (!strncmp(coiscsi_param_set[V_TTADDR].name, token, strlen(token))) {

			tmp = NULL;
			rdp = NULL;

			/* Find redirect portal */
			rdp = strchr(val, ',');
			if (rdp) {
				*rdp = '\0';
				rdp++;
				tmp = strrchr(rdp, ']');
				if (*(rdp) == '[' && tmp) {
					*tmp = '\0';
					*rdp = '\0';
					rdp++;
					redir_p = atoi(rdp);
				}
			} else {
				redir_p = 0;
			}

			tmp = strchr(val, '@');
			/* Find target portal group tag */
			if (tmp) {
				*tmp = '\0';
				tpgt = atoi(val);
				val = tmp + 1;
			} else
				tpgt = 0;


			/* Find port */
			tmp = strrchr(val, ':');
			if (tmp) {
				/* ipv4 with port */
				if (strchr(val, ':') == tmp) {
					*tmp = '\0';
					val_i = atoi(tmp + 1);
				/* ipv6 with port */
				} else if (*(tmp - 1) == ']') {
					*(tmp - 1) = '\0';
					*tmp = '\0';
					val_i = atoi(tmp + 1);
				/* part of ipv6 address, ignore */
				} else
					val_i = 3260;
			} else
				val_i = 3260;

			if (*val == '[') {
				*val = '\0';
				val++;
			}

			tmp = NULL;
			tmp = strrchr(val, ']');
			if(tmp)
				*tmp = '\0';

			enqueue_lun_port(targ_block, NULL, val_i, val, tpgt, type_port, redir_p);

			continue;

		/* FirstBurstLength */
		} else if (!strncmp(coiscsi_param_set[V_TFSTBL].name, token, strlen(token))) {
			val_i = atoi(val);
			if (!param_verify(V_TFSTBL, NULL, val_i))
				targ_block->first_burst = val_i;
			else
				goto err_out;
			continue;

		/* MaxOutstandingR2T */
		} else if (!strncmp(coiscsi_param_set[V_TMAXR2T].name, token, strlen(token))) {
			val_i = atoi(val);
			if (!param_verify(V_TMAXR2T, NULL, val_i))
				targ_block->max_r2t = val_i;
			else
				goto err_out;
			continue;

		/* MaxBurstLength */
		} else if (!strncmp(coiscsi_param_set[V_TMAXBL].name, token, strlen(token))) {
                        val_i = atoi(val);
                        if (!param_verify(V_TMAXBL, NULL, val_i))
                                targ_block->max_burst = val_i;
                        else
                                goto err_out;
			continue;

		/* MaxRecvDataSegmentLength */
		} else if (!strncmp(coiscsi_param_set[V_TMAXRDSL].name, token, strlen(token))) {
			val_i = atoi(val);
			if (val_i > ULP2_MAX_PDU_PAYLOAD) {
				csio_app_log_info(stdout,
					"Setting MaxRecvDataSegmentLength to "
					"Max possible value %d\n",
					ULP2_MAX_PDU_PAYLOAD);
				val_i = ULP2_MAX_PDU_PAYLOAD;
			}

                        if (!param_verify(V_TMAXRDSL, NULL, val_i))
                                targ_block->max_rcv_dsl = val_i;
                        else
                                goto err_out;
			continue;
		/* ACL */
		} else if (!strncmp(coiscsi_param_set[V_ACL].name, token, strlen(token))) {
			if (!param_verify(V_ACL, val, 0))
				enqueue_lun_port(targ_block, val, 0, NULL, 0, type_acl, 0);
			else
				goto err_out;
			continue;
		/* ACL_Enable */
		} else if (!strncmp(coiscsi_param_set[V_ACLEN].name, token, strlen(token))) {
			if (!param_verify(V_ACLEN, val, 0)) {
				if (!strncmp(val, "Yes", 3))
					targ_block->acl_en = 1;
				else
					targ_block->acl_en = 0;
			} else
				goto err_out;
                        continue;
		/* ShadowMode */
		} else if (!strncmp(coiscsi_param_set[V_SHADOW].name, token, strlen(token))) {
			if (!param_verify(V_SHADOW, val, 0)) {
				if (!strncmp(val, "Yes", 3))
					targ_block->shadow = 1;
				else
					targ_block->shadow = 0;
			} else
				goto err_out;
			continue;
		} else if (!strncmp(coiscsi_param_set[V_TINITR2T].name, token, strlen(token))) {
			if (!param_verify(V_TINITR2T, val, 0)) {
				if (!strncmp(val, "No", 2)) {
					fprintf(stderr, "Warning: %s: Initial R2T set to Yes for coiscsi, overriding config file value\n",
						targ_block->tgt_name);
				}
			}
		} else if (!strncmp(coiscsi_param_set[V_TIDATA].name, token, strlen(token))) {
			if (!param_verify(V_TIDATA, val, 0)) {
				if (!strncmp(val, "Yes", 3)) {
					fprintf(stderr, "Warning: %s: Immediate data set to No for coiscsi, overriding config file value\n",
						targ_block->tgt_name);
				}
			}
		}
       }

complete:
	/* Edge case for when only a single target block was defined.
	 * Logic won't see the end of the block and hence won't fill up ioctl struct */
	if (ioctl_pending && targ_block) {
		make_ioctl(hw, rp, targ_block, &d_auth, cmd, op);
	}

/*
	for (i = 0; i < V_TPARAM_MAX; i++)
		printf("param %s\n", param_set[i].name);
*/
	if (line)
		free(line);
	if (fp)
		fclose(fp);
	if (targ_block)
		free(targ_block);
	else if (nodename)
		fprintf(stderr,"Target block for %s not found.\n",nodename);
	return 0;

err_out:
	if (line)
		free(line);
	if (fp)
		fclose(fp);

	if (targ_block)
		free(targ_block);

	fprintf(stderr,"Config file parse error\n");
	return -1;
}

int32_t
csio_coiscsi_target_up(adap_handle_t hw, int32_t op, int nodeid, 
		char * sip, char *nodename, int port, uint8_t tcp_wscale,
		uint8_t tcp_wsen)
{
	int32_t rc = 0;
	uint32_t cmd=0;
	struct coiscsi_target_ioctl *req = NULL;

	struct coiscsi_ioctl_list *ioctl_buf_list = NULL, *tmp = NULL;

        if (hw < 0) {
                fprintf(stderr, "%s: No chelsio T4 CNA available\n", coiscsi_name);
                rc = CSIO_EINVAL;
                goto out;
        }

	if(op == CSIO_APP_OP_ASSIGN)
		cmd = CSIO_COISCSI_START_TARGET_IOCTL;
	else if(op == CSIO_APP_OP_MOD)
		cmd = CSIO_COISCSI_UPDATE_TARGET_IOCTL;

	if(!strcmp(nodename, "ALL"))
		parse(hw, &ioctl_buf_list, NULL, cmd, op, tcp_wscale, tcp_wsen);
	else
		parse(hw, &ioctl_buf_list, nodename, cmd, op, tcp_wscale,
			tcp_wsen);

	while(ioctl_buf_list) {

		req = get_payload(ioctl_buf_list->i_buf);

		if (op == CSIO_APP_OP_MOD)
			req->op = MOD_TARGET;

		rc = issue_ioctl(hw, ioctl_buf_list->i_buf, ioctl_buf_list->len);

		req = get_payload(ioctl_buf_list->i_buf);

		if (rc) {
			/* something went wrong */
			fprintf(stderr,"Failed to start target %s\nError: %s\n",
					req->tinst.tgt_name,
					csio_err_to_msg(req->retval));
		} else {
			if (req->tinst.tgt_name)
				printf("Target %s started.\n",
						req->tinst.tgt_name);
		}

		csio_app_log_devel_debug("%s: rc %d\n", __FUNCTION__, req->retval);

		ioctl_buffer_free(ioctl_buf_list->i_buf);

		tmp = ioctl_buf_list;

		ioctl_buf_list = ioctl_buf_list->next;

		free(tmp);
	}

	if (ioctl_buf_list) {
		ioctl_buffer_free(ioctl_buf_list->i_buf);
		free(ioctl_buf_list);
	}

out:
        return rc;
}

int32_t
csio_coiscsi_target_down(adap_handle_t hw, int nodeid, char *nodename, int port)
{
        int32_t rc = 0;
        struct coiscsi_target_ioctl *req = NULL;

        struct coiscsi_ioctl_list *ioctl_buf_list = NULL, *tmp = NULL;

        if (hw < 0) {
 		fprintf(stderr, "%s: No chelsio T4 CNA available\n", coiscsi_name);
 		rc = CSIO_EINVAL;
 		goto out;
        }

        if(!strcmp(nodename, "ALL"))
                parse(hw, &ioctl_buf_list, NULL,
			CSIO_COISCSI_STOP_TARGET_IOCTL, 0, 0, 0);
        else
                parse(hw, &ioctl_buf_list, nodename,
			CSIO_COISCSI_STOP_TARGET_IOCTL, 0, 0, 0);

        while(ioctl_buf_list) {
		rc = issue_ioctl(hw, ioctl_buf_list->i_buf, ioctl_buf_list->len);

                req = get_payload(ioctl_buf_list->i_buf);

                rc = req->retval;

                csio_app_log_devel_debug("%s: Target %s rc %d\n", __FUNCTION__, req->tinst.tgt_name, rc);

                ioctl_buffer_free(ioctl_buf_list->i_buf);

                tmp = ioctl_buf_list;

                ioctl_buf_list = ioctl_buf_list->next;

                free(tmp);
        }

        if (ioctl_buf_list) {
                ioctl_buffer_free(ioctl_buf_list->i_buf);
                free(ioctl_buf_list);
        }
out:
        return rc;
}

int32_t csio_coiscsi_target_show(adap_handle_t hw, int nodeid, char *nodename, int port)
{
	void *buffer = NULL;
	struct coiscsi_target_info_ioctl *req = NULL;
	struct coiscsi_target_ioctl *treq = NULL;
	struct coiscsi_vla_block v_block;
	struct coiscsi_portal_info co_portal;
	size_t len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_info_ioctl));
	uint32_t cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_TARGET_INFO_IOCTL);
	uint32_t rc=0, l_count, p_count, i, ip_temp = 0;
	int nn_len = 0;
	uint16_t l_size = 0, total_size = 0, prn_len = 0;
	char *ltmp = NULL, *atmp = NULL;
	char ip_str[INET6_ADDRSTRLEN];

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	req = (struct coiscsi_target_info_ioctl *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	if (nodename) {
		nn_len = min(strlen(nodename), FW_FOISCSI_NAME_MAX_LEN);
		memcpy(req->tgt_name, nodename, nn_len);
	}

	rc = issue_ioctl(hw, buffer, len);
	req = (struct coiscsi_target_info_ioctl *)get_payload(buffer);

	if (rc)
		goto out;

	csio_app_log_devel_debug(" Found %s lun_c %d p_c %d\n", req->tgt_name, req->lun_count, req->portal_count);

	l_count = req->lun_count;
	p_count = req->portal_count;
	total_size = req->lun_buf_size;

	/* session/connection details */
	printf("%s\n", req->databuf);

	ioctl_buffer_free(buffer);

	/* Move from info to actual target params */
	cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_SHOW_TARGET_IOCTL);

	len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_ioctl) + (sizeof(char) * total_size) + sizeof(struct coiscsi_portal_info) * p_count);

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {                    
		fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
		rc = CSIO_ENOMEM;
		goto out; 
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	treq = (struct coiscsi_target_ioctl *)get_payload(buffer);
	memset(treq, 0, sizeof(*treq));

	if (nodename)
		memcpy(treq->tinst.tgt_name, nodename, nn_len);

	rc = issue_ioctl(hw, buffer, len);
	treq = get_payload(buffer);

	if (rc)
		goto out;

	csio_printf("[ Target IQN : %s ]\n", treq->tinst.tgt_name);
	csio_printf("\tTarget Alias \t: %s\n"
			"\tMax R2T \t: %u\n"
			"\tMax RecvDsl \t: %u\n"
			"\tMax Burst \t: %u\n"
			"\tFirst Burst \t: %u\n",
		treq->tinst.tgt_alias, treq->tinst.max_r2t,
		treq->tinst.max_rcv_dsl, treq->tinst.max_burst,
		treq->tinst.first_burst);

	csio_printf("\tAuthMethod \t: ");
	if (treq->tinst.auth_method == FW_FOISCSI_AUTH_METHOD_NONE) {
		csio_printf("None\n");
	} else {
		csio_printf("CHAP\n");
		csio_printf("\tAuthPolicy \t: ");
		if (treq->tinst.auth_policy == FW_FOISCSI_AUTH_POLICY_ONEWAY)
			csio_printf("Oneway\n");
		else
			csio_printf("Mutual\n");

		csio_printf("\tUsernameIN \t: %s\n", treq->tinst.ini_chap_id);
		csio_printf("\tPasswordIN \t: ************\n"); // treq->tinst.ini_chap_sec

		if (treq->tinst.auth_policy == FW_FOISCSI_AUTH_POLICY_MUTUAL) {
			csio_printf("\tUsername \t: %s\n", treq->tinst.chap_id);
			csio_printf("\tPassword \t: ************\n"); // treq->tinst.chap_sec
		}
	}
	csio_printf("\tLUN count : %d\n", l_count);
	ltmp = (char *)treq->tinst.tgt_disk;

	if (l_count) {
		/* Skip total length */
		ltmp += sizeof(struct coiscsi_vla_block);
		for (i = 0; i < l_count; i++) {
			memcpy(&l_size, ltmp, sizeof(uint16_t));
			ltmp += sizeof(uint16_t);

			csio_printf("\t\tLUN %d \t: %s", i, ltmp);
			/* print any extra lun info */
			prn_len = strlen(ltmp);
			while(prn_len < l_size - 1) {
				prn_len++;
				csio_printf(",%s", ltmp + prn_len);
				prn_len += strlen(ltmp + prn_len);
			}
			csio_printf("\n");
			ltmp += l_size;
		}
	}

	if (treq->tinst.acl_enable) {
		csio_printf("\n\tACL Enabled\n");
		memset(&v_block, 0, sizeof(struct coiscsi_vla_block));
		memcpy(&v_block, ltmp, sizeof(struct coiscsi_vla_block));

		atmp = ltmp;
		atmp += sizeof(struct coiscsi_vla_block);

		while(atmp < ltmp + v_block.block_len) {
			memcpy(&l_size, atmp, sizeof(uint16_t));
			atmp += sizeof(uint16_t);

			csio_printf("\t\tACL\t: %s\n", atmp);
			atmp += l_size;
		}
	}
	/* Reusing l_size to store port now */
	csio_printf("\n\tPortal Count : %d\n", p_count);

	ltmp = (char *)treq->tinst.tgt_disk + total_size;
	for (i = 0; i < p_count; i++) {
		memset(&co_portal, 0, sizeof(struct coiscsi_portal_info));
		memset(ip_str, 0, INET6_ADDRSTRLEN);

		memcpy(&co_portal, ltmp, sizeof(struct coiscsi_portal_info));

		if (co_portal.ip_type == CSIO_CHNET_L3CFG_TYPE_IPV6) {
			inet_ntop(AF_INET6, &(co_portal.ip.ip6), ip_str, INET6_ADDRSTRLEN);
			csio_printf("\t\t\t%u@[%s]:%u", co_portal.tpgt, ip_str, co_portal.port);
		} else {
			ip_temp = ((co_portal.ip.ip4 >> 24) & 0xFF) |
			                ((co_portal.ip.ip4 >> 16) & 0xFF) << 8 |
			                ((co_portal.ip.ip4 >> 8) & 0xFF) << 16 |
			                ((co_portal.ip.ip4 & 0xFF) << 24);
			inet_ntop(AF_INET, &ip_temp, ip_str, INET_ADDRSTRLEN);
			csio_printf("\t\t\t%u@%s:%u", co_portal.tpgt, ip_str, co_portal.port);
		}

		if (co_portal.redir)
			csio_printf(",[%d]", co_portal.redir);

		csio_printf("\n");
		ltmp += sizeof(struct coiscsi_portal_info);
	}
	csio_printf("\n\n");

out:
	ioctl_buffer_free(buffer);
	return rc;

}

int32_t csio_coiscsi_target_stats(adap_handle_t hw, int32_t op)
{
	void *buffer = NULL;
	struct coiscsi_target_stats_ioctl *req = NULL;
	size_t len = os_agnostic_buffer_len(sizeof(struct coiscsi_target_stats_ioctl));
	uint32_t cmd = 0;
	uint32_t rc=0;
	uint8_t i;

	if(op == CSIO_APP_OP_STATS)
		cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_TARGET_STATS_IOCTL);
	else
		cmd = CSIO_STOR_COISCSI_OPCODE(CSIO_COISCSI_TARGET_STATS_CLR_IOCTL);

	buffer = ioctl_buffer_alloc(len, CSIO_IOCTL_SIGNATURE);
	if (!buffer) {
		fprintf(stderr, "%s: Out of memory\n", coiscsi_name);
		rc = CSIO_ENOMEM;
		goto out;
	}

	csio_init_header(buffer, cmd, CSIO_IOCTL_SIGNATURE, len, CSIO_IOCD_RW);

	req = (struct coiscsi_target_stats_ioctl *)get_payload(buffer);
	memset(req, 0, sizeof(*req));

	rc = issue_ioctl(hw, buffer, len);
	req = (struct coiscsi_target_stats_ioctl *)get_payload(buffer);

	csio_app_log_devel_debug(" COISCSI TARGET STATS IOCTL rc %d\n", rc);
	
	if (rc) {
		fprintf(stderr, "%s: ioctl failed, rc %d\n", coiscsi_name, rc);
		goto out;
	}

#define P1(str, val) \
	csio_printf("%-12s \t  %6d       %6d       %6d\n", str, \
		    req->u.rsrc.val[TGT_FW_RSRC_TOT], \
		    req->u.rsrc.val[TGT_FW_RSRC_MAX], \
		    req->u.rsrc.val[TGT_FW_RSRC_CUR])

	csio_printf("\n\n ********** TARGET FIRMWARE RESOURCE STATS **********\n");
	csio_printf("\t\t   TOTAL      MAXIMUM      CURRENT\n");
	csio_printf("\t\t   _____      _______      _______\n");
	P1("IPV4 TGT", num_ipv4_tgt);
	P1("IPV6 TGT", num_ipv6_tgt);
	P1("L2T ENTRIES", num_l2t_entries);
	P1("CSOCKS", num_csocks);
	P1("TASKS", num_tasks);
	P1("BUF_LL_64", num_bufll64);
	for(i=0 ; i<11 ; i++) {
		csio_printf("PPOD_ZONE%02d \t  %6d       %6d       %6d\n", i,
			    req->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_TOT],
			    req->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_MAX],
			    req->u.rsrc.num_ppods_zone[i][TGT_FW_RSRC_CUR]);
	}
	csio_printf("\n\n ****************************************************\n");

#undef P1
	
out:
	if(buffer)
		ioctl_buffer_free(buffer);

	return rc;

}

int32_t csio_coissci_get_target_count_list(int *target_count, char *iqn_list)
{

	char *line = NULL;
	size_t len = 0;
	ssize_t read;
	int tg_count = 0;
	FILE *fp = NULL;
	char *token, *val;

	if(!(fp = fopen(ISCSI_TGT_PARAM_FILE, "r"))) {
		csio_printf("Unable to open Config file\n");
		return -1;
	}

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
                //printf("Retrieved line of length %zu :\n", read);

                /* Skip any line that does not have a token:value pair */
		if (!token || !val)
                	continue;

		if (!strncmp(coiscsi_param_set[V_TTNAME].name, token, strlen(token))) {
			if (iqn_list) {
				memcpy(iqn_list + (FW_FOISCSI_NAME_MAX_LEN * tg_count), val, FW_FOISCSI_NAME_MAX_LEN);
			}
			tg_count++;

		}

	}

	if (target_count)
		*target_count = tg_count;

	if (line)
		free(line);
	if (fp)
		fclose(fp);

	return 0;
}

int32_t csio_coiscsi_target_do_all_op(adap_handle_t hw, int32_t op, char *sip)
{
	int target_count = 0;
	char *iqn_list;
	int rc = 0, i;

	rc = csio_coissci_get_target_count_list(&target_count, NULL);
	if (rc)
		return rc;
	if (!target_count) {
		fprintf(stderr, "No targets found\n");
		return -EINVAL;
	}

	iqn_list = (char *)malloc(sizeof(char *) * FW_FOISCSI_NAME_MAX_LEN * target_count);
	memset(iqn_list, 0, (sizeof(char *) * FW_FOISCSI_NAME_MAX_LEN * target_count));
	rc = csio_coissci_get_target_count_list(NULL, iqn_list);
	if (rc)
		goto out;

	for (i = 0; i < target_count; i++) {
		switch (op) {
		case CSIO_APP_OP_SHOW:
			rc = csio_coiscsi_target_show(hw, i, iqn_list + (FW_FOISCSI_NAME_MAX_LEN * i), 0);
			break;
		default:
			break;
		}
	}
out:
	if (iqn_list)
		free(iqn_list);
	return rc;	
}

int32_t
csio_target_do_op(adap_handle_t hw, int32_t op, int nodeid, char *sip,
		char *nodename, int port, int tid, uint8_t tcp_wscale,
		uint8_t tcp_wsen)
{
       int32_t rc = 0;

	if (!nodename && (op != CSIO_APP_OP_STATS && op != CSIO_APP_OP_STATS_CLR))
		return -EINVAL;

	switch (op) {
	case CSIO_APP_OP_ASSIGN:
	case CSIO_APP_OP_MOD:
		rc = csio_coiscsi_target_up(hw, op, nodeid, sip, nodename, port,
							tcp_wscale, tcp_wsen);
		break;
	case CSIO_APP_OP_CLEAR:
		rc = csio_coiscsi_target_down(hw, nodeid, nodename, port);
		break;
	case CSIO_APP_OP_SHOW:
		if (!strcmp(nodename, "ALL"))
			rc = csio_coiscsi_target_do_all_op(hw, op, sip);
		else
			rc = csio_coiscsi_target_show(hw, nodeid, nodename, port);
		break;
	case CSIO_APP_OP_STATS:
	case CSIO_APP_OP_STATS_CLR:
		rc = csio_coiscsi_target_stats(hw, op);
		break;
	default:
		fprintf(stderr, "Invalid options\n");
		break;
	}
       return rc;
}

int run_coiscsi_cmd(int argc, char *argv[])
{
	int ch, longindex, mode=-1;
	int rc=0, op=CSIO_APP_OP_NOOP;
	char /**ip = NULL,*/ *sip = NULL;
	int /*tpgt,*/ tcp_port = DEFAULT_ISCSI_TARGET_PORT;
	int nodeid = -1;
	/*uint8_t ifid = -1;*/
	int tid = -1;
	uint8_t tcp_wscale = 0, tcp_wsen = 0;
	char *nodename = NULL/*, *alias = NULL*/;
/*
        char *tgt_user = NULL, *tgt_sec = NULL;\
	char *auth_method = NULL, *policy = NULL;
*/
	char *device = NULL;
	adap_handle_t hw = -1;
	int oup_cnt = 0;
	int odown_cnt = 0;
	int oassign_cnt = 0;
	int oshow_cnt = 0;
	int ostats_cnt = 0;

	csio_app_log_devel_debug("%s: entering\n", coiscsi_name);
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	optopt = 0;
	optind = 3;

	if (!strncmp(argv[2], coiscsi_base_opt, strlen(coiscsi_base_opt))) {
		memset(argv[2], 0, strlen(coiscsi_base_opt));
		strncpy(argv[2], "coiscsi", strlen(coiscsi_base_opt));
	}
	csio_app_log_devel_debug("%s: argv[0] %s, argv[1] %s\n",
					coiscsi_name, argv[0], argv[1]);


	while ((ch = getopt_long(argc, argv, short_options, long_options, &longindex)) >= 0) {
		csio_app_log_devel_debug("%s: ch : %c, longindex %d\n",
						coiscsi_name, ch, longindex);

		switch (ch) {
		case 'd':
			device = optarg;
			csio_app_log_devel_debug("%s: device %s\n",
							coiscsi_name, device);
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
			else if (op == CSIO_APP_OP_STATS || op == CSIO_APP_OP_STATS_CLR)
				ostats_cnt++;
			
			csio_app_log_devel_debug("%s: opcode %d\n", coiscsi_name, op);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			csio_app_log_devel_debug("%s: mode %d\n", coiscsi_name, mode);
			break;
		/*case 'a':
			alias = optarg;
			csio_app_log_devel_debug("%s: alias %s\n", coiscsi_name, alias);
			break;*/
		case 'n':
			nodename = optarg;
			csio_app_log_devel_debug("%s: nodename %s\n", coiscsi_name, nodename);
			break;
		case 'p':
			csio_app_log_devel_debug("%s: optarg %s\n", coiscsi_name, optarg);
			break;
		case 'P':
			/*ip = str_to_ipport(optarg, &tcp_port, &tpgt);*/
			break;
		case 'r':
			sip = optarg;
			csio_app_log_devel_debug("%s: saddr %s\n", coiscsi_name, optarg);
			break;
		case 'e':
			nodeid = strtoull(optarg, NULL, 10);
			break;
/*		case 'i':
			ifid = atoi(optarg);
			csio_app_log_devel_debug("%s: ifid %d\n", coiscsi_name, ifid);
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
*/
		case 't':
			tid = atoi(optarg);
			csio_app_log_devel_debug("%s: tid [%d]\n", coiscsi_name, tid);
			break;
		case 'h':
			usage(0);
			break;
		case 'w':
			tcp_wscale = atoi(optarg);
			csio_app_log_devel_debug("%s: tcp_window_scale [%d]\n",
				coiscsi_name, tcp_wscale);
			break;
		case 'c':
			tcp_wsen = 1;
			csio_app_log_devel_debug("%s: tcp_window_scale:[%s]\n",
				coiscsi_name, (tcp_wsen) ? "ENABLED" :
				"DISABLED");
			break;
		case '?':
		default:
			usage(1);
			csio_app_log_devel_debug("in default\n");
			csio_app_log_devel_debug("%s: Invalid character %c\n", coiscsi_name, optopt);
			rc = CSIO_EINVAL;
			goto out;

			break;
		}
	}

	if (argc == 2)
		usage(0);
	
	csio_app_log_devel_debug("optind %d, argc %d\n", optind, argc);
	
	if (optind < argc) {
		fprintf(stderr, "%s: unrecognised option %s\n", coiscsi_name, argv[optind]);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (optopt) {
		fprintf(stderr, "%s: Invalid character %c\n", coiscsi_name, optopt);
		rc = CSIO_EINVAL;
		goto out;
	}

	if (!device) {
		fprintf(stderr, "%s: Please specify Chelsio device node\n", coiscsi_name);
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
			fprintf(stderr, "%s: error opening device %s, %s\n", coiscsi_name, device, strerror(errno));
			rc = errno;
			goto out;
		}
	}

	switch (mode) {
	case CSIO_APP_MOD_COISCSI_TGT:
		if ((rc = verify_short_mode_params(argc, argv, "namedproPiwc",
				0))) {
			fprintf(stderr, "%s: target option '-%c' is not "
					"supported\n", coiscsi_name, rc);
			rc = CSIO_EINVAL;
			goto out;
		} else if (tcp_wscale && !tcp_wsen) {
			fprintf(stderr, "%s: Must enable '--tcp_wsen' to use"
				" '--tcp_wscale <0-3>'\n", coiscsi_name);
			rc = CSIO_EINVAL;
			goto out;
		} else if (tcp_wscale > 3) {
			fprintf(stderr, "%s: Using max possible value"
				" '--tcp_wscale 3'\n", coiscsi_name);
			tcp_wscale = 3;
		}
		rc = csio_target_do_op(hw, op, nodeid, sip, nodename, tcp_port,
						tid, tcp_wscale, tcp_wsen);
		break;

	case CSIO_APP_MOD_HW:
		if ((rc = verify_short_mode_params(argc, argv, "mdo", 0))) {
			fprintf(stderr, "%s: target option '-%c' is not "
			                "supported\n", coiscsi_name, rc);
			rc = CSIO_EINVAL;
			goto out;
                }
                if (op == CSIO_APP_OP_DCBX)
                        rc = csio_print_all_dcbx_info(hw);
                else
                        rc = csio_print_hw_info(hw);

                break;

	default:
		fprintf(stderr, "%s: Unsupported Mode\n", coiscsi_name);
		usage(0);
	}

out:
	if (rc > 0 && rc <= CSIO_ELAST)
		fprintf(stderr, "%s\n", csio_err_to_msg(rc));
	else if (rc > CSIO_ELAST)
		fprintf(stderr, "Invalid parameter, retval %d\n", rc);
	
	if (hw != -1)
		close_adapter(hw);
	
	csio_app_log_devel_debug("%s: %d: \n", coiscsi_name, rc);
	
	return 0;
}
