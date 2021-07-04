#ifndef	CXGBTOOL_ISNS_STOR_H
#define	CXGBTOOL_ISNS_STOR_H

#include <csio_services.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>

#define DEFAULT_ISNS_SERVER_PORT 3205
#define FORMAT_IPV6             "%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x"
#define FORMAT_IPV6_PORT        "[" FORMAT_IPV6 "]:%u"
#define FORMAT_IPV4             "%u.%u.%u.%u"
#define FORMAT_IPV4_PORT        FORMAT_IPV4 ":%u"


struct isns_ioctl_list {
	struct isns_ioctl_list *next;
	int    len;
	void   *i_buf;
};

extern int run_isns_cmd(int, char **);

#endif	/* CXGBTOOL_ISNS_STOR_H */
