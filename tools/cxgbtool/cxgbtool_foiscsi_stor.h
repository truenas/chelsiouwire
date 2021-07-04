#ifndef	CXGBTOOL_FOISCSI_STOR_H
#define	CXGBTOOL_FOISCSI_STOR_H

#include <csio_services.h>
#include <csio_foiscsi_persistent.h>
#include <csio_foiscsi_ioctl.h>

#define DEFAULT_ISCSI_TARGET_PORT 3260

extern int run_foiscsi_stor(int, char **);


#endif	/* CXGBTOOL_FOISCSI_STOR_H */
