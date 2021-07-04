#ifndef	__CSIO_APP_COMMON_H__
#define __CSIO_APP_COMMON_H__

#include <stdint.h>
#include <csio_common_ioctl.h>
#include <csio_services.h>


/*#define CSIO_APP_BRINGUP*/
#define FILE_BUF_SIZE           1024

#ifdef CSIO_APP_BRINGUP
#define csio_app_log_devel_debug(fmt, args...)\
	fprintf(stderr, fmt, ##args)
#else
#define csio_app_log_devel_debug(fmt, args...)\
	do {} while (0)
#endif

#define csio_app_log_info(file, fmt, arg...)\
	fprintf(file, fmt, ##arg)

#define CSIO_CHNET_VLAN_NONE	0xFFF

static inline int csio_chnet_is_valid_vlan(uint16_t vlan)
{
	uint16_t vlanid = vlan & 0x0fff;
	return (vlanid >= 2 && vlanid < 4095);
}

void convert_decimal_ip(char *, uint32_t);
adap_handle_t open_adapter_handle(char *);
void shift_argv(int *, char **, int);

char *str_to_ipport(char *, int *, int *);

int str_to_mode(const char *);
int str_to_op(const char *);

const char *csio_err_to_msg(enum csio_app_err);

#endif	/* __CSIO_APP_COMMON_H__ */
