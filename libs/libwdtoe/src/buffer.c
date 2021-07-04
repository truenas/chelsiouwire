#include <assert.h>
#include <pthread.h>
#include "atomic.h"
#include "device.h"
#include "buffer.h"


/*
 * returns the index to an entry of new Tx and Rx buf,
 * returns -1 if no new entry available.
 */
int get_new_buf(struct wdtoe_device *dev)
{
	int i;
	pthread_spin_lock(&dev->stack_info->buf.lock);
	for (i = 0; i < NWDTOECONN; i++) {
		if (dev->stack_info->buf.flags[i] == 0) {
			dev->stack_info->buf.flags[i] = 1;
			pthread_spin_unlock(&dev->stack_info->buf.lock);
			return i;
		}
	}
	pthread_spin_unlock(&dev->stack_info->buf.lock);
	return -1;
}
