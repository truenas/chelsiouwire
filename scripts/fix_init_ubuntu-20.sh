#!/bin/bash

GREEN='\033[0;32m'
RESET='\033[0m'

echo -en "Removing Chelsio Modules from initramfs :  "

initimg_file=$(echo ${initimg} | awk -F "/" '{print $NF}')
initrdBackupModPath="/var/chelsio/backup/initrdBackupMod"

if [[ ! -d $initrdBackupModPath ]] ; then
		mkdir -p $initrdBackupModPath
fi


# Take backup of inbox drivers
if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb/cxgb.ko ]] ;then
	mv /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb/cxgb.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb3/cxgb3.ko ]] ;then
	mv /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb3/cxgb3.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4vf/cxgb4vf.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4vf/cxgb4vf.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/libcxgb/libcxgb.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/libcxgb/libcxgb.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/csiostor/csiostor.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/csiostor/csiostor.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb3i/cxgb3i.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb3i/cxgb3i.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb4i/cxgb4i.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb4i/cxgb4i.ko $initrdBackupModPath
fi

if [[ -f /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/libcxgbi.ko ]] ;then
        mv /usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/libcxgbi.ko $initrdBackupModPath
fi


# Regenerate initrd
update-initramfs -u -v -k $(uname -r) > /dev/null 2>&1

# Restore inbox drivers
cp $initrdBackupModPath/cxgb.ko         /usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb/cxgb.ko > /dev/null 2>&1
cp $initrdBackupModPath/cxgb3.ko    	/usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb3/cxgb3.ko > /dev/null 2>&1
cp $initrdBackupModPath/cxgb4.ko  	/usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4/cxgb4.ko > /dev/null 2>&1
cp $initrdBackupModPath/cxgb4vf.ko	/usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/cxgb4vf/cxgb4vf.ko > /dev/null 2>&1
cp $initrdBackupModPath/libcxgb.ko	/usr/lib/modules/$(uname -r)/kernel/drivers/net/ethernet/chelsio/libcxgb/libcxgb.ko > /dev/null 2>&1
cp $initrdBackupModPath/csiostor.ko	/usr/lib/modules/$(uname -r)/kernel/drivers/scsi/csiostor/csiostor.ko > /dev/null 2>&1
cp $initrdBackupModPath/cxgb3i.ko	/usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb3i/cxgb3i.ko > /dev/null 2>&1
cp $initrdBackupModPath/cxgb4i.ko	/usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/cxgb4i/cxgb4i.ko > /dev/null 2>&1
cp $initrdBackupModPath/libcxgbi.ko 	/usr/lib/modules/$(uname -r)/kernel/drivers/scsi/cxgbi/libcxgbi.ko > /dev/null 2>&1

echo -ne "${GREEN}Done${RESET}\n"
