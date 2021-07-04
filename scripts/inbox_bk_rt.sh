#! /bin/bash

PWD=$(pwd)
dList="cxgb4 cxgb4vf iw_cxgb4 csiostor libcxgbi cxgb4i libcxgb cxgbit chcr"
ixDpath=/lib/modules/$(uname -r)/kernel
ixLpatha=/usr/lib64/
ixLpathb=/usr/lib/
chmbpath=/var/chelsio/backup/
fdList=""
modDir=$(uname -r | sed -e 's/-/_/g')_chmods
chbpath=${chmbpath}/${modDir}
TAR_CP="tar czf "
isUbuntu=$(cat /etc/issue | head -1 | awk '{print$1}')

if [[ ${isUbuntu} == "Ubuntu"   ]]; then
	ixLpath=$ixLpathb
else
	ixLpath=$ixLpatha
fi

#echo "path=$ixLpath"

function backup_drivers
{
	for ds in $dList ; do 
		k=$(find $ixDpath -name ${ds}.ko | head -1 )
		if [[ $k == "" ]] ; then
			k=$(find $ixDpath -name ${ds}.ko.xz | head -1 )
		fi
		#echo $k, `find $ixDpath -name ${ds}.ko | head -1` 
		if [[ $k != "" ]] ; then
			mkdir -p $chbpath 2>/dev/null
			cd $chbpath
			#echo "Backing up $ds inbox module"
			modpath=`echo $k | awk -F "${ds}.ko" '{print $1}'`
			mkdir -p ./${modpath}
			cp $k ./${modpath} -af ;
			rm -rf $k
		fi
	done
	#echo "Backup Created at $chbpath"
	cd $PWD
}

function backup_libs
{
	for k in $(find $ixLpath -name libcxgb4\* ) ; do 
		#echo $k
		if [[ $k != "" ]] ; then
			mkdir -p $chbpath 2>/dev/null
			cd $chbpath
	                #echo "Backing up inbox libraries"
			sp=$(echo $k | awk -F "/" '{print $NF}')
		        modpath=`echo $k | awk -F "${sp}" '{print $1}'`
			mkdir -p ./${modpath}
			cp $k ./${modpath} -af ;
		fi
	done

}

function backup_fw
{
	echo
	#cp -af $ixFwDir/* ./${modpath} -afv ;
	for k in $(find /lib/firmware/cxgb4/ -name \*) ; do
		#echo $k
		if [[ $k != "" ]] ; then
			mkdir -p $chbpath 2>/dev/null
			cd $chbpath
	                #echo "Backing up inbox FW"
			sp=$(echo $k | awk -F "/" '{print $NF}')
			if [[ $sp != "" ]] ; then
			        modpath=`echo $k | awk -F "${sp}" '{print $1}'`
				mkdir -p ./${modpath}
				cp $k ./${modpath} -af ;
			fi
		fi
	done


}

function create_backup
{
	backup_drivers
	backup_libs
	backup_fw
}

function progress
{
	p=0 
	pid=$1
	spin='-\|/'
	while kill -0 $pid 2>/dev/null ; do
		p=$(( (p+1) %4 ))
		echo -en "\b${spin:$p:1}"
		sleep .1
	done
	echo -ne "\b${GREEN}Done${RESET}\n"
}

function create_tar
{
	cd ${chmbpath}
	$TAR_CP ${modDir}.tar.gz ${modDir}
	echo "Created Backup Tar file : ${chbpath}.tar.gz"
	rm -rf $modDir
	cd $PWD
}

function backup_inbox
{
	if [[ ! -d $chmbpath ]] ; then
		mkdir -p $chmbpath
	fi
	if [[ ! -f ${chbpath}.tar.gz ]] ; then
		echo -en "Backing up chelsio inbox modules :  "
		create_backup
		echo -en "${GREEN}Done${RESET}\n"
		create_tar
		#progress $!
	fi
}

function restore_inbox
{
	echo -en "Restoring inbox modules :  "
	if [[ -f ${chbpath}.tar.gz ]]; then
		( cd ${chmbpath} ;
		tar xf ${modDir}.tar.gz ;
		cd ${modDir}
		for dir in `ls ` ; do
			cp -rf ${dir}/*  /${dir} ;
		done
		cd ${chmbpath} ;
		rm -rf ${modDir} )
		#progress $!
		echo -ne "${GREEN}Done${RESET}\n"
		cd $PWD
	fi

}

if [[ $1 -eq 0 ]] ; then
	backup_inbox
elif [[ $1 -eq 1 ]] ; then
	restore_inbox
fi
