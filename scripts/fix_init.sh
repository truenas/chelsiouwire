#!/bin/bash
#title          :fix_init.sh
#author         :Allwin Prabhu<rallwin@chelsio.com>
#version        :0.1    
# This script will add/remove the specified modules in initramfs image
# It supports only with ubuntu14.X, RHEL6.X, RHEL7.x, SLES12.X
#==============================================================================

VERSION="0.1"
ADDFG=0
REMFG=0
SUCCESS=0
UNSUPPORTED=-1
ERROR=5
#initfile_ubuntu="/usr/share/initramfs-tools/modules"
initfile_ubuntu="/etc/initramfs-tools/modules"
prom=1
declare -a chmods
GREEN='\033[0;32m'
WARNING='\033[93m'
FAIL='\033[91m'
RESET='\033[0m'
PWD=$(pwd)
#if [ $logfile == "" ] ; then
	logfile=${PWD}/initramfs.log
#fi

#export logfile

function usage
{
	echo -e "\nChelsio initramfs script v$VERSION"
	echo -e "\nAdd/Remove chelsio modules in initramfs image"
	echo "This script must be executed with root privileges"
	echo -e "\nOptions:\n\t-a|--add\t\t- Add specified modules to initramsfs image seperated by comma"
	echo -e "\t-r|--remove\t\t- Remove specified modules from initramsfs image seperated by comma"
	echo -e "\t-y\t\t\t- Assume Yes to all queries and do not prompt"
}

if [[ $# == 0 ]] ; then
	echo "Please specify atleast one arguement."
	usage
	exit $ERROR
fi

while [[ $# > 0 ]] ; do
	akey="$1"
	case $akey in
		-a|--add)
		addMod="$2"
		ADDFG=1
		shift
		;;
		-r|--remove)
		remMod="$2"
		REMFG=1
		shift
		;;
		-y) prom=0
		;;
		-h|--help)
		usage
		exit 0
		;;
		*)
		echo "Invalid argument - $akey"
		usage
		exit 1
		;;
	esac
	shift
done

if [[ $EUID -ne 0 ]] ; then 
	echo "Please execute this script with root privileges."
	exit 1
fi

if [[ $ADDFG == 1 ]] && [[ $REMFG == 1 ]] ; then
	echo "Only one operation allowed at a time."
	exit 2
fi
if [[ $(echo $addMod | grep -c \- ) -eq 1 ]] || [[ $(echo $remMod | grep -c \- ) -eq 1 ]] ; then
	echo "Invalid value specified."
	usage
	exit 3
fi

function unsupported
{
	#echo "Unsupported Platform"
	echo "Unable to find initrd image."
	exit $UNSUPPORTED
}

function progress
{
	p=0 
	pid=$1
	spin='-\|/'
	while kill -0 $pid 2>/dev/null ; do
		p=$(( (p+1) %4 ))
		echo -en "${spin:$p:1}"
		sleep .1
	done
	echo -ne "${GREEN}Done${RESET}\n"
}

# Function to add module to initramfs.
# 1 - ubuntu
# 2 - RHEL/SLES
function addinitmodule 
{
	distType=$1
	if [[ $distType -eq 1 ]]; then
		#ubuntu
		echo
		for mods in ${chmods[*]}; do
			while read -r line ; do 
				modname=$line
				if [[ $(echo ${modname:0:1}) == "#" ]] ; then
					continue
				elif [[ $modname == $mods ]] ; then
					initmod=1
					break
				fi
			done < $initfile_ubuntu
			if [[ $initmod -ne 1 ]] ; then
				echo $mods >> $initfile_ubuntu
			fi
			initmod=0
		done
		update-initramfs -u -v -k $(uname -r)
	elif [[ $distType -eq 2 ]] ; then
		#RHEL/SLES
		dr=$(echo ${chmods[*]})
		dracut --add-drivers "$dr" --force -v
	else
		#Unsupported
		unsupported
	fi

}


# Function to remove module from initramfs.
# 1 - ubuntu - sed -i.bak '/cxgb4/d' /usr/share/initramfs-tools/modules
# 2 - RHEL/SLES
function reminitmodule
{
	distType=$1
	if [[ $distType -eq 1 ]]; then
		#ubuntu
		if [[ $prom == 1 ]] ; then
			echo "Please uninstall the drivers before removing them"
			read -p "Do you wish to continue(Y/N) : " ch
			case $ch in
		        	[Yy]* ) break;;
			        [Nn]* ) exit;;
			        * ) echo "Please answer yes(y) or no(N).";;
			esac
		fi
	
		#for mods in ${chmods[*]}; do
		#	sed -i "/$mods/d" $initfile_ubuntu
		#done
		#update-initramfs -u -v -k $(uname -r)
		initrdpath="/var/chelsio/backup/initrd"
		extractinitrdpath="/var/chelsio/backup/initrd/extract"
		newinitrdpath="/var/chelsio/backup/new-initrd"
		initimg_file=$(echo ${initimg} | awk -F "/" '{print $NF}')

		if [[ ! -d $initrdpath ]] ; then
        		mkdir -p $initrdpath
		fi

		if [[ ! -d $newinitrdpath ]] ; then
        		mkdir -p $newinitrdpath
		fi

		cp /boot/$initimg_file $initrdpath
		cd $initrdpath
		unmkinitramfs $initimg_file $extractinitrdpath
		#zcat ${initimg_file} | cpio -id > /dev/null 2>&1
		rm -rf $initimg_file
		cd $extractinitrdpath
		mv main/* .
		mv early/* .
		rm -rf main early
		lsinitramfs /boot/$initimg_file | grep -i .ko | grep -i "csio\|cxgb" > /var/chelsio/backup/init-modules
		( for i in `cat /var/chelsio/backup/init-modules` ;  do rm -rf $i ; done  )
		( cd $extractinitrdpath && (find . 2>/dev/null | cpio --quiet --dereference -o -H newc | gzip -9 > $newinitrdpath/$initimg_file) )
		rm -rf /boot/$initimg_file 
	       	cp $newinitrdpath/$initimg_file /boot/ 
		rm -rf $initrdpath $newinitrdpath ${extractinitrdpath}
		
	elif [[ $distType -eq 2 ]] ; then
		#RHEL/SLES
		dr=$(echo ${chmods[*]})
		dracut --omit-drivers "$dr" --force -v
	else
		unsupported
	fi

}

# This function will process the specified modules and calls the appropriate functions.
function procinit
{
	distType=$1
	if [[ $ADDFG == 1 ]] ; then
		procMod=$addMod
	elif [[ $REMFG == 1 ]] ; then
		procMod=$remMod
	else
		exit 1
	fi
	c=0
	while IFS="," <<< $procMod; do
		for mods in ${procMod[@]}; do
			chmods[c]=$mods
			c=` expr $c + 1 `
		done
		break
	done
	unset IFS
	#TODO: Add sorting of modules in array based on dependency.
	if [[ $ADDFG == 1 ]] ; then
		addinitmodule $distType 
	elif [[ $REMFG == 1 ]] ; then
		echo -en "Removing Chelsio Modules from initramfs :  "
		reminitmodule $distType &> $logfile &
		pid=$!
		#progress $pid
		echo -ne "${GREEN}Done${RESET}\n"
	else
		exit 1 
	fi

}

#Check Distro type using os-release file
if [[ -f /etc/os-release ]] ; then
	#Check for RHEL7.X/SLES12.X/ubuntu14.X
	distro=$(cat /etc/os-release  | grep NAME | head -1 | awk -F "=" '{print $2}' | awk -F "\"" '{print $2}' | tr '[:upper:]' '[:lower:]')
	distver=$(cat /etc/os-release  | grep VERSION_ID | head -1 | awk -F "=" '{print $2}' | awk -F "\"" '{print $2}' | awk -F "." '{print $1}' | tr '[:upper:]' '[:lower:]')
	if [[ $(echo $distro | grep -c red ) -eq 1 ]] || [[ $(echo $distro | grep -ic centos ) -gt 0 ]] ; then
		distro="redhat"
	fi
	if [[ $distro == "ubuntu" ]] && [[ $distver > 13 ]] ; then
		procinit 1
	elif [[ $distro == "sles"  ]] && [[ $distver > 11 ]] ; then
		procinit 2
	elif [[ $distro == "redhat"  ]] && [[ $distver > 6 ]] ; then
		procinit 2
	else
		unsupported
	fi
elif [[ -f /etc/redhat-release ]] ; then
	#Check for RHEL6.X
	distro=$(cat /etc/redhat-release  | awk '{print $1$2}' | tr '[:upper:]' '[:lower:]')
	if [[ $distro == "redhat" ]] ; then 
		distver=$(cat /etc/redhat-release  | awk '{print $7}' | awk -F "." '{print $1}' | head -1 )
	elif [[ $(echo $distro | grep -ic centos ) -gt 0 ]] ; then
		distver=$(cat /etc/redhat-release  | awk '{print $3}' | awk -F "." '{print $1}' | head -1 )
	else
		unsupported
	fi
	if [[ $distver > 5 ]] ; then 
		procinit 2
	else
		unsupported
	fi
else
	unsupported
fi

exit $SUCCESS
