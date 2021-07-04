#!/bin/bash

# Find Chelsio devices

# commands path
MODPROBE=`which modprobe`
ETHTOOL=`which ethtool 2> /dev/null`
IFUP=/sbin/ifup
CXGBTOOL=`which cxgbtool 2> /dev/null`
KILLALL=$(which killall 2>/dev/null)
if [[ $? -ne 0 ]]; then
	KILLALL="echo No 'killall' available, not killing";
else
	KILLALL="$KILLALL -q"
fi
SYSCTL="`which sysctl`" 
VERSION=`echo $BASH_VERSION | cut -d '.' -f1`

if [[ $VERSION -lt 4 ]]; then
	echo "Bash version greater than 4.0 required for some features of this script."
	echo "Install latest version from http://ftp.gnu.org/gnu/bash/"
	exit 0
fi

# SYSCTL TUNABLES ##############################################################
# Linux core, ipv4, and tcp tuning paramters,                                  #
# Setting any of these values to "" will skip writing of the sysctl.           #
                                                                               #
core_rmem_max=16777216 # Increase maximum read socket buffer size.             #
core_wmem_max=16777216 # Increase maximum write socket buffer size.            #
tcp_timestamps=0       # Disable timestamps to increase throughput.            #
tcp_sack=""            # Disable SACK to increase throughput.                  #
tcp_low_latency=""                                                             #
tcp_adv_win_scale=""                                                           #
moderate_rcvbuf=""                                                             #
                                                                               #
# TCP read buffer (min/default/max), default 4096 87380 174760.                #
ipv4_tcp_rmem="4096 262144 16777216" # overrides net.core.rmem_default.        #
# TCP write buffer (min/default/max), default 4096 16384 131072.               #
ipv4_tcp_wmem="4096 262144 16777216" # overrides net.core.wmem_default.        #
                                                                               #
# TCP memory allocation (min/pressure/max).                                    #
# default values are calculated by the kernel at boot time and depend          #
# on the amount of physical memory.                                            #
ipv4_tcp_mem=""                                                                #
                                                                               #
# max length of iovec or ancilliary data.                                      #
optmem_max=524288     # default 20480.                                         #
                                                                               #
# log length of network packets. kernel will drop unprocessed packets          #
# beyond this. simple algorithm for throughput:                                #
# <backlog> * 100(HZ) * <avg bytes/packet> = throughput bytes/second.          #
netdev_max_backlog=200000 # log length of network packets.                     #
                                                                               #
# Allows control over what percentage of the congestion window can be          #
# consumed by a single TSO frame. Default is 3 on older kernels, 8 on new.     #
tso_win_divisor=""                                                             #
                                                                               #
# TOE SYSCTLS TUNEABLES ########################################################
                                                                               #
################################################################################
# sysctl config file                                                           #
sysctl_conf_file="/etc/sysctl.conf"                                            #
# sysctl_data array, need to include the sysctl name and the data variable.    #
# Comma delimited.                                                             #
sysctl_data=(                                                                  #
	"net.core.wmem_max,$core_wmem_max"                                         #
	"net.core.rmem_max,$core_rmem_max"                                         #
	"net.ipv4.tcp_timestamps,$tcp_timestamps"                                  #
	"net.ipv4.tcp_sack,$tcp_sack"                                              #
	"net.ipv4.tcp_low_latency,$tcp_low_latency"                                #
	"net.ipv4.tcp_adv_win_scale,$tcp_adv_win_scale"                            #
	"net.ipv4.tcp_moderate_rcvbuf,$moderate_rcvbuf"                            #
	"net.ipv4.tcp_rmem,$ipv4_tcp_rmem"                                         #
	"net.ipv4.tcp_wmem,$ipv4_tcp_wmem"                                         #
	"net.ipv4.tcp_mem,$ipv4_tcp_mem"                                           #
	"net.core.optmem_max,$optmem_max"                                          #
	"net.core.netdev_max_backlog,$netdev_max_backlog"                          #
	"net.ipv4.tcp_tso_win_divisor,$tso_win_divisor"                            #
)                                                                              #
# SYSCTL TUNING ################################################################

# The uldq strings as seen in /proc/interrupts file
# For a new uld, append the string in below format
# [uld-name]="qname in proc/interrupts"
#
declare -A uld_qs=(\
[ofld]=ofld        \
[tls]=tls          \
[rdma]=rdma-ciq    \
[iSCSI]=iSCSI      \
[iSCSIT]=iSCSIT    \
[crypto]=crypto    \
)

declare -A if_qs=(	\
[rdma]=iw_cxgb4	\
[crypto]=chcr   \
[tls]=chtls	\
[iSCSI]=cxgb4i  \
[iSCSIT]=cxgbit  \
)

usage()
{
        echo "Usage: $0 [options]"
		echo "options:"
		echo " -C    Disable binding IRQs to CPUs (smp_affinity)."
		echo " -D    Do not disable IRQ balance daemon." 
		echo " -t    Write tx_coal=2 to modprobe.d/conf."
		echo " -T    Remove tx_coal=2 from modprobe.d/conf."
		echo " -n    Dont reload drivers/change link settings"
		echo
		echo " -Q <q-grp>  Queue group string to tune"
		echo "             Valid Queues - nic ${!uld_qs[@]}"
		echo " -s    Tune sysctls also"
		echo " -N    Dont do NUMA based perftune"
		echo " -c    Restrict perftuning to a range of cpus(eg: 1,3-5,7)"
		echo " -i    Tune irqs only associated with this interface(s)."
		echo " -b    Tune irqs only associated with this particular bus id(format: 01:00.4 or 0000:01:00.4)"
		echo
        exit

}

# Look for cxgb4 devices
list_chelsio_dev()
{
	if [ ! -z $interface_list ]; then
		echo ${interface_list[@]} | tr " " "\n" | sort | uniq
		return
	fi

        list_dev=`/sbin/ip link show | grep mtu | cut -d':' -f2`
        for dev in $list_dev
        do
                desc_dev=`$ETHTOOL -i $dev 2>&1 | grep cxgb4`
                if [ $? -eq 0 ]; then
                        echo $dev
                fi
        done
}

list_chelsio_bus_func()
{
	if [ ! -z $bus_list ]; then
		echo ${bus_list[@]} | tr " " "\n" | sort | uniq
		return
	fi

        list_dev=`/sbin/ip link show | grep mtu | cut -d':' -f2`
        for dev in $list_dev
        do
                desc_dev=`$ETHTOOL -i $dev 2>&1 | grep cxgb4`
                if [ $? -eq 0 ]; then
                        bus_func+="$($ETHTOOL -i $dev | grep bus-info | awk '{print $2}') "
		fi
	done
	echo  $bus_func | tr " " "\n" | sort | uniq
}

bringup()
{
	# Privilege ifup as it will apply the interfaces'settings.
	# If it fails, presumably due to the lack of config file,
	# just bring the link up. IP settings can be applied later.
        $IFUP $1 2>/dev/null
        if [ $? -ne 0 ];
        then
                /sbin/ip link set dev $1 up
        fi
}

#Parses ranges to a continuous list(for eg: 0,1-3,5 to 0,1,2,3)
parse_ranges()
{
	echo $1 | awk 'BEGIN { RS=","; FS="-"; ORS="" }
			       NR > 1  { print " " }
			       NF > 1  { for (i=$1; i<$2; ++i) { print i " " } print $2; next }
			     { print $1 }'
}

# cpumask is used in msi_x_perftune function to evenly spread interrupts around
# all the ports/CPUs
# It is declared external to the function as we want a stateful cpumask rotor
# which spreads interrupts as evenly as possible around all the ports/CPUs
cpumask=1

# grep /proc/interrupts to figure out cxgb4's interfaces all interrupts.
# Extract msix interrupts from this list using the information from 
# /sys/*device*/msi_irqs/* nodes. 
# On recent kernels, typical lines look like:
# 81: 0  0   0   0   PCI-MSI-edge      eth25-Rx1
# 89: 0  0   0   0   PCI-MSI-edge      0000:08:00.4-ofld3
# 90: 0  0   0   0   PCI-MSI-edge      0000:08:00.4-rdma0
# hence the grep on interface name/pci_bus_func-mode
msi_x_perftune()
{
        ETH=$1
	MODE=$2
	IS_IFQ=$3

	if [[ $MODE = "" ]]; then
		irq_path="/sys/class/net/$ETH/device/msi_irqs"
		irqs_all=($(cat /proc/interrupts | grep -w "$ETH" | \
			  grep -w "(queue [0-9]\+)$\|Rx[0-9]\+$" | \
			  awk '{ split($0,a,":"); print a[1] }'))
	else
		if [[ $IS_IFQ == "1" ]]; then
			irq_path="/sys/class/net/$ETH/device/msi_irqs"
		else
			irq_path="/sys/bus/pci/devices/$ETH/msi_irqs"
		fi
		irqs_all=($(cat /proc/interrupts | grep $ETH-$MODE | \
	      		    awk '{ split($0,a,":"); print a[1] }'))

	fi

	# Extract the MSI-X irqs from irqs_all array
	j=0
	unset irqs
	for i in "${irqs_all[@]}";do
		if [ -d $irq_path/$i ]; then
			ival=$(cat $irq_path/$i/mode)
		else
			ival=$(cat $irq_path/$i)
		fi
		if [[ $ival = "msix" ]]; then
			irqs[$j]=$i
			j=$((j + 1))
		fi
	done

	if [ ${#irqs[@]} == "0" ]; then
		echo "Zero IRQ table length for $ETH $MODE, Skipping ..."
		return
	fi

	echo "IRQ table length ${#irqs[@]}"

	maxcpu=$(( $(grep processor /proc/cpuinfo|wc -l)))

	if [[ ! -z $cpu_range ]]; then
		cpus=($cpu_range)
	elif [[ ${numa_nodes_no} -gt 1 ]]; then
		if [ -d /sys/class/net/$dev ]; then
			numa_node=$(cat /sys/class/net/$dev/device/numa_node)
		else
			numa_node=$(cat /sys/bus/pci/devices/$dev/numa_node)
		fi
		if [[ $numa_node == -1 ]]; then
			echo "Numa node unknown for device $dev, Disabling NUMA based perftune"
			numa_nodes_no=1
		else
			node_str="node$numa_node"
			# Get CPU indices in the associated numa node
			cpulist=$(cat /sys/devices/system/node/$node_str/cpulist)
			cpus=($(parse_ranges $cpulist))
		fi

	# Either NUMA is not present, NUMA perftune is disabled by user or NUMA node value returned a -1
	elif [[ ${numa_nodes_no} == 1 ]]; then 
		# Get All CPU indices
		cpulist=$(cat /sys/devices/system/node/node*/cpulist | tr "\n" ",")
		cpus=($(parse_ranges $cpulist))
	else
		echo "Invalid value of NUMA node"
		exit 1
	fi

	echo "Using CPU(s) ${cpus[@]} for SMP Affintiy"

	for (( c=0, k=0; c < ${#irqs[@]}; c++ ));
	do
		cpuid="${cpus[$k]}"
		cpumask=$(echo "16o 2 $cpuid ^p" | dc |
			  awk '{ words = int((length($0)+7)/8);
				 padding = words*8 - length($0);
				 printf("%*s%s\n", padding, " ", $0); }' |
			  sed -e 's/\(........\)/,\1/g' -e 's/^,//')
		echo "Writing $cpumask in /proc/irq/${irqs[$c]}/smp_affinity"
		echo $cpumask > /proc/irq/${irqs[$c]}/smp_affinity

		k=$((k + 1))
		if [[ ${k} -ge ${maxcpu} ]] || [[ ${k} -ge  ${#cpus[@]} ]]; then
			k=0
		fi
        done
}

dev_perftune()
{
	ETH=$1
	MODE=$2
	IS_IFQ=$3

	if ! (( disable_smp_affinity )); then
		if [[ $MODE == "" ]]; then
			echo "Tuning $ETH"
			msi_x_perftune $ETH
		else
			echo "Tuning $ETH-$MODE"
			msi_x_perftune $ETH $MODE $IS_IFQ
		fi
	fi

	# Dont set coalesce settings for ULD queues
	if [ -z $MODE  ]; then
		$ETHTOOL -C $ETH rx-frames 4
	fi
}

i=0
j=0
k=0
l=0
valid=0
Options="CDTQ:thnsNc:i:b:"
while getopts $Options option; do
	case $option in
		C ) disable_smp_affinity=1;;
		D ) dont_disable_irqbalance=1;;
		Q ) if [[ $OPTARG == "nic" ]]; then
			nicq=1
		   else 
			for ifq in ${!if_qs[@]}; do
				if [[ $ifq != $OPTARG ]]; then
					continue
				fi
				if_q_grp_str[$((i++))]=${if_qs[$OPTARG]}
				valid=1
			done

			for uldq in ${!uld_qs[@]}; do
				if [[ $uldq != $OPTARG ]]; then
					continue
				fi
				uld_q_grp_str[$((j++))]=${uld_qs[$OPTARG]}
				valid=1
			done

			if [[ $valid == 0 ]]; then
				usage
			fi
		fi;;
		t ) tx_coal=2;;
		T ) tx_coal=1;;
		n ) no_reload=1;;
		s ) tune_sysctl_enable=1;;
		N ) numa_perftune=0;;
		c ) echo "Using CPU ranges will override NUMA based perftune."
		    cpu_range=$(parse_ranges $OPTARG);;
		i ) $ETHTOOL -i $OPTARG 2>&1 | grep cxgb4 > /dev/null
		    if [ $? -ne 0 ]; then
			echo $OPTARG not a valid Chelsio interface
			exit 1
		    fi
		    interface_list[$((k++))]=$OPTARG;;
		b ) if ! [[ $OPTARG =~ ^0000.* ]]; then
		    	busid=0000:$OPTARG
		    else
			busid=$OPTARG
		    fi
		    busid=${busid%.*}.4
		    bus_path="/sys/bus/pci/devices/${busid}"
		    if [ ! -e $bus_path ]; then
			echo $OPTARG is not a valid bus interface
			exit 1
		    fi
		    vendor=$(cat $bus_path/vendor 2>/dev/null)
		    if [[ $vendor != 0x1425 ]]; then
			echo $OPTARG is not a Chelsio bus
		    fi
		    bus_list[$((l++))]=$busid
		    interface_list+=(${interface_list[@]} $(ls $bus_path/net));;
		* ) usage;;
	esac
done
shift $(($OPTIND - 1))

if [ $# -ne 0 ]; 
then
        usage
fi

if [ -z $CXGBTOOL ];
then
        echo "Error: please install cxgbtool utility"
        exit 1
fi

if [ -z $ETHTOOL ];
then
	echo "Error: please install ethtool utility"
	exit 1
fi

# start fresh

# If iw_cxgb4 and cxgb4 modules are not loaded then trying to
# remove them will result into FATAL error. This can lead user
# to wrong direction. Hence removing errors getting displyed to
# user evenif modules are not loaded.
if [ -z $no_reload ]; then
	$MODPROBE -r iw_cxgb4 > /dev/null 2>&1
	$MODPROBE -r cxgb4 > /dev/null 2>&1
fi

if ! (( dont_disable_irqbalance )); then
	$KILLALL irqbalance
fi


if [ -e /etc/modprobe.conf ]; then
	modprobe_config=/etc/modprobe.conf
elif [ -e /etc/modules.conf ]; then
	modprobe_config=/etc/modules.conf
elif [ -d /etc/modprobe.d/ ]; then
	modprobe_config=/etc/modprobe.d
fi

# Option for ipforwarding mode.
if [ "$tx_coal" == "2" ]; then
	if [ -d "$modprobe_config" ]; then
		# modprobe_config is a directory, need to scan all files.
		cf=$(grep -r -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config/* \
			 2>/dev/null | awk 'BEGIN{FS=":"}{print $1}')
	else
		cf=$(grep -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config \
			 2>/dev/null)
		[ -n "$cf" ] && cf=$modprobe_config
	fi

	if [ -z "$cf" ]; then
		if [ -d "$modprobe_config" ]; then
			cf=/etc/modprobe.d/chelsio.conf
		else
			cf=$modprobe_config
		fi
		echo "options cxgb4 tx_coal=2" >> $cf
		logger -s "cxgb4 added tx_coal=2 to $cf"
	else
		# The tx_coal option is already set. Dump an error to syslog and continue.
		logger -s "cxgb4 tx_coal value already set. Please check your $cf file."
	fi
# Back to default mode.
elif [ "$tx_coal" == "1" ]; then
	if [ -d "$modprobe_config" ]; then
		cf=$(grep -r -l 'options\s*cxgb4\s*.*tx_coal=.*' $modprobe_config/* \
			 2>/dev/null)
	else
		cf=$modprobe_config
	fi

	if [[ ! -z "$cf" ]]; then
		# If tx_coal is the only option on the line, then remove the
		#  line, otherwise, remove just the tx_coal option.
		sed -i 's/\(\s\)*/\1/g' $cf # get rid of multiple spaces
		t=$(grep "^options\s*cxgb4\s*.*tx_coal=2" $cf)
		t=$(echo $t | sed 's/options\s*cxgb4\s*.*tx_coal=.//')
		if [ -z "$t" ]; then
			logger -s "cxgb4 tx_coal=2 removed from $cf"
			sed -i 's/^options\s*cxgb4\s*tx_coal=.//' $cf
		else
			logger -s "cxgb4 tx_coal=2 removed from $cf"
			sed -i 's/^\(options\s*cxgb4\s*.*\)tx_coal=./\1/' $cf
		fi
	fi
fi

echo "Discovering Chelsio T4/T5/T6 devices ..."

if [ -z $no_reload ]; then
	$MODPROBE cxgb4 max_eth_qsets=64
	$MODPROBE iw_cxgb4

	# Allow the dust to settle. Sometimes the OS will rename the network interfaces,
	# so if we bringup an interface before it finishes renaming them
	# /proc/interrupts will associate irqs with stale interface names.
	sleep 2;
fi

# Get cxgb4 devices, bring them up

chelsio_devs=`list_chelsio_dev`
if [ -z $no_reload ]; then
	for dev in $chelsio_devs
	do
        	bringup $dev
	done
fi

chelsio_bus_func=`list_chelsio_bus_func`

echo "Configuring Chelsio T4/T5/T6 devices ..."

# get devices again, after potential renaming
# Complete the performance tuning on interfaces now up
# If user has specified uld list manually, set chelsio_devs
# only if nic parameter is set
if [[ ${#uld_q_grp_str[@]} == "0" || ${#if_q_grp_str[@]} -gt "0" || $nicq == "1" ]]; then
	chelsio_devs=`list_chelsio_dev`
else
	chelsio_devs=""
fi

# Copy user provided uldqs to default array.
# This is needed to do a full perftune if user doesnt specify any
# specific Q for perftune
if [[ ${#uld_q_grp_str[@]} -gt 0  || ${#if_q_grp_str[@]} -gt 0 || $nicq == "1" ]]; then
	unset uld_qs
	unset if_qs
	uld_qs=( "${uld_q_grp_str[@]}" )
	if_qs=( "${if_q_grp_str[@]}" )
fi

numa_nodes_no=($(ls /sys/devices/system/node/ 2>/dev/null | grep -c node))

if [[ ${numa_perftune} == "0" ]]; then
	echo "Skipping NUMA perftune on user request.. Note that this may affect performance"
	numa_nodes_no=1
fi

if [[ ${numa_nodes_no} -gt 1 && -z $cpu_range ]]; then
	echo "Machine contains NUMA nodes..CPU's will be assigned accordingly"	
fi

for dev in $chelsio_devs
do
# Condition to avoid perftune for interfaces when user just specified
# interface q's
	if [[ ${#if_q_grp_str[@]} -eq "0"  ||  $nicq == "1" ]]; then
		dev_perftune $dev
	fi

	for ifq in ${if_qs[@]}
	do
		dev_perftune $dev $ifq 1
	done
done

# Assign CPUs for ULD queues
for dev in $chelsio_bus_func
do
	for uld in ${uld_qs[@]}
	do
		dev_perftune $dev $uld
	done
done

if (( $tune_sysctl_enable )); then
	echo "Set sysctls..."
	# Create a backup file.
	if [ ! -e "$sysctl_conf_file.perftune.bak" ]; then
		cp -fa $sysctl_conf_file "$sysctl_conf_file.perftune.bak"
	fi
	IFS=$'\n'
	for control in ${sysctl_data[@]}; do
		unset IFS
		sysctl_param=${control%%,*}
		sysctl_param=$(echo $sysctl_param | sed 's/^[ \t]*//;s/[ \t]*$//')
		data=${control##*,}
		data=$(echo $data | sed 's/^[ \t]*//;s/[ \t]*$//')
		[ -z "$data" ] && continue
		unset failed_sysctl

		if $SYSCTL $sysctl_param >/dev/null 2>&1; then
			echo "Set $sysctl_param=\"$data\""
			$SYSCTL -w "$sysctl_param=$data" >/dev/null 2>&1
			if [[ $? -ne 0 ]]; then
			  (( failed_sysctl++ ))
			fi
		else
			echo "$sysctl_param not valid for this system."
		fi
	done
	unset IFS
	(( $failed_sysctl )) && echo "Some sysctls failed, system may not be tuned!"
fi

echo "System tuning is complete."
exit

# kill netserver
# killall -v netserver 2>&1 > /dev/null
# start netserver
# taskset -c 4-7 netserver 2>&1 > /dev/null
