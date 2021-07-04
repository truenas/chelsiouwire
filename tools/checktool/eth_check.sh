#!/bin/bash
# Initial version : 2017/OCT/17
# check couter of ethtool -S
# $0 <interval> <count> <all_counter_check>

declare -A statics

interval=1
all_check=0
if [ -n "$1" ]; then
	interval=$1
fi

if [ -n "$2" ] && [ $2 -gt 0 ]; then
	count=$2
fi

if [ -n "$3" ]; then
	all_check=$3
fi

ETHTOOL=`which ethtool 2> /dev/null`
if [ -z $ETHTOOL ]; then
	echo "Failed: ethtool is not found."
	exit
fi

int_list=`ls /sys/class/net/`
cxgb4_list=`ls -d /sys/kernel/debug/cxgb4/*`

i=0
while [ -z $count ] || [  $i -le $count ]; do  # i=0 : read initial value. it is not couter check. i=1..$count : check counter

	for dev in $int_list
   	do
		[ $dev = "lo" ] && continue
		[ $dev = "virbr0" ] && continue
		[ $dev = "virbr0-nic" ] && continue

		while read item; do
			p1=$(echo $item | cut -d':' -f1)
			p2=$(echo $item | cut -d':' -f2)

			if [ $i -gt 0 ]; then
				p3=${statics[$dev$p1]}
				if [[ $p1 = *err* ]]  || [[ $p1 = *drop* ]] || [[ $p1 = *retr* ]] || [ $all_check -eq 1 ] ; then
					if [ "$p3" != "$p2" ]; then
						echo -n `date +%Y%m%d%H%M%S`
						driver=$($ETHTOOL -i $dev | grep driver)
						if [[ $driver == *cxg* ]] ; then
							echo -n " Chelsio $driver :"
						else
							echo -n " Another $driver :"
						fi
						echo " $dev : $p1 $p3 -> $p2"
					fi
				fi
			fi
			statics[$dev$p1]=$p2
		done < <( $ETHTOOL -S $dev 2> /dev/null )
     	done

	for cxgb4 in $cxgb4_list
	do
		qtype_index=1 # start from 1. counter for multiple same Qtype name
		qtype=""
		while read item; do
			# split
			j=1  # column start from 1
			qtype_flag=0 # scope : line
			for  p1 in $item 
			do
				if [ $j -eq 1 ]; then
					if [[ $p1 == QType* ]]; then
						qtype_flag=1
					else
						parameterName=$p1
					fi
				else 
					if [ $j -eq 2 ] && [ $qtype_flag -eq 1 ]; then
						if [[ "$qtype" != "$p1" ]]; then
							qtype=$p1
							let qtype_index=1 
						else
							let qtype_index+=1
						fi
					elif [ $qtype_flag -eq 0 ] && \
						([[ $parameterName = *Err* ]]  || [[ $parameterName = *Drop* ]] || [ $all_check -eq 1 ]) ; then
						if [ $i -gt 0 ]; then # skip compare if i == 0
							p3=${statics[$qtype$qtype_index$parameterName$j]}
							if [ "$p1" != "$p3" ]; then
								echo -n `date +%Y%m%d%H%M%S`
								let jj=$j-1
								echo " cxgb4 qstats $qtype($qtype_index) $parameterName($jj): $p3 -> $p1 "
							fi
						fi
#						echo "$p1"
						statics[$qtype$qtype_index$parameterName$j]=$p1

					fi
				fi
				let j+=1
			done
		done < <( cat $cxgb4/qstats )
	done

	let i+=1
	sleep $interval
done


