#!/bin/bash

function check_cmd_exist
{
	path=`which $1`
	if [ -z "$path" ]; then
		echo "$1 NOT available, bail out."
		exit 0
	fi
}

check_cmd_exist pgrep 
check_cmd_exist taskset

cpu=`cat /proc/cpuinfo | grep processor | wc -l`

cnt=0
while [ $cnt -lt $cpu ]; do
	proc=`pgrep -x ch_tworker_$cnt`
	taskset -pc $cnt $proc > /dev/null
	v=`taskset -p $proc`
	echo "ch_tworker_$cnt: $v."
	let cnt=$cnt+1
done

cnt=0
while [ $cnt -lt $cpu ]; do
	proc=`pgrep -x ch_tlu_$cnt`
	taskset -pc $cnt $proc > /dev/null
	v=`taskset -p $proc`
	echo "ch_tlu_$cnt: $v."
	let cnt=$cnt+1
done
