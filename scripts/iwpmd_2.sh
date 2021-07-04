#! /bin/bash

PWD=$(pwd)
rpmdir=${PWD}/support

rpm -q iwpmd-1.0.6-1.x86_64 &> /dev/null
if [[ $? -ne 0 ]] ; then
		rpm -ivh ${rpmdir}/iwpmd-1.0.6-1.x86_64.rpm  --force --nodeps &> /dev/null
fi
rpm -q iwpmd-debuginfo-1.0.6-1.x86_64 &> /dev/null
if [[ $? -ne 0 ]] ; then
		rpm -ivh ${rpmdir}/iwpmd-debuginfo-1.0.6-1.x86_64.rpm  --force --nodeps  &> /dev/null
fi

