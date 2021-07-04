#! /bin/bash

chmbpath=/var/chelsio/backup

initimg_file=$(echo ${initimg} | awk -F "/" '{print $NF}')

rm -rf ${initimg}.chbak

if [[ ! -d $chmbpath ]] ; then
	mkdir -p $chmbpath
fi

if [[ ! -f $chmbpath/${initimg_file}.chbak-${vers} ]] ; then
	cp -f ${initimg} $chmbpath/${initimg_file}.chbak-${vers}
fi

if [[ -f ${initimg}.chbak-3.11.0.0 ]] ; then
	rm -rf 	$chmbpath/${initimg_file}.chbak-3.11.0.0
fi
