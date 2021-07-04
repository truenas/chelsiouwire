PWD=$(pwd)
srcDir=${PWD}/support
srcFile="Python-2.7.16.tgz"

distver=$(cat /etc/os-release  | grep VERSION_ID | head -1 | awk -F "=" '{print $2}' | awk -F "\"" '{print $2}' | awk -F "." '{print $1}' | tr '[:upper:]' '[:lower:]')
if [[ $distver -eq 8 ]];then
	if [[ ! -f /usr/bin/python ]]  ; then
		if [[ ! -f /usr/bin/python2 ]]  ; then
			printf "The python package is missing.Installing now, this will take some time please wait... "
			cd $srcDir
			tar xf  ${srcFile}
			(cd $srcDir/Python-2.7.16 && ( ./configure && make && make install)&> /dev/null)
			rm -rf $srcDir/Python-2.7.16 
			cp /usr/local/bin/python /usr/bin 
			printf "Done."
		else
			ln -s /usr/bin/python2 /usr/bin/python	
			printf "python2 Already Installed. Creating a symlink python->python2. "
		fi
	fi
fi
