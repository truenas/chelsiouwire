
#!/bin/bash

if [[ -f /etc/os-release ]] ; then
        #Check for Ubuntu OS

        distver=$(cat /etc/os-release  | grep VERSION_ID | head -1 | awk -F "=" '{print $2}' | awk -F "\"" '{print $2}' | awk -F "." '{print $1}' | tr '[:upper:]' '[:lower:]')

        if [[ -f /usr/bin/dpkg ]] && [[ $distver -gt 13 ]] && [[ $distver -lt 16 ]] ; then
                tgt_ver=$(dpkg -s targetcli | grep -i "Version:" | awk '{print $2}')
                TGT_MAJVER=$(echo $tgt_ver|  awk -F "." '{print $1}')
                TGT_MINVER=$(echo $tgt_ver|  awk -F "." '{print $2}' |  awk -F "-" '{print $1}'  )
                TGT_BUILD=$(echo $tgt_ver|  awk -F "." '{print $2}' |  awk -F "-" '{print $2}'  )

                TGTCHK=$(echo $TGT_MAJVER | grep -c "^[0-9]" )

                if [[ $TGTCHK -gt 0 ]] ; then

                        if [[ $TGT_MAJVER -eq 2 ]] && [[  $TGT_MINVER -lt 1  ]] || [[  $TGT_BUILD -lt 41  ]] ; then
                                lio_tgtcli=1
                        else
                                lio_tgtcli=0
                        fi
                        if [[ $TGT_MAJVER -lt 2 ]] ; then
                                lio_tgtcli=1
                        else
                                lio_tgtcli=$lio_tgtcli
                        fi
                else
                        lio_tgtcli= 1
                fi

        elif [[ -f /usr/bin/dpkg ]] && [[ $distver -gt 15 ]]  ; then
                lio_tgtcli=0
        else
                tgt_ver=$( targetcli -v 2>&1| awk '{print $3}';)
                TGT_MAJVER=$(echo $tgt_ver|  awk -F "." '{print $1}')
                TGT_MINVER=$(echo $tgt_ver|  awk -F "." '{print $2}'  )
                TGT_BUILD=$(echo $tgt_ver|  awk -F "." '{print $3}' )
                TGT_SBUILD=$(echo $TGT_BUILD | awk -F 'fb' '{print $2}' )
		if [[  $TGT_SBUILD -eq ''  ]] ; then
			TGT_SBUILD=$(echo $TGT_BUILD)
		fi	

                TGTCHK=$(echo $TGT_MAJVER | grep -c "^[0-9]" )
			
                if [[ $TGTCHK -gt 0 ]] ; then

                        if [[ $TGT_MAJVER -eq 2 ]] && [[  $TGT_MINVER -lt 1 ]] ||  [[ $TGT_SBUILD -lt 41 ]] ; then
                                lio_tgtcli=1
                        else
                                lio_tgtcli=0
                        fi
                        if [[ $TGT_MAJVER -lt 2 ]] ; then
                                lio_tgtcli=1
                        else
                                lio_tgtcli=$lio_tgtcli
                        fi
                else
                        lio_tgtcli=1
                fi

    fi


else

        tgt_ver=$( targetcli -v 2>&1| awk '{print $3}';)
        TGT_MAJVER=$(echo $tgt_ver|  awk -F "." '{print $1}')
        TGT_MINVER=$(echo $tgt_ver|  awk -F "." '{print $2}'  )
        TGT_BUILD=$(echo $tgt_ver|  awk -F "." '{print $3}' )
        TGT_SBUILD=$(echo $TGT_BUILD | awk -F 'fb' '{print $2}' )
	if [[  $TGT_SBUILD -eq ''  ]] ; then
		TGT_SBUILD=$(echo $TGT_BUILD)
	fi	

        TGTCHK=$(echo $TGT_MAJVER | grep -c "^[0-9]" )

        if [[ $TGTCHK -gt 0 ]] ; then

                if [[ $TGT_MAJVER -eq 2 ]] && [[  $TGT_MINVER -lt 1 ]] ||  [[ $TGT_SBUILD -lt 41 ]] ; then
                        lio_tgtcli=1
                else
                        lio_tgtcli=0
                fi
                if [[ $TGT_MAJVER -lt 2 ]] ; then
                        lio_tgtcli=1
                else
                        lio_tgtcli=$lio_tgtcli
                fi
        else
                lio_tgtcli=1
        fi

fi

echo $lio_tgtcli

