#! /bin/bash

PWD=$(pwd)
kdist=$1
supportdir=${PWD}/support
sslconf="/usr/lib/ssl/openssl.cnf"


cp -f ${supportdir}/openssl.cnf.ch  ${sslconf}.rpmsave
cp -f ${sslconf}.rpmsave ${sslconf}.chbak

[[ -f ${sslconf}.rpmsave ]] && cp -f ${sslconf}.rpmsave ${sslconf}

sed -i '/oid_section/a openssl_conf = default_modules\n\n[ default_modules ]\n\n#ssl_conf = ssl_module\nengines = openssl_engines\n\n[openssl_engines]\nafalg = afalg_engine\n\n[afalg_engine]\n#default_algorithms = ALL\ninit =1\n\n[ ssl_module ]\n\nsystem_default = crypto_policy\n[ crypto_policy ]\n#.include /etc/crypto-policies/back-ends/opensslcnf.config'  ${sslconf}

sed -i '/oid_section/a openssl_conf = default_modules\n\n[ default_modules ]\n\n#ssl_conf = ssl_module\nengines = openssl_engines\n\n[openssl_engines]\nafalg = afalg_engine\n\n[afalg_engine]\n#default_algorithms = ALL\ninit =1\n\n[ ssl_module ]\n\nsystem_default = crypto_policy\n[ crypto_policy ]\n#.include /etc/crypto-policies/back-ends/opensslcnf.config' /usr/chssl/openssl/openssl.cnf

[[ ! -f  /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig ]] &&  cp /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so /usr/lib/x86_64-linux-gnu/engines-1.1/afalg.so.orig &&  cp /usr/chssl/lib/engines-1.1/afalg.so /usr/lib/x86_64-linux-gnu/engines-1.1/

[[ ! -f  /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1.orig ]] &&  cp /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1  /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1.orig &&  cp /usr/chssl/lib/libcrypto.so.1.1 /usr/lib/x86_64-linux-gnu/libcrypto.so.1.1

[[ ! -f  /usr/lib/x86_64-linux-gnu/libssl.so.1.1.orig ]] &&  cp /usr/lib/x86_64-linux-gnu/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1.orig && cp /usr/chssl/lib/libssl.so.1.1 /usr/lib/x86_64-linux-gnu/libssl.so.1.1
