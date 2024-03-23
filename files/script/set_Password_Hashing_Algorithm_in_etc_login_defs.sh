#!/bin/bash

# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'login' 2>/dev/null | grep -q installed; then

var_password_hashing_algorithm='yescrypt'


if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then
	sed -i "s/^ENCRYPT_METHOD .*/ENCRYPT_METHOD $var_password_hashing_algorithm/g" /etc/login.defs
else
	echo "" >> /etc/login.defs
	echo "ENCRYPT_METHOD $var_password_hashing_algorithm" >> /etc/login.defs
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
