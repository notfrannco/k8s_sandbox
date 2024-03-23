#!/bin/bash

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ] && { dpkg-query --show --showformat='${db:Status-Status}\n' 'postfix' 2>/dev/null | grep -q installed; }; then

var_postfix_inet_interfaces='loopback-only'


if [ -e "/etc/postfix/main.cf" ] ; then
    
    LC_ALL=C sed -i "/^\s*inet_interfaces\s\+=\s\+/Id" "/etc/postfix/main.cf"
else
    touch "/etc/postfix/main.cf"
fi
# make sure file has newline at the end
sed -i -e '$a\' "/etc/postfix/main.cf"

cp "/etc/postfix/main.cf" "/etc/postfix/main.cf.bak"
# Insert at the end of the file
printf '%s\n' "inet_interfaces=$var_postfix_inet_interfaces" >> "/etc/postfix/main.cf"
# Clean up after ourselves.
rm "/etc/postfix/main.cf.bak"

systemctl restart postfix

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
