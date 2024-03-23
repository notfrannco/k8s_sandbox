#!/bin/bash

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install rds" /etc/modprobe.d/rds.conf ; then
	
	sed -i 's#^install rds.*#install rds /bin/true#g' /etc/modprobe.d/rds.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/rds.conf
	echo "install rds /bin/true" >> /etc/modprobe.d/rds.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist rds$" /etc/modprobe.d/rds.conf ; then
	echo "blacklist rds" >> /etc/modprobe.d/rds.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
