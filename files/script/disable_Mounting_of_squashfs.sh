#!/bin/bash

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

if LC_ALL=C grep -q -m 1 "^install squashfs" /etc/modprobe.d/squashfs.conf ; then
	
	sed -i 's#^install squashfs.*#install squashfs /bin/true#g' /etc/modprobe.d/squashfs.conf
else
	echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/squashfs.conf
	echo "install squashfs /bin/true" >> /etc/modprobe.d/squashfs.conf
fi

if ! LC_ALL=C grep -q -m 1 "^blacklist squashfs$" /etc/modprobe.d/squashfs.conf ; then
	echo "blacklist squashfs" >> /etc/modprobe.d/squashfs.conf
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
