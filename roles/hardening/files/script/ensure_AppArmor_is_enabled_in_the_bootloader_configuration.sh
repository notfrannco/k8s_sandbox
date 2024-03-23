#!/bin/bash

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

# Correct the form of default kernel command line in GRUB
if grep -q '^\s*GRUB_CMDLINE_LINUX=.*apparmor=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an apparmor= arg already exists
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)apparmor=[^[:space:]]\+\(.*\"\)/\1apparmor=1\2/"  '/etc/default/grub'
# Add to already existing GRUB_CMDLINE_LINUX parameters
elif grep -q '^\s*GRUB_CMDLINE_LINUX='  '/etc/default/grub' ; then
       # no apparmor=arg is present, append it
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)\"/\1 apparmor=1\"/"  '/etc/default/grub'
# Add GRUB_CMDLINE_LINUX parameters line
else
       echo "GRUB_CMDLINE_LINUX=\"apparmor=1\"" >> '/etc/default/grub'
fi
# Correct the form of default kernel command line in GRUB
if grep -q '^\s*GRUB_CMDLINE_LINUX=.*security=.*"'  '/etc/default/grub' ; then
       # modify the GRUB command-line if an security= arg already exists
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)security=[^[:space:]]\+\(.*\"\)/\1security=apparmor\2/"  '/etc/default/grub'
# Add to already existing GRUB_CMDLINE_LINUX parameters
elif grep -q '^\s*GRUB_CMDLINE_LINUX='  '/etc/default/grub' ; then
       # no security=arg is present, append it
       sed -i "s/\(^\s*GRUB_CMDLINE_LINUX=\".*\)\"/\1 security=apparmor\"/"  '/etc/default/grub'
# Add GRUB_CMDLINE_LINUX parameters line
else
       echo "GRUB_CMDLINE_LINUX=\"security=apparmor\"" >> '/etc/default/grub'
fi


update-grub

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
