#!/bin/bash

# Remediation is applicable only in certain platforms
if [ ! -f /.dockerenv ] && [ ! -f /run/.containerenv ]; then

var_accounts_tmout='900'


# if 0, no occurence of tmout found, if 1, occurence found
tmout_found=0

for f in /etc/bash.bashrc /etc/profile /etc/profile.d/*.sh; do
    if grep --silent '^\s*TMOUT' $f; then
        sed -i -E "s/^(\s*)TMOUT\s*=\s*(\w|\$)*(.*)$/\1TMOUT=$var_accounts_tmout\3/g" $f
        tmout_found=1
        if ! grep --silent '^\s*readonly TMOUT' $f ; then
            echo "readonly TMOUT" >> $f
        fi
        if ! grep --silent '^\s*export TMOUT' $f ; then
            echo "export TMOUT" >> $f
        fi
    fi
done

if [ $tmout_found -eq 0 ]; then
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile.d/tmout.sh
        echo "TMOUT=$var_accounts_tmout" >> /etc/profile.d/tmout.sh
        echo "readonly TMOUT" >> /etc/profile.d/tmout.sh
        echo "export TMOUT" >> /etc/profile.d/tmout.sh
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
