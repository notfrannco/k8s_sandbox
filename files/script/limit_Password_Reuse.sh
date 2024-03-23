#!/bin/bash

# Remediation is applicable only in certain platforms
if dpkg-query --show --showformat='${db:Status-Status}\n' 'libpam-runtime' 2>/dev/null | grep -q installed; then

var_password_pam_unix_remember='5'


if [ -e "/etc/pam.d/common-password" ] ; then
    valueRegex="$var_password_pam_unix_remember" defaultValue="$var_password_pam_unix_remember"
    # non-empty values need to be preceded by an equals sign
    [ -n "${valueRegex}" ] && valueRegex="=${valueRegex}"
    # add an equals sign to non-empty values
    [ -n "${defaultValue}" ] && defaultValue="=${defaultValue}"

    # fix 'type' if it's wrong
    if grep -q -P "^\\s*(?"'!'"password\\s)[[:alnum:]]+\\s+[[:alnum:]]+\\s+pam_unix.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*)[[:alnum:]]+(\\s+[[:alnum:]]+\\s+pam_unix.so)/\\1password\\2/" "/etc/pam.d/common-password"
    fi

    # fix 'control' if it's wrong
    if grep -q -P "^\\s*password\\s+(?"'!'"\[success=[[:alnum:]].*\])[[:alnum:]]+\\s+pam_unix.so" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+)[[:alnum:]]+(\\s+pam_unix.so)/\\1\[success=[[:alnum:]].*\]\\2/" "/etc/pam.d/common-password"
    fi

    # fix the value for 'option' if one exists but does not match 'valueRegex'
    if grep -q -P "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s+remember(?"'!'"${valueRegex}(\\s|\$))" < "/etc/pam.d/common-password" ; then
        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s)remember=[^[:space:]]*/\\1remember${defaultValue}/" "/etc/pam.d/common-password"

    # add 'option=default' if option is not set
    elif grep -q -E "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so" < "/etc/pam.d/common-password" &&
            grep    -E "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so" < "/etc/pam.d/common-password" | grep -q -E -v "\\sremember(=|\\s|\$)" ; then

        sed --follow-symlinks -i -E -e "s/^(\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so[^\\n]*)/\\1 remember${defaultValue}/" "/etc/pam.d/common-password"
    # add a new entry if none exists
    elif ! grep -q -P "^\\s*password\\s+\[success=[[:alnum:]].*\]\\s+pam_unix.so(\\s.+)?\\s+remember${valueRegex}(\\s|\$)" < "/etc/pam.d/common-password" ; then
        echo "password \[success=[[:alnum:]].*\] pam_unix.so remember${defaultValue}" >> "/etc/pam.d/common-password"
    fi
else
    echo "/etc/pam.d/common-password doesn't exist" >&2
fi

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
