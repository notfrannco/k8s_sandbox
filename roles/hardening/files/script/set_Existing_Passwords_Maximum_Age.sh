#!/bin/bash

var_accounts_maximum_age_login_defs='365'


while IFS= read -r i; do
    
    chage -M $var_accounts_maximum_age_login_defs $i

done <   <(awk -v var="$var_accounts_maximum_age_login_defs" -F: '(/^[^:]+:[^!*]/ && ($5 > var || $5 == "")) {print $1}' /etc/shadow)
