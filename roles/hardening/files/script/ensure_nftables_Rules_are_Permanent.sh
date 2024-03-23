#!/bin/bash

# Remediation is applicable only in certain platforms
if ( dpkg-query --show --showformat='${db:Status-Status}\n' 'nftables' 2>/dev/null | grep -q installed ); then

var_nftables_master_config_file='/etc/nftables.conf'


var_nftables_family='inet'


if [ ! -f "${var_nftables_master_config_file}" ]; then
    touch "${var_nftables_master_config_file}"
fi

nft list ruleset > "/etc/${var_nftables_family}-filter.rules"

grep -qxF 'include "/etc/'"${var_nftables_family}"'-filter.rules"' "${var_nftables_master_config_file}" \
    || echo 'include "/etc/'"${var_nftables_family}"'-filter.rules"' >> "${var_nftables_master_config_file}"

else
    >&2 echo 'Remediation is not applicable, nothing was done'
fi
