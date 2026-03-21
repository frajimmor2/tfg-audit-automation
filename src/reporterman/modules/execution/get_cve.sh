#!/bin/bash

module="$1"

info=$(msfconsole -q 2>/dev/null <<EOF
use $module
info
EOF
)

cve_url=$(msfconsole -q -x "use exploit/unix/irc/unreal_ircd_3281_backdoor; info; exit" 2>/dev/null | grep -i 'CVE-' | head -n 1)
cve=$(echo "$cve_url" | grep -oE 'CVE-[0-9]{4}-[0-9]+')
echo "$cve,$cve_url"
