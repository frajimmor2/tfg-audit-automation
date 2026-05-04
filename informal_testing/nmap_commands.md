# 1 Output ports

nmap -p- --open --min-rate 5000 -n -Pn 192.168.100.2 | sed -n 's/^[[:space:]]*\([0-9][0-9]*\)\/tcp[[:space:]]\+open.*/\1/p' | sed ':a;N;$!ba;s/\n/,/g'

# 2 Deep Scan

 nmap -p139,445 -sVC --script "default,safe,discovery,version" 192.168.100.2
