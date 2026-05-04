Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-11-11 06:41 EST
Pre-scan script results:
|_http-robtex-shared-ns: TEMPORARILY DISABLED due to changes in Robtex's API. See https://www.robtex.com/api/
|_hostmap-robtex: TEMPORARILY DISABLED due to changes in Robtex's API. See https://www.robtex.com/api/
| targets-asn: 
|_  targets-asn.asn is a mandatory parameter
| broadcast-netbios-master-browser: 
|_ip  server  domain
Stats: 0:00:46 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 0.00% done
Nmap scan report for 192.168.100.2
Host is up (0.00038s latency).
                                                                                                                          
PORT    STATE SERVICE     VERSION
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Host script results:
|_smb2-time: Protocol negotiation failed (SMB2)
| dns-blacklist: 
|   SPAM
|     l2.apews.org - FAIL
|_    list.quorum.to - SPAM
|_dns-brute: Can't guess domain of "192.168.100.2"; use dns-brute.domain script argument.
| smb-protocols: 
|   dialects: 
|_    NT LM 0.12 (SMBv1) [dangerous, but default]
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-system-info: ERROR: Script execution failed (use -d to debug)
|_smb2-capabilities: SMB 2+ not supported
|_msrpc-enum: NT_STATUS_OBJECT_NAME_NOT_FOUND
|_smb-enum-sessions: ERROR: Script execution failed (use -d to debug)
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: metasploitable
|   NetBIOS computer name: 
|   Domain name: localdomain
|   FQDN: metasploitable.localdomain
|_  System time: 2025-11-11T06:42:22-05:00
| smb-mbenum: 
|   Master Browser
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Print server
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Server
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Server service
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Unix server
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Windows NT/2000/XP/2003 server
|     METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
|   Workstation
|_    METASPLOITABLE  0.0  metasploitable server (Samba 3.0.20-Debian)
| smb-enum-shares: 
|   account_used: <blank>
|   \\192.168.100.2\ADMIN$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (metasploitable server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\192.168.100.2\IPC$: 
|     Type: STYPE_IPC
|     Comment: IPC Service (metasploitable server (Samba 3.0.20-Debian))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|   \\192.168.100.2\opt: 
|     Type: STYPE_DISKTREE
|     Comment: 
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: <none>
|   \\192.168.100.2\print$: 
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|   \\192.168.100.2\tmp: 
|     Type: STYPE_DISKTREE
|     Comment: oh noes!
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|_    Anonymous access: READ/WRITE
| port-states: 
|   tcp: 
|_    open: 139,445
|_clock-skew: mean: 2h29m59s, deviation: 3h32m08s, median: -1s
| smb-ls: Volume \\192.168.100.2\tmp
| SIZE   TIME                 FILENAME
| <DIR>  2025-11-11T11:42:36  .
| <DIR>  2012-05-20T19:36:12  ..
| <DIR>  2025-11-11T11:25:31  orbit-msfadmin
| 0      2025-11-11T11:13:06  4501.jsvc_up
| <DIR>  2025-11-11T11:25:01  gconfd-msfadmin
|_
|_nbstat: NetBIOS name: METASPLOITABLE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
|_fcrdns: FAIL (No PTR record)

Post-scan script results:
| reverse-index: 
|   139/tcp: 192.168.100.2
|_  445/tcp: 192.168.100.2
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 472.27 seconds
