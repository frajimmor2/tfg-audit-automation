
scan = "Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-27 08:51 +0000\nNmap scan report for 192.168.1.78\nHost is up (0.00037s latency).\nNot shown: 977 closed tcp ports (reset)\nPORT     STATE SERVICE     VERSION\n21/tcp   open  ftp         vsftpd 2.3.4\n22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\n23/tcp   open  telnet      Linux telnetd\n25/tcp   open  smtp        Postfix smtpd\n53/tcp   open  domain      ISC BIND 9.4.2\n80/tcp   open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)\n111/tcp  open  rpcbind     2 (RPC #100000)\n139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n445/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n512/tcp  open  exec?\n513/tcp  open  login       OpenBSD or Solaris rlogind\n514/tcp  open  tcpwrapped\n1099/tcp open  java-rmi    GNU Classpath grmiregistry\n1524/tcp open  bindshell   Metasploitable root shell\n2049/tcp open  nfs         2-4 (RPC #100003)\n2121/tcp open  ftp         ProFTPD 1.3.1\n3306/tcp open  mysql       MySQL 5.0.51a-3ubuntu5\n5432/tcp open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7\n5900/tcp open  vnc         VNC (protocol 3.3)\n6000/tcp open  X11         (access denied)\n6667/tcp open  irc         UnrealIRCd\n8009/tcp open  ajp13       Apache Jserv (Protocol v1.3)\n8180/tcp open  http        Apache Tomcat/Coyote JSP engine 1.1\nMAC Address: 08:00:27:DC:47:F6 (Oracle VirtualBox virtual NIC)\nDevice type: general purpose\nRunning: Linux 2.6.X\nOS CPE: cpe:/o:linux:linux_kernel:2.6\nOS details: Linux 2.6.9 - 2.6.33\nNetwork Distance: 1 hop\nService Info: Hosts:  metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel\n\nOS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 64.41 seconds\n"

listed_scan= scan.split("\n")
# CPE Values: 0 = vendor 1 = product 2 = version 3 = other
vendor = product = version = other = ""
for line in listed_scan: 
    match line:
        case _ if "OS CPE:" in line:
            parts = line.split(":")
            vendor = parts[3]
            product = parts[4]
            version = parts[5]
        case _ if ("OS details:" in line) or ("Service Info:" in line):
            if other != "":
                other = other + " " + line
            else:
                other = line
        case _:
            pass
cpe = [vendor, product, version, other]
print(cpe)
