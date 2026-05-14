scan = "Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-28 11:08 +0000\nNmap scan report for 192.168.1.78\nHost is up (0.00056s latency).\n\nPORT      STATE SERVICE     VERSION\n21/tcp    open  ftp         vsftpd 2.3.4\n| ftp-syst: \n|   STAT: \n| FTP server status:\n|      Connected to 192.168.1.13\n|      Logged in as ftp\n|      TYPE: ASCII\n|      No session bandwidth limit\n|      Session timeout in seconds is 300\n|      Control connection is plain text\n|      Data connections will be plain text\n|      vsFTPd 2.3.4 - secure, fast, stable\n|_End of status\n|_ftp-anon: Anonymous FTP login allowed (FTP code 230)\n22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\n| ssh-hostkey: \n|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)\n|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)\n23/tcp    open  telnet      Linux telnetd\n25/tcp    open  smtp        Postfix smtpd\n|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN\n| sslv2: \n|   SSLv2 supported\n|   ciphers: \n|     SSL2_RC4_128_EXPORT40_WITH_MD5\n|     SSL2_RC2_128_CBC_WITH_MD5\n|     SSL2_DES_64_CBC_WITH_MD5\n|     SSL2_DES_192_EDE3_CBC_WITH_MD5\n|     SSL2_RC4_128_WITH_MD5\n|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5\n|_ssl-date: 2025-12-28T11:11:12+00:00; +1s from scanner time.\n| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX\n| Not valid before: 2010-03-17T14:07:45\n|_Not valid after:  2010-04-16T14:07:45\n53/tcp    open  domain      ISC BIND 9.4.2\n| dns-nsid: \n|_  bind.version: 9.4.2\n80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)\n|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2\n|_http-title: Metasploitable2 - Linux\n111/tcp   open  rpcbind     2 (RPC #100000)\n139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n445/tcp   open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)\n512/tcp   open  exec?\n513/tcp   open  login       OpenBSD or Solaris rlogind\n514/tcp   open  tcpwrapped\n1099/tcp  open  java-rmi    GNU Classpath grmiregistry\n1524/tcp  open  bindshell   Metasploitable root shell\n2049/tcp  open  nfs         2-4 (RPC #100003)\n2121/tcp  open  ftp         ProFTPD 1.3.1\n3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5\n3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))\n5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7\n5900/tcp  open  vnc         VNC (protocol 3.3)\n6000/tcp  open  X11         (access denied)\n6667/tcp  open  irc         UnrealIRCd\n6697/tcp  open  irc         UnrealIRCd\n8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)\n8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1\n8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)\nMAC Address: 08:00:27:DC:47:F6 (Oracle VirtualBox virtual NIC)\nService Info: Hosts: metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel\n\nNmap done: 1 IP address (1 host up) scanned in 136.26 seconds"

lscan = scan.split("\n")


def version_scan_cpe_parser(scan_results: list[str]) -> list:
    output_cpe = []  # CPE list
    last_lines = False
    other = ""
    current_cpe = None
    for line in scan_results:
        # Is port
        if line and line[0].isdigit() and ("/tcp" in line or "/udp" in line):
            if current_cpe:
                output_cpe.append(current_cpe)
                other = ""
            info = line.split()
            s_product = info[2]
            s_version = " ".join(info[3:]) if len(info) > 3 else ""
            other = info[0]
            current_cpe = [s_product, s_version, other]
        # End of las port
        elif current_cpe and line.startswith("Service Info:"):
            output_cpe.append(current_cpe)
            current_cpe = None
            other = line
        # Port info
        elif current_cpe:
            other = " " + line
        # End of the scan
        elif line.startswith("Service detection performed"):
            break
        else:
            other = other + " " + line
    return [output_cpe, other]


print(version_scan_cpe_parser(lscan))
