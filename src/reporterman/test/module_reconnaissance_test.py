from reporterman.modules.reconnaissance.formatters import (
    domain_target_formatter,
    list_target_formatter,
)

from reporterman.modules.reconnaissance.nmap_scanners import (
    check_connectivity,
    nmap_scan,
    vulns_scan_parser,
    version_scan_cpe_parser,
)
import typer
import subprocess
import pytest
import hashlib
import json


# -- FORMATTERS --
def test_neg_domain_target_formatter():
    with pytest.raises(typer.BadParameter):
        domain_target_formatter("0.0.0.3/30")
        domain_target_formatter("0.1.2.3/20")


def test_pos_domain_target_formatter():
    output = domain_target_formatter("192.0.0.0/30")
    expected = ["192.0.0.1", "192.0.0.2"]

    assert output == expected


def test_list_target_formatter():
    value = "10.10.10.10,10.10.10.11"
    output = list_target_formatter(value)
    expected = ["10.10.10.10", "10.10.10.11"]

    assert output == expected


# -- NMAP SCANNERS --
def test_pos_check_connectivity(monkeypatch):
    # Fake good workflow
    class DummyCompletedProcess:
        returncode = 0

    # Monkeypatch replaces the real behavior of subprocess for the test
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: DummyCompletedProcess()
    )  # noqa
    assert check_connectivity("192.168.0.34") is True


def test_neg_check_connectivity(monkeypatch):
    # Fake bad path
    def dummy_run(*args, **kwargs):
        raise Exception("ping failed")

    monkeypatch.setattr(subprocess, "run", dummy_run)
    assert check_connectivity("192.168.0.34") is False


# Class dummy Popen simulator
class DummyPopen:
    def __init__(self, stdout_text: str = "", raise_exc: bool = False):
        self._stdout_text = stdout_text
        self.raise_exc = raise_exc

    def communicate(self):
        if self.raise_exc:
            raise Exception("Simulated error")
        return (self._stdout_text, None)  # stdout, stderr


def test_nmap_scan_exception(monkeypatch):
    # Class dummy Popen simulator
    class DummyPopen:
        def __init__(self, stdout_text: str = "", raise_exc: bool = False):
            self._stdout_text = stdout_text
            self.raise_exc = raise_exc

        def communicate(self):
            if self.raise_exc:
                raise Exception("Simulated error")
            return (self._stdout_text, None)  # stdout, stderr

    def dummy_popen(*args, **kwargs):
        return DummyPopen(raise_exc=True)

    monkeypatch.setattr(subprocess, "Popen", dummy_popen)

    with pytest.raises(typer.Exit):
        nmap_scan(["nmap", "-sVC", "192.168.0.1"])


def test_version_scan_cpe_parser():
    scan = "Starting Nmap 7.98 ( https://nmap.org ) at 2025-12-28 11:08 +0000\nNmap scan report for 192.168.1.78\nHost is up (0.00056s latency).\n\nPORT      STATE SERVICE     VERSION\n21/tcp    open  ftp         vsftpd 2.3.4\n| ftp-syst: \n|   STAT: \n| FTP server status:\n|      Connected to 192.168.1.13\n|      Logged in as ftp\n|      TYPE: ASCII\n|      No session bandwidth limit\n|      Session timeout in seconds is 300\n|      Control connection is plain text\n|      Data connections will be plain text\n|      vsFTPd 2.3.4 - secure, fast, stable\n|_End of status\n|_ftp-anon: Anonymous FTP login allowed (FTP code 230)\n22/tcp    open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)\n| ssh-hostkey: \n|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)\n|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)\n23/tcp    open  telnet      Linux telnetd\n25/tcp    open  smtp        Postfix smtpd\n|_smtp-commands: metasploitable.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN\n| sslv2: \n|   SSLv2 supported\n|   ciphers: \n|     SSL2_RC4_128_EXPORT40_WITH_MD5\n|     SSL2_RC2_128_CBC_WITH_MD5\n|     SSL2_DES_64_CBC_WITH_MD5\n|     SSL2_DES_192_EDE3_CBC_WITH_MD5\n|     SSL2_RC4_128_WITH_MD5\n|_    SSL2_RC2_128_CBC_EXPORT40_WITH_MD5\n|_ssl-date: 2025-12-28T11:11:12+00:00; +1s from scanner time.\n| ssl-cert: Subject: commonName=ubuntu804-base.localdomain/organizationName=OCOSA/stateOrProvinceName=There is no such thing outside US/countryName=XX\n| Not valid before: 2010-03-17T14:07:45\n|_Not valid after:  2010-04-16T14:07:45\n53/tcp    open  domain      ISC BIND 9.4.2\n| dns-nsid: \n|_  bind.version: 9.4.2\n80/tcp    open  http        Apache httpd 2.2.8 ((Ubuntu) DAV/2)\n|_http-server-header: Apache/2.2.8 (Ubuntu) DAV/2\n|_http-title: Metasploitable2 - Linux\n111/tcp   open  rpcbind     2 (RPC #100000)\n139/tcp   open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)\n445/tcp   open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)\n512/tcp   open  exec?\n513/tcp   open  login       OpenBSD or Solaris rlogind\n514/tcp   open  tcpwrapped\n1099/tcp  open  java-rmi    GNU Classpath grmiregistry\n1524/tcp  open  bindshell   Metasploitable root shell\n2049/tcp  open  nfs         2-4 (RPC #100003)\n2121/tcp  open  ftp         ProFTPD 1.3.1\n3306/tcp  open  mysql       MySQL 5.0.51a-3ubuntu5\n3632/tcp  open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))\n5432/tcp  open  postgresql  PostgreSQL DB 8.3.0 - 8.3.7\n5900/tcp  open  vnc         VNC (protocol 3.3)\n6000/tcp  open  X11         (access denied)\n6667/tcp  open  irc         UnrealIRCd\n6697/tcp  open  irc         UnrealIRCd\n8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)\n8180/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1\n8787/tcp  open  drb         Ruby DRb RMI (Ruby 1.8; path /usr/lib/ruby/1.8/drb)\nMAC Address: 08:00:27:DC:47:F6 (Oracle VirtualBox virtual NIC)\nService Info: Hosts: metasploitable.localdomain, irc.Metasploitable.LAN; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel\n\nNmap done: 1 IP address (1 host up) scanned in 136.26 seconds"  # noqa

    lscan = scan.split("\n")
    output = version_scan_cpe_parser(lscan)
    json_output = json.dumps(output, sort_keys=True)
    bytes_output = json_output.encode("utf-8")
    h_output = hashlib.sha256(bytes_output).hexdigest()

    assert (
        h_output == "b32f16543ac1548daff68c6df3fede36436defc77c9796dfad078e8608c4d1aa"
    )  # noqa


def test_vulns_scan_parser():
    scan = "Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-29 11:28 CET\nNmap scan report for 192.168.1.78\nHost is up (0.00051s latency).\n\nPORT     STATE SERVICE    VERSION\n3306/tcp open  mysql      MySQL 5.0.51a-3ubuntu5\n| vulners: \n|   cpe:/a:mysql:mysql:5.0.51a-3ubuntu5: \n|     \tSSV:19118\t8.5\thttps://vulners.com/seebug/SSV:19118\t*EXPLOIT*\n|     \tCVE-2017-15945\t7.8\thttps://vulners.com/cve/CVE-2017-15945\n|     \tSSV:15006\t6.8\thttps://vulners.com/seebug/SSV:15006\t*EXPLOIT*\n|     \tCVE-2009-4028\t6.8\thttps://vulners.com/cve/CVE-2009-4028\n|     \tSSV:15004\t6.0\thttps://vulners.com/seebug/SSV:15004\t*EXPLOIT*\n|     \tCVE-2010-1621\t5.0\thttps://vulners.com/cve/CVE-2010-1621\n|     \tCVE-2024-21057\t4.9\thttps://vulners.com/cve/CVE-2024-21057\n|     \tCVE-2015-2575\t4.9\thttps://vulners.com/cve/CVE-2015-2575\n|     \tSSV:3280\t4.6\thttps://vulners.com/seebug/SSV:3280\t*EXPLOIT*\n|     \tCVE-2008-2079\t4.6\thttps://vulners.com/cve/CVE-2008-2079\n|     \tCVE-2010-3682\t4.0\thttps://vulners.com/cve/CVE-2010-3682\n|     \tCVE-2010-3677\t4.0\thttps://vulners.com/cve/CVE-2010-3677\n|     \tCVE-2009-0819\t4.0\thttps://vulners.com/cve/CVE-2009-0819\n|     \tCVE-2007-5925\t4.0\thttps://vulners.com/cve/CVE-2007-5925\n|_    \tCVE-2010-1626\t3.6\thttps://vulners.com/cve/CVE-2010-1626\n5432/tcp open  postgresql PostgreSQL DB 8.3.0 - 8.3.7\n| vulners: \n|   cpe:/a:postgresql:postgresql:8.3: \n|     \tSSV:60718\t10.0\thttps://vulners.com/seebug/SSV:60718\t*EXPLOIT*\n|     \tCVE-2013-1903\t10.0\thttps://vulners.com/cve/CVE-2013-1903\n|     \tCVE-2013-1902\t10.0\thttps://vulners.com/cve/CVE-2013-1902\n|     \tPOSTGRESQL:CVE-2019-10211\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2019-10211\n|     \tPOSTGRESQL:CVE-2018-16850\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2018-16850\n|     \tPOSTGRESQL:CVE-2017-7546\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2017-7546\n|     \tPOSTGRESQL:CVE-2015-3166\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2015-3166\n|     \tPOSTGRESQL:CVE-2015-0244\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2015-0244\n|     \tPACKETSTORM:189316\t9.8\thttps://vulners.com/packetstorm/PACKETSTORM:189316\t*EXPLOIT*\n|     \tMSF:EXPLOIT-LINUX-HTTP-BEYONDTRUST_PRA_RS_UNAUTH_RCE-\t9.8\thttps://vulners.com/metasploit/MSF:EXPLOIT-LINUX-HTTP-BEYONDTRUST_PRA_RS_UNAUTH_RCE-\t*EXPLOIT*\n|     \tCVE-2019-10211\t9.8\thttps://vulners.com/cve/CVE-2019-10211\n|     \tCVE-2015-3166\t9.8\thttps://vulners.com/cve/CVE-2015-3166\n|     \tCVE-2015-0244\t9.8\thttps://vulners.com/cve/CVE-2015-0244\n|     \tCNVD-2020-02196\t9.8\thttps://vulners.com/cnvd/CNVD-2020-02196\n|     \tCNVD-2017-26577\t9.8\thttps://vulners.com/cnvd/CNVD-2017-26577\n|     \tB675EF91-A407-518F-9D46-5325ACF11AAC\t9.8\thttps://vulners.com/githubexploit/B675EF91-A407-518F-9D46-5325ACF11AAC\t*EXPLOIT*\n|     \t1337DAY-ID-39921\t9.8\thttps://vulners.com/zdt/1337DAY-ID-39921\t*EXPLOIT*\n|_    \tOSV:BIT-POSTGRESQL-2025-12817\t3.1\thttps://vulners.com/osv/OSV:BIT-POSTGRESQL-2025-12817\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 6.28 seconds"  # noqa

    lscan = scan.split("\n")
    output = vulns_scan_parser(lscan)
    json_output = json.dumps(output, sort_keys=True)
    bytes_output = json_output.encode("utf-8")
    h_output = hashlib.sha256(bytes_output).hexdigest()

    assert (
        h_output == "a042cc98163047fe50ae7f0fa0e593271d68bfbc4d0a90ba6ce0ec922fa9bf4a"
    )  # noqa
