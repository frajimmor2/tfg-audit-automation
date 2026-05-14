scan = "Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-12-29 11:28 CET\nNmap scan report for 192.168.1.78\nHost is up (0.00051s latency).\n\nPORT     STATE SERVICE    VERSION\n3306/tcp open  mysql      MySQL 5.0.51a-3ubuntu5\n| vulners: \n|   cpe:/a:mysql:mysql:5.0.51a-3ubuntu5: \n|     \tSSV:19118\t8.5\thttps://vulners.com/seebug/SSV:19118\t*EXPLOIT*\n|     \tCVE-2017-15945\t7.8\thttps://vulners.com/cve/CVE-2017-15945\n|     \tSSV:15006\t6.8\thttps://vulners.com/seebug/SSV:15006\t*EXPLOIT*\n|     \tCVE-2009-4028\t6.8\thttps://vulners.com/cve/CVE-2009-4028\n|     \tSSV:15004\t6.0\thttps://vulners.com/seebug/SSV:15004\t*EXPLOIT*\n|     \tCVE-2010-1621\t5.0\thttps://vulners.com/cve/CVE-2010-1621\n|     \tCVE-2024-21057\t4.9\thttps://vulners.com/cve/CVE-2024-21057\n|     \tCVE-2015-2575\t4.9\thttps://vulners.com/cve/CVE-2015-2575\n|     \tSSV:3280\t4.6\thttps://vulners.com/seebug/SSV:3280\t*EXPLOIT*\n|     \tCVE-2008-2079\t4.6\thttps://vulners.com/cve/CVE-2008-2079\n|     \tCVE-2010-3682\t4.0\thttps://vulners.com/cve/CVE-2010-3682\n|     \tCVE-2010-3677\t4.0\thttps://vulners.com/cve/CVE-2010-3677\n|     \tCVE-2009-0819\t4.0\thttps://vulners.com/cve/CVE-2009-0819\n|     \tCVE-2007-5925\t4.0\thttps://vulners.com/cve/CVE-2007-5925\n|_    \tCVE-2010-1626\t3.6\thttps://vulners.com/cve/CVE-2010-1626\n5432/tcp open  postgresql PostgreSQL DB 8.3.0 - 8.3.7\n| vulners: \n|   cpe:/a:postgresql:postgresql:8.3: \n|     \tSSV:60718\t10.0\thttps://vulners.com/seebug/SSV:60718\t*EXPLOIT*\n|     \tCVE-2013-1903\t10.0\thttps://vulners.com/cve/CVE-2013-1903\n|     \tCVE-2013-1902\t10.0\thttps://vulners.com/cve/CVE-2013-1902\n|     \tPOSTGRESQL:CVE-2019-10211\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2019-10211\n|     \tPOSTGRESQL:CVE-2018-16850\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2018-16850\n|     \tPOSTGRESQL:CVE-2017-7546\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2017-7546\n|     \tPOSTGRESQL:CVE-2015-3166\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2015-3166\n|     \tPOSTGRESQL:CVE-2015-0244\t9.8\thttps://vulners.com/postgresql/POSTGRESQL:CVE-2015-0244\n|     \tPACKETSTORM:189316\t9.8\thttps://vulners.com/packetstorm/PACKETSTORM:189316\t*EXPLOIT*\n|     \tMSF:EXPLOIT-LINUX-HTTP-BEYONDTRUST_PRA_RS_UNAUTH_RCE-\t9.8\thttps://vulners.com/metasploit/MSF:EXPLOIT-LINUX-HTTP-BEYONDTRUST_PRA_RS_UNAUTH_RCE-\t*EXPLOIT*\n|     \tCVE-2019-10211\t9.8\thttps://vulners.com/cve/CVE-2019-10211\n|     \tCVE-2015-3166\t9.8\thttps://vulners.com/cve/CVE-2015-3166\n|     \tCVE-2015-0244\t9.8\thttps://vulners.com/cve/CVE-2015-0244\n|     \tCNVD-2020-02196\t9.8\thttps://vulners.com/cnvd/CNVD-2020-02196\n|     \tCNVD-2017-26577\t9.8\thttps://vulners.com/cnvd/CNVD-2017-26577\n|     \tB675EF91-A407-518F-9D46-5325ACF11AAC\t9.8\thttps://vulners.com/githubexploit/B675EF91-A407-518F-9D46-5325ACF11AAC\t*EXPLOIT*\n|     \t1337DAY-ID-39921\t9.8\thttps://vulners.com/zdt/1337DAY-ID-39921\t*EXPLOIT*\n|_    \tOSV:BIT-POSTGRESQL-2025-12817\t3.1\thttps://vulners.com/osv/OSV:BIT-POSTGRESQL-2025-12817\n\nService detection performed. Please report any incorrect results at https://nmap.org/submit/ .\nNmap done: 1 IP address (1 host up) scanned in 6.28 seconds"


def vulns_scan_cve_parser(scan_results: list) -> list:
    output = []
    for line in scan_results:
        try:
            info = line.split()
            cond1 = info[0] == "|"
            cond2 = info[1].startswith("CVE")
            cond3 = info[3].startswith("http")
            if cond1 and cond2 and cond3:
                cve = info[1]
                link = info[3]
                output.append([cve, link])
        except:
            pass
    return output


print(vulns_scan_cve_parser(scan.split("\n")))
