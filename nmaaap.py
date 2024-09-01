import nmap

# قائمة المنافذ الشائعة والخدمات المرتبطة بها
common_ports = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    119: "NNTP",
    123: "NTP",
    135: "MS RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "Microsoft-DS",
    465: "SMTPS",
    500: "ISAKMP",
    587: "SMTP (Submission)",
    631: "IPP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1352: "Lotus Notes",
    1433: "Microsoft SQL Server",
    1521: "Oracle Database",
    1723: "PPTP",
    1812: "RADIUS",
    1863: "MSN",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2181: "ZooKeeper",
    2222: "DirectAdmin",
    2375: "Docker",
    2483: "Oracle DB (TCP)",
    2484: "Oracle DB (TCP/SSL)",
    3128: "Squid Proxy",
    3306: "MySQL",
    3389: "RDP",
    3690: "Subversion",
    4444: "Metasploit",
    4786: "Smart Install",
    4848: "GlassFish",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5984: "CouchDB",
    6379: "Redis",
    6667: "IRC",
    7001: "WebLogic",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8086: "InfluxDB",
    8443: "HTTPS-alt",
    8888: "Alternate HTTP",
    9000: "SonarQube",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    1900: "UPnP",
    1716: "XMsg",
}

# إنشاء كائن nmap
nm = nmap.PortScanner()

# عنوان الـ IP الهدف
target_ip = '192.168.1.111'  # استبدل بـ IP الخاص بك

# مسح المنافذ الشائعة على الهدف
nm.scan(target_ip, arguments='-sV')

# عرض الخدمات وإصداراتها لكل منفذ مفتوح
for port in common_ports:
    if nm[target_ip].has_tcp(port):
        state = nm[target_ip]['tcp'][port]['state']
        service = nm[target_ip]['tcp'][port]['name']
        version = nm[target_ip]['tcp'][port]['version']
        print(f"Port: {port} ({common_ports[port]}) | State: {state} | Service: {service} | Version: {version}")
