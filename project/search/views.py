# views.py

from django.shortcuts import render
import socket
from concurrent.futures import ThreadPoolExecutor

# أشهر منافذ TCP
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
    631: "IPP (Internet Printing Protocol)",
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
    6667: "IRC (Internet Relay Chat)",
    7001: "WebLogic",
    8000: "Common HTTP-alt",
    8080: "HTTP-alt",
    8086: "InfluxDB",
    8443: "HTTPS-alt",
    8888: "Alternate HTTP",
    9000: "SonarQube",
    9092: "Kafka",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
    1900: "upnp",
    1716: "xmsg",
}

def scan_port(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect((ip, port))
        return port, True
    except (socket.timeout, socket.error):
        return port, False
    finally:
        sock.close()

def scan_ip(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=100) as executor:
        results = executor.map(lambda p: scan_port(ip, p), common_ports.keys())
    
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
    
    return open_ports 

def index(request):
    if request.method == 'POST':
        ip_target = request.POST.get('ip_target')
        # check_port = request.POST.get('check_port')
        
        # if not check_port:
        #     # يمكنك إرسال رسالة خطأ هنا إذا أردت
        #     return render(request, 'index.html', {'error': 'يجب تحديد "Check the port"'})
        open_ports = scan_ip(ip_target)
        context = {
            'ip_target': ip_target,
            'open_ports': open_ports,
            'common_port': common_ports,
        }
        return render(request, 'index.html', context)
    return render(request, 'index.html')

def test(request):
    return render(request, 'cc.html')
