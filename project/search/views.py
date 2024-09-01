# views.py
import re
from django.shortcuts import render, redirect
import socket
from concurrent.futures import ThreadPoolExecutor
from django.contrib.auth import authenticate, login as auth_login
from django.contrib import messages
from django.contrib.auth.decorators import login_required
#============================================================
import requests
from bs4 import BeautifulSoup
import whois
import socket
import dns.resolver
import urllib.parse
import subprocess
import json


def view_(request):
    return render(request, 'cc.html')
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


class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urllib.parse.urlparse(target_url).netloc

    def scan(self):
        # طباعة الرسالة الأولى فقط
        print("Scanning:", self.target_url)

        # جمع المعلومات في قاموس بدلاً من طباعتها
        scan_results = {}

        # Get website information
        response = requests.get(self.target_url)
        scan_results['status_code'] = response.status_code
        scan_results['headers'] = dict(response.headers)

        # Get HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        scan_results['html_title'] = soup.title.string if soup.title else None
        scan_results['meta_tags'] = {meta.get('name', ''): meta.get('content', '') for meta in soup.find_all('meta')}

        # Get DNS information
        try:
            dns_result = dns.resolver.resolve(self.domain, 'A')
            scan_results['dns_a_record'] = dns_result[0].to_text()
        except dns.resolver.NoAnswer:
            scan_results['dns_a_record'] = "No DNS A Record found"

        try:
            dns_result = dns.resolver.resolve(self.domain, 'MX')
            scan_results['dns_mx_record'] = dns_result[0].to_text()
        except dns.resolver.NoAnswer:
            scan_results['dns_mx_record'] = "No DNS MX Record found"

        # Get WHOIS information
        whois_result = whois.query(self.domain)
        scan_results['whois_info'] = {key: value for key, value in whois_result.__dict__.items()}

        # Get IP address information
        ip_address = socket.gethostbyname(self.domain)
        scan_results['ip_address'] = ip_address

        # Get server information
        response = requests.head(self.target_url)
        scan_results['server'] = response.headers.get('Server')

        # Get website technologies
        try:
            import builtwith
            technologies = builtwith.parse(self.target_url)
            scan_results['technologies'] = technologies
        except ImportError:
            scan_results['technologies'] = "BuiltWith library not installed"

        return scan_results





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


def get_http_banner(ip, port=80):
    try:
        # إنشاء اتصال TCP
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        sock.connect((ip, port))

        # إرسال طلب HTTP
        request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
        sock.sendall(request.encode())

        # استقبال الرد (البانر)
        response = sock.recv(4096)
        sock.close()

        # محاولة فك الترميز باستخدام 'utf-8' أولاً
        try:
            banner = response.decode('utf-8')
        except UnicodeDecodeError:
            # إذا فشلت محاولة فك الترميز، استخدام الترميز 'iso-8859-1'
            banner = response.decode('iso-8859-1', errors='ignore')

        return banner

    except socket.error as e:
        return f"Error: {e}"


def fetch_banner(ip_target, port, service):
    banner = get_http_banner(ip_target, port)
    if "Error" not in banner:
        return (
            f"Port: {port} ({service})\n"
            f"Response:\n{banner}\n"
            "-------------------------------------------------\n"
        )
    return ""



def scan_services(ip, open_ports):
    services = {}
    service_names = []
    versions = []
    ports = ','.join(str(port) for port in open_ports)
    command = ['nmap', '-sV', '-p', ports, ip]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout
        print("Nmap output:\n", output)  # طباعة نتائج nmap

        # التعبير النمطي لتطابق اسم الخدمة والإصدار
        service_regex = re.compile(r"(\d+/tcp)\s+open\s+(\S+)\s*(.*)")

        for line in output.splitlines():
            match = service_regex.search(line)
            if match:
                port = int(match.group(1).split('/')[0])
                service_info = match.group(2)  # اسم الخدمة
                version_info = match.group(3).strip() if match.group(3) else 'Unknown'  # الإصدار أو 'Unknown' إذا لم يكن هناك إصدار
                services[port] = {
                    'service_name': service_info,
                    'version': version_info
                }
                service_names.append(service_info)
                versions.append(version_info)
            elif 'Nmap scan report for' in line:
                if ip not in line:
                    services['error'] = 'IP not found in scan results'
    except subprocess.CalledProcessError as e:
        return ["error"], []

    # التأكد من تطابق الطول بين names و versions
    if len(service_names) != len(versions):
        versions = ['Unknown'] * len(service_names)

    return service_names, versions



@login_required(login_url='login')
def index(request):
    res = ""
    if request.method == 'POST':
        ip_target = request.POST.get('ip_target')
        open_ports = scan_ip(ip_target)  # هنا تقوم بمسح المنافذ المفتوحة
        ip_orginal = []
        ip_orginal.append(ip_target)

        service_names = []
        versions = []

        # التحقق إذا تم تحديد خيار "Port version"
        if request.POST.get('port_version'):
            service_names, versions = scan_services(ip_orginal[0], open_ports)
            print("Port version scan results:")
            print(service_names)
            print(versions)
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(fetch_banner, ip_target, port, service) for port, service in common_ports.items()]
            results = [future.result() for future in futures]
        
        output = "".join(results)

        def is_domain(name):
            domain_pattern = re.compile(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
            return domain_pattern.match(name) is not None

        if request.POST.get('check_port'):
            if is_domain(ip_target):
                if not ip_target.startswith('http://') and not ip_target.startswith('https://'):
                    ip_target = 'http://' + ip_target

                scanner = Scanner(ip_target)
                data = scanner.scan()

                def format_scan_results(data):
                    result = []
                    result.append(f"Scanning: {data.get('html_title')}")
                    result.append(f"Status Code: {data.get('status_code', 'N/A')}")
                    result.append("Response Headers:")
                    for header, value in data.get('headers', {}).items():
                        result.append(f"  {header}: {value}")

                    result.append(f"HTML Title: {data.get('html_title', 'N/A')}")
                    result.append("Meta Tags:")
                    for tag, value in data.get('meta_tags', {}).items():
                        result.append(f"  {tag}: {value}")

                    result.append(f"DNS A Record: {data.get('dns_a_record', 'N/A')}")
                    result.append(f"DNS MX Record: {data.get('dns_mx_record', 'N/A')}")

                    result.append("WHOIS Information:")
                    for key, value in data.get('whois_info', {}).items():
                        result.append(f"  {key}: {value}")

                    result.append(f"IP Address: {data.get('ip_address', 'N/A')}")
                    result.append(f"Server: {data.get('server', 'N/A')}")

                    result.append("Technologies:")
                    for tech, value in data.get('technologies', {}).items():
                        result.append(f"  {tech}: {value}")

                    return "\n".join(result)

                res = format_scan_results(data)
            else:
                res = "Website analysis not performed."

        # تجميع البيانات في قائمة مسطحة إذا تم تحديد خيار "Port version"
        if request.POST.get('port_version'):
            port_info = zip(open_ports, service_names, versions)
        else:
            port_info = zip(open_ports, ['Unknown']*len(open_ports), ['Unknown']*len(open_ports))

        context = {
            'ip_target': ip_target,
            'open_ports': port_info,
            'common_port': common_ports,
            'banners': output if output else "No banners found",
            'resulte': res,
        }

        return render(request, 'index.html', context)

    return render(request, 'index.html')







def login(request): #'common_port': common_ports,
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            messages.success(request, 'Login successful!')
            return redirect('index')  # Redirect to a success page or home page
        else:
            messages.error(request, 'Invalid username or password.')
    return render(request, 'cc.html')

def view_(request):
    return render(request, 'cc.html')



