import requests
from bs4 import BeautifulSoup
import whois
import socket
import dns.resolver
import urllib.parse

class Scanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.domain = urllib.parse.urlparse(target_url).netloc

    def scan(self):
        print("Scanning:", self.target_url)

        # Get website information
        response = requests.get(self.target_url)
        print("Status Code:", response.status_code)
        print("Response Headers:")
        for key, value in response.headers.items():
            print(f"  {key}: {value}")

        # Get HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        print("HTML Title:", soup.title.string)
        print("Meta Tags:")
        for meta in soup.find_all('meta'):
            print(f"  {meta.get('name', '')}: {meta.get('content', '')}")

        # Get DNS information
        try:
            dns_result = dns.resolver.resolve(self.domain, 'A')
            print("DNS A Record:", dns_result[0].to_text())
        except dns.resolver.NoAnswer:
            print("No DNS A Record found")

        try:
            dns_result = dns.resolver.resolve(self.domain, 'MX')
            print("DNS MX Record:", dns_result[0].to_text())
        except dns.resolver.NoAnswer:
            print("No DNS MX Record found")

        # Get WHOIS information
        whois_result = whois.query(self.domain)
        print("WHOIS Information:")
        for key, value in whois_result.__dict__.items():
            print(f"  {key}: {value}")

        # Get IP address information
        ip_address = socket.gethostbyname(self.domain)
        print("IP Address:", ip_address)

        # Get server information
        response = requests.head(self.target_url)
        print("Server:", response.headers.get('Server'))

        # Get website technologies
        try:
            import builtwith
            technologies = builtwith.parse(self.target_url)
            print("Technologies:")
            for tech in technologies:
                print(f"  {tech}: {technologies[tech]}")
        except ImportError:
            print("BuiltWith library not installed")

scanner = Scanner("https://blue-elite.tech")
scanner.scan()
# class Scanner:
#     def __init__(self, target_url):
#         self.target_url = target_url
#         self.domain = urllib.parse.urlparse(target_url).netloc

#     def scan(self):
#         # طباعة الرسالة الأولى فقط
#         print("Scanning:", self.target_url)

#         # جمع المعلومات في قاموس بدلاً من طباعتها
#         scan_results = {}

#         # Get website information
#         response = requests.get(self.target_url)
#         scan_results['status_code'] = response.status_code
#         scan_results['headers'] = dict(response.headers)

#         # Get HTML content
#         soup = BeautifulSoup(response.text, 'html.parser')
#         scan_results['html_title'] = soup.title.string if soup.title else None
#         scan_results['meta_tags'] = {meta.get('name', ''): meta.get('content', '') for meta in soup.find_all('meta')}

#         # Get DNS information
#         try:
#             dns_result = dns.resolver.resolve(self.domain, 'A')
#             scan_results['dns_a_record'] = dns_result[0].to_text()
#         except dns.resolver.NoAnswer:
#             scan_results['dns_a_record'] = "No DNS A Record found"

#         try:
#             dns_result = dns.resolver.resolve(self.domain, 'MX')
#             scan_results['dns_mx_record'] = dns_result[0].to_text()
#         except dns.resolver.NoAnswer:
#             scan_results['dns_mx_record'] = "No DNS MX Record found"

#         # Get WHOIS information
#         whois_result = whois.query(self.domain)
#         scan_results['whois_info'] = {key: value for key, value in whois_result.__dict__.items()}

#         # Get IP address information
#         ip_address = socket.gethostbyname(self.domain)
#         scan_results['ip_address'] = ip_address

#         # Get server information
#         response = requests.head(self.target_url)
#         scan_results['server'] = response.headers.get('Server')

#         # Get website technologies
#         try:
#             import builtwith
#             technologies = builtwith.parse(self.target_url)
#             scan_results['technologies'] = technologies
#         except ImportError:
#             scan_results['technologies'] = "BuiltWith library not installed"

#         return scan_results

# scanner = Scanner("https://blue-elite.tech")
# scanner.scan()