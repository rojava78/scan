import nmap

def scan_services(ip, open_ports):
    nm = nmap.PortScanner()
    services = {}

    # تحويل قائمة المنافذ إلى سلسلة مفصولة بفواصل
    ports = ','.join(str(port) for port in open_ports)

    try:
        # فحص المنافذ المحددة فقط
        nm.scan(ip, arguments=f'-sV -p {ports}')
    except Exception as e:
        return {"error": str(e)}

    # التحقق مما إذا كان IP في نتائج الفحص
    if ip in nm.all_hosts():
        for port in open_ports:
            if 'tcp' in nm[ip] and port in nm[ip]['tcp']:
                service_name = nm[ip]['tcp'][port].get('name', 'Unknown')
                version = nm[ip]['tcp'][port].get('version', 'Unknown')
                services[port] = {
                    'service_name': service_name,
                    'version': version
                }
            else:
                services[port] = {
                    'service_name': 'Unknown',
                    'version': 'Unknown'
                }
    else:
        services['error'] = 'IP not found in scan results'

scan_services(192.168.1.231 , )