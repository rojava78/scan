import socket  
import os  

# قائمة البورتات والخدمات  
ports_services = {  
    21: "FTP",  
    22: "SSH",  
    23: "Telnet",  
    25: "SMTP",  
    53: "DNS",  
    69: "TFTP",  
    80: "HTTP",  
    110: "POP3",  
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
    1900: "UPnP",  
    1716: "XMSG"  
}  

def get_http_banner(ip, port=80):  
    try:  
        # إنشاء اتصال TCP  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        sock.settimeout(1)  
        sock.connect((ip, port))  

        # إرسال طلب HTTP  
        request = "GET / HTTP/1.1\r\nHost: {}\r\n\r\n".format(ip)  
        sock.sendall(request.encode())  

        # استقبال الرد (البانر)  
        response = sock.recv(4096).decode(errors='ignore')  
        sock.close()  

        return response  
    except socket.error as e:  
        return f"Error: {e}"  

# عنوان IP للتجربة  
ip_address = "192.168.1.231"  

# مسار الملف  
file_path = "http_banner_output.txt"  

# التحقق من وجود الملف وإنشاؤه إذا لم يكن موجودًا  
if not os.path.exists(file_path):  
    with open(file_path, "w") as file:  
        # إنشاء الملف  
        pass  

# إفراغ الملف إذا كان يحتوي على بيانات  
if os.path.getsize(file_path) > 0:  
    with open(file_path, "w") as file:  
        # فقط إفراغ الملف  
        pass  

# بدء عملية الاستعلام عن البانرز  
for port, service in ports_services.items():  
    banner = get_http_banner(ip_address, port)  
    if "Error" not in banner:  
        output = (  
            f"Port: {port} ({service})\n"  
            f"Response:\n{banner}\n"  
            "-------------------------------------------------\n"  
        )  
        print(output)
    
    # كتابة البيانات إلى الملف في كل مرة  
    with open(file_path, "a") as file:  
        # إذا لم يكن هناك خطأ في الاتصال، قم بكتابة البيانات في الملف  
        if "Error" not in banner:  
            output = (  
                f"Port: {port} ({service})\n"  
                f"Response:\n{banner}\n"  
                "-------------------------------------------------\n"  
            )  
            file.write(output)  

print(f"Banner and details for available ports saved to {file_path}")