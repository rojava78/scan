from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet import ICMP
from socket import getservbyport

def scan_ports(target_ip, ports):
    open_ports = []
    
    for port in ports:
        # Scan TCP ports
        response = sr1(IP(dst=target_ip)/TCP(dport=port, flags="S"), timeout=1, verbose=False)
        if response and response.haslayer(TCP) and response[TCP].flags == 0x12:
            open_ports.append((port, "TCP"))
            send(IP(dst=target_ip)/TCP(dport=port, flags="R"), verbose=False)  # Send RST to close the connection
        
        # Scan UDP ports
        response = sr1(IP(dst=target_ip)/UDP(dport=port), timeout=1, verbose=False)
        if response is None:
            open_ports.append((port, "UDP"))
    
    return open_ports

def get_service_name(port, protocol):
    try:
        return getservbyport(port, protocol.lower())
    except OSError:
        return "Unknown"

def main():
    target_ip = input("Enter the target IP address: ")
    ports = list(range(1, 1025))  # Scanning common ports (1-1024)
    
    print(f"Scanning {target_ip} for TCP and UDP ports...")
    open_ports = scan_ports(target_ip, ports)
    
    print(f"\nOpen Ports on {target_ip}:")
    for port, protocol in open_ports:
        service_name = get_service_name(port, protocol)
        print(f"Port: {port}, Protocol: {protocol}, Service: {service_name}")

if __name__ == "__main__":
    main()
    
#========================================================================================

# port scanner
import argparse
from scapy.all import *

# output format # TODO make prettier 
def print_ports(port, state):
	print("%s | %s" % (port, state))

# syn scan
def syn_scan(target, ports):
	print("syn scan on, %s with ports %s" % (target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "Closed")
				elif pkt[TCP].flags == 18:
					print_ports(port, "Open")
				else:
					print_ports(port, "TCP packet resp / filtered")
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Unanswered")

# udp scan
def udp_scan(target, ports):
	print("udp scan on, %s with ports %s" % (target, ports))
	for port in ports:
		pkt = sr1(IP(dst=target)/UDP(sport=port, dport=port), timeout=2, verbose=0)
		if pkt == None:
			print_ports(port, "Open / filtered")
		else:
			if pkt.haslayer(ICMP):
				print_ports(port, "Closed")
			elif pkt.haslayer(UDP):
				print_ports(port, "Open / filtered")
			else:
				print_ports(port, "Unknown")
				print(pkt.summary())

# xmas scan
def xmas_scan(target, ports):
	print("Xmas scan on, %s with ports %s" %(target, ports))
	sport = RandShort()
	for port in ports:
		pkt = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
		if pkt != None:
			if pkt.haslayer(TCP):
				if pkt[TCP].flags == 20:
					print_ports(port, "Closed")
				else:
					print_ports(port, "TCP flag %s" % pkt[TCP].flag)
			elif pkt.haslayer(ICMP):
				print_ports(port, "ICMP resp / filtered")
			else:
				print_ports(port, "Unknown resp")
				print(pkt.summary())
		else:
			print_ports(port, "Open / filtered")

# argument setup
parser = argparse.ArgumentParser("Port scanner using Scapy")
parser.add_argument("-t", "--target", help="Specify target IP", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specify ports (21 23 80 ...)")
parser.add_argument("-s", "--scantype", help="Scan type, syn/udp/xmas", required=True)
args = parser.parse_args()

# arg parsing
target = args.target
scantype = args.scantype.lower()
# set ports if passed
if args.ports:
	ports = args.ports
else:
	# default port range
	ports = range(1, 1024)

# scan types
if scantype == "syn" or scantype == "s":
	syn_scan(target, ports)
elif scantype == "udp" or scantype == "u":
	udp_scan(target, ports)
elif scantype == "xmas" or scantype == "x":
	xmas_scan(target, ports)
else:
	print("Scan type not supported")
 
