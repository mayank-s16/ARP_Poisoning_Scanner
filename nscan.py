#! usr/bin/env python
import scapy.all as scapy

def scan(ip):
    arprequest=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arprequest_broadcast=broadcast/arprequest
    answered_list=scapy.srp(arprequest_broadcast,timeout=3)[0]
    print("IP\t\t\tMAC ADDRESS\n.........................................................")
    clientlist=[]
    for element in answered_list:
        print(element[1].psrc+"\t\t"+element[1].hwsrc)

s=input("Enter default gateway: ")
scan(s)
