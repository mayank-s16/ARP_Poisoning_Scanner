import scapy.all as scapy
import os
import uuid
from python_arptable import ARPTABLE

attempts=dict()
history=dict()

def isBlacklisted(ip):
	if ip in attempts and attempts[ip]>5:
		return True
	else:
		return False

def updateAttempCounter(ip):
	if ip in attempts:
		attempts[ip]+=1
	else:
		attempts[ip]=0

def updateHistory(packet):
	if packet[scapy.ARP].psrc in history:
		if history[packet[scapy.ARP].psrc][len(history[packet[scapy.ARP].psrc])-1] != packet[scapy.ARP].hwsrc:
			history[packet[scapy.ARP].psrc].append(packet[scapy.ARP].hwsrc)
		else:
			print("last packet is the same")
	else:
		history[packet[scapy.ARP].psrc] = [packet[scapy.ARP].hwsrc]

def resetFromHistory(ip, hw):
	print("need to update", ip,"=", history[ip])
	if(history[ip][0] != hw):
		os.system("arp -s "+ip+" "+history[ip][0])
		print("arp compromised ", ip, hw)
	

def get_mac(ip):
	arp_request = scapy.ARP(pdst=ip)
	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	arp_request_broadcast = arp_request/broadcast
	answered_list = scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]

def sniff(interface):
	scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
	if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op==2 and str(packet[scapy.ARP].pdst)==ip:
		print("arp packet captured!\n")
		try:
			srcIp=str(packet[scapy.ARP].psrc)
			updateAttempCounter(srcIp)
			updateHistory(packet)
			if isBlacklisted(srcIp):
				print("\rsystem might be under attack ")
				resetFromHistory(srcIp, packet[scapy.ARP].hwsrc)
			else:
				print("sent ICMP packet to "+srcIp)
				icmp = scapy.IP(dst=srcIp)/scapy.ICMP()
				resp = scapy.sr1(icmp,timeout=10)
		except IndexError:
			pass

x="ens33"#input("Enter the interface: ")
ip="192.168.153.133"#input("Enter IP address: ")
print("initial ARP table:\n")
for e in ARPTABLE:
	history[e["IP address"]] = [e["HW address"]]
	print(e["IP address"], "  =>  ",e["HW address"])

sniff(x)
