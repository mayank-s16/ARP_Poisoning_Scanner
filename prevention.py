import scapy.all as scapy
def get_mac(ip):
    arp_request=scap.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = arp_request/broadcast
    answered_list=scapy.srp(arp_request_broadcast,timeout=1,verbose=False)[0]

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def process_sniffed_packet(packet):
    if paket.haslayer(scapy.ARP) and packet[scapy.ARP].op==2:
        try:
            real_mac=get_mac(packet[scapy.ARP].psrc)
            response_mac=packet[scapy.ARP].hwsrc

            if real_mac != response_mac:
                print("[+] You are under attack!!")
                
        except IndexError:
            pass

x=input("Enter the interface: ")
sniff(x)

    
