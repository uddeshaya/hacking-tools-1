#!/usr/bin/env python3
"""
    arpspoof_ids: Detect if an ARP spoof atack is occuring on a target machine.
    Author: Yusef Karim

"""
##### Scapy modules #####
from scapy.sendrecv import sniff, srp
from scapy.layers.l2 import Ether, ARP
##### Other python3 modules #####
from sys import exit, argv
from os import getuid

global REAL_MAC

def get_mac(target):
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=ARP.who_has, pdst=target)
    answered = srp(arp_broadcast, timeout=1, verbose=False)[0]
    # Return the MAC address of the target machine that responded to our ARP broadcast
    return answered[0][1].hwsrc

def pkt_callback(pkt):
    # -------------------- ARP  --------------------
    if(pkt.haslayer(ARP)):
        arp = pkt.getlayer(ARP)
        if(arp.op == ARP.is_at):
            current_mac = arp.hwsrc
            if(current_mac != REAL_MAC):
                print("[!] ANOMALY DETECTED, MAC address has changed to {}".format(
                      current_mac))


if __name__ == "__main__":
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    elif(len(argv) != 3):
        print("[-] Invalid number of arguments\n"
              "[+] USAGE: {} <INTERFACE> <IP YOU WANT TO MONITOR>".format(__file__))
        exit(2)
    else:
        print("[+] Starting ARP spoof detection on {} for address {}".format(
              argv[1], argv[2]))
        REAL_MAC = get_mac(argv[2])
        print("[+] {} currently has the MAC address {}".format(argv[2], REAL_MAC))
        sniff(filter=None, iface=argv[1], count=0, prn=pkt_callback, store=False)


