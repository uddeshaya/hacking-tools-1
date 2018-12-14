#!/usr/bin/env python3
"""
    arp: Send out ARP requests to specified target(s) and print a table of found hosts
    Author: Yusef Karim
"""
from os import getuid
from sys import exit, argv
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp

def broadcast_arp(target):
    sep = '-' * 33
    arp_broadcast = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=ARP.who_has, pdst=target)
    answered = srp(arp_broadcast, timeout=1, verbose=False)[0]
    # The 'answered' list contains tuples of size 2 where each tuple contains the
    # sent and received packet. We only care about the received packets.
    print("{}\n{:15} {:18}\n{}".format(sep, "Host IP", "MAC Address", sep))
    for _, recv in answered:
        arp = recv.getlayer(ARP)
        print("{:15} {:18}".format(arp.psrc, arp.hwsrc))
    print("Scan is done: {} hosts found".format(len(answered)))


if __name__ == "__main__":
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    elif(len(argv) != 2):
        print("[-] Invalid number of arguments\n"
              "[+] USAGE: {} <TARGET(s)>".format(__file__))
        exit(2)
    else:
        broadcast_arp(argv[1])
