#!/usr/bin/env python3
"""
    psniff: Uses Scapy as a packet sniffer. All TCP and UDP packets are saved into
            a JSON file at the end of the program. The program will notify the user
            if any interesting keywords are found in any of the packet payloads.
    Author: Yusef Karim

    NOTE: I am storing data temporarily in a python shelve data structure. I think
          this uses an external storage file instead of taking up program memory.
          I have not confirmed if this is actually what is happening.

    * Setting promiscuous mode (optional):
        ip link set dev INTERFACE promisc on/off
    * Example HTTP site for testing:
        http://www.imagebam.com/login
"""
##### Scapy modules #####
from scapy.sendrecv import sniff
from scapy.packet import Raw
from scapy.layers.inet import IP, TCP, UDP
from scapy.utils import hexstr
##### Other python3 modules #####
import re
import shelve
import json
from signal import signal, SIGINT
from sys import exit, argv
from os import getuid, remove

global OUTPUT_FILE
TEMP_STORAGE_FILE = "packets.temp"
TEMP_STORAGE = shelve.open(TEMP_STORAGE_FILE)
INTEREST_REGEX =re.compile("(log(\w+)?|pass(\w+)?|user(\w+)?|pw(\w+)?|nick(\w+)?)(\.\w+)?")
URL_REGEX = re.compile("https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(/[0-9a-zA-Z]+)+")
PACKET_COUNT = 0

def writeDataAndCleanUp(signum, frame):
    global TEMP_STORAGE
    packets = {}
    print("\n[+] Cleaning up and exporting packet data to {}".format(OUTPUT_FILE))
    for i in range(len(TEMP_STORAGE)):
        packets[str(i)] = TEMP_STORAGE[str(i)]

    with open(OUTPUT_FILE, 'w') as f:
        f.write(json.dumps(packets, indent=4, sort_keys=True))

    TEMP_STORAGE.close()
    remove(TEMP_STORAGE_FILE)
    print("[+] Done, all your packets are stored as JSON in {}".format(OUTPUT_FILE))
    exit(0)


def getAllLayers(pkt):
    yield pkt.name
    while pkt.payload:
        pkt = pkt.payload
        yield pkt.name


def print_interesting_things(raw_data):
    thing = INTEREST_REGEX.search(raw_data)
    if(thing):
        url = URL_REGEX.search(raw_data)
        if(url):
            print("\r[+] Possible login information in packet {:4}--> "
                    "URL: {:20}".format(str(PACKET_COUNT), url.group(0)))
        else:
            print("\r[+] Possible login information in packet {:40}".format(
                  str(PACKET_COUNT)))


def pktCallback(pkt):
    global PACKET_COUNT
    packet = { 'layers': [] }

    all_layers = list(getAllLayers(pkt))
    print("\r[+] Collected {} packets | Current packet contains {:40}".format(
          PACKET_COUNT, ":".join(all_layers)), end='')
    packet['layers'] = all_layers

    # -------------------- IP  --------------------
    if(pkt.haslayer(IP)):
        ip = pkt.getlayer(IP)
        packet[ip.name] = {}
        packet[ip.name]['ttl'] = ip.ttl
        packet[ip.name]['protocol'] = ip.proto
        packet[ip.name]['src'] = ip.src
        packet[ip.name]['dst'] = ip.dst

    # -------------------- TCP  --------------------
    if(pkt.haslayer(TCP)):
        tcp = pkt.getlayer(TCP)
        packet[tcp.name] = {}
        packet[tcp.name]['sport'] = tcp.sport
        packet[tcp.name]['dport'] = tcp.dport
        packet[tcp.name]['seq'] = tcp.seq
        packet[tcp.name]['ack'] = tcp.ack
        packet[tcp.name]['flags'] = str(tcp.flags)

    # -------------------- UDP  --------------------
    if(pkt.haslayer(UDP)):
        udp = pkt.getlayer(UDP)
        packet[udp.name] = {}
        packet[udp.name]['sport'] = udp.sport
        packet[udp.name]['dport'] = udp.dport
        packet[udp.name]['len'] = udp.len

    # -------------------- RAW  --------------------
    if(pkt.haslayer(Raw)):
        raw = pkt.getlayer(Raw).load
        raw_ascii = hexstr(raw, onlyasc=True)
        print_interesting_things(raw_ascii)
        packet['raw'] = raw_ascii

    # Write packet to temporary external data structure
    TEMP_STORAGE[str(PACKET_COUNT)] = packet
    PACKET_COUNT += 1



if __name__ == "__main__":
    signal(SIGINT, writeDataAndCleanUp)
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    elif(len(argv) != 4):
        print("[-] Invalid number of arguments\n"
              "[+] USAGE: {} <INTERFACE> <TARGET IP> <OUTPUT FILENAME>".format(__file__))
        exit(2)
    else:
        OUTPUT_FILE = argv[3]
        target_filter = "host {}".format(argv[2])
        print("[+] Starting packet capture on {}, press ctrl-c to quit".format(argv[1]))
        sniff(filter=target_filter, iface=argv[1], count=0, prn=pktCallback, store=False)


