#!/usr/bin/env python3
# DHCP RFCs: https://tools.ietf.org/html/rfc2131
#            https://tools.ietf.org/html/rfc2132
from enum import IntEnum, auto
from scapy import all as scapy


class DHCPType(IntEnum):
    DISCOVER = auto()
    OFFER = auto()
    REQUEST = auto()
    DECLINE = auto()
    ACK = auto()
    NAK = auto()
    RELEASE = auto()
    INFORM = auto()
    FORCE_RENEW = auto()
    LEASE_QUERY = auto()
    LEASE_UNASSIGNED = auto()
    LEASE_UNKNOWN = auto()
    LEASE_ACTIVE = auto()


USEFUL_DHCP_INFO = ['hostname', 'subnet_mask', 'lease_time', 'router',
                    'name_server', 'domain', 'vendor_class_id',
                    'requested_addr']


def handle_dhcp_packet(pkt):
    global USEFUL_DHCP_INFO

    if pkt.haslayer(scapy.DHCP):
        dhcp = pkt.getlayer(scapy.DHCP)
        dhcp_type = dhcp.options[0][1]
        dhcp_options = {key: value for key, value in dhcp.options[:-1]
                        if key in USEFUL_DHCP_INFO}
        hwsrc, src = pkt[scapy.Ether].src, pkt[scapy.IP].src

        if dhcp_type == DHCPType.DISCOVER:
            print("[+] DHCP DISCOVER")
            print(f"DHCP discover from {hwsrc}")
        elif dhcp_type == DHCPType.OFFER:
            print("[+] DHCP OFFER")
            offered_addr = pkt[scapy.BOOTP].yiaddr
            print(f"DHCP server {src} ({hwsrc}) offered {offered_addr}")
        elif dhcp_type == DHCPType.REQUEST:
            print("[+] DHCP REQUEST")
            print(f"DHCP request from {hwsrc}")
        elif dhcp_type == DHCPType.ACK:
            print("[+] DHCP ACK")
            acked_addr = pkt[scapy.BOOTP].yiaddr
            print(f"DHCP server {src} ({hwsrc}) acked {acked_addr}")
        elif dhcp_type == DHCPType.INFORM:
            print("[+] DHCP INFORM")
            print(f"DHCP inform from {src} ({hwsrc})")
        else:
            print("[-] UNHANDLED DHCP PACKET")

        print('\n'.join(f"{k}: {v}" for k, v in dhcp_options.items()))
        #  pkt.show()


if __name__ == "__main__":
    server_interface = "enp0s25"
    server_ip = "192.168.1.1"
    with open(f"/sys/class/net/{server_interface}/address", 'r') as fd:
        server_mac = fd.read().strip()

    scapy.sniff(iface=server_interface,
                filter="udp and (port 67 or 68)",
                prn=handle_dhcp_packet)
