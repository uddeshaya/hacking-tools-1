#!/usr/bin/env python3
"""
    macchanger: Simple MAC Address Changer
    Author: Yusef Karim
"""
from os import getuid
from sys import exit, argv
from re import match, search
from subprocess import call, check_output

def change_mac(interface,  new_mac_addr):
    if(call(['ip', 'link', 'set', interface, 'down']) != 0):
        exit(1)
    elif(call(['ip', 'link', 'set', interface, 'address', new_mac_addr]) != 0):
        exit(2)
    elif(call(['ip', 'link', 'set', interface, 'up']) != 0):
        exit(3)
    else:
        addr_output = check_output(['ip', 'addr', 'show', interface]).decode('ascii')
        curr_mac = search("(?:[0-9a-fA-F]:?){12}", addr_output).group(0)
        if(curr_mac == new_mac_addr):
            print("[+] MAC Address of {} changed to {}".format(interface, new_mac_addr))
        else:
            print("[-] Changing the MAC Address of {} FAILED!".format(interface))


if __name__ == "__main__":
    if(getuid() != 0):
        print("[-] This program must be run as root")
        exit(1)
    elif(len(argv) != 3):
        print("[-] Invalid number of arguments\n"
              "[+] USAGE: {} <INTERFACE> <MAC ADDRESS>".format(__file__))
        exit(2)
    elif(not match("(?:[0-9a-fA-F]:?){12}$", argv[2])):
        print("[-] Invalid MAC Address, fix it you idiot")
        exit(3)
    else:
        change_mac(argv[1], argv[2])

