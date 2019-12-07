#!/usr/bin/env python3
"""
    Continously scans for WIFI networks using the 'iw list' command
    WARNING: VERY BAD CODE, NEEDS CLEANING UP
"""
import subprocess
import re
from time import sleep

ssid = re.compile(br"ESSID:\"(.*)\"")
address = re.compile(br"Address:\s*(.*)")
quality = re.compile(br"Quality=(\d*)\/(\d*)")
channel = re.compile(br"Channel:(\d*)")
wpa = re.compile(br"IE:\s(WPA)\sVersion\s1")
wpa2 = re.compile(br"IE:\sIEEE\s802\.11i/(WPA2)\sVersion\s1")


def print_results(iwlist):
    for cell in iwlist.split(b'Cell')[1:]:
        #
        cell_ssid = ssid.search(cell)
        cell_ssid = cell_ssid.group(1).decode() if cell_ssid else "Unknown"
        #
        cell_addr = address.search(cell)
        cell_addr = cell_addr.group(1).decode() if cell_addr else "Unknown"
        #
        cell_qual = quality.findall(cell)
        if cell_qual:
            value, divisor = cell_qual[0]
            cell_qual = (float(value) / float(divisor))*100
        #
        cell_chan = channel.search(cell)
        cell_chan = cell_chan.group(1).decode() if cell_chan else "Unknown"
        #
        cell_auth = ""
        cell_wpa = wpa.search(cell)
        cell_auth += cell_wpa.group(1).decode() + " " if cell_wpa else ""
        #
        cell_wpa2 = wpa2.search(cell)
        cell_auth += cell_wpa2.group(1).decode() if cell_wpa2 else ""

        print("{}\t\t{:4.3}%\t\t{:7}\t\t{:13}\t\t{}".format(cell_addr, cell_qual,
            cell_chan, cell_auth, cell_ssid))

def loop_iwlist(interface):
    try:
        while True:
            iwlist = subprocess.check_output(['sudo', 'iw', interface, 'scan'])
            print(iwlist)
            # subprocess.call(['clear'])
            # print("{:17}\t\t{}\t\t{}\t\t{:13}\t\t{}".format("Address", "Quality",
            #     "Channel", "Encryption", "ESSID"))
            # print("-"*80)
            # print_results(iwlist)
            sleep(3)
    except KeyboardInterrupt:
        return


if __name__ == "__main__":
    interface = "wlp4s0"
    loop_iwlist(interface)


