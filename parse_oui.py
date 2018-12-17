#!/usr/bin/env python3
from requests import get
from os.path import exists
from re import findall
import json

def get_oui_file(url):
    # TODO: change to check last day updated
    if not exists("oui.txt"):
        print("[+] Fetching OUI text file from {}".format(url))
        r = get(url)
        if r.status_code == 200:
            with open("oui.txt", 'wb') as fd:
                fd.write(r.content)

def parse_oui_file_to_json():
    # TODO: change to check last day updated
    if exists("oui.json"):
        return

    with open("oui.txt", 'r') as fd:
        oui_contents = fd.read()
        oui_list = findall("(\w*)\s*\(base 16\)\s*(.*)", oui_contents)

    oui_dict = {}
    for oui, company in oui_list:
        oui = ":".join([oui.lower()[i:i+2] for i in range(0, len(oui), 2)])
        oui_dict[oui] = company

    with open("oui.json", 'w') as fd:
        json.dump(oui_dict, fd)

def read_oui_json_file():
    with open("oui.json", 'r') as fd:
        return json.load(fd)

if __name__ == "__main__":
    get_oui_file("http://standards-oui.ieee.org/oui/oui.txt")
    parse_oui_file_to_json()
    oui_dict = read_oui_json_file()
    print(oui_dict['74:da:da'])


