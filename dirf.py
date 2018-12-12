#!/usr/bin/env python3
"""
    dirf: Website Directory Fuzzing Tool
    Author: Yusef Karim
    TODO: Add directory traversal
"""
import argparse
import requests

def get_words(wordlist, extension):
    with open(wordlist) as f:
        if extension:
            words = [line.rstrip('\n') + extension for line in f]
        else:
            words = [line.rstrip('\n') for line in f]

    return words

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Website Directory Fuzzing Tool")
    parser._action_groups.pop()
    req = parser.add_argument_group("required arguments")
    opt = parser.add_argument_group("optional arguments")
    req.add_argument("-t", "--target", type=str, required=True,
                     help="http(s)://TARGET:PORT")
    req.add_argument("-w", "--wordlist", type=str, required=True)
    opt.add_argument("-e", "--ext", type=str,
                     help="Adds an extension onto each word in your word list")
    args = parser.parse_args()


    words = get_words(args.wordlist, args.ext)

    if not args.target.endswith('/'):
        args.target = args.target + '/'

    for word in words:
        url = args.target + word
        r = requests.get(url)
        if(r.status_code != 404):
            print("[+] Status Code {}\t{}".format(r.status_code, url))


