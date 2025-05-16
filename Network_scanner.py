import scapy.all as scapy
import argparse
import sys
import csv
import json

# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"

#terminal argument parser
def get_arguments():
    """
    Parse and Validate command line arguments
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Use this to specify the IP Address or range of IP Addresses. For example: 192.168.0.0 or 127.0.0.1/24")
    parser.add_argument('-v', "--verbose", dest="verbose", action="store_true", help="Show additional information about scanning.")
    args = parser.parse_args()
    if not args.target:
        parser.error("[-] Please specify the IP Address.")
    return args


options = get_arguments()

#network scanner function
def scan(ip):
    """
    Perform an ARP scan on provided IP address or range.
    """
    try:
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast/request
        answered = scapy.srp(packet, timeout=1, verbose=(options.verbose or False))[0]
        client_list = []
        for element in answered:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict)
        return client_list
    except Exception as e:
        print(f"[-] Error in Scanning: {e}")
        sys.exit(1)

# save results to a file
def save_results(results_list):
    save_choice = input(
        "Do you want save the results?(yes/no) > ").strip().lower()
    if save_choice == "yes":
        filename = input("Enter filename > ")
        format_type = input(
            "Enter the file format(txt, csv, json) > ").strip().lower()
        try:
            if format_type == "txt":
                with open(f"{filename}", "w") as f:
                    f.write("-"*100)
                    f.write(f"\nIP(s)\t\t\tMAC Address\n")
                    f.write("-"*100+"\n")
                    for client in results_list:
                        f.write(f"{client["ip"]}\t\t\t{client["mac"]}\n")
                    f.write("="*100)
                print(f"[+] Saving results in {filename}.{format_type}")
            elif format_type == "csv":
                with open(f"{filename}", "w", newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["ip", "mac"])
                    writer.writeheader()
                    writer.writerows(results_list)
                print(f"[+] Results save to {filename}.{format_type}")
            elif format_type == "json":
                with open(f"{filename}", "w") as f:
                    json.dump(results_list, f, indent=4)
                print(f"[+] Results save to {filename}.{format_type}")
        except Exception as e:
            print(f"Error while saving {e}")
    elif save_choice == "no":
        print("[-] The results above will remain visible until you close this terminal.")
        sys.exit()
    else:
        print(f"{RED}[!] Invalid option selected. The results above will remain visible until you close this terminal.{RESET}")
        sys.exit(1)

#print results on the screen
def print_results(results_list):
    """
    Print the results of scan
    """
    if not results_list:
        print("[-] Sorry, no device found.")
        return
    print("-"*100)
    print("IP(s)\t\t\tMAC Address")
    print("-"*100)
    for client in results_list:
        print(f"{client['ip']}\t\t\t{client['mac']}")
    print("="*100)
    save_results(results_list)

def main():
    """
    Main function to execute program
    """
    print("[+] Starting Network Scanner")
    scan_result = scan(options.target)
    print_results(scan_result)


if __name__ == "__main__":
    main()
