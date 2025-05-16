import re
import subprocess
import argparse
import os
import sys

#terminal argument parser
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface to change its MAC address")
    parser.add_argument("-m", "--mac-address", dest="new_mac", help="New MAC address which has to be assigned to the interface")
    args = parser.parse_args()
    if not args.interface:
        parser.error("[-] Please specify a network interface. Use --interface or -i. (e.g., eth0, wlan0)")
    elif not args.new_mac:
        parser.error("[-] Please provide a new MAC address. Use --mac-address or -m. (e.g., 00:11:22:33:44:55)")
    return args

#mac address changing function
def mac_changer(interface, new_mac):
    print(f"[+] Changing MAC address for {interface} to {new_mac}")

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw", "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])

#get current mac address
def get_current_mac(interface):
    ifconfig_output = subprocess.check_output(["ifconfig", interface])
    print(ifconfig_output.decode())

    pattern = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"

    match = re.search(pattern, ifconfig_output.decode())

    if match:
        return match.group(0)
    else:
        print("[-] Sorry, Unable to read MAC Address")

#main function
def main():
    if os.geteuid() != 0:
        print("[-] Please run this script with sudo or as root.")
        sys.exit()
    else:
        options = get_arguments()
        valid_mac = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
        match = re.search(valid_mac, options.new_mac)
        if match:
            current_mac = get_current_mac(options.interface)
            print("[+] Current MAC Address > ", str(current_mac))

            mac_changer(options.interface, options.new_mac)

            current_mac = get_current_mac(options.interface)

            try: 
                if current_mac.lower() == options.interface.lower():
                    print("[+] New Mac Address > ", str(current_mac))
            except Exception as e:
                print(f"[-] Sorry, unable to change MAC Address: {e}")
        else:
            print("[-] Please enter a valid Mac Address.")
            sys.exit()


if __name__ == "__main__":
    main()
