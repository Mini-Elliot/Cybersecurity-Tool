import re
import subprocess
import argparse
import os
import sys


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface",
                        help="Network interface to change its MAC address")
    parser.add_argument("-m", "--mac-address", dest="new_mac",
                        help="New MAC address to assign to the interface")
    args = parser.parse_args()
    if not args.interface:
        parser.error(
            "[-] Please specify a network interface. Use --interface or -i. (e.g., eth0, wlan0)")
    elif not args.new_mac:
        parser.error(
            "[-] Please provide a new MAC address. Use --mac-address or -m. (e.g., 00:11:22:33:44:55)")

    return args


def mac_changer(interface, new_mac):
    print(f"[+] Chaning MAC address for {interface} to {new_mac}")

    subprocess.call(["ifconfig", interface, "down"])
    subprocess.call(["ifconfig", interface, "hw",
                    "ether", new_mac])
    subprocess.call(["ifconfig", interface, "up"])


def get_current_MAC(interface):
    ifconfig_output = subprocess.check_output(["ifconfig", interface])
    print(ifconfig_output.decode())

    pattern = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"

    result = re.search(pattern, ifconfig_output.decode())

    if result:
        return result.group(0)
    else:
        print("[-] Sorry, Unable to read MAC Address")


def main():
    if os.geteuid() != 0:
        print("[-] Please run this script as sudo or as root.")
        exit()
    else:
        options = get_arguments()
        valid_mac = r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}"
        match = re.search(valid_mac, options.new_mac)
        if match:
            current_mac = get_current_MAC(options.interface)
            print("Current MAC = ", str(current_mac))

            mac_changer(options.interface, options.new_mac)

            current_mac = get_current_MAC(options.interface)

            if current_mac.lower() == options.interface.lower():
                print("New Mac > ", str(current_mac))
            else:
                print("Sorry, unable to change MAC Address")
        else:
            print("[-] Please enter a valid Mac Address.")
            sys.exit()


if __name__ == "__main__":
    main()
