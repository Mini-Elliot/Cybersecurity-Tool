# 🛡️ CyberSecurity Toolkit - Educational Offensive Security Tools

This repository is a collection of essential cybersecurity tools designed for **educational use**, **network auditing**, and **authorized penetration testing**. These tools provide low-level access to network behavior and are widely used in ethical hacking practices.

> ⚠️ **These tools are for authorized, ethical, and educational use only. Misuse can result in criminal prosecution. You have been warned.**

---

## 🚀 Tools Included

### 1. 🔄 MAC Address Changer

**Description:**  
Allows you to spoof (change) your MAC address temporarily to anonymize your device on a network.

**Use Cases:**
- Bypass MAC-based network filters
- Perform anonymity tests
- Reset DHCP leases

### 2. 🕵️ ARP Spoofing / ARP Poisoning Tool

**Description:**  
Performs ARP spoofing attacks by sending forged ARP responses to redirect network traffic through your device (Man-in-the-Middle).

**Use Cases:**
- Intercept unencrypted traffic for analysis
- Test IDS/IPS responses
- Evaluate network segmentation and trust relationships

> ✏️ Automatically enables and disables IP forwarding depending on your OS.

### 3. 🌐 Network Scanner

**Description:**  
Scans the local network for live hosts and retrieves their IP and MAC addresses.

**Use Cases:**
- Identify active devices in a subnet
- Detect unauthorized devices on a corporate or home network
- Perform recon as part of ethical hacking assessments

### 4. 📡 Packet Sniffer

**Description:**  
Captures and analyzes raw packets on your network interface. Allows filtering by protocol (e.g., HTTP, DNS, ARP).

**Use Cases:**
- Monitor data sent over a network
- Debug and audit protocols
- Learn how protocols operate at low levels

---

## 🛠️ Requirements

- Python 3.x
- `scapy`
- Administrative/root privileges

Install dependencies using:

```bash
pip install scapy
