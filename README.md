# 🛡️ CyberSecurity Toolkit - Educational Offensive Security Tools

This repository is a collection of essential cybersecurity tools designed for **educational use**, **network auditing**, and **authorized penetration testing**. These tools provide low-level access to network behavior and are widely used in ethical hacking practices.

> ⚠️ **WARNING:** These tools are strictly for **educational, ethical, and authorized use only**.  
> Unauthorized use against systems or networks you do not own or have explicit permission to test is **illegal** and punishable under cybercrime laws.  
> The developer is **not responsible** for any misuse or damage caused by these tools.

---

## 🚀 Tools Included

### 1. 🔄 MAC Address Changer

**Description:**  
Spoofs (changes) your MAC address temporarily to anonymize your device on a network.

**Use Cases:**
- Bypass MAC-based network filters
- Perform anonymity tests
- Reset DHCP leases

---

### 2. 🕵️ ARP Spoofing / ARP Poisoning Tool

**Description:**  
Performs ARP spoofing by sending forged ARP responses to redirect traffic through your device (Man-in-the-Middle attack).

**Use Cases:**
- Intercept unencrypted traffic for analysis
- Test IDS/IPS responses
- Evaluate network segmentation and trust boundaries

> ✏️ Automatically enables/disables IP forwarding depending on your OS.

---

### 3. 🌐 Network Scanner

**Description:**  
Scans the local network for live hosts and retrieves their IP and MAC addresses.

**Use Cases:**
- Identify active devices in a subnet
- Detect unauthorized devices on a network
- Reconnaissance in authorized assessments

---

### 4. 📡 Packet Sniffer

**Description:**  
Captures and analyzes raw packets on your network interface. Supports filtering by protocol (e.g., HTTP, DNS, ARP).

**Use Cases:**
- Monitor data transmission
- Protocol analysis and debugging
- Educational exploration of low-level networking

---

### 5. 🔐 Backdoor & Listener (Reverse Shell)

**Description:**  
A basic backdoor that establishes a reverse TCP connection to a listener for remote command execution.  
**Listener** waits for the incoming connection, then receives and sends commands to the backdoor.

**Use Cases:**
- Practice reverse shell mechanics
- Simulate payload delivery in lab environments
- Understand command-and-control (C2) basics

> ⚠️ **This tool is extremely sensitive and dangerous if misused. Only run it in isolated environments under your full control.**

---

## 🛠️ Requirements

- Python 3.x
- `scapy` (for scanner, sniffer, ARP spoofing)
- Root/Administrator privileges for some tools

Install dependencies using:

```bash
pip install scapy
