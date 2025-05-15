# 🛡️ CyberSecurity Toolkit - Educational Offensive Security Tools

This repository is a collection of essential cybersecurity tools designed for **educational use**, **network auditing**, and **authorized penetration testing**. These tools provide low-level access to network behavior and are widely used in ethical hacking practices.

> ⚠️ **WARNING:** These tools are strictly for **educational, ethical, and authorized use only**.  
> Unauthorized use against systems or networks you do not own or have explicit permission to test is **illegal** and punishable under cybercrime laws.  
> I am **not responsible** for any misuse or damage caused by these tools.

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

### 6. 🧪 File Interceptor (HTTP File Replacement)

**Description:**  
Intercepts HTTP requests and responses to identify `.exe` download attempts and replaces them with a fake redirect (e.g., 301 to another file or URL).

**Use Cases:**
- Demonstrate HTTP response tampering  
- Simulate file replacement in MiTM scenarios  
- Test detection by endpoint or IDS/IPS systems

> ⚠️ Requires root privileges and sets up `iptables` rules to redirect traffic via `NFQUEUE`.

---

### 7. 🌍 DNS Spoofer

**Description:**  
Intercepts DNS response packets and forges DNS answers (e.g., redirecting `www.bing.com` to a chosen IP address).

**Use Cases:**
- Practice DNS poisoning in lab environments  
- Demonstrate DNS-based redirection attacks  
- Evaluate DNS resolution vulnerabilities

> ⚠️ Use only on test networks with devices you control. Automatically hooks into `iptables` to forward DNS packets via `NFQUEUE`.

---

### 8. ⌨️ Keylogger (Educational)

**Description:**  
Logs all keystrokes and periodically sends the log to a configured email address.

**Use Cases:**
- Demonstrate how keylogging works  
- Simulate credential theft in labs  
- Understand key event monitoring

> ⚠️ **Highly sensitive tool!** Only run in controlled, isolated environments where you have explicit authorization.

---

## 🛠️ Requirements

- Python 3.x
- Administrator/root privileges (for certain tools)
- Linux is recommended for full feature support (especially for packet interception tools)

### 🧩 Python Modules

Install dependencies using pip:

```bash
pip install scapy netfilterqueue pynput
